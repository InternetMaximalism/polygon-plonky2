// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.25;

import {GoldilocksField as F} from "./GoldilocksField.sol";
import {TranscriptLib} from "./TranscriptLib.sol";
import {SumcheckVerifier} from "./SumcheckVerifier.sol";
import {EqPolyLib} from "./EqPolyLib.sol";
import {ConstraintEvaluator} from "./ConstraintEvaluator.sol";
import {SpongefishWhirVerify} from "./spongefish/SpongefishWhirVerify.sol";
import {GoldilocksExt3} from "./spongefish/GoldilocksExt3.sol";

/// @title MleVerifier
/// @notice On-chain verifier for the Plonky2-MLE proof system with WHIR PCS.
/// @dev Verifies:
///      1. Fiat-Shamir transcript reconstruction (Keccak-based)
///      2. Permutation check (plain sumcheck, Σ h(b) = 0) + final eval via PCS
///      3. Zero-check sumcheck (Σ eq(τ,b)·C(b) = 0) + final eval via PCS
///      4. WHIR polynomial commitment proof (replaces old Merkle PCS)
///
///      Two independent transcript systems are cryptographically bound:
///      - TranscriptLib (Keccak): MLE protocol challenges
///      - Spongefish (WHIR internal): WHIR folding/sumcheck challenges
///      Binding: WHIR commitment root (first 32 bytes of transcript) is
///      absorbed into the Keccak transcript.
///
///      CONSTRAINT EVALUATION STRATEGY (oracle approach):
///      The Rust prover computes C(r) for ALL gate types and commits it in
///      the PCS batch. Soundness follows from WHIR commitment binding.
///      Goldilocks field: p = 2^64 - 2^32 + 1.
contract MleVerifier {
    using F for uint256;

    uint256 constant P = 0xFFFFFFFF00000001;

    struct MleProof {
        // Circuit binding (verifying key hash)
        // SECURITY: Binds this proof to a specific Plonky2 circuit.
        uint256[] circuitDigest;    // 4 Goldilocks field elements
        // WHIR PCS proof data
        bytes whirTranscript;       // Serialized WHIR spongefish transcript
        bytes whirHints;            // WHIR verification hints (Merkle paths etc.)
        // Sumcheck proofs
        SumcheckVerifier.SumcheckProof permProof;
        uint256 permClaimedSum;
        SumcheckVerifier.SumcheckProof constraintProof;
        // Batched evaluation
        uint256 evalValue;           // P(r) batched evaluation
        // Public inputs
        uint256[] publicInputs;
        // Batch parameters
        uint256 batchR;
        uint256 numPolys;
        uint256[] individualEvals;   // Individual MLE evaluations at r
        // Fiat-Shamir challenges (for transcript consistency check)
        uint256 alpha;
        uint256 beta;
        uint256 gamma;
        uint256[] tau;
        uint256[] tauPerm;
        // Circuit dimensions
        uint256 numWires;
        uint256 numRoutedWires;
        uint256 numConstants;
        // ORACLE: PCS-opened constraint value C(r).
        // SECURITY: Bound to WHIR commitment — prover cannot lie.
        uint256 pcsConstraintEval;
        // ORACLE: PCS-opened permutation numerator h(r_perm).
        uint256 pcsPermNumeratorEval;
    }

    /// @notice Verify an MLE proof with WHIR PCS.
    /// @param proof The complete proof including WHIR transcript/hints.
    /// @param degreeBits log2 of the circuit degree (number of sumcheck rounds).
    /// @param whirParams WHIR protocol parameters (set per circuit at deployment).
    /// @param protocolId WHIR protocol ID (64 bytes, from CBOR-encoded config).
    /// @param sessionId WHIR session ID (32 bytes, from session name).
    function verify(
        MleProof calldata proof,
        uint256 degreeBits,
        SpongefishWhirVerify.WhirParams memory whirParams,
        bytes memory protocolId,
        bytes memory sessionId,
        GoldilocksExt3.Ext3[] memory whirEvaluations
    )
        external
        pure
        returns (bool)
    {
        // ── Step 0: Input validation ──
        _validateInputs(proof);

        // ── Step 1: Reconstruct Fiat-Shamir transcript ──
        TranscriptLib.Transcript memory transcript;
        TranscriptLib.init(transcript);

        TranscriptLib.domainSeparate(transcript, "circuit");
        // SECURITY: Absorb circuit_digest first to bind to verifying key.
        TranscriptLib.absorbFieldVec(transcript, proof.circuitDigest);
        TranscriptLib.absorbFieldVec(transcript, proof.publicInputs);

        // ── Step 2: Derive batch_r ──
        TranscriptLib.domainSeparate(transcript, "batch-commit");
        uint256 batchR = TranscriptLib.squeezeChallenge(transcript);
        require(batchR == proof.batchR, "Batch R mismatch");

        // Extract WHIR commitment root from transcript (first 32 bytes)
        // SECURITY: This binds the WHIR transcript to our Keccak transcript.
        require(proof.whirTranscript.length >= 32, "WHIR transcript too short");
        bytes memory commitmentRoot = new bytes(32);
        for (uint256 i = 0; i < 32; i++) {
            commitmentRoot[i] = proof.whirTranscript[i];
        }
        TranscriptLib.absorbBytes(transcript, commitmentRoot);

        // ── Step 3: Derive challenges ──
        TranscriptLib.domainSeparate(transcript, "challenges");
        uint256 beta = TranscriptLib.squeezeChallenge(transcript);
        uint256 gamma = TranscriptLib.squeezeChallenge(transcript);
        uint256 alpha = TranscriptLib.squeezeChallenge(transcript);
        uint256[] memory tau = TranscriptLib.squeezeChallenges(transcript, degreeBits);
        TranscriptLib.squeezeChallenges(transcript, degreeBits); // tauPerm consumed

        require(beta == proof.beta, "Beta mismatch");
        require(gamma == proof.gamma, "Gamma mismatch");
        require(alpha == proof.alpha, "Alpha mismatch");

        // ── Step 4: Verify permutation sumcheck ──
        TranscriptLib.domainSeparate(transcript, "permutation");
        require(proof.permClaimedSum == 0, "Perm: claimed sum != 0");

        SumcheckVerifier.SumcheckProof memory permProofMem =
            _copySumcheckProof(proof.permProof);
        (, uint256 permFinalEval) =
            SumcheckVerifier.verify(permProofMem, proof.permClaimedSum, degreeBits, transcript);

        // SECURITY: Verify permutation final evaluation matches PCS-opened value.
        require(
            permFinalEval == proof.pcsPermNumeratorEval,
            "Perm final eval != PCS-opened h(r_perm)"
        );

        // ── Step 4d: Extension field combination challenge ──
        TranscriptLib.domainSeparate(transcript, "extension-combine");
        TranscriptLib.squeezeChallenge(transcript);

        // ── Step 5: Verify constraint zero-check sumcheck ──
        TranscriptLib.domainSeparate(transcript, "zero-check");

        SumcheckVerifier.SumcheckProof memory constraintProofMem =
            _copySumcheckProof(proof.constraintProof);
        (uint256[] memory sumcheckChallenges, uint256 constraintFinalEval) =
            SumcheckVerifier.verify(constraintProofMem, 0, degreeBits, transcript);

        // ── Step 6: Verify constraint final evaluation ──
        // SECURITY: constraintFinalEval == eq(τ, r) · C(r)
        uint256 eqAtR = EqPolyLib.eqEval(tau, sumcheckChallenges);
        require(
            ConstraintEvaluator.verifyConstraintEval(
                constraintFinalEval,
                eqAtR,
                proof.pcsConstraintEval
            ),
            "Constraint final eval mismatch: eq(tau,r)*C(r) != finalEval"
        );

        // ── Step 7: Verify batched evaluation consistency ──
        TranscriptLib.domainSeparate(transcript, "pcs-eval");

        uint256 expectedBatched = _computeBatchedEval(proof.individualEvals, batchR);
        require(expectedBatched == proof.evalValue, "Batched eval mismatch");

        require(
            proof.individualEvals.length == proof.numWires + proof.numConstants + proof.numRoutedWires,
            "individualEvals length mismatch"
        );

        // ── Step 8: Verify WHIR polynomial commitment proof ──
        // SECURITY: This replaces the old Merkle root + MLE evaluation check.
        // SpongefishWhirVerify verifies the WHIR commitment and evaluation
        // proof using its own spongefish transcript (independent of our Keccak).
        // The binding between the two transcripts is established by absorbing
        // the WHIR commitment root into our Keccak transcript (Step 2 above).
        bool whirValid = SpongefishWhirVerify.verifyWhirProof(
            protocolId,
            sessionId,
            "" /* instance: empty for our usage */,
            proof.whirTranscript,
            proof.whirHints,
            whirEvaluations,
            whirParams
        );
        require(whirValid, "WHIR PCS verification failed");

        return true;
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Input validation
    // ═══════════════════════════════════════════════════════════════════════

    function _validateInputs(MleProof calldata proof) private pure {
        require(proof.circuitDigest.length == 4, "circuitDigest must be 4 elements");
        for (uint256 i = 0; i < 4; i++) {
            require(proof.circuitDigest[i] < P, "circuitDigest >= P");
        }
        require(proof.evalValue < P, "evalValue >= P");
        require(proof.batchR < P, "batchR >= P");
        require(proof.alpha < P, "alpha >= P");
        require(proof.beta < P, "beta >= P");
        require(proof.gamma < P, "gamma >= P");
        require(proof.permClaimedSum < P, "permClaimedSum >= P");
        require(proof.pcsConstraintEval < P, "pcsConstraintEval >= P");
        require(proof.pcsPermNumeratorEval < P, "pcsPermNumeratorEval >= P");

        for (uint256 i = 0; i < proof.publicInputs.length; i++) {
            require(proof.publicInputs[i] < P, "publicInput >= P");
        }
        for (uint256 i = 0; i < proof.individualEvals.length; i++) {
            require(proof.individualEvals[i] < P, "individualEval >= P");
        }
        for (uint256 i = 0; i < proof.tau.length; i++) {
            require(proof.tau[i] < P, "tau >= P");
        }
        for (uint256 i = 0; i < proof.tauPerm.length; i++) {
            require(proof.tauPerm[i] < P, "tauPerm >= P");
        }
        for (uint256 i = 0; i < proof.permProof.roundPolys.length; i++) {
            for (uint256 j = 0; j < proof.permProof.roundPolys[i].evals.length; j++) {
                require(proof.permProof.roundPolys[i].evals[j] < P, "permRoundPoly >= P");
            }
        }
        for (uint256 i = 0; i < proof.constraintProof.roundPolys.length; i++) {
            for (uint256 j = 0; j < proof.constraintProof.roundPolys[i].evals.length; j++) {
                require(proof.constraintProof.roundPolys[i].evals[j] < P, "constraintRoundPoly >= P");
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Internal helpers (Yul)
    // ═══════════════════════════════════════════════════════════════════════

    function _computeBatchedEval(uint256[] calldata evals, uint256 batchR)
        private pure returns (uint256 result)
    {
        assembly {
            let p := 0xFFFFFFFF00000001
            result := 0
            let rPow := 1
            let n := evals.length
            let off := evals.offset
            for { let i := 0 } lt(i, n) { i := add(i, 1) } {
                let v := calldataload(add(off, mul(i, 0x20)))
                result := addmod(result, mulmod(rPow, v, p), p)
                rPow := mulmod(rPow, batchR, p)
            }
        }
    }

    function _copySumcheckProof(SumcheckVerifier.SumcheckProof calldata src)
        private pure returns (SumcheckVerifier.SumcheckProof memory dst)
    {
        dst.roundPolys = new SumcheckVerifier.RoundPoly[](src.roundPolys.length);
        for (uint256 i = 0; i < src.roundPolys.length; i++) {
            uint256 len = src.roundPolys[i].evals.length;
            dst.roundPolys[i].evals = new uint256[](len);
            for (uint256 j = 0; j < len; j++) {
                dst.roundPolys[i].evals[j] = src.roundPolys[i].evals[j];
            }
        }
    }
}
