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
/// @dev Two-commitment architecture:
///      - Preprocessed commitment (constants + sigmas): bound to VK
///      - Witness commitment (wires): per-proof
///
///      SECURITY: The preprocessedCommitmentRoot parameter is the VK.
///      It binds the verifier to a specific circuit's constants and
///      permutation routing. Without it, an attacker could substitute
///      fabricated constants/sigmas that trivially satisfy all constraints.
///
///      Two independent WHIR session names prevent cross-protocol confusion:
///      - Preprocessed: "plonky2-mle-whir-preprocessed"
///      - Witness: "plonky2-mle-whir-witness"
///
///      Goldilocks field: p = 2^64 - 2^32 + 1.
contract MleVerifier {
    using F for uint256;

    uint256 constant P = 0xFFFFFFFF00000001;

    struct MleProof {
        // Circuit binding (verifying key hash)
        // SECURITY: Binds this proof to a specific Plonky2 circuit.
        uint256[] circuitDigest;    // 4 Goldilocks field elements

        // ── Preprocessed PCS (constants + sigmas) ────────────────────────
        bytes preprocessedWhirTranscript;   // WHIR proof for preprocessed polynomial
        bytes preprocessedWhirHints;
        uint256 preprocessedEvalValue;      // Batched eval for preprocessed
        uint256 preprocessedBatchR;         // Deterministic from circuit_digest
        uint256[] preprocessedIndividualEvals; // [const_0..C, sigma_0..R]

        // ── Witness PCS (wires) ──────────────────────────────────────────
        bytes witnessWhirTranscript;        // WHIR proof for witness polynomial
        bytes witnessWhirHints;
        uint256 witnessEvalValue;           // Batched eval for witness
        uint256 witnessBatchR;              // Fiat-Shamir derived
        uint256[] witnessIndividualEvals;   // [wire_0..W]

        // ── Sumcheck proofs ──────────────────────────────────────────────
        SumcheckVerifier.SumcheckProof permProof;
        uint256 permClaimedSum;
        SumcheckVerifier.SumcheckProof constraintProof;

        // ── Public data ──────────────────────────────────────────────────
        uint256[] publicInputs;
        uint256 alpha;
        uint256 beta;
        uint256 gamma;
        uint256[] tau;
        uint256[] tauPerm;

        // ── Circuit dimensions ───────────────────────────────────────────
        uint256 numWires;
        uint256 numRoutedWires;
        uint256 numConstants;

        // ── Oracle values (PCS-bound) ────────────────────────────────────
        uint256 pcsConstraintEval;
        uint256 pcsPermNumeratorEval;
    }

    /// @notice Verify an MLE proof with two-commitment WHIR PCS.
    /// @param proof The complete proof with preprocessed and witness WHIR data.
    /// @param degreeBits log2 of the circuit degree (number of sumcheck rounds).
    /// @param preprocessedCommitmentRoot VK: expected WHIR Merkle root for preprocessed polynomial.
    /// @param whirParams WHIR protocol parameters (shared between both commitments).
    /// @param protocolId WHIR protocol ID (64 bytes, shared).
    /// @param preprocessedSessionId WHIR session ID for preprocessed (32 bytes).
    /// @param witnessSessionId WHIR session ID for witness (32 bytes).
    /// @param preprocessedWhirEvals WHIR Ext3 evaluations for preprocessed.
    /// @param witnessWhirEvals WHIR Ext3 evaluations for witness.
    function verify(
        MleProof calldata proof,
        uint256 degreeBits,
        bytes32 preprocessedCommitmentRoot,
        SpongefishWhirVerify.WhirParams memory whirParams,
        bytes memory protocolId,
        bytes memory preprocessedSessionId,
        bytes memory witnessSessionId,
        GoldilocksExt3.Ext3[] memory preprocessedWhirEvals,
        GoldilocksExt3.Ext3[] memory witnessWhirEvals
    )
        external
        pure
        returns (bool)
    {
        // ── Step 0: Input validation ──
        _validateInputs(proof);

        // ── Step 1: Verify preprocessed batch_r is correctly derived ──
        // SECURITY: preprocessedBatchR must be deterministic from circuitDigest.
        // This prevents the prover from choosing a favorable batching scalar.
        uint256 expectedPreBatchR = _derivePreprocessedBatchR(proof.circuitDigest);
        require(expectedPreBatchR == proof.preprocessedBatchR, "Preprocessed batch_r mismatch");

        // ── Step 2: VK binding check ──
        // SECURITY: The first 32 bytes of the preprocessed WHIR transcript are
        // the commitment root. This must match the VK parameter to ensure the
        // prover used the correct constants and sigma permutation values.
        require(proof.preprocessedWhirTranscript.length >= 32, "Preprocessed WHIR transcript too short");
        bytes memory preRootBytes = _extractFirst32(proof.preprocessedWhirTranscript);
        bytes32 proofPreRoot;
        assembly {
            proofPreRoot := mload(add(preRootBytes, 0x20))
        }
        require(
            proofPreRoot == preprocessedCommitmentRoot,
            "VK binding violated: preprocessed commitment root mismatch"
        );

        // ── Step 3: Reconstruct Fiat-Shamir transcript ──
        TranscriptLib.Transcript memory transcript;
        TranscriptLib.init(transcript);

        TranscriptLib.domainSeparate(transcript, "circuit");
        TranscriptLib.absorbFieldVec(transcript, proof.circuitDigest);
        TranscriptLib.absorbFieldVec(transcript, proof.publicInputs);

        // Absorb preprocessed commitment root into transcript
        // SECURITY: This binds subsequent challenges to the preprocessed polynomial.
        TranscriptLib.absorbBytes(transcript, preRootBytes);

        // ── Step 4: Derive witness batch_r ──
        TranscriptLib.domainSeparate(transcript, "batch-commit-witness");
        uint256 witnessBatchR = TranscriptLib.squeezeChallenge(transcript);
        require(witnessBatchR == proof.witnessBatchR, "Witness batch_r mismatch");

        // Absorb witness commitment root
        require(proof.witnessWhirTranscript.length >= 32, "Witness WHIR transcript too short");
        bytes memory witRootBytes = _extractFirst32(proof.witnessWhirTranscript);
        TranscriptLib.absorbBytes(transcript, witRootBytes);

        // ── Step 5: Derive challenges ──
        TranscriptLib.domainSeparate(transcript, "challenges");
        uint256 beta = TranscriptLib.squeezeChallenge(transcript);
        uint256 gamma = TranscriptLib.squeezeChallenge(transcript);
        uint256 alpha = TranscriptLib.squeezeChallenge(transcript);
        uint256[] memory tau = TranscriptLib.squeezeChallenges(transcript, degreeBits);
        TranscriptLib.squeezeChallenges(transcript, degreeBits); // tauPerm consumed

        require(beta == proof.beta, "Beta mismatch");
        require(gamma == proof.gamma, "Gamma mismatch");
        require(alpha == proof.alpha, "Alpha mismatch");

        // ── Step 6: Verify permutation sumcheck ──
        TranscriptLib.domainSeparate(transcript, "permutation");
        require(proof.permClaimedSum == 0, "Perm: claimed sum != 0");

        SumcheckVerifier.SumcheckProof memory permProofMem =
            _copySumcheckProof(proof.permProof);
        (, uint256 permFinalEval) =
            SumcheckVerifier.verify(permProofMem, proof.permClaimedSum, degreeBits, transcript);

        require(
            permFinalEval == proof.pcsPermNumeratorEval,
            "Perm final eval != PCS-opened h(r_perm)"
        );

        // ── Step 7: Extension field combination challenge ──
        TranscriptLib.domainSeparate(transcript, "extension-combine");
        TranscriptLib.squeezeChallenge(transcript);

        // ── Step 8: Verify constraint zero-check sumcheck ──
        TranscriptLib.domainSeparate(transcript, "zero-check");

        SumcheckVerifier.SumcheckProof memory constraintProofMem =
            _copySumcheckProof(proof.constraintProof);
        (uint256[] memory sumcheckChallenges, uint256 constraintFinalEval) =
            SumcheckVerifier.verify(constraintProofMem, 0, degreeBits, transcript);

        // ── Step 9: Verify constraint final evaluation ──
        uint256 eqAtR = EqPolyLib.eqEval(tau, sumcheckChallenges);
        require(
            ConstraintEvaluator.verifyConstraintEval(
                constraintFinalEval,
                eqAtR,
                proof.pcsConstraintEval
            ),
            "Constraint final eval mismatch: eq(tau,r)*C(r) != finalEval"
        );

        // ── Step 10: Verify batched evaluation consistency ──
        TranscriptLib.domainSeparate(transcript, "pcs-eval");

        // Preprocessed batch consistency
        uint256 expectedPreBatched = _computeBatchedEval(
            proof.preprocessedIndividualEvals, proof.preprocessedBatchR
        );
        require(expectedPreBatched == proof.preprocessedEvalValue, "Preprocessed batched eval mismatch");
        require(
            proof.preprocessedIndividualEvals.length == proof.numConstants + proof.numRoutedWires,
            "preprocessedIndividualEvals length mismatch"
        );

        // Witness batch consistency
        uint256 expectedWitBatched = _computeBatchedEval(
            proof.witnessIndividualEvals, proof.witnessBatchR
        );
        require(expectedWitBatched == proof.witnessEvalValue, "Witness batched eval mismatch");
        require(
            proof.witnessIndividualEvals.length == proof.numWires,
            "witnessIndividualEvals length mismatch"
        );

        // ── Step 11: Verify WHIR polynomial commitment proofs ──
        // SECURITY: Two separate WHIR verifications with different session names
        // prevent cross-protocol proof swapping.
        bool preWhirValid = SpongefishWhirVerify.verifyWhirProof(
            protocolId,
            preprocessedSessionId,
            "" /* instance: empty */,
            proof.preprocessedWhirTranscript,
            proof.preprocessedWhirHints,
            preprocessedWhirEvals,
            whirParams
        );
        require(preWhirValid, "Preprocessed WHIR PCS verification failed");

        bool witWhirValid = SpongefishWhirVerify.verifyWhirProof(
            protocolId,
            witnessSessionId,
            "" /* instance: empty */,
            proof.witnessWhirTranscript,
            proof.witnessWhirHints,
            witnessWhirEvals,
            whirParams
        );
        require(witWhirValid, "Witness WHIR PCS verification failed");

        return true;
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Preprocessed batch_r derivation
    // ═══════════════════════════════════════════════════════════════════════

    /// @dev Derive the deterministic preprocessed batch_r from circuit_digest.
    ///      Must match Rust's derive_preprocessed_batch_r() exactly.
    ///      Uses a separate mini-transcript: init() + domain("preprocessed-batch-r")
    ///      + absorb(circuitDigest) + squeeze.
    function _derivePreprocessedBatchR(uint256[] calldata circuitDigest)
        private pure returns (uint256)
    {
        TranscriptLib.Transcript memory t;
        TranscriptLib.init(t); // Adds "plonky2-mle-v0" protocol separator

        TranscriptLib.domainSeparate(t, "preprocessed-batch-r");

        // Copy circuitDigest from calldata to memory for absorbFieldVec
        uint256[] memory digestMem = new uint256[](circuitDigest.length);
        for (uint256 i = 0; i < circuitDigest.length; i++) {
            digestMem[i] = circuitDigest[i];
        }
        TranscriptLib.absorbFieldVec(t, digestMem);

        return TranscriptLib.squeezeChallenge(t);
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Input validation
    // ═══════════════════════════════════════════════════════════════════════

    function _validateInputs(MleProof calldata proof) private pure {
        require(proof.circuitDigest.length == 4, "circuitDigest must be 4 elements");
        for (uint256 i = 0; i < 4; i++) {
            require(proof.circuitDigest[i] < P, "circuitDigest >= P");
        }
        require(proof.preprocessedEvalValue < P, "preprocessedEvalValue >= P");
        require(proof.preprocessedBatchR < P, "preprocessedBatchR >= P");
        require(proof.witnessEvalValue < P, "witnessEvalValue >= P");
        require(proof.witnessBatchR < P, "witnessBatchR >= P");
        require(proof.alpha < P, "alpha >= P");
        require(proof.beta < P, "beta >= P");
        require(proof.gamma < P, "gamma >= P");
        require(proof.permClaimedSum < P, "permClaimedSum >= P");
        require(proof.pcsConstraintEval < P, "pcsConstraintEval >= P");
        require(proof.pcsPermNumeratorEval < P, "pcsPermNumeratorEval >= P");

        for (uint256 i = 0; i < proof.publicInputs.length; i++) {
            require(proof.publicInputs[i] < P, "publicInput >= P");
        }
        for (uint256 i = 0; i < proof.preprocessedIndividualEvals.length; i++) {
            require(proof.preprocessedIndividualEvals[i] < P, "preprocessedIndividualEval >= P");
        }
        for (uint256 i = 0; i < proof.witnessIndividualEvals.length; i++) {
            require(proof.witnessIndividualEvals[i] < P, "witnessIndividualEval >= P");
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

    /// @dev Extract the first 32 bytes from a calldata bytes array into memory.
    function _extractFirst32(bytes calldata data) private pure returns (bytes memory result) {
        result = new bytes(32);
        for (uint256 i = 0; i < 32; i++) {
            result[i] = data[i];
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
