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
/// @dev Unified WHIR proof architecture:
///      - Single split-commit WHIR proof covering both preprocessed and witness vectors
///      - Preprocessed commitment root (first 32 bytes) bound to VK
///      - Witness commitment root (next 32 bytes) per-proof
///
///      SECURITY: The preprocessedCommitmentRoot parameter is the VK.
///      It binds the verifier to a specific circuit's constants and
///      permutation routing. Without it, an attacker could substitute
///      fabricated constants/sigmas that trivially satisfy all constraints.
///
///      Goldilocks field: p = 2^64 - 2^32 + 1.
contract MleVerifier {
    using F for uint256;

    uint256 constant P = 0xFFFFFFFF00000001;

    struct MleProof {
        // Circuit binding (verifying key hash)
        // SECURITY: Binds this proof to a specific Plonky2 circuit.
        uint256[] circuitDigest;    // 4 Goldilocks field elements

        // ── Unified WHIR PCS (preprocessed + witness) ───────────────────
        bytes whirTranscript;              // Single WHIR proof transcript
        bytes whirHints;                   // Single WHIR hints
        bytes32 preprocessedRoot;          // Preprocessed Merkle root (VK binding)
        bytes32 witnessRoot;               // Witness Merkle root

        // ── Preprocessed PCS (constants + sigmas) ────────────────────────
        uint256 preprocessedEvalValue;      // Batched eval for preprocessed
        uint256 preprocessedBatchR;         // Deterministic from circuit_digest
        uint256[] preprocessedIndividualEvals; // [const_0..C, sigma_0..R]

        // ── Witness PCS (wires) ──────────────────────────────────────────
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

    /// @notice Verify an MLE proof with unified WHIR PCS (split-commit).
    /// @param proof The complete proof with single unified WHIR data.
    /// @param degreeBits log2 of the circuit degree (number of sumcheck rounds).
    /// @param preprocessedCommitmentRoot VK: expected WHIR Merkle root for preprocessed polynomial.
    /// @param numConstants VK: number of constant columns (from circuit setup).
    /// @param numRoutedWires VK: number of routed wire columns (from circuit setup).
    /// @param whirParams WHIR protocol parameters.
    /// @param protocolId WHIR protocol ID (64 bytes).
    /// @param splitSessionId WHIR session ID for split-commit mode (32 bytes).
    /// @param whirEvals WHIR Ext3 evaluations [preprocessed, witness].
    function verify(
        MleProof calldata proof,
        uint256 degreeBits,
        bytes32 preprocessedCommitmentRoot,
        uint256 numConstants,
        uint256 numRoutedWires,
        SpongefishWhirVerify.WhirParams memory whirParams,
        bytes memory protocolId,
        bytes memory splitSessionId,
        GoldilocksExt3.Ext3[] memory whirEvals
    )
        external
        pure
        returns (bool)
    {
        // ── Step 0: Input validation ──
        _validateInputs(proof);

        // ── Step 0b: Dimension authentication ──
        // SECURITY: numConstants and numRoutedWires are VK parameters (set at deploy time).
        // Without this check, the prover could lie about dimensions to bypass
        // the individual_evals array length checks.
        require(proof.numConstants == numConstants, "numConstants mismatch with VK");
        require(proof.numRoutedWires == numRoutedWires, "numRoutedWires mismatch with VK");

        // ── Step 1: Verify preprocessed batch_r is correctly derived ──
        // SECURITY: preprocessedBatchR must be deterministic from circuitDigest.
        // This prevents the prover from choosing a favorable batching scalar.
        uint256 expectedPreBatchR = _derivePreprocessedBatchR(proof.circuitDigest);
        require(expectedPreBatchR == proof.preprocessedBatchR, "Preprocessed batch_r mismatch");

        // ── Step 2: VK binding check ──
        // SECURITY: The preprocessed root in the proof must match the VK.
        require(
            proof.preprocessedRoot == preprocessedCommitmentRoot,
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
        bytes memory preRootBytes = abi.encodePacked(proof.preprocessedRoot);
        TranscriptLib.absorbBytes(transcript, preRootBytes);

        // ── Step 4: Derive witness batch_r ──
        TranscriptLib.domainSeparate(transcript, "batch-commit-witness");
        uint256 witnessBatchR = TranscriptLib.squeezeChallenge(transcript);
        require(witnessBatchR == proof.witnessBatchR, "Witness batch_r mismatch");

        // Absorb witness commitment root
        bytes memory witRootBytes = abi.encodePacked(proof.witnessRoot);
        TranscriptLib.absorbBytes(transcript, witRootBytes);

        // ── Step 5: Derive challenges ──
        TranscriptLib.domainSeparate(transcript, "challenges");
        uint256 beta = TranscriptLib.squeezeChallenge(transcript);
        uint256 gamma = TranscriptLib.squeezeChallenge(transcript);
        uint256 alpha = TranscriptLib.squeezeChallenge(transcript);
        uint256[] memory tau = TranscriptLib.squeezeChallenges(transcript, degreeBits);
        uint256[] memory tauPerm = TranscriptLib.squeezeChallenges(transcript, degreeBits);

        require(beta == proof.beta, "Beta mismatch");
        require(gamma == proof.gamma, "Gamma mismatch");
        require(alpha == proof.alpha, "Alpha mismatch");
        // SECURITY: Validate tau_perm matches the transcript-derived value.
        // Without this check, a prover could supply arbitrary tau_perm values.
        for (uint256 i = 0; i < degreeBits; i++) {
            require(tauPerm[i] == proof.tauPerm[i], "TauPerm mismatch");
        }

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

        // ── Step 11: Verify unified WHIR split-commit proof ──
        // SECURITY: Single WHIR verification covers both committed polynomials
        // with cross-term binding via OOD evaluations.
        bool whirValid = SpongefishWhirVerify.verifyWhirProof(
            protocolId,
            splitSessionId,
            "" /* instance: empty */,
            proof.whirTranscript,
            proof.whirHints,
            whirEvals,
            whirParams
        );
        require(whirValid, "Unified WHIR PCS verification failed");

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

        // Validate scalar fields < P
        require(proof.circuitDigest[0] < P && proof.circuitDigest[1] < P
             && proof.circuitDigest[2] < P && proof.circuitDigest[3] < P, "circuitDigest >= P");
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

        // Validate array fields < P using assembly loops
        _validateCalldataArray(proof.publicInputs);
        _validateCalldataArray(proof.preprocessedIndividualEvals);
        _validateCalldataArray(proof.witnessIndividualEvals);
        _validateCalldataArray(proof.tau);
        _validateCalldataArray(proof.tauPerm);

        // Validate sumcheck round polys
        for (uint256 i = 0; i < proof.permProof.roundPolys.length; i++) {
            _validateCalldataArray(proof.permProof.roundPolys[i].evals);
        }
        for (uint256 i = 0; i < proof.constraintProof.roundPolys.length; i++) {
            _validateCalldataArray(proof.constraintProof.roundPolys[i].evals);
        }
    }

    /// @dev Validate all elements of a calldata uint256 array are < P.
    function _validateCalldataArray(uint256[] calldata arr) private pure {
        assembly {
            let p := 0xFFFFFFFF00000001
            let n := arr.length
            let off := arr.offset
            for { let i := 0 } lt(i, n) { i := add(i, 1) } {
                let v := calldataload(add(off, mul(i, 0x20)))
                if iszero(lt(v, p)) {
                    // revert with "Field >= P"
                    mstore(0x00, 0x08c379a000000000000000000000000000000000000000000000000000000000)
                    mstore(0x04, 0x20)
                    mstore(0x24, 10)
                    mstore(0x44, "Field >= P")
                    revert(0x00, 0x64)
                }
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

    /// @dev Extract 32 bytes from a calldata bytes array at a given offset.
    function _extractBytes32At(bytes calldata data, uint256 offset) private pure returns (bytes memory result) {
        require(data.length >= offset + 32, "Insufficient data for extraction");
        result = new bytes(32);
        assembly {
            calldatacopy(add(result, 0x20), add(data.offset, offset), 32)
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
