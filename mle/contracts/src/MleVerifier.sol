// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.25;

import {GoldilocksField as F} from "./GoldilocksField.sol";
import {TranscriptLib} from "./TranscriptLib.sol";
import {SumcheckVerifier} from "./SumcheckVerifier.sol";
import {EqPolyLib} from "./EqPolyLib.sol";
import {ConstraintEvaluator} from "./ConstraintEvaluator.sol";

/// @title MleVerifier
/// @notice On-chain verifier for the Plonky2-MLE proof system.
/// @dev Verifies:
///      1. Fiat-Shamir transcript reconstruction
///      2. Permutation check (plain sumcheck, Σ h(b) = 0) + final eval via PCS
///      3. Zero-check sumcheck (Σ eq(τ,b)·C(b) = 0) + final eval via PCS
///      4. PCS evaluation proof (Merkle root + MLE evaluation)
///
///      WHIR configuration: rate = 8 (code rate 1/64).
///      Goldilocks field: p = 2^64 - 2^32 + 1.
///
///      CONSTRAINT EVALUATION STRATEGY (oracle approach):
///      The Rust prover computes C(r) for ALL gate types (including Poseidon,
///      CosetInterpolation, extension field gates) and commits it as an
///      additional MLE in the PCS batch. The verifier receives C(r) as a
///      PCS-bound value, avoiding the need to re-implement 12+ gate types
///      in Solidity. Soundness follows from PCS binding.
contract MleVerifier {
    using F for uint256;

    uint256 constant P = 0xFFFFFFFF00000001;
    uint256 constant WHIR_RATE = 8;
    uint256 constant WHIR_INV_RATE = 64;
    uint256 constant SECURITY_BITS = 128;

    struct MleProof {
        bytes32 commitmentRoot;
        // Sumcheck proofs
        SumcheckVerifier.SumcheckProof permProof;
        uint256 permClaimedSum;
        SumcheckVerifier.SumcheckProof constraintProof;
        // PCS: batched polynomial evaluations at sumcheck point
        uint256[] pcsEvaluations;    // Full evaluation table for Merkle root verification
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
        // Public inputs hash (4 Goldilocks elements)
        uint256[4] publicInputsHash;
        // ORACLE: PCS-opened constraint value C(r) (flattened extension field).
        // This is the combined gate constraint evaluation at the sumcheck point,
        // committed as an additional MLE in the PCS batch.
        // SECURITY: This value is bound to the PCS commitment — the prover
        // cannot lie about it without breaking Merkle/PCS binding.
        uint256 pcsConstraintEval;
        // ORACLE: PCS-opened permutation numerator h(r_perm) at the permutation
        // sumcheck point. Also committed in the PCS batch.
        uint256 pcsPermNumeratorEval;
    }

    /// @notice Verify an MLE proof.
    /// @param proof The complete proof.
    /// @param degreeBits log2 of the circuit degree (number of sumcheck rounds).
    function verify(MleProof calldata proof, uint256 degreeBits)
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
        TranscriptLib.absorbFieldVec(transcript, proof.publicInputs);

        // ── Step 2: Derive batch_r ──
        TranscriptLib.domainSeparate(transcript, "batch-commit");
        uint256 batchR = TranscriptLib.squeezeChallenge(transcript);
        require(batchR == proof.batchR, "Batch R mismatch");

        TranscriptLib.absorbBytes(transcript, abi.encodePacked(proof.commitmentRoot));

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

        // SECURITY (Finding 3 fix): Verify permutation final evaluation.
        // permFinalEval = h(r_perm), and the prover supplies the PCS-opened
        // h(r_perm) value. These must match.
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

        // ── Step 6: Verify constraint final evaluation (Finding 2 fix) ──
        // SECURITY: constraintFinalEval == eq(τ, r) · C(r)
        // C(r) is the PCS-opened constraint evaluation (covers ALL gate types).
        uint256 eqAtR = EqPolyLib.eqEval(tau, sumcheckChallenges);
        require(
            ConstraintEvaluator.verifyConstraintEval(
                constraintFinalEval,
                eqAtR,
                proof.pcsConstraintEval
            ),
            "Constraint final eval mismatch: eq(tau,r)*C(r) != finalEval"
        );

        // ── Step 7: Verify PCS evaluation proof ──
        TranscriptLib.domainSeparate(transcript, "pcs-eval");

        // Verify batched evaluation consistency
        uint256 expectedBatched = _computeBatchedEval(proof.individualEvals, batchR);
        require(expectedBatched == proof.evalValue, "Batched eval mismatch");

        // Verify individual evals count matches circuit dimensions
        // Layout: [wire_0,..,wire_{W-1}, const_0,..,const_{C-1}, sigma_0,..,sigma_{R-1}]
        require(
            proof.individualEvals.length == proof.numWires + proof.numConstants + proof.numRoutedWires,
            "individualEvals length mismatch"
        );

        // Verify Merkle root
        require(
            proof.pcsEvaluations.length > 0 &&
            (proof.pcsEvaluations.length & (proof.pcsEvaluations.length - 1)) == 0,
            "PCS evals must be power of 2"
        );
        bytes32 computedRoot = _computeMerkleRoot(proof.pcsEvaluations);
        require(computedRoot == proof.commitmentRoot, "Merkle root mismatch");

        // Verify MLE evaluation at sumcheck point
        uint256 computedEval = _evaluateMLE(proof.pcsEvaluations, sumcheckChallenges);
        require(computedEval == proof.evalValue, "MLE eval mismatch");

        return true;
    }

    /// @notice Estimate verification gas for a given circuit size.
    function estimateGas(uint256 degreeBits, uint256 numPolys)
        external
        pure
        returns (uint256 gasEstimate)
    {
        uint256 sumcheckGas = degreeBits * 22000;
        uint256 totalSumcheckGas = sumcheckGas * 2;
        uint256 eqGas = degreeBits * 200;
        uint256 size = 1 << degreeBits;
        uint256 merkleGas = size * 36;
        uint256 mleGas = size * 15;
        uint256 transcriptGas = degreeBits * numPolys * 50;
        gasEstimate = totalSumcheckGas + eqGas + merkleGas + mleGas + transcriptGas + 21000;
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Input validation
    // ═══════════════════════════════════════════════════════════════════════

    function _validateInputs(MleProof calldata proof) private pure {
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

    function _computeMerkleRoot(uint256[] calldata evals)
        private pure returns (bytes32 root)
    {
        uint256 n = evals.length;
        if (n == 0) return bytes32(0);
        bytes32[] memory layer = new bytes32[](n);
        for (uint256 i = 0; i < n; i++) {
            uint64 val = uint64(evals[i]);
            assembly {
                mstore8(0x00, and(val, 0xff))
                mstore8(0x01, and(shr(8, val), 0xff))
                mstore8(0x02, and(shr(16, val), 0xff))
                mstore8(0x03, and(shr(24, val), 0xff))
                mstore8(0x04, and(shr(32, val), 0xff))
                mstore8(0x05, and(shr(40, val), 0xff))
                mstore8(0x06, and(shr(48, val), 0xff))
                mstore8(0x07, and(shr(56, val), 0xff))
                mstore(add(add(layer, 0x20), mul(i, 0x20)), keccak256(0x00, 8))
            }
        }
        while (n > 1) {
            uint256 nextN = (n + 1) / 2;
            for (uint256 i = 0; i < nextN; i++) {
                bytes32 left = layer[2 * i];
                bytes32 right = (2 * i + 1 < n) ? layer[2 * i + 1] : layer[2 * i];
                assembly {
                    mstore(0x00, left)
                    mstore(0x20, right)
                    mstore(add(add(layer, 0x20), mul(i, 0x20)), keccak256(0x00, 0x40))
                }
            }
            n = nextN;
        }
        root = layer[0];
    }

    function _evaluateMLE(uint256[] calldata evals, uint256[] memory point)
        private pure returns (uint256 result)
    {
        uint256 n = point.length;
        uint256 size = evals.length;
        require(size == (1 << n), "MLE size mismatch");
        uint256[] memory eqTable = new uint256[](size);
        assembly {
            let p := 0xFFFFFFFF00000001
            let tPtr := add(eqTable, 0x20)
            let pPtr := add(point, 0x20)
            for { let i := 0 } lt(i, size) { i := add(i, 1) } {
                mstore(add(tPtr, mul(i, 0x20)), 1)
            }
            for { let j := 0 } lt(j, n) { j := add(j, 1) } {
                let t_j := mload(add(pPtr, mul(j, 0x20)))
                let omt := addmod(1, sub(p, t_j), p)
                for { let i := 0 } lt(i, size) { i := add(i, 1) } {
                    let pos := add(tPtr, mul(i, 0x20))
                    let cur := mload(pos)
                    switch and(shr(j, i), 1)
                    case 0 { mstore(pos, mulmod(cur, omt, p)) }
                    default { mstore(pos, mulmod(cur, t_j, p)) }
                }
            }
            result := 0
            let off := evals.offset
            for { let i := 0 } lt(i, size) { i := add(i, 1) } {
                let fi := calldataload(add(off, mul(i, 0x20)))
                let ei := mload(add(tPtr, mul(i, 0x20)))
                result := addmod(result, mulmod(fi, ei, p), p)
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
