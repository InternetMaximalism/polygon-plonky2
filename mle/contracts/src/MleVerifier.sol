// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.25;

import {GoldilocksField as F} from "./GoldilocksField.sol";
import {TranscriptLib} from "./TranscriptLib.sol";
import {SumcheckVerifier} from "./SumcheckVerifier.sol";
import {EqPolyLib} from "./EqPolyLib.sol";
import {SpongefishWhirVerify} from "./spongefish/SpongefishWhirVerify.sol";
import {GoldilocksExt3} from "./spongefish/GoldilocksExt3.sol";
import {Plonky2GateEvaluator} from "./Plonky2GateEvaluator.sol";

/// @title MleVerifier — Combined sumcheck + single WHIR (3 vectors)
contract MleVerifier {
    using F for uint256;
    uint256 constant P = 0xFFFFFFFF00000001;

    struct MleProof {
        uint256[] circuitDigest;
        bytes whirTranscript;
        bytes whirHints;
        bytes32 preprocessedRoot;
        bytes32 witnessRoot;
        bytes32 auxCommitmentRoot;
        uint256 preprocessedEvalValue;
        uint256 preprocessedBatchR;
        uint256[] preprocessedIndividualEvals;
        uint256 witnessEvalValue;
        uint256 witnessBatchR;
        uint256[] witnessIndividualEvals;
        uint256 auxBatchR;
        uint256 auxConstraintEval;
        uint256 auxPermEval;
        uint256 auxEvalValue;
        SumcheckVerifier.SumcheckProof combinedProof;
        uint256[] publicInputs;
        uint256 alpha;
        uint256 beta;
        uint256 gamma;
        uint256 mu;
        // SECURITY note (Issue #5): tau, tauPerm and ext_challenge are NOT carried
        // in the proof struct — they are deterministically re-derived from the
        // transcript inside verify(). Including a prover-supplied tau would be a
        // dead field at best and a footgun (an unchecked field used as if authoritative).
        //
        // SECURITY (Issue #3 + #7): WHIR-bound ext3 evaluations are part of the proof.
        // Previously these were passed as a separate `whirEvals` external parameter,
        // which allowed an adversarial caller to pass arbitrary values that pass WHIR
        // but disagree with the proof's other fields. By moving them into MleProof,
        // they become part of the same atomic object the verifier validates. Their
        // soundness ↔ *EvalValue chain is enforced by Schwartz-Zippel over batch_r
        // (see verifier.rs::mle_verify SECURITY NOTE about Ext3 ↔ Goldilocks binding).
        GoldilocksExt3.Ext3 preprocessedWhirEval;
        GoldilocksExt3.Ext3 witnessWhirEval;
        GoldilocksExt3.Ext3 auxWhirEval;

        // ── v2 logUp soundness fix (Issue R2-#2, paper §4.2) ────────────
        // Inverse helpers A_j(b) = 1/D_j^id(b), B_j(b) = 1/D_j^σ(b) committed
        // via WHIR (additional 4th vector in the same split-commit session).
        // Bound by Φ_inv (zero-check) and Φ_h (linear sumcheck), both of
        // which produce their own terminal points r_inv, r_h.
        bytes32 inverseHelpersCommitmentRoot;
        uint256 inverseHelpersBatchR;
        SumcheckVerifier.SumcheckProof invSumcheckProof;
        SumcheckVerifier.SumcheckProof hSumcheckProof;
        uint256 lambdaInv;
        uint256 muInv;
        uint256 lambdaH;
        // Goldilocks individual evals at r_inv:
        // - witnessIndividualEvalsAtRInv  : length = numWires
        // - preprocessedIndividualEvalsAtRInv : length = numConstants + numRoutedWires,
        //                                        layout [const_0..const_C, sigma_0..sigma_R].
        //                                        Sigma subset feeds Φ_inv terminal;
        //                                        const subset only enters batch consistency.
        // - inverseHelpersEvalsAtRInv     : length = 2 · numRoutedWires
        //                                   layout [a_0, …, a_{R-1}, b_0, …, b_{R-1}]
        uint256[] witnessIndividualEvalsAtRInv;
        uint256[] preprocessedIndividualEvalsAtRInv;
        uint256[] inverseHelpersEvalsAtRInv;
        // Inverse-helpers individual evals at r_h (same layout as above)
        uint256[] inverseHelpersEvalsAtRH;
        // Verifier-recomputable g_sub(r_inv) — enclosed in proof for a hard
        // cross-check against subgroupGenPowers.
        uint256 gSubEvalAtRInv;
        // Batched Goldilocks evals at r_inv (for batch consistency vs WHIR)
        uint256 witnessEvalValueAtRInv;
        uint256 preprocessedEvalValueAtRInv;
        // Per-point Ext3 WHIR evals: 4 vectors × 3 points = 12 entries
        // Layout [point][vector]: point 0 = r_gate, 1 = r_inv, 2 = r_h
        // Vectors: 0 = preprocessed, 1 = witness, 2 = aux, 3 = inverse_helpers
        GoldilocksExt3.Ext3 inverseHelpersWhirEvalAtRGate;
        GoldilocksExt3.Ext3 preprocessedWhirEvalAtRInv;
        GoldilocksExt3.Ext3 witnessWhirEvalAtRInv;
        GoldilocksExt3.Ext3 auxWhirEvalAtRInv;
        GoldilocksExt3.Ext3 inverseHelpersWhirEvalAtRInv;
        GoldilocksExt3.Ext3 preprocessedWhirEvalAtRH;
        GoldilocksExt3.Ext3 witnessWhirEvalAtRH;
        GoldilocksExt3.Ext3 auxWhirEvalAtRH;
        GoldilocksExt3.Ext3 inverseHelpersWhirEvalAtRH;

        // ── v2 gate binding fix (Issue R2-#1, paper §7.3) ─────────────
        // Additional sumcheck Φ_gate whose terminal check runs the actual
        // Plonky2 gate-constraint formula at a random point r_gate_v2,
        // closing the MLE-commutativity gap for gates of degree ≥ 2.
        uint256 extChallenge;
        SumcheckVerifier.SumcheckProof gateSumcheckProof;
        // Individual evals at r_gate_v2 (PCS-bound via WHIR 4th point):
        //  - witnessIndividualEvalsAtRGateV2  : length = numWires
        //  - preprocessedIndividualEvalsAtRGateV2 : length = numConstants + numRoutedWires
        uint256[] witnessIndividualEvalsAtRGateV2;
        uint256[] preprocessedIndividualEvalsAtRGateV2;
        uint256 witnessEvalValueAtRGateV2;
        uint256 preprocessedEvalValueAtRGateV2;
        GoldilocksExt3.Ext3 preprocessedWhirEvalAtRGateV2;
        GoldilocksExt3.Ext3 witnessWhirEvalAtRGateV2;
        GoldilocksExt3.Ext3 auxWhirEvalAtRGateV2;
        GoldilocksExt3.Ext3 inverseHelpersWhirEvalAtRGateV2;
        // Circuit metadata needed by Plonky2GateEvaluator.
        uint256 quotientDegreeFactor;
        uint256 numSelectors;
        uint256 numGateConstraints;
        Plonky2GateEvaluator.GateInfo[] gates;
        uint256[4] publicInputsHash;
    }

    /// @dev Wrap call args into a struct to drastically reduce stack pressure.
    /// Without this, verify() crosses Solc's 16-slot stack limit even with
    /// via_ir + heavy helper extraction (Yul optimizer issue with calldata-derived
    /// memory pointers).
    struct VerifyParams {
        uint256 degreeBits;
        bytes32 preprocessedCommitmentRoot;
        uint256 numConstants;
        uint256 numRoutedWires;
        bytes protocolId;
        bytes sessionId;
        // Issue #2: VK-bound permutation context. These determine the identity
        // permutation MLE id_col(b) = k_is[col] · subgroup[b], whose evaluation at
        // the sumcheck point r is needed to verify h̃(r) is actually the logUp
        // permutation numerator and not an arbitrary polynomial summing to 0.
        // SECURITY: kIs and subgroupGenPowers MUST be the values consistent with
        // the circuit's VK (caller-supplied; they are not transcript-bound here
        // because they are public per-circuit constants).
        uint256[] kIs;                // length = numRoutedWires
        uint256[] subgroupGenPowers;  // length = degreeBits, [g, g^2, g^4, ..., g^{2^(n-1)}]
    }

    /// @dev Version byte for the gatesDigest encoding. Bump when the
    /// GateInfo struct layout or the list of hashed fields changes.
    uint8 internal constant GATES_DIGEST_VERSION = 1;

    // NOTE on `gatesDigest`:
    // The VK-bound digest that pins gate-layout metadata was intentionally
    // added as a standalone verify() parameter rather than a field of
    // VerifyParams. Growing the struct triggers a Yul-optimizer stack-too-deep
    // failure in this already-tight function; an external parameter is
    // API-cleaner and keeps the Yul layout stable.
    // Digest formula (MUST match the off-chain deployer):
    //   keccak256(abi.encode(
    //       uint8(GATES_DIGEST_VERSION),
    //       proof.witnessIndividualEvalsAtRGateV2.length,   // numWires
    //       proof.numSelectors,
    //       proof.numGateConstraints,
    //       proof.quotientDegreeFactor,
    //       proof.gates                                     // Plonky2GateEvaluator.GateInfo[]
    //   ))

    /// @notice External entrypoint. Performs C1 + C2 boundary checks, then
    /// delegates to `_verifyCore` for the actual proof verification.
    function verify(
        MleProof calldata proof,
        VerifyParams memory vp,
        SpongefishWhirVerify.WhirParams memory whirParams,
        bytes32 gatesDigest
    ) external pure returns (bool) {
        _requireGatesDigest(proof, gatesDigest);
        _requireCanonicalProofInputs(proof);
        return _verifyCore(proof, vp, whirParams);
    }

    function _verifyCore(
        MleProof calldata proof,
        VerifyParams memory vp,
        SpongefishWhirVerify.WhirParams memory whirParams
    ) internal pure returns (bool) {
        require(proof.circuitDigest.length == 4, "digest len");
        require(_derivePreprocessedBatchR(proof.circuitDigest) == proof.preprocessedBatchR, "preBatchR");
        require(proof.preprocessedRoot == vp.preprocessedCommitmentRoot, "VK binding");

        TranscriptLib.Transcript memory ts;
        (uint256[] memory tau, uint256[] memory tauInv) =
            _initTranscriptAndChallenges(ts, proof, vp.degreeBits);

        // Combined sumcheck (eq(τ,b)·C̃(b) + μ·h̃(b)): max round-poly degree = 2.
        SumcheckVerifier.SumcheckProof memory sc = _copySumcheckProof(proof.combinedProof);
        (uint256[] memory rGate, uint256 gateFinal) =
            SumcheckVerifier.verify(sc, 0, vp.degreeBits, 2, ts);

        // ── v2 logUp: Φ_inv zero-check sumcheck (round-poly degree ≤ 3) ──
        TranscriptLib.domainSeparate(ts, "v2-inv-zerocheck");
        SumcheckVerifier.SumcheckProof memory invSc = _copySumcheckProof(proof.invSumcheckProof);
        (uint256[] memory rInv, uint256 invFinal) =
            SumcheckVerifier.verify(invSc, 0, vp.degreeBits, 3, ts);

        // ── v2 logUp: Φ_h linear sumcheck (round-poly degree = 1) ──
        TranscriptLib.domainSeparate(ts, "v2-h-linear");
        SumcheckVerifier.SumcheckProof memory hSc = _copySumcheckProof(proof.hSumcheckProof);
        (uint256[] memory rH, uint256 hFinal) =
            SumcheckVerifier.verify(hSc, 0, vp.degreeBits, 1, ts);

        // ── R2-#1: Φ_gate zero-check sumcheck + terminal check. Returns
        // `rGateV2` (needed for the WHIR binding below). `tauGate` and
        // `gateFinalV2` are scoped inside the helper so they do not occupy
        // stack slots alongside `rGateV2` during `_runBatchAndWhir`. Without
        // this split, adding the C1/C2 boundary checks overflows the Yul
        // optimizer's 16-slot stack limit.
        uint256[] memory rGateV2 = _runGateSumcheckAndTerminal(proof, vp, ts);

        // Bind the WHIR multi-point opening to the four sumcheck-derived points.
        whirParams.evaluationPoint = _deriveEvalPoint(rGate);
        whirParams.evaluationPoint2 = _deriveEvalPoint(rInv);
        whirParams.additionalEvaluationPoints = new GoldilocksExt3.Ext3[][](2);
        whirParams.additionalEvaluationPoints[0] = _deriveEvalPoint(rH);
        whirParams.additionalEvaluationPoints[1] = _deriveEvalPoint(rGateV2);

        _runBatchAndWhir(proof, whirParams, vp, ts);

        // ── Terminal check: legacy combined sumcheck. Issue R2-#2 still
        //    leaves h̃(r) un-bound (which is exactly why we run Φ_inv + Φ_h
        //    below); the legacy check is preserved for backwards compatibility
        //    with the existing C̃ commitment but its h̃ part is no longer the
        //    soundness anchor for permutation correctness.
        require(
            EqPolyLib.eqEval(tau, rGate).mul(proof.auxConstraintEval)
                .add(proof.mu.mul(proof.auxPermEval)) == gateFinal,
            "final"
        );

        // ── v2 logUp: g_sub(r_inv) consistency (subgroup MLE from VK powers)
        require(
            _evalSubgroupMle(rInv, vp.subgroupGenPowers) == proof.gSubEvalAtRInv,
            "gSub(r_inv)"
        );

        // ── v2 logUp: batch consistency at r_inv (witness + preprocessed)
        require(
            _computeBatchedEval(proof.witnessIndividualEvalsAtRInv, proof.witnessBatchR)
                == proof.witnessEvalValueAtRInv,
            "wit batch r_inv"
        );

        // ── v2 logUp: terminal checks for Φ_inv and Φ_h
        _checkInvTerminal(proof, vp, tauInv, rInv, invFinal);
        _checkHTerminal(proof, vp, hFinal);

        return true;
    }

    /// @dev Φ_inv terminal check (paper §4.2.2):
    /// eq(τ_inv,r_inv) · Σ_j λ_inv^j · ( a_j·D_id − 1 + μ_inv·(b_j·D_σ − 1) ) ?= invFinal
    /// where D_id = β + w_j(r_inv) + γ·k_j·g_sub(r_inv),
    ///       D_σ  = β + w_j(r_inv) + γ·σ_j(r_inv).
    function _checkInvTerminal(
        MleProof calldata proof,
        VerifyParams memory vp,
        uint256[] memory tauInv,
        uint256[] memory rInv,
        uint256 invFinal
    ) private pure {
        uint256 nr = vp.numRoutedWires;
        require(proof.witnessIndividualEvalsAtRInv.length >= nr, "wit r_inv len");
        require(
            proof.preprocessedIndividualEvalsAtRInv.length == vp.numConstants + nr,
            "pre r_inv len"
        );
        require(proof.inverseHelpersEvalsAtRInv.length == 2 * nr, "inv r_inv len");
        require(vp.kIs.length >= nr, "kIs len");

        uint256 inner = _invInner(proof, vp, nr);
        uint256 eqAtRInv = EqPolyLib.eqEval(tauInv, rInv);
        require(eqAtRInv.mul(inner) == invFinal, "Phi_inv terminal");
    }

    /// @dev Φ_gate terminal check (Issue R2-#1, paper §7.3):
    ///   gateFinal ?= eq(τ_gate, r_gate_v2) · flatten_ext(
    ///       Σ_j α^j · filter_j · gate_j.eval( w(r_gate_v2), c(r_gate_v2) ),
    ///       ext_challenge
    ///   )
    ///
    /// SECURITY: All inputs to Plonky2GateEvaluator are WHIR-bound (wire +
    /// const evals at r_gate_v2 via the 4th WHIR point opening) or
    /// Fiat-Shamir-derived (α, ext_challenge, τ_gate). No prover oracle is
    /// trusted for the formula result — the verifier runs the same gate
    /// evaluator the Rust prover uses.
    function _checkGateTerminal(
        MleProof calldata proof,
        uint256[] memory tauGate,
        uint256[] memory rGateV2,
        uint256 gateFinal
    ) private pure {
        uint256 flat = Plonky2GateEvaluator.evalCombinedFlat(
            proof.witnessIndividualEvalsAtRGateV2,
            proof.preprocessedIndividualEvalsAtRGateV2,
            proof.alpha,
            proof.extChallenge,
            proof.publicInputsHash,
            proof.gates,
            proof.numSelectors,
            0, // numConstants: computed inside the evaluator from preprocessed length if needed
            proof.numGateConstraints
        );
        uint256 eqAtRGateV2 = EqPolyLib.eqEval(tauGate, rGateV2);
        require(eqAtRGateV2.mul(flat) == gateFinal, "Phi_gate terminal");
    }

    /// @dev Inner sum of the Φ_inv terminal predicate. Extracted so we can
    /// use the direct calldata arrays as typed parameters (allowing `.offset`
    /// access inside assembly).
    function _invInner(
        MleProof calldata proof,
        VerifyParams memory vp,
        uint256 nr
    ) private pure returns (uint256 inner) {
        uint256[] calldata w_ = proof.witnessIndividualEvalsAtRInv;
        uint256[] calldata pre_ = proof.preprocessedIndividualEvalsAtRInv;
        uint256[] calldata ih_ = proof.inverseHelpersEvalsAtRInv;
        // vp.kIs lives in memory: take its data-pointer so inner-loop reads
        // go through a single `mload` too.
        uint256 kPtr;
        {
            uint256[] memory kArr = vp.kIs;
            assembly { kPtr := add(kArr, 0x20) }
        }
        uint256 gSub = proof.gSubEvalAtRInv;
        uint256 beta = proof.beta;
        uint256 gamma = proof.gamma;
        uint256 muInv = proof.muInv;
        uint256 lambdaInv = proof.lambdaInv;
        uint256 numConsts = vp.numConstants;
        assembly {
            let p := 0xFFFFFFFF00000001
            let wOff := w_.offset
            let pOff := pre_.offset
            let aOff := ih_.offset
            let acc := 0
            let lambdaPow := 1
            for { let j := 0 } lt(j, nr) { j := add(j, 1) } {
                let wv := calldataload(add(wOff, mul(j, 0x20)))
                let sv := calldataload(add(pOff, mul(add(j, numConsts), 0x20)))
                let aVal := calldataload(add(aOff, mul(j, 0x20)))
                let bVal := calldataload(add(aOff, mul(add(j, nr), 0x20)))
                let kj := mload(add(kPtr, mul(j, 0x20)))
                let idJ := mulmod(kj, gSub, p)
                let sum_bw := addmod(beta, wv, p)
                let denomId := addmod(sum_bw, mulmod(gamma, idJ, p), p)
                let denomSigma := addmod(sum_bw, mulmod(gamma, sv, p), p)
                let zId := mulmod(aVal, denomId, p)
                switch zId
                case 0 { zId := sub(p, 1) }
                default { zId := sub(zId, 1) }
                let zSigma := mulmod(bVal, denomSigma, p)
                switch zSigma
                case 0 { zSigma := sub(p, 1) }
                default { zSigma := sub(zSigma, 1) }
                let combined := addmod(zId, mulmod(muInv, zSigma, p), p)
                acc := addmod(acc, mulmod(lambdaPow, combined, p), p)
                lambdaPow := mulmod(lambdaPow, lambdaInv, p)
            }
            inner := acc
        }
    }

    /// @dev Φ_h terminal check (paper §4.2.3):
    /// h_final ?= Σ_j (a_j(r_h) − b_j(r_h))
    /// (unweighted — only the unweighted Σ_j (A_j − B_j) telescopes via logUp).
    function _checkHTerminal(
        MleProof calldata proof,
        VerifyParams memory vp,
        uint256 hFinal
    ) private pure {
        uint256 nr = vp.numRoutedWires;
        require(proof.inverseHelpersEvalsAtRH.length == 2 * nr, "inv r_h len");
        uint256 acc;
        {
            uint256[] calldata ih_ = proof.inverseHelpersEvalsAtRH;
            assembly {
                let p := 0xFFFFFFFF00000001
                let aOff := ih_.offset
                let sum := 0
                for { let j := 0 } lt(j, nr) { j := add(j, 1) } {
                    let aVal := calldataload(add(aOff, mul(j, 0x20)))
                    let bVal := calldataload(add(aOff, mul(add(j, nr), 0x20)))
                    // SECURITY (C2): self-reduce `bVal` before sub(P, bVal).
                    // `inverseHelpersEvalsAtRH` is prover-supplied uint256 with
                    // no canonical check before reaching here; a non-canonical
                    // `bVal = v + k·P` would otherwise inject K = 2^256 mod P
                    // into the sum. Caller-side canonicalization (added in
                    // verify() entry) also covers this; belt-and-suspenders.
                    sum := addmod(sum, addmod(aVal, sub(p, mod(bVal, p)), p), p)
                }
                acc := sum
            }
        }
        require(acc == hFinal, "Phi_h terminal");
    }

    /// @dev Evaluate g_sub MLE at r using VK-bound subgroup generator powers.
    /// result = Π_i ((1-r_i) + r_i·g^{2^i}).
    function _evalSubgroupMle(uint256[] memory r, uint256[] memory gPow)
        internal pure returns (uint256 result)
    {
        assembly {
            let p := 0xFFFFFFFF00000001
            result := 1
            let rLen := mload(r)
            let rPtr := add(r, 0x20)
            let gPtr := add(gPow, 0x20)
            for { let i := 0 } lt(i, rLen) { i := add(i, 1) } {
                let ri := mload(add(rPtr, mul(i, 0x20)))
                let gi := mload(add(gPtr, mul(i, 0x20)))
                let oneMinusR := addmod(1, sub(p, ri), p)
                let rTimesG := mulmod(ri, gi, p)
                let factor := addmod(oneMinusR, rTimesG, p)
                result := mulmod(result, factor, p)
            }
        }
    }

    /// @dev Initialize transcript, absorb commitments, squeeze and check Fiat-Shamir
    /// challenges. Mirrors the Rust prover transcript order, including the v2
    /// logUp inverse-helpers commit + new challenges.
    /// Returns the transcript-derived (tau, tauInv) used in terminal checks.
    function _initTranscriptAndChallenges(
        TranscriptLib.Transcript memory ts,
        MleProof calldata proof,
        uint256 degreeBits
    ) private pure returns (uint256[] memory tau, uint256[] memory tauInv) {
        TranscriptLib.init(ts);
        TranscriptLib.domainSeparate(ts, "circuit");
        TranscriptLib.absorbFieldVec(ts, proof.circuitDigest);
        TranscriptLib.absorbFieldVec(ts, proof.publicInputs);
        TranscriptLib.absorbBytes(ts, abi.encodePacked(proof.preprocessedRoot));

        TranscriptLib.domainSeparate(ts, "batch-commit-witness");
        require(TranscriptLib.squeezeChallenge(ts) == proof.witnessBatchR, "witBatchR");
        TranscriptLib.absorbBytes(ts, abi.encodePacked(proof.witnessRoot));

        TranscriptLib.domainSeparate(ts, "challenges");
        require(TranscriptLib.squeezeChallenge(ts) == proof.beta, "beta");
        require(TranscriptLib.squeezeChallenge(ts) == proof.gamma, "gamma");

        // ── v2 logUp: inverse-helpers commit absorbed AFTER β,γ. ─────────
        TranscriptLib.domainSeparate(ts, "inverse-helpers-batch-r");
        require(
            TranscriptLib.squeezeChallenge(ts) == proof.inverseHelpersBatchR,
            "invBatchR"
        );
        TranscriptLib.absorbBytes(ts, abi.encodePacked(proof.inverseHelpersCommitmentRoot));

        require(TranscriptLib.squeezeChallenge(ts) == proof.alpha, "alpha");
        tau = TranscriptLib.squeezeChallenges(ts, degreeBits);
        TranscriptLib.squeezeChallenges(ts, degreeBits); // tauPerm sync (unused)

        TranscriptLib.domainSeparate(ts, "v2-logup-challenges");
        require(TranscriptLib.squeezeChallenge(ts) == proof.lambdaInv, "lambdaInv");
        require(TranscriptLib.squeezeChallenge(ts) == proof.muInv, "muInv");
        require(TranscriptLib.squeezeChallenge(ts) == proof.lambdaH, "lambdaH");
        tauInv = TranscriptLib.squeezeChallenges(ts, degreeBits);

        TranscriptLib.domainSeparate(ts, "extension-combine");
        require(TranscriptLib.squeezeChallenge(ts) == proof.extChallenge, "extChallenge");

        // Aux commit
        TranscriptLib.domainSeparate(ts, "aux-commit");
        require(TranscriptLib.squeezeChallenge(ts) == proof.auxBatchR, "auxBatchR");
        TranscriptLib.absorbBytes(ts, abi.encodePacked(proof.auxCommitmentRoot));
        require(
            proof.auxConstraintEval.add(proof.auxBatchR.mul(proof.auxPermEval)) == proof.auxEvalValue,
            "aux decomp"
        );

        // Combined sumcheck
        TranscriptLib.domainSeparate(ts, "combined-sumcheck");
        require(TranscriptLib.squeezeChallenge(ts) == proof.mu, "mu");
    }

    /// @dev Run batch-eval consistency and invoke WHIR verification using the
    /// proof's own ext3 eval fields. Extracted to keep verify() stack frame small.
    function _runBatchAndWhir(
        MleProof calldata proof,
        SpongefishWhirVerify.WhirParams memory whirParams,
        VerifyParams memory vp,
        TranscriptLib.Transcript memory ts
    ) private pure {
        TranscriptLib.domainSeparate(ts, "pcs-eval");
        require(
            _computeBatchedEval(proof.preprocessedIndividualEvals, proof.preprocessedBatchR) ==
                proof.preprocessedEvalValue,
            "pre batch"
        );
        require(
            proof.preprocessedIndividualEvals.length == vp.numConstants + vp.numRoutedWires,
            "pre len"
        );
        require(
            _computeBatchedEval(proof.witnessIndividualEvals, proof.witnessBatchR) ==
                proof.witnessEvalValue,
            "wit batch"
        );

        // ── v2 logUp: also bind preprocessed batch eval at r_inv. ────────
        require(
            _computeBatchedEval(proof.preprocessedIndividualEvalsAtRInv, proof.preprocessedBatchR)
                == proof.preprocessedEvalValueAtRInv,
            "pre batch r_inv"
        );

        // SECURITY (Issue #3 + #7 + v2 logUp + R2-#1): Pull whirEvals from
        // the proof itself. Layout: [point][vector], 4 points × 4 vectors.
        GoldilocksExt3.Ext3[] memory whirEvals = new GoldilocksExt3.Ext3[](16);
        // Point 0: r_gate (combined sumcheck output)
        whirEvals[0] = proof.preprocessedWhirEval;
        whirEvals[1] = proof.witnessWhirEval;
        whirEvals[2] = proof.auxWhirEval;
        whirEvals[3] = proof.inverseHelpersWhirEvalAtRGate;
        // Point 1: r_inv
        whirEvals[4] = proof.preprocessedWhirEvalAtRInv;
        whirEvals[5] = proof.witnessWhirEvalAtRInv;
        whirEvals[6] = proof.auxWhirEvalAtRInv;
        whirEvals[7] = proof.inverseHelpersWhirEvalAtRInv;
        // Point 2: r_h
        whirEvals[8] = proof.preprocessedWhirEvalAtRH;
        whirEvals[9] = proof.witnessWhirEvalAtRH;
        whirEvals[10] = proof.auxWhirEvalAtRH;
        whirEvals[11] = proof.inverseHelpersWhirEvalAtRH;
        // Point 3: r_gate_v2 (Φ_gate sumcheck output — Issue R2-#1)
        whirEvals[12] = proof.preprocessedWhirEvalAtRGateV2;
        whirEvals[13] = proof.witnessWhirEvalAtRGateV2;
        whirEvals[14] = proof.auxWhirEvalAtRGateV2;
        whirEvals[15] = proof.inverseHelpersWhirEvalAtRGateV2;

        // Batch consistency at r_gate_v2 (witness + full preprocessed)
        require(
            _computeBatchedEval(proof.witnessIndividualEvalsAtRGateV2, proof.witnessBatchR)
                == proof.witnessEvalValueAtRGateV2,
            "wit batch r_gate_v2"
        );
        require(
            _computeBatchedEval(proof.preprocessedIndividualEvalsAtRGateV2, proof.preprocessedBatchR)
                == proof.preprocessedEvalValueAtRGateV2,
            "pre batch r_gate_v2"
        );

        require(
            SpongefishWhirVerify.verifyWhirProof(
                vp.protocolId,
                vp.sessionId,
                "",
                proof.whirTranscript,
                proof.whirHints,
                whirEvals,
                whirParams
            ),
            "WHIR"
        );
    }


    /// @dev Run the Φ_gate sumcheck and its terminal check in a single scope
    /// so that `tauGate` and `gateFinalV2` don't live in `_verifyCore`'s stack
    /// frame during the subsequent WHIR batching. Returns `rGateV2` which is
    /// still needed for the WHIR evaluation-point binding.
    function _runGateSumcheckAndTerminal(
        MleProof calldata proof,
        VerifyParams memory vp,
        TranscriptLib.Transcript memory ts
    ) private pure returns (uint256[] memory rGateV2) {
        TranscriptLib.domainSeparate(ts, "v2-gate-challenges");
        uint256[] memory tauGate = TranscriptLib.squeezeChallenges(ts, vp.degreeBits);
        TranscriptLib.domainSeparate(ts, "v2-gate-zerocheck");
        SumcheckVerifier.SumcheckProof memory gateSc = _copySumcheckProof(proof.gateSumcheckProof);
        uint256 gateFinalV2;
        (rGateV2, gateFinalV2) = SumcheckVerifier.verify(
            gateSc,
            0,
            vp.degreeBits,
            2 + proof.quotientDegreeFactor,
            ts
        );
        // Terminal check uses proof.gates / wire+const evals at r_gate_v2 —
        // all now C1+C2 bound at the verify() entry.
        _checkGateTerminal(proof, tauGate, rGateV2, gateFinalV2);
    }

    /// @notice Public helper: compute the VK-bound gate-layout digest.
    ///
    /// The digest protects against the gate-reinterpretation forgery
    /// described in phase3_c1_threat_model.md. The on-chain verifier
    /// (`_requireGatesDigest` inside `verify`) re-computes this value and
    /// compares against the `gatesDigest` passed by the caller; a mismatch
    /// reverts with `"gatesDigest"`.
    ///
    /// Deployers and test harnesses MUST invoke this function (or emit the
    /// identical byte layout off-chain) to pin a circuit's expected digest.
    ///
    /// Hashed layout (deterministic):
    ///   [0x00] version       (32 bytes)
    ///   [0x20] numWires      (32 bytes)
    ///   [0x40] numSelectors  (32 bytes)
    ///   [0x60] numGateConstr (32 bytes)
    ///   [0x80] qdf           (32 bytes)
    ///   [0xa0] gatesLen      (32 bytes)
    ///   [0xc0] gates data    (gatesLen × 288 bytes, raw calldata copy)
    ///
    /// Each GateInfo element occupies 9 × 32 = 288 bytes in calldata because
    /// uint8/uint16 fields are individually padded to the 32-byte word
    /// boundary; this matches the layout `calldatacopy` would produce.
    function computeGatesDigest(
        Plonky2GateEvaluator.GateInfo[] calldata gates,
        uint256 numWires,
        uint256 numSelectors,
        uint256 numGateConstraints,
        uint256 quotientDegreeFactor
    ) public pure returns (bytes32 computed) {
        assembly {
            let ptr := mload(0x40)
            mstore(ptr,            GATES_DIGEST_VERSION)
            mstore(add(ptr, 0x20), numWires)
            mstore(add(ptr, 0x40), numSelectors)
            mstore(add(ptr, 0x60), numGateConstraints)
            mstore(add(ptr, 0x80), quotientDegreeFactor)
            let gatesLen := gates.length
            mstore(add(ptr, 0xa0), gatesLen)
            let gatesBytes := mul(gatesLen, 288)
            calldatacopy(add(ptr, 0xc0), gates.offset, gatesBytes)
            computed := keccak256(ptr, add(0xc0, gatesBytes))
        }
    }

    /// @dev C1 VK-binding check. Delegates to `computeGatesDigest` so the
    /// on-chain and off-chain hashes stay in lockstep.
    function _requireGatesDigest(MleProof calldata proof, bytes32 expected) private pure {
        bytes32 computed = computeGatesDigest(
            proof.gates,
            proof.witnessIndividualEvalsAtRGateV2.length,
            proof.numSelectors,
            proof.numGateConstraints,
            proof.quotientDegreeFactor
        );
        require(computed == expected, "gatesDigest");
    }

    /// @dev C2 boundary canonicalization — fully Yul-ified.
    ///
    /// Every prover-supplied `uint256` array consumed by inline-assembly
    /// `sub(P, X)` (directly or via MleProof fields reaching
    /// `Plonky2GateEvaluator` / `PoseidonGate`) must be `< P` to prevent the
    /// K = 2^32 − 1 injection attack documented in phase2_c2_poc_report.md.
    ///
    /// The entire check runs in a single assembly block so the per-array
    /// function-call overhead is amortized and the `P` constant lives in one
    /// stack slot. On a medium_mul fixture this saves ~40k gas over the
    /// previous `_requireCanonicalArray` helper-per-array structure.
    function _requireCanonicalProofInputs(MleProof calldata proof) private pure {
        // Split into two halves to stay under the Yul stack limit (each half
        // has 5 calldata array offset+length pairs = 10 stack slots, plus
        // locals = ~14, well within budget).
        _canonHalfA(
            proof.preprocessedIndividualEvals,
            proof.witnessIndividualEvals,
            proof.preprocessedIndividualEvalsAtRInv,
            proof.witnessIndividualEvalsAtRInv,
            proof.inverseHelpersEvalsAtRInv
        );
        _canonHalfB(
            proof.inverseHelpersEvalsAtRH,
            proof.witnessIndividualEvalsAtRGateV2,
            proof.preprocessedIndividualEvalsAtRGateV2,
            proof.circuitDigest,
            proof.publicInputs
        );
        _canonPih(proof.publicInputsHash);
    }

    /// @dev Five-array canonicalization — first half. Single Yul block,
    /// shared revert path, one `P` constant on the stack.
    function _canonHalfA(
        uint256[] calldata a0,
        uint256[] calldata a1,
        uint256[] calldata a2,
        uint256[] calldata a3,
        uint256[] calldata a4
    ) private pure {
        assembly {
            function checkArr(off, n, p) {
                for { let i := 0 } lt(i, n) { i := add(i, 1) } {
                    let v := calldataload(add(off, mul(i, 0x20)))
                    if iszero(lt(v, p)) {
                        mstore(0x00, 0x08c379a000000000000000000000000000000000000000000000000000000000)
                        mstore(0x04, 0x20)
                        mstore(0x24, 9)
                        mstore(0x44, "canonical")
                        revert(0x00, 0x64)
                    }
                }
            }
            let P_ := 0xFFFFFFFF00000001
            checkArr(a0.offset, a0.length, P_)
            checkArr(a1.offset, a1.length, P_)
            checkArr(a2.offset, a2.length, P_)
            checkArr(a3.offset, a3.length, P_)
            checkArr(a4.offset, a4.length, P_)
        }
    }

    function _canonHalfB(
        uint256[] calldata a0,
        uint256[] calldata a1,
        uint256[] calldata a2,
        uint256[] calldata a3,
        uint256[] calldata a4
    ) private pure {
        assembly {
            function checkArr(off, n, p) {
                for { let i := 0 } lt(i, n) { i := add(i, 1) } {
                    let v := calldataload(add(off, mul(i, 0x20)))
                    if iszero(lt(v, p)) {
                        mstore(0x00, 0x08c379a000000000000000000000000000000000000000000000000000000000)
                        mstore(0x04, 0x20)
                        mstore(0x24, 9)
                        mstore(0x44, "canonical")
                        revert(0x00, 0x64)
                    }
                }
            }
            let P_ := 0xFFFFFFFF00000001
            checkArr(a0.offset, a0.length, P_)
            checkArr(a1.offset, a1.length, P_)
            checkArr(a2.offset, a2.length, P_)
            checkArr(a3.offset, a3.length, P_)
            checkArr(a4.offset, a4.length, P_)
        }
    }

    /// @dev Fixed-size 4-element publicInputsHash canonicalization. Unrolled.
    function _canonPih(uint256[4] calldata pih) private pure {
        assembly {
            let P_ := 0xFFFFFFFF00000001
            let h0 := calldataload(pih)
            let h1 := calldataload(add(pih, 0x20))
            let h2 := calldataload(add(pih, 0x40))
            let h3 := calldataload(add(pih, 0x60))
            if or(
                or(iszero(lt(h0, P_)), iszero(lt(h1, P_))),
                or(iszero(lt(h2, P_)), iszero(lt(h3, P_)))
            ) {
                mstore(0x00, 0x08c379a000000000000000000000000000000000000000000000000000000000)
                mstore(0x04, 0x20)
                mstore(0x24, 13)
                mstore(0x44, "canonical pih")
                revert(0x00, 0x64)
            }
        }
    }

    /// @dev Yul-optimized: replaces the per-element calldata→memory loop with
    /// a single `calldatacopy`.
    function _derivePreprocessedBatchR(uint256[] calldata cd) private pure returns (uint256) {
        TranscriptLib.Transcript memory t;
        TranscriptLib.init(t);
        TranscriptLib.domainSeparate(t, "preprocessed-batch-r");
        uint256 n = cd.length;
        uint256[] memory m = new uint256[](n);
        assembly {
            calldatacopy(add(m, 0x20), cd.offset, mul(n, 0x20))
        }
        TranscriptLib.absorbFieldVec(t, m);
        return TranscriptLib.squeezeChallenge(t);
    }

    function _computeBatchedEval(uint256[] calldata evals, uint256 batchR) private pure returns (uint256 result) {
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

    /// @dev Derive WHIR evaluationPoint from sumcheck output r.
    /// Each r[i] (Goldilocks base field) is embedded as Ext3(r[i], 0, 0).
    /// SECURITY: The PCS evaluation point MUST be the sumcheck output point,
    /// not an external parameter — this is the binding described in paper §4.4.
    ///
    /// Yul-optimized: avoids per-element struct allocation. We allocate one
    /// contiguous memory region for the full `Ext3[]` (header + n×96 bytes
    /// since Ext3 is 3×32 = 96 bytes in memory) and fill it from the `r` array
    /// in one loop, pointer-patching the array element pointers at the same
    /// time. Note that in memory, `Ext3[] memory arr` stores `arr[i]` as a
    /// pointer at `arr + 0x20 + 32·i`, with each Ext3 struct body following
    /// after the pointer table.
    function _deriveEvalPoint(uint256[] memory r)
        private pure returns (GoldilocksExt3.Ext3[] memory pt)
    {
        uint256 n = r.length;
        pt = new GoldilocksExt3.Ext3[](n);
        assembly {
            // Payload of r: word i at add(r, 0x20 + 32·i).
            // Each Ext3 struct has 3 uint64 fields, laid out in memory as
            // 3 × 32-byte words (Solidity pads uint64 to word). With Solidity
            // allocating each Ext3 separately, `pt[i]` contains a pointer.
            let rPtr := add(r, 0x20)
            let ptPtr := add(pt, 0x20)
            for { let i := 0 } lt(i, n) { i := add(i, 1) } {
                let ri := mload(add(rPtr, mul(i, 0x20)))
                // Allocate Ext3 struct body: 3 words.
                let structPtr := mload(0x40)
                mstore(0x40, add(structPtr, 0x60))
                mstore(structPtr, ri)              // c0 = r[i] (uint64 fits in word)
                mstore(add(structPtr, 0x20), 0)    // c1 = 0
                mstore(add(structPtr, 0x40), 0)    // c2 = 0
                mstore(add(ptPtr, mul(i, 0x20)), structPtr)
            }
        }
    }

    /// @dev Copy a sumcheck proof from calldata to memory using `calldatacopy`
    /// for the inner `uint256[] evals` arrays (instead of an element-wise
    /// Solidity loop). Called 4× per verify — on a 16-round fixture this
    /// saves ~5 × 16 × #rounds gas vs the naïve loop.
    function _copySumcheckProof(SumcheckVerifier.SumcheckProof calldata src)
        private pure returns (SumcheckVerifier.SumcheckProof memory dst)
    {
        uint256 nRounds = src.roundPolys.length;
        dst.roundPolys = new SumcheckVerifier.RoundPoly[](nRounds);
        for (uint256 i = 0; i < nRounds; i++) {
            uint256[] calldata srcEvals = src.roundPolys[i].evals;
            uint256 n = srcEvals.length;
            uint256[] memory dstEvals = new uint256[](n);
            assembly {
                // Copy n · 32 bytes from calldata into memory starting at
                // the `uint256[]` payload (skipping the 0x20 length prefix).
                calldatacopy(add(dstEvals, 0x20), srcEvals.offset, mul(n, 0x20))
            }
            dst.roundPolys[i].evals = dstEvals;
        }
    }
}
