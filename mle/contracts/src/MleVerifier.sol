// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.25;

import {GoldilocksField as F} from "./GoldilocksField.sol";
import {TranscriptLib} from "./TranscriptLib.sol";
import {SumcheckVerifier} from "./SumcheckVerifier.sol";
import {EqPolyLib} from "./EqPolyLib.sol";
import {SpongefishWhirVerify} from "./spongefish/SpongefishWhirVerify.sol";
import {GoldilocksExt3} from "./spongefish/GoldilocksExt3.sol";

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
        uint256[] tau;
    }

    function verify(
        MleProof calldata proof,
        uint256 degreeBits,
        bytes32 preprocessedCommitmentRoot,
        uint256 numConstants,
        uint256 numRoutedWires,
        SpongefishWhirVerify.WhirParams memory whirParams,
        bytes memory protocolId,
        bytes memory sessionId,
        GoldilocksExt3.Ext3[] memory whirEvals
    ) external pure returns (bool) {
        require(proof.circuitDigest.length == 4, "digest len");
        require(_derivePreprocessedBatchR(proof.circuitDigest) == proof.preprocessedBatchR, "preBatchR");
        require(proof.preprocessedRoot == preprocessedCommitmentRoot, "VK binding");

        // Transcript
        TranscriptLib.Transcript memory ts;
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
        require(TranscriptLib.squeezeChallenge(ts) == proof.alpha, "alpha");
        uint256[] memory tau = TranscriptLib.squeezeChallenges(ts, degreeBits);
        TranscriptLib.squeezeChallenges(ts, degreeBits); // tauPerm sync

        TranscriptLib.domainSeparate(ts, "extension-combine");
        TranscriptLib.squeezeChallenge(ts); // ext_challenge sync

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

        SumcheckVerifier.SumcheckProof memory sc = _copySumcheckProof(proof.combinedProof);
        (uint256[] memory r, uint256 finalEval) = SumcheckVerifier.verify(sc, 0, degreeBits, ts);

        // Batch consistency
        TranscriptLib.domainSeparate(ts, "pcs-eval");
        require(_computeBatchedEval(proof.preprocessedIndividualEvals, proof.preprocessedBatchR) == proof.preprocessedEvalValue, "pre batch");
        require(proof.preprocessedIndividualEvals.length == numConstants + numRoutedWires, "pre len");
        require(_computeBatchedEval(proof.witnessIndividualEvals, proof.witnessBatchR) == proof.witnessEvalValue, "wit batch");
        // witnessIndividualEvals length is validated by WHIR binding

        // WHIR (3 vectors)
        require(SpongefishWhirVerify.verifyWhirProof(
            protocolId, sessionId, "",
            proof.whirTranscript, proof.whirHints, whirEvals, whirParams
        ), "WHIR");

        // Final: eq(τ,r)·C̃(r) + μ·h̃(r) = finalEval
        uint256 eqAtR = EqPolyLib.eqEval(tau, r);
        require(eqAtR.mul(proof.auxConstraintEval).add(proof.mu.mul(proof.auxPermEval)) == finalEval, "final");

        return true;
    }

    function _derivePreprocessedBatchR(uint256[] calldata cd) private pure returns (uint256) {
        TranscriptLib.Transcript memory t;
        TranscriptLib.init(t);
        TranscriptLib.domainSeparate(t, "preprocessed-batch-r");
        uint256[] memory m = new uint256[](cd.length);
        for (uint256 i = 0; i < cd.length; i++) m[i] = cd[i];
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
