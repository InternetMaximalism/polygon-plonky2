// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.25;

import {Test} from "forge-std/Test.sol";
import {MleVerifier} from "../src/MleVerifier.sol";
import {SumcheckVerifier} from "../src/SumcheckVerifier.sol";
import {SpongefishWhirVerify} from "../src/spongefish/SpongefishWhirVerify.sol";
import {GoldilocksExt3} from "../src/spongefish/GoldilocksExt3.sol";
import {Plonky2GateEvaluator} from "../src/Plonky2GateEvaluator.sol";

/// @title BoundaryCheckTest — negative tests for C1 (gatesDigest) and C2
/// (canonicalization) boundary checks added under `vulcheck-mle-solidity`.
///
/// Reuses the `small_mul.json` fixture as a valid baseline and then mutates
/// exactly one field to verify each attack path is rejected.
contract BoundaryCheckTest is Test {
    MleVerifier verifier;

    uint256 constant P = 0xFFFFFFFF00000001;

    function setUp() public {
        verifier = new MleVerifier();
    }

    // ──────────────────────────────────────────────────────────────────
    //  C1 — gatesDigest mismatch must revert
    // ──────────────────────────────────────────────────────────────────

    function test_c1_wrong_gatesDigest_reverts() public {
        (
            MleVerifier.MleProof memory proof,
            MleVerifier.VerifyParams memory vp,
            SpongefishWhirVerify.WhirParams memory whir,
            bytes32 correctDigest
        ) = _loadFixture("test/fixtures/small_mul.json");

        // Bump one byte of the expected digest — the pre-verify check must
        // fire before any sumcheck work happens.
        bytes32 wrongDigest = bytes32(uint256(correctDigest) ^ 1);

        vm.expectRevert(bytes("gatesDigest"));
        verifier.verify(proof, vp, whir, wrongDigest);
    }

    function test_c1_mutated_gates_entry_reverts() public {
        (
            MleVerifier.MleProof memory proof,
            MleVerifier.VerifyParams memory vp,
            SpongefishWhirVerify.WhirParams memory whir,
            bytes32 correctDigest
        ) = _loadFixture("test/fixtures/small_mul.json");

        // Mutate gates[0].selectorIndex — simulates the gate-reinterpretation
        // attack. The deployer's digest was computed from the ORIGINAL layout,
        // so the mutated proof.gates produces a different computed digest.
        proof.gates[0].selectorIndex = uint8(uint256(proof.gates[0].selectorIndex) ^ 0xff);

        vm.expectRevert(bytes("gatesDigest"));
        verifier.verify(proof, vp, whir, correctDigest);
    }

    function test_c1_mutated_numSelectors_reverts() public {
        (
            MleVerifier.MleProof memory proof,
            MleVerifier.VerifyParams memory vp,
            SpongefishWhirVerify.WhirParams memory whir,
            bytes32 correctDigest
        ) = _loadFixture("test/fixtures/small_mul.json");

        proof.numSelectors = proof.numSelectors + 1;

        vm.expectRevert(bytes("gatesDigest"));
        verifier.verify(proof, vp, whir, correctDigest);
    }

    function test_c1_mutated_quotientDegreeFactor_reverts() public {
        // A higher-than-real `quotientDegreeFactor` would widen the sumcheck
        // accepting-set. Must be bound by gatesDigest.
        (
            MleVerifier.MleProof memory proof,
            MleVerifier.VerifyParams memory vp,
            SpongefishWhirVerify.WhirParams memory whir,
            bytes32 correctDigest
        ) = _loadFixture("test/fixtures/small_mul.json");

        proof.quotientDegreeFactor = proof.quotientDegreeFactor + 1;

        vm.expectRevert(bytes("gatesDigest"));
        verifier.verify(proof, vp, whir, correctDigest);
    }

    // ──────────────────────────────────────────────────────────────────
    //  C2 — non-canonical individual-eval entry must revert
    // ──────────────────────────────────────────────────────────────────

    function test_c2_non_canonical_witness_at_r_gate_v2_reverts() public {
        (
            MleVerifier.MleProof memory proof,
            MleVerifier.VerifyParams memory vp,
            SpongefishWhirVerify.WhirParams memory whir,
            bytes32 gatesDigest
        ) = _loadFixture("test/fixtures/small_mul.json");

        // Shift wire[0] by +P (attack representative from phase2_c2_poc_report.md).
        proof.witnessIndividualEvalsAtRGateV2[0] += P;

        vm.expectRevert(bytes("canonical"));
        verifier.verify(proof, vp, whir, gatesDigest);
    }

    function test_c2_non_canonical_preprocessed_at_r_gate_v2_reverts() public {
        (
            MleVerifier.MleProof memory proof,
            MleVerifier.VerifyParams memory vp,
            SpongefishWhirVerify.WhirParams memory whir,
            bytes32 gatesDigest
        ) = _loadFixture("test/fixtures/small_mul.json");

        proof.preprocessedIndividualEvalsAtRGateV2[0] += P;

        vm.expectRevert(bytes("canonical"));
        verifier.verify(proof, vp, whir, gatesDigest);
    }

    function test_c2_non_canonical_public_inputs_hash_reverts() public {
        (
            MleVerifier.MleProof memory proof,
            MleVerifier.VerifyParams memory vp,
            SpongefishWhirVerify.WhirParams memory whir,
            bytes32 gatesDigest
        ) = _loadFixture("test/fixtures/small_mul.json");

        // publicInputsHash entry >= P
        proof.publicInputsHash[0] = P;

        vm.expectRevert(bytes("canonical pih"));
        verifier.verify(proof, vp, whir, gatesDigest);
    }

    function test_c2_non_canonical_inverse_helpers_at_r_h_reverts() public {
        (
            MleVerifier.MleProof memory proof,
            MleVerifier.VerifyParams memory vp,
            SpongefishWhirVerify.WhirParams memory whir,
            bytes32 gatesDigest
        ) = _loadFixture("test/fixtures/small_mul.json");

        proof.inverseHelpersEvalsAtRH[0] += P;

        vm.expectRevert(bytes("canonical"));
        verifier.verify(proof, vp, whir, gatesDigest);
    }

    function test_c2_exactly_P_is_rejected() public {
        (
            MleVerifier.MleProof memory proof,
            MleVerifier.VerifyParams memory vp,
            SpongefishWhirVerify.WhirParams memory whir,
            bytes32 gatesDigest
        ) = _loadFixture("test/fixtures/small_mul.json");

        // Exactly P (not P-1) is the boundary case. `requireCanonical` uses
        // strict `< P`, so P itself must revert.
        proof.witnessIndividualEvalsAtRGateV2[0] = P;

        vm.expectRevert(bytes("canonical"));
        verifier.verify(proof, vp, whir, gatesDigest);
    }

    function test_c2_max_canonical_passes_digest_check() public {
        // Sanity: P-1 in a wire position passes the canonical check, so
        // C2 only rejects NON-canonical reps, not valid large values.
        // (Full verify still fails downstream because we tampered with data,
        // but it must not fail with "canonical".)
        (
            MleVerifier.MleProof memory proof,
            MleVerifier.VerifyParams memory vp,
            SpongefishWhirVerify.WhirParams memory whir,
            bytes32 gatesDigest
        ) = _loadFixture("test/fixtures/small_mul.json");

        proof.witnessIndividualEvalsAtRGateV2[0] = P - 1;

        // Revert will come from downstream batch-eval inconsistency, NOT
        // from the canonical check. We assert the error string is not
        // "canonical".
        bytes memory err;
        try verifier.verify(proof, vp, whir, gatesDigest) returns (bool) {
            revert("expected tampering to be caught downstream");
        } catch Error(string memory reason) {
            err = bytes(reason);
        }
        require(keccak256(err) != keccak256(bytes("canonical")), "C2 misfired on canonical P-1");
        require(keccak256(err) != keccak256(bytes("canonical pih")), "C2 misfired on canonical P-1");
    }

    // ──────────────────────────────────────────────────────────────────
    //  Fixture loader — thin shim around MleE2ETest's parsing.
    // ──────────────────────────────────────────────────────────────────
    //
    // We re-implement a minimal loader here rather than importing the large
    // MleE2ETest parser; only the fields we mutate in these tests matter.
    // The digest is computed consistently with MleE2ETest._runE2E.

    function _loadFixture(string memory path)
        internal
        returns (
            MleVerifier.MleProof memory proof,
            MleVerifier.VerifyParams memory vp,
            SpongefishWhirVerify.WhirParams memory whir,
            bytes32 gatesDigest
        )
    {
        string memory json = vm.readFile(path);
        MleE2ETestShim shim = new MleE2ETestShim();
        (proof, vp, whir) = shim.parseAll(json);

        gatesDigest = verifier.computeGatesDigest(
            proof.gates,
            proof.witnessIndividualEvalsAtRGateV2.length,
            proof.numSelectors,
            proof.numGateConstraints,
            proof.quotientDegreeFactor
        );
    }
}

/// @dev Thin wrapper that exposes MleE2ETest's internal parsing helpers.
/// Kept separate so BoundaryCheckTest doesn't need to inherit the whole
/// MleE2ETest contract (which would pull all of its tests into this suite).
contract MleE2ETestShim is Test {
    function parseAll(string memory json)
        external
        view
        returns (
            MleVerifier.MleProof memory proof,
            MleVerifier.VerifyParams memory vp,
            SpongefishWhirVerify.WhirParams memory whir
        )
    {
        // Intentionally re-implement the minimal slice needed — any code
        // drift in MleE2ETest parser would otherwise silently break tests.
        proof.circuitDigest = _parseUintArray(json, ".circuitDigest");
        proof.whirTranscript = vm.parseJsonBytes(json, ".whirTranscript");
        proof.whirHints = vm.parseJsonBytes(json, ".whirHints");
        proof.preprocessedRoot = vm.parseJsonBytes32(json, ".preprocessedCommitmentRoot");
        proof.witnessRoot = vm.parseJsonBytes32(json, ".witnessCommitmentRoot");
        proof.preprocessedEvalValue = vm.parseUint(vm.parseJsonString(json, ".preprocessedEvalValue"));
        proof.preprocessedBatchR = vm.parseUint(vm.parseJsonString(json, ".preprocessedBatchR"));
        proof.preprocessedIndividualEvals = _parseUintArray(json, ".preprocessedIndividualEvals");
        proof.witnessEvalValue = vm.parseUint(vm.parseJsonString(json, ".witnessEvalValue"));
        proof.witnessBatchR = vm.parseUint(vm.parseJsonString(json, ".witnessBatchR"));
        proof.witnessIndividualEvals = _parseUintArray(json, ".witnessIndividualEvals");
        proof.auxCommitmentRoot = vm.parseJsonBytes32(json, ".auxCommitmentRoot");
        proof.auxBatchR = vm.parseUint(vm.parseJsonString(json, ".auxBatchR"));
        proof.auxConstraintEval = vm.parseUint(vm.parseJsonString(json, ".auxConstraintEval"));
        proof.auxPermEval = vm.parseUint(vm.parseJsonString(json, ".auxPermEval"));
        proof.auxEvalValue = vm.parseUint(vm.parseJsonString(json, ".auxEvalValue"));
        proof.preprocessedWhirEval = _parseExt3(json, ".preprocessedWhirEval");
        proof.witnessWhirEval = _parseExt3(json, ".witnessWhirEval");
        proof.auxWhirEval = _parseExt3(json, ".auxWhirEval");

        uint256 degreeBits = vm.parseJsonUint(json, ".degreeBits");
        proof.combinedProof = _parseSumcheckProof(json, ".combinedProof", degreeBits);
        proof.alpha = vm.parseUint(vm.parseJsonString(json, ".alpha"));
        proof.beta = vm.parseUint(vm.parseJsonString(json, ".beta"));
        proof.gamma = vm.parseUint(vm.parseJsonString(json, ".gamma"));
        proof.mu = vm.parseUint(vm.parseJsonString(json, ".mu"));
        proof.publicInputs = _parseUintArray(json, ".publicInputs");

        _parseV2(json, proof, degreeBits);
        _parseGates(json, proof, degreeBits);

        vp.degreeBits = degreeBits;
        vp.preprocessedCommitmentRoot = proof.preprocessedRoot;
        vp.numConstants = vm.parseJsonUint(json, ".numConstants");
        vp.numRoutedWires = vm.parseJsonUint(json, ".numRoutedWires");
        vp.protocolId = vm.parseJsonBytes(json, ".whirProtocolId");
        vp.sessionId = vm.parseJsonBytes(json, ".whirSplitSessionId");
        vp.kIs = _parseUintArray(json, ".kIs");
        vp.subgroupGenPowers = _parseUintArray(json, ".subgroupGenPowers");

        whir = _parseWhir(json, ".whirParams");
        whir.numCommitments = 4;
    }

    function _parseV2(string memory json, MleVerifier.MleProof memory proof, uint256 degreeBits)
        internal pure
    {
        proof.inverseHelpersCommitmentRoot = vm.parseJsonBytes32(json, ".inverseHelpersCommitmentRoot");
        proof.inverseHelpersBatchR = vm.parseUint(vm.parseJsonString(json, ".inverseHelpersBatchR"));
        proof.invSumcheckProof = _parseSumcheckProof(json, ".invSumcheckProof", degreeBits);
        proof.hSumcheckProof = _parseSumcheckProof(json, ".hSumcheckProof", degreeBits);
        proof.lambdaInv = vm.parseUint(vm.parseJsonString(json, ".lambdaInv"));
        proof.muInv = vm.parseUint(vm.parseJsonString(json, ".muInv"));
        proof.lambdaH = vm.parseUint(vm.parseJsonString(json, ".lambdaH"));
        proof.witnessIndividualEvalsAtRInv = _parseUintArray(json, ".witnessIndividualEvalsAtRInv");
        proof.preprocessedIndividualEvalsAtRInv = _parseUintArray(json, ".preprocessedIndividualEvalsAtRInv");
        proof.inverseHelpersEvalsAtRInv = _parseUintArray(json, ".inverseHelpersEvalsAtRInv");
        proof.inverseHelpersEvalsAtRH = _parseUintArray(json, ".inverseHelpersEvalsAtRH");
        proof.gSubEvalAtRInv = vm.parseUint(vm.parseJsonString(json, ".gSubEvalAtRInv"));
        proof.witnessEvalValueAtRInv = vm.parseUint(vm.parseJsonString(json, ".witnessEvalValueAtRInv"));
        proof.preprocessedEvalValueAtRInv = vm.parseUint(vm.parseJsonString(json, ".preprocessedEvalValueAtRInv"));
        proof.inverseHelpersWhirEvalAtRGate = _parseExt3(json, ".inverseHelpersWhirEvalAtRGate");
        proof.preprocessedWhirEvalAtRInv = _parseExt3(json, ".preprocessedWhirEvalAtRInv");
        proof.witnessWhirEvalAtRInv = _parseExt3(json, ".witnessWhirEvalAtRInv");
        proof.auxWhirEvalAtRInv = _parseExt3(json, ".auxWhirEvalAtRInv");
        proof.inverseHelpersWhirEvalAtRInv = _parseExt3(json, ".inverseHelpersWhirEvalAtRInv");
        proof.preprocessedWhirEvalAtRH = _parseExt3(json, ".preprocessedWhirEvalAtRH");
        proof.witnessWhirEvalAtRH = _parseExt3(json, ".witnessWhirEvalAtRH");
        proof.auxWhirEvalAtRH = _parseExt3(json, ".auxWhirEvalAtRH");
        proof.inverseHelpersWhirEvalAtRH = _parseExt3(json, ".inverseHelpersWhirEvalAtRH");
    }

    function _parseGates(string memory json, MleVerifier.MleProof memory proof, uint256 degreeBits)
        internal pure
    {
        proof.extChallenge = vm.parseUint(vm.parseJsonString(json, ".extChallenge"));
        proof.gateSumcheckProof = _parseSumcheckProof(json, ".gateSumcheckProof", degreeBits);
        proof.witnessIndividualEvalsAtRGateV2 = _parseUintArray(json, ".witnessIndividualEvalsAtRGateV2");
        proof.preprocessedIndividualEvalsAtRGateV2 = _parseUintArray(json, ".preprocessedIndividualEvalsAtRGateV2");
        proof.witnessEvalValueAtRGateV2 = vm.parseUint(vm.parseJsonString(json, ".witnessEvalValueAtRGateV2"));
        proof.preprocessedEvalValueAtRGateV2 = vm.parseUint(vm.parseJsonString(json, ".preprocessedEvalValueAtRGateV2"));
        proof.preprocessedWhirEvalAtRGateV2 = _parseExt3(json, ".preprocessedWhirEvalAtRGateV2");
        proof.witnessWhirEvalAtRGateV2 = _parseExt3(json, ".witnessWhirEvalAtRGateV2");
        proof.auxWhirEvalAtRGateV2 = _parseExt3(json, ".auxWhirEvalAtRGateV2");
        proof.inverseHelpersWhirEvalAtRGateV2 = _parseExt3(json, ".inverseHelpersWhirEvalAtRGateV2");
        proof.quotientDegreeFactor = vm.parseJsonUint(json, ".quotientDegreeFactor");
        proof.numSelectors = vm.parseJsonUint(json, ".numSelectors");
        proof.numGateConstraints = vm.parseJsonUint(json, ".numGateConstraints");

        uint256 nGates = 0;
        for (uint256 i = 0; i < 32; i++) {
            try vm.parseJsonUint(json, string.concat(".gates[", vm.toString(i), "].gateId"))
                returns (uint256) { nGates = i + 1; } catch { break; }
        }
        proof.gates = new Plonky2GateEvaluator.GateInfo[](nGates);
        for (uint256 i = 0; i < nGates; i++) {
            string memory p = string.concat(".gates[", vm.toString(i), "]");
            proof.gates[i] = Plonky2GateEvaluator.GateInfo({
                gateId: uint8(vm.parseJsonUint(json, string.concat(p, ".gateId"))),
                selectorIndex: uint8(vm.parseJsonUint(json, string.concat(p, ".selectorIndex"))),
                groupStart: uint8(vm.parseJsonUint(json, string.concat(p, ".groupStart"))),
                groupEnd: uint8(vm.parseJsonUint(json, string.concat(p, ".groupEnd"))),
                gateRowIndex: uint8(vm.parseJsonUint(json, string.concat(p, ".gateRowIndex"))),
                numConstraints: uint16(vm.parseJsonUint(json, string.concat(p, ".numConstraints"))),
                numOrConsts: uint16(vm.parseJsonUint(json, string.concat(p, ".numOrConsts"))),
                param2: uint16(vm.parseJsonUint(json, string.concat(p, ".param2"))),
                param3: uint16(vm.parseJsonUint(json, string.concat(p, ".param3")))
            });
        }

        try vm.parseJsonStringArray(json, ".publicInputsHash") returns (string[] memory hs) {
            for (uint256 i = 0; i < 4 && i < hs.length; i++) {
                proof.publicInputsHash[i] = vm.parseUint(hs[i]);
            }
        } catch {}
    }

    function _parseSumcheckProof(string memory json, string memory path, uint256 n)
        internal pure returns (SumcheckVerifier.SumcheckProof memory p)
    {
        p.roundPolys = new SumcheckVerifier.RoundPoly[](n);
        for (uint256 i = 0; i < n; i++) {
            string[] memory strs = vm.parseJsonStringArray(json, string.concat(path, ".roundPolys[", vm.toString(i), "]"));
            uint256[] memory e = new uint256[](strs.length);
            for (uint256 j = 0; j < strs.length; j++) e[j] = vm.parseUint(strs[j]);
            p.roundPolys[i].evals = e;
        }
    }

    function _parseExt3(string memory json, string memory path)
        internal pure returns (GoldilocksExt3.Ext3 memory)
    {
        return GoldilocksExt3.Ext3(
            uint64(vm.parseUint(vm.parseJsonString(json, string.concat(path, ".c0")))),
            uint64(vm.parseUint(vm.parseJsonString(json, string.concat(path, ".c1")))),
            uint64(vm.parseUint(vm.parseJsonString(json, string.concat(path, ".c2"))))
        );
    }

    function _parseUintArray(string memory json, string memory path)
        internal pure returns (uint256[] memory)
    {
        string[] memory strs = vm.parseJsonStringArray(json, path);
        uint256[] memory result = new uint256[](strs.length);
        for (uint256 i = 0; i < strs.length; i++) result[i] = vm.parseUint(strs[i]);
        return result;
    }

    function _parseWhir(string memory json, string memory bp)
        internal pure returns (SpongefishWhirVerify.WhirParams memory w)
    {
        w.numVariables = vm.parseJsonUint(json, string.concat(bp, ".numVariables"));
        w.foldingFactor = vm.parseJsonUint(json, string.concat(bp, ".foldingFactor"));
        w.numVectors = vm.parseJsonUint(json, string.concat(bp, ".numVectors"));
        w.numCommitments = vm.parseJsonUint(json, string.concat(bp, ".numCommitments"));
        w.outDomainSamples = vm.parseJsonUint(json, string.concat(bp, ".outDomainSamples"));
        w.inDomainSamples = vm.parseJsonUint(json, string.concat(bp, ".inDomainSamples"));
        w.initialSumcheckRounds = vm.parseJsonUint(json, string.concat(bp, ".initialSumcheckRounds"));
        w.numRounds = vm.parseJsonUint(json, string.concat(bp, ".numRounds"));
        w.finalSumcheckRounds = vm.parseJsonUint(json, string.concat(bp, ".finalSumcheckRounds"));
        w.finalSize = vm.parseJsonUint(json, string.concat(bp, ".finalSize"));
        w.initialCodewordLength = vm.parseJsonUint(json, string.concat(bp, ".initialCodewordLength"));
        w.initialMerkleDepth = vm.parseJsonUint(json, string.concat(bp, ".initialMerkleDepth"));
        w.initialDomainGenerator = uint64(vm.parseUint(vm.parseJsonString(json, string.concat(bp, ".initialDomainGenerator"))));
        w.initialInterleavingDepth = vm.parseJsonUint(json, string.concat(bp, ".initialInterleavingDepth"));
        w.initialNumVariables = vm.parseJsonUint(json, string.concat(bp, ".initialNumVariables"));
        w.initialCosetSize = vm.parseJsonUint(json, string.concat(bp, ".initialCosetSize"));
        w.initialNumCosets = vm.parseJsonUint(json, string.concat(bp, ".initialNumCosets"));

        uint256 nr = w.numRounds;
        w.rounds = new SpongefishWhirVerify.RoundParams[](nr);
        for (uint256 i = 0; i < nr; i++) {
            string memory rp = string.concat(bp, ".rounds[", vm.toString(i), "]");
            w.rounds[i].codewordLength = vm.parseJsonUint(json, string.concat(rp, ".codewordLength"));
            w.rounds[i].merkleDepth = vm.parseJsonUint(json, string.concat(rp, ".merkleDepth"));
            w.rounds[i].domainGenerator = uint64(vm.parseUint(vm.parseJsonString(json, string.concat(rp, ".domainGenerator"))));
            w.rounds[i].inDomainSamples = vm.parseJsonUint(json, string.concat(rp, ".inDomainSamples"));
            w.rounds[i].outDomainSamples = vm.parseJsonUint(json, string.concat(rp, ".outDomainSamples"));
            w.rounds[i].sumcheckRounds = vm.parseJsonUint(json, string.concat(rp, ".sumcheckRounds"));
            w.rounds[i].interleavingDepth = vm.parseJsonUint(json, string.concat(rp, ".interleavingDepth"));
            w.rounds[i].cosetSize = vm.parseJsonUint(json, string.concat(rp, ".cosetSize"));
            w.rounds[i].numCosets = vm.parseJsonUint(json, string.concat(rp, ".numCosets"));
            w.rounds[i].numVariables = vm.parseJsonUint(json, string.concat(rp, ".numVariables"));
        }
        w.evaluationPoint = new GoldilocksExt3.Ext3[](0);
        w.evaluationPoint2 = new GoldilocksExt3.Ext3[](0);
    }
}
