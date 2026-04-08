// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {MleVerifier} from "../src/MleVerifier.sol";
import {SumcheckVerifier} from "../src/SumcheckVerifier.sol";
import {SpongefishWhirVerify} from "../src/spongefish/SpongefishWhirVerify.sol";
import {GoldilocksExt3} from "../src/spongefish/GoldilocksExt3.sol";

/// @title MleE2ETest
/// @notice Full end-to-end test: MleVerifier.verify() with sumcheck + WHIR.
///         Exercises the complete verification pipeline including:
///         - Fiat-Shamir transcript reconstruction
///         - Permutation sumcheck verification
///         - Constraint zero-check sumcheck verification
///         - Batched evaluation consistency
///         - WHIR PCS polynomial commitment verification
contract MleE2ETest is Test {
    MleVerifier verifier;

    function setUp() public {
        verifier = new MleVerifier();
    }

    function test_e2e_small_mul() public view {
        _runE2E("test/fixtures/small_mul.json");
    }

    function test_e2e_medium_mul() public view {
        _runE2E("test/fixtures/medium_mul.json");
    }

    function test_e2e_large_mul() public view {
        _runE2E("test/fixtures/large_mul.json");
    }

    function test_e2e_poseidon_hash() public view {
        _runE2E("test/fixtures/poseidon_hash.json");
    }

    function test_e2e_recursive_verify() public view {
        _runE2E("test/fixtures/recursive_verify.json");
    }

    function test_e2e_huge_mul() public view {
        _runE2E("test/fixtures/huge_mul.json");
    }

    /// @notice Negative test: tampered eval_value should fail batched eval check.
    function test_e2e_tampered_eval_fails() public {
        string memory json = vm.readFile("test/fixtures/small_mul.json");
        MleVerifier.MleProof memory proof = _parseProof(json);
        uint256 degreeBits = vm.parseJsonUint(json, ".degreeBits");
        SpongefishWhirVerify.WhirParams memory whirParams = _parseWhirParams(json);
        bytes memory protocolId = vm.parseJsonBytes(json, ".whirProtocolId");
        bytes memory sessionId = vm.parseJsonBytes(json, ".whirSessionId");
        GoldilocksExt3.Ext3[] memory whirEvals = _parseWhirEvals(json);

        // Tamper with evalValue
        proof.evalValue = (proof.evalValue + 1) % 0xFFFFFFFF00000001;

        bool success;
        try verifier.verify(proof, degreeBits, whirParams, protocolId, sessionId, whirEvals) returns (bool) {
            success = true;
        } catch {
            success = false;
        }
        assertFalse(success, "Tampered evalValue should fail");
    }

    /// @notice Negative test: tampered pcsConstraintEval should fail constraint check.
    function test_e2e_tampered_constraint_eval_fails() public {
        string memory json = vm.readFile("test/fixtures/small_mul.json");
        MleVerifier.MleProof memory proof = _parseProof(json);
        uint256 degreeBits = vm.parseJsonUint(json, ".degreeBits");
        SpongefishWhirVerify.WhirParams memory whirParams = _parseWhirParams(json);
        bytes memory protocolId = vm.parseJsonBytes(json, ".whirProtocolId");
        bytes memory sessionId = vm.parseJsonBytes(json, ".whirSessionId");
        GoldilocksExt3.Ext3[] memory whirEvals = _parseWhirEvals(json);

        proof.pcsConstraintEval = (proof.pcsConstraintEval + 1) % 0xFFFFFFFF00000001;

        bool success;
        try verifier.verify(proof, degreeBits, whirParams, protocolId, sessionId, whirEvals) returns (bool) {
            success = true;
        } catch {
            success = false;
        }
        assertFalse(success, "Tampered pcsConstraintEval should fail");
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  E2E runner
    // ═══════════════════════════════════════════════════════════════════════

    function _runE2E(string memory fixturePath) internal view {
        string memory json = vm.readFile(fixturePath);

        MleVerifier.MleProof memory proof = _parseProof(json);
        uint256 degreeBits = vm.parseJsonUint(json, ".degreeBits");
        SpongefishWhirVerify.WhirParams memory whirParams = _parseWhirParams(json);
        bytes memory protocolId = vm.parseJsonBytes(json, ".whirProtocolId");
        bytes memory sessionId = vm.parseJsonBytes(json, ".whirSessionId");
        GoldilocksExt3.Ext3[] memory whirEvals = _parseWhirEvals(json);

        console.log("=== E2E:", fixturePath);
        console.log("  degreeBits:", degreeBits);
        console.log("  publicInputs count:", proof.publicInputs.length);
        console.log("  individualEvals count:", proof.individualEvals.length);

        uint256 gasBefore = gasleft();
        bool valid = verifier.verify(proof, degreeBits, whirParams, protocolId, sessionId, whirEvals);
        uint256 gasUsed = gasBefore - gasleft();
        console.log("  TOTAL verify gas:", gasUsed);

        assertTrue(valid, "E2E verification should pass");
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Fixture parsing
    // ═══════════════════════════════════════════════════════════════════════

    function _parseProof(string memory json) internal pure returns (MleVerifier.MleProof memory proof) {
        proof.circuitDigest = _parseUintArray(json, ".circuitDigest");
        proof.whirTranscript = vm.parseJsonBytes(json, ".whirTranscript");
        proof.whirHints = vm.parseJsonBytes(json, ".whirHints");

        // Sumcheck proofs (numRounds = degreeBits)
        uint256 degreeBits = vm.parseJsonUint(json, ".degreeBits");
        proof.permProof = _parseSumcheckProof(json, ".permProof", degreeBits);
        proof.permClaimedSum = vm.parseUint(vm.parseJsonString(json, ".permClaimedSum"));
        proof.constraintProof = _parseSumcheckProof(json, ".constraintProof", degreeBits);

        // Scalars (stored as decimal strings in JSON for IEEE 754 safety)
        proof.evalValue = vm.parseUint(vm.parseJsonString(json, ".evalValue"));
        proof.batchR = vm.parseUint(vm.parseJsonString(json, ".batchR"));
        proof.numPolys = vm.parseJsonUint(json, ".numPolys");
        proof.alpha = vm.parseUint(vm.parseJsonString(json, ".alpha"));
        proof.beta = vm.parseUint(vm.parseJsonString(json, ".beta"));
        proof.gamma = vm.parseUint(vm.parseJsonString(json, ".gamma"));

        // Arrays
        proof.publicInputs = _parseUintArray(json, ".publicInputs");
        proof.individualEvals = _parseUintArray(json, ".individualEvals");
        proof.tau = _parseUintArray(json, ".tau");
        proof.tauPerm = _parseUintArray(json, ".tauPerm");

        // Circuit dimensions
        proof.numWires = vm.parseJsonUint(json, ".numWires");
        proof.numRoutedWires = vm.parseJsonUint(json, ".numRoutedWires");
        proof.numConstants = vm.parseJsonUint(json, ".numConstants");

        // Oracle values
        proof.pcsConstraintEval = vm.parseUint(vm.parseJsonString(json, ".pcsConstraintEval"));
        proof.pcsPermNumeratorEval = vm.parseUint(vm.parseJsonString(json, ".pcsPermNumeratorEval"));
    }

    function _parseSumcheckProof(string memory json, string memory path, uint256 numRounds)
        internal pure returns (SumcheckVerifier.SumcheckProof memory proof)
    {
        proof.roundPolys = new SumcheckVerifier.RoundPoly[](numRounds);
        for (uint256 i = 0; i < numRounds; i++) {
            string memory roundPath = string.concat(path, ".roundPolys[", vm.toString(i), "]");
            string[] memory strs = vm.parseJsonStringArray(json, roundPath);
            uint256[] memory evals = new uint256[](strs.length);
            for (uint256 j = 0; j < strs.length; j++) {
                evals[j] = vm.parseUint(strs[j]);
            }
            proof.roundPolys[i].evals = evals;
        }
    }

    function _parseUintArray(string memory json, string memory path)
        internal pure returns (uint256[] memory)
    {
        // Field elements are serialized as decimal strings in JSON to prevent
        // IEEE 754 precision loss. Parse string array → uint256 array.
        string[] memory strs = vm.parseJsonStringArray(json, path);
        uint256[] memory result = new uint256[](strs.length);
        for (uint256 i = 0; i < strs.length; i++) {
            result[i] = vm.parseUint(strs[i]);
        }
        return result;
    }

    function _parseWhirEvals(string memory json) internal pure returns (GoldilocksExt3.Ext3[] memory) {
        uint64 c0 = uint64(vm.parseUint(vm.parseJsonString(json, ".whirEval.c0")));
        uint64 c1 = uint64(vm.parseUint(vm.parseJsonString(json, ".whirEval.c1")));
        uint64 c2 = uint64(vm.parseUint(vm.parseJsonString(json, ".whirEval.c2")));

        GoldilocksExt3.Ext3[] memory evals = new GoldilocksExt3.Ext3[](1);
        evals[0] = GoldilocksExt3.Ext3(c0, c1, c2);
        return evals;
    }

    function _parseWhirParams(string memory json) internal pure returns (SpongefishWhirVerify.WhirParams memory params) {
        params.numVariables = vm.parseJsonUint(json, ".whirParams.numVariables");
        params.foldingFactor = vm.parseJsonUint(json, ".whirParams.foldingFactor");
        params.numVectors = vm.parseJsonUint(json, ".whirParams.numVectors");
        params.outDomainSamples = vm.parseJsonUint(json, ".whirParams.outDomainSamples");
        params.inDomainSamples = vm.parseJsonUint(json, ".whirParams.inDomainSamples");
        params.initialSumcheckRounds = vm.parseJsonUint(json, ".whirParams.initialSumcheckRounds");
        params.numRounds = vm.parseJsonUint(json, ".whirParams.numRounds");
        params.finalSumcheckRounds = vm.parseJsonUint(json, ".whirParams.finalSumcheckRounds");
        params.finalSize = vm.parseJsonUint(json, ".whirParams.finalSize");
        params.initialCodewordLength = vm.parseJsonUint(json, ".whirParams.initialCodewordLength");
        params.initialMerkleDepth = vm.parseJsonUint(json, ".whirParams.initialMerkleDepth");
        params.initialDomainGenerator = uint64(vm.parseJsonUint(json, ".whirParams.initialDomainGenerator"));
        params.initialInterleavingDepth = vm.parseJsonUint(json, ".whirParams.initialInterleavingDepth");
        params.initialNumVariables = vm.parseJsonUint(json, ".whirParams.initialNumVariables");
        params.initialCosetSize = vm.parseJsonUint(json, ".whirParams.initialCosetSize");
        params.initialNumCosets = vm.parseJsonUint(json, ".whirParams.initialNumCosets");

        // Rounds
        uint256 numRounds = params.numRounds;
        params.rounds = new SpongefishWhirVerify.RoundParams[](numRounds);
        for (uint256 i = 0; i < numRounds; i++) {
            string memory p = string.concat(".whirParams.rounds[", vm.toString(i), "]");
            params.rounds[i].codewordLength = vm.parseJsonUint(json, string.concat(p, ".codewordLength"));
            params.rounds[i].merkleDepth = vm.parseJsonUint(json, string.concat(p, ".merkleDepth"));
            params.rounds[i].domainGenerator = uint64(vm.parseJsonUint(json, string.concat(p, ".domainGenerator")));
            params.rounds[i].inDomainSamples = vm.parseJsonUint(json, string.concat(p, ".inDomainSamples"));
            params.rounds[i].outDomainSamples = vm.parseJsonUint(json, string.concat(p, ".outDomainSamples"));
            params.rounds[i].sumcheckRounds = vm.parseJsonUint(json, string.concat(p, ".sumcheckRounds"));
            params.rounds[i].interleavingDepth = vm.parseJsonUint(json, string.concat(p, ".interleavingDepth"));
            params.rounds[i].cosetSize = vm.parseJsonUint(json, string.concat(p, ".cosetSize"));
            params.rounds[i].numCosets = vm.parseJsonUint(json, string.concat(p, ".numCosets"));
            params.rounds[i].numVariables = vm.parseJsonUint(json, string.concat(p, ".numVariables"));
        }

        // Empty evaluation points (canonical mode)
        params.evaluationPoint = new GoldilocksExt3.Ext3[](0);
        params.evaluationPoint2 = new GoldilocksExt3.Ext3[](0);
    }
}
