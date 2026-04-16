// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {MleVerifier} from "../src/MleVerifier.sol";
import {SumcheckVerifier} from "../src/SumcheckVerifier.sol";
import {SpongefishWhirVerify} from "../src/spongefish/SpongefishWhirVerify.sol";
import {GoldilocksExt3} from "../src/spongefish/GoldilocksExt3.sol";

/// @title MleE2ETest
/// @notice Full end-to-end test: combined sumcheck + main WHIR + auxiliary WHIR.
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

    // ═══════════════════════════════════════════════════════════════════
    //  E2E runner
    // ═══════════════════════════════════════════════════════════════════

    /// @dev Intermediate struct to avoid stack-too-deep.
    struct E2EData {
        MleVerifier.MleProof proof;
        uint256 degreeBits;
        bytes32 preCommitRoot;
        uint256 numConstants;
        uint256 numRoutedWires;
        SpongefishWhirVerify.WhirParams whirParams;
        bytes protocolId;
        bytes sessionId;
        GoldilocksExt3.Ext3[] whirEvals;
    }

    function _runE2E(string memory fixturePath) internal view {
        string memory json = vm.readFile(fixturePath);
        E2EData memory d = _parseAll(json);

        console.log("=== E2E:", fixturePath);
        console.log("  degreeBits:", d.degreeBits);

        uint256 gasBefore = gasleft();
        bool valid = verifier.verify(
            d.proof, d.degreeBits, d.preCommitRoot, d.numConstants, d.numRoutedWires,
            d.whirParams, d.protocolId, d.sessionId, d.whirEvals
        );
        uint256 gasUsed = gasBefore - gasleft();
        console.log("  TOTAL verify gas:", gasUsed);

        assertTrue(valid, "E2E verification should pass");
    }

    // ═══════════════════════════════════════════════════════════════════
    //  Fixture parsing
    // ═══════════════════════════════════════════════════════════════════

    function _parseAll(string memory json) internal pure returns (E2EData memory d) {
        d.proof = _parseProof(json);
        d.degreeBits = vm.parseJsonUint(json, ".degreeBits");

        // Single WHIR (3 vectors: preprocessed + witness + auxiliary)
        d.whirParams = _parseWhirParams(json, ".whirParams");
        d.whirParams.numCommitments = 3; // Override for 3-vector phased commit
        d.protocolId = vm.parseJsonBytes(json, ".whirProtocolId");
        d.sessionId = vm.parseJsonBytes(json, ".whirSplitSessionId");

        // 3 Ext3 evals: [preprocessed, witness, auxiliary]
        d.whirEvals = new GoldilocksExt3.Ext3[](3);
        d.whirEvals[0] = _parseExt3(json, ".preprocessedWhirEval");
        d.whirEvals[1] = _parseExt3(json, ".witnessWhirEval");
        d.whirEvals[2] = _parseExt3(json, ".auxWhirEval");

        // Evaluation point (sumcheck output r)
        GoldilocksExt3.Ext3[] memory evalPt = _parseExt3Array(json, ".evaluationPoint");
        d.whirParams.evaluationPoint = evalPt;
        d.whirParams.evaluationPoint2 = new GoldilocksExt3.Ext3[](0);

        // VK values
        d.preCommitRoot = vm.parseJsonBytes32(json, ".preprocessedCommitmentRoot");
        d.numConstants = vm.parseJsonUint(json, ".numConstants");
        d.numRoutedWires = vm.parseJsonUint(json, ".numRoutedWires");
    }

    function _parseProof(string memory json) internal pure returns (MleVerifier.MleProof memory proof) {
        proof.circuitDigest = _parseUintArray(json, ".circuitDigest");

        // Main WHIR PCS
        proof.whirTranscript = vm.parseJsonBytes(json, ".whirTranscript");
        proof.whirHints = vm.parseJsonBytes(json, ".whirHints");
        proof.preprocessedRoot = vm.parseJsonBytes32(json, ".preprocessedCommitmentRoot");
        proof.witnessRoot = vm.parseJsonBytes32(json, ".witnessCommitmentRoot");

        // Preprocessed batch
        proof.preprocessedEvalValue = vm.parseUint(vm.parseJsonString(json, ".preprocessedEvalValue"));
        proof.preprocessedBatchR = vm.parseUint(vm.parseJsonString(json, ".preprocessedBatchR"));
        proof.preprocessedIndividualEvals = _parseUintArray(json, ".preprocessedIndividualEvals");

        // Witness batch
        proof.witnessEvalValue = vm.parseUint(vm.parseJsonString(json, ".witnessEvalValue"));
        proof.witnessBatchR = vm.parseUint(vm.parseJsonString(json, ".witnessBatchR"));
        proof.witnessIndividualEvals = _parseUintArray(json, ".witnessIndividualEvals");

        // Auxiliary polynomial (3rd vector in same WHIR proof)
        proof.auxCommitmentRoot = vm.parseJsonBytes32(json, ".auxCommitmentRoot");
        proof.auxBatchR = vm.parseUint(vm.parseJsonString(json, ".auxBatchR"));
        proof.auxConstraintEval = vm.parseUint(vm.parseJsonString(json, ".auxConstraintEval"));
        proof.auxPermEval = vm.parseUint(vm.parseJsonString(json, ".auxPermEval"));
        proof.auxEvalValue = vm.parseUint(vm.parseJsonString(json, ".auxEvalValue"));

        // Combined sumcheck
        uint256 degreeBits = vm.parseJsonUint(json, ".degreeBits");
        proof.combinedProof = _parseSumcheckProof(json, ".combinedProof", degreeBits);

        // Challenges
        proof.alpha = vm.parseUint(vm.parseJsonString(json, ".alpha"));
        proof.beta = vm.parseUint(vm.parseJsonString(json, ".beta"));
        proof.gamma = vm.parseUint(vm.parseJsonString(json, ".gamma"));
        proof.mu = vm.parseUint(vm.parseJsonString(json, ".mu"));

        // Arrays
        proof.publicInputs = _parseUintArray(json, ".publicInputs");
        proof.tau = _parseUintArray(json, ".tau");

        // (circuit dimensions from VK, not proof)
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

    function _parseWhirParams(string memory json, string memory basePath)
        internal pure returns (SpongefishWhirVerify.WhirParams memory params)
    {
        params.numVariables = vm.parseJsonUint(json, string.concat(basePath, ".numVariables"));
        params.foldingFactor = vm.parseJsonUint(json, string.concat(basePath, ".foldingFactor"));
        params.numVectors = vm.parseJsonUint(json, string.concat(basePath, ".numVectors"));
        params.numCommitments = vm.parseJsonUint(json, string.concat(basePath, ".numCommitments"));
        params.outDomainSamples = vm.parseJsonUint(json, string.concat(basePath, ".outDomainSamples"));
        params.inDomainSamples = vm.parseJsonUint(json, string.concat(basePath, ".inDomainSamples"));
        params.initialSumcheckRounds = vm.parseJsonUint(json, string.concat(basePath, ".initialSumcheckRounds"));
        params.numRounds = vm.parseJsonUint(json, string.concat(basePath, ".numRounds"));
        params.finalSumcheckRounds = vm.parseJsonUint(json, string.concat(basePath, ".finalSumcheckRounds"));
        params.finalSize = vm.parseJsonUint(json, string.concat(basePath, ".finalSize"));
        params.initialCodewordLength = vm.parseJsonUint(json, string.concat(basePath, ".initialCodewordLength"));
        params.initialMerkleDepth = vm.parseJsonUint(json, string.concat(basePath, ".initialMerkleDepth"));
        params.initialDomainGenerator = uint64(vm.parseUint(vm.parseJsonString(json, string.concat(basePath, ".initialDomainGenerator"))));
        params.initialInterleavingDepth = vm.parseJsonUint(json, string.concat(basePath, ".initialInterleavingDepth"));
        params.initialNumVariables = vm.parseJsonUint(json, string.concat(basePath, ".initialNumVariables"));
        params.initialCosetSize = vm.parseJsonUint(json, string.concat(basePath, ".initialCosetSize"));
        params.initialNumCosets = vm.parseJsonUint(json, string.concat(basePath, ".initialNumCosets"));

        uint256 nr = params.numRounds;
        params.rounds = new SpongefishWhirVerify.RoundParams[](nr);
        for (uint256 i = 0; i < nr; i++) {
            string memory rp = string.concat(basePath, ".rounds[", vm.toString(i), "]");
            params.rounds[i].codewordLength = vm.parseJsonUint(json, string.concat(rp, ".codewordLength"));
            params.rounds[i].merkleDepth = vm.parseJsonUint(json, string.concat(rp, ".merkleDepth"));
            params.rounds[i].domainGenerator = uint64(vm.parseUint(vm.parseJsonString(json, string.concat(rp, ".domainGenerator"))));
            params.rounds[i].inDomainSamples = vm.parseJsonUint(json, string.concat(rp, ".inDomainSamples"));
            params.rounds[i].outDomainSamples = vm.parseJsonUint(json, string.concat(rp, ".outDomainSamples"));
            params.rounds[i].sumcheckRounds = vm.parseJsonUint(json, string.concat(rp, ".sumcheckRounds"));
            params.rounds[i].interleavingDepth = vm.parseJsonUint(json, string.concat(rp, ".interleavingDepth"));
            params.rounds[i].cosetSize = vm.parseJsonUint(json, string.concat(rp, ".cosetSize"));
            params.rounds[i].numCosets = vm.parseJsonUint(json, string.concat(rp, ".numCosets"));
            params.rounds[i].numVariables = vm.parseJsonUint(json, string.concat(rp, ".numVariables"));
        }

        params.evaluationPoint = new GoldilocksExt3.Ext3[](0);
        params.evaluationPoint2 = new GoldilocksExt3.Ext3[](0);
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

    function _parseExt3Array(string memory json, string memory path)
        internal pure returns (GoldilocksExt3.Ext3[] memory result)
    {
        // Parse array length by trying indices
        uint256 len = 0;
        for (uint256 i = 0; i < 20; i++) {
            try vm.parseJsonString(json, string.concat(path, "[", vm.toString(i), "].c0")) returns (string memory) {
                len = i + 1;
            } catch {
                break;
            }
        }
        result = new GoldilocksExt3.Ext3[](len);
        for (uint256 i = 0; i < len; i++) {
            string memory ep = string.concat(path, "[", vm.toString(i), "]");
            result[i] = GoldilocksExt3.Ext3(
                uint64(vm.parseUint(vm.parseJsonString(json, string.concat(ep, ".c0")))),
                uint64(vm.parseUint(vm.parseJsonString(json, string.concat(ep, ".c1")))),
                uint64(vm.parseUint(vm.parseJsonString(json, string.concat(ep, ".c2"))))
            );
        }
    }

    function _parseUintArray(string memory json, string memory path)
        internal pure returns (uint256[] memory)
    {
        string[] memory strs = vm.parseJsonStringArray(json, path);
        uint256[] memory result = new uint256[](strs.length);
        for (uint256 i = 0; i < strs.length; i++) {
            result[i] = vm.parseUint(strs[i]);
        }
        return result;
    }

    /// @dev Compute WHIR session ID from a session name string via CBOR + Keccak.
    function _computeSessionId(string memory sessionName) internal pure returns (bytes memory) {
        // CBOR encoding of a text string: major type 3
        bytes memory nameBytes = bytes(sessionName);
        bytes memory cbor;
        if (nameBytes.length < 24) {
            cbor = abi.encodePacked(uint8(0x60 + nameBytes.length), nameBytes);
        } else {
            cbor = abi.encodePacked(uint8(0x78), uint8(nameBytes.length), nameBytes);
        }
        return abi.encodePacked(keccak256(cbor));
    }
}
