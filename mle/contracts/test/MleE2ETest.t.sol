// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {MleVerifier} from "../src/MleVerifier.sol";
import {SumcheckVerifier} from "../src/SumcheckVerifier.sol";
import {SpongefishWhirVerify} from "../src/spongefish/SpongefishWhirVerify.sol";
import {GoldilocksExt3} from "../src/spongefish/GoldilocksExt3.sol";
import {Plonky2GateEvaluator} from "../src/Plonky2GateEvaluator.sol";

/// @title MleE2ETest
/// @notice Full end-to-end test: combined sumcheck + main WHIR + auxiliary WHIR.
contract MleE2ETest is Test {
    MleVerifier verifier;

    function setUp() public {
        verifier = new MleVerifier();
    }

    // Issue R2-#1: Solidity port now supports the full mul-chain gate set
    // (ArithmeticGate, ConstantGate, PublicInputGate, NoopGate, PoseidonGate).
    // recursive_verify uses additional gates (CosetInterpolationGate,
    // RandomAccessGate, ReducingGate, ExponentiationGate, BaseSumGate, …)
    // that are NOT yet ported; it is expected to revert with
    // "unsupported gate with non-zero filter".
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

    function test_e2e_huge_mul() public view {
        _runE2E("test/fixtures/huge_mul.json");
    }

    function test_e2e_recursive_verify() public view {
        _runE2E("test/fixtures/recursive_verify.json");
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
        // Issue #2: VK-bound permutation context
        uint256[] kIs;
        uint256[] subgroupGenPowers;
    }

    function _runE2E(string memory fixturePath) internal view {
        string memory json = vm.readFile(fixturePath);
        E2EData memory d = _parseAll(json);

        console.log("=== E2E:", fixturePath);
        console.log("  degreeBits:", d.degreeBits);

        // C1: compute expected gatesDigest via the verifier's public helper.
        // In a real deployment the deployer computes this off-chain and pins
        // it into the on-chain wrapper; the test harness derives it on the
        // fly so valid fixtures continue to verify.
        bytes32 gatesDigest = verifier.computeGatesDigest(
            d.proof.gates,
            d.proof.witnessIndividualEvalsAtRGateV2.length,
            d.proof.numSelectors,
            d.proof.numGateConstraints,
            d.proof.quotientDegreeFactor
        );

        MleVerifier.VerifyParams memory vp = MleVerifier.VerifyParams({
            degreeBits: d.degreeBits,
            preprocessedCommitmentRoot: d.preCommitRoot,
            numConstants: d.numConstants,
            numRoutedWires: d.numRoutedWires,
            protocolId: d.protocolId,
            sessionId: d.sessionId,
            kIs: d.kIs,
            subgroupGenPowers: d.subgroupGenPowers
        });

        uint256 gasBefore = gasleft();
        bool valid = verifier.verify(d.proof, vp, d.whirParams, gatesDigest);
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

        // Multi-point WHIR (4 vectors: preprocessed + witness + aux + inverse_helpers
        // at 3 points: r_gate, r_inv, r_h)
        d.whirParams = _parseWhirParams(json, ".whirParams");
        d.whirParams.numCommitments = 4; // 4 phased split-commit vectors
        d.protocolId = vm.parseJsonBytes(json, ".whirProtocolId");
        d.sessionId = vm.parseJsonBytes(json, ".whirSplitSessionId");

        // Evaluation points are derived inside MleVerifier.verify from the
        // sumcheck output points. No need to set them here.

        // VK values
        d.preCommitRoot = vm.parseJsonBytes32(json, ".preprocessedCommitmentRoot");
        d.numConstants = vm.parseJsonUint(json, ".numConstants");
        d.numRoutedWires = vm.parseJsonUint(json, ".numRoutedWires");

        // Issue #2: permutation argument context
        d.kIs = _parseUintArray(json, ".kIs");
        d.subgroupGenPowers = _parseUintArray(json, ".subgroupGenPowers");
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

        // Issue #3 + #7: WHIR ext3 eval values are now part of MleProof
        proof.preprocessedWhirEval = _parseExt3(json, ".preprocessedWhirEval");
        proof.witnessWhirEval = _parseExt3(json, ".witnessWhirEval");
        proof.auxWhirEval = _parseExt3(json, ".auxWhirEval");

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
        // proof.tau intentionally not parsed: tau is re-derived from the transcript
        // inside MleVerifier.verify(), the prover-supplied value would be a dead field.

        // ── v2 logUp soundness fix (Issue R2-#2) ────────────────────────
        _parseV2LogupFields(json, proof);

        // ── R2-#1: Φ_gate fields + circuit metadata ─────────────────────
        _parseGateFields(json, proof);
    }

    function _parseGateFields(string memory json, MleVerifier.MleProof memory proof) internal pure {
        uint256 degreeBits = vm.parseJsonUint(json, ".degreeBits");
        proof.extChallenge = vm.parseUint(vm.parseJsonString(json, ".extChallenge"));
        proof.gateSumcheckProof = _parseSumcheckProof(json, ".gateSumcheckProof", degreeBits);
        proof.witnessIndividualEvalsAtRGateV2 =
            _parseUintArray(json, ".witnessIndividualEvalsAtRGateV2");
        proof.preprocessedIndividualEvalsAtRGateV2 =
            _parseUintArray(json, ".preprocessedIndividualEvalsAtRGateV2");
        proof.witnessEvalValueAtRGateV2 =
            vm.parseUint(vm.parseJsonString(json, ".witnessEvalValueAtRGateV2"));
        proof.preprocessedEvalValueAtRGateV2 =
            vm.parseUint(vm.parseJsonString(json, ".preprocessedEvalValueAtRGateV2"));
        proof.preprocessedWhirEvalAtRGateV2 = _parseExt3(json, ".preprocessedWhirEvalAtRGateV2");
        proof.witnessWhirEvalAtRGateV2 = _parseExt3(json, ".witnessWhirEvalAtRGateV2");
        proof.auxWhirEvalAtRGateV2 = _parseExt3(json, ".auxWhirEvalAtRGateV2");
        proof.inverseHelpersWhirEvalAtRGateV2 = _parseExt3(json, ".inverseHelpersWhirEvalAtRGateV2");
        proof.quotientDegreeFactor = vm.parseJsonUint(json, ".quotientDegreeFactor");
        proof.numSelectors = vm.parseJsonUint(json, ".numSelectors");
        proof.numGateConstraints = vm.parseJsonUint(json, ".numGateConstraints");

        // Gates array
        uint256 nGates = _countGates(json);
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

        // Public inputs hash is the Poseidon digest computed by the prover.
        // Parse from publicInputsHash field of the fixture (4 base-field values).
        // If not present (older fixtures), fall back to zero.
        try vm.parseJsonStringArray(json, ".publicInputsHash") returns (string[] memory hs) {
            for (uint256 i = 0; i < 4 && i < hs.length; i++) {
                proof.publicInputsHash[i] = vm.parseUint(hs[i]);
            }
        } catch {
            // Fixture does not serialize public_inputs_hash explicitly —
            // derive from proof.publicInputs via Poseidon (unimplemented here).
            // Supported fixtures (large/huge_mul) require this field; if
            // missing, the terminal check will fail below.
        }
    }

    function _countGates(string memory json) internal pure returns (uint256 n) {
        for (uint256 i = 0; i < 32; i++) {
            try vm.parseJsonUint(json, string.concat(".gates[", vm.toString(i), "].gateId"))
                returns (uint256)
            {
                n = i + 1;
            } catch {
                break;
            }
        }
    }

    /// @dev Populate the v2 logUp fields on `proof` from JSON. Extracted to
    /// keep the main _parseProof stack frame small.
    function _parseV2LogupFields(string memory json, MleVerifier.MleProof memory proof) internal pure {
        proof.inverseHelpersCommitmentRoot = vm.parseJsonBytes32(json, ".inverseHelpersCommitmentRoot");
        proof.inverseHelpersBatchR = vm.parseUint(vm.parseJsonString(json, ".inverseHelpersBatchR"));
        uint256 degreeBits = vm.parseJsonUint(json, ".degreeBits");
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
