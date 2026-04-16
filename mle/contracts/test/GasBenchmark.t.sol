// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.25;

import {MleVerifierTest} from "./MleVerifierTest.sol";
import {MleVerifier} from "../src/MleVerifier.sol";

/// @title GasBenchmark
/// @notice Foundry test contract for gas measurement.
///         Run with: forge test -vvv --gas-report
contract GasBenchmarkTest {
    MleVerifierTest testContract;
    MleVerifier verifier;

    function setUp() public {
        testContract = new MleVerifierTest();
        verifier = new MleVerifier();
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Field operation tests
    // ═══════════════════════════════════════════════════════════════════════

    function test_fieldAdd() public view {
        testContract.testFieldAdd();
    }

    function test_fieldMul() public view {
        testContract.testFieldMul();
    }

    function test_fieldInv() public view {
        testContract.testFieldInv();
    }

    function test_fieldSub() public view {
        testContract.testFieldSub();
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  EqPoly tests
    // ═══════════════════════════════════════════════════════════════════════

    function test_eqEvalBooleanPoint() public view {
        testContract.testEqEvalBooleanPoint();
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Sumcheck tests
    // ═══════════════════════════════════════════════════════════════════════

    function test_sumcheckTrivial() public view {
        testContract.testSumcheckTrivial();
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Gas benchmarks
    // ═══════════════════════════════════════════════════════════════════════

    function test_benchFieldOps() public view {
        (uint256 addGas, uint256 mulGas, uint256 invGas) = testContract.benchmarkFieldOps();
        // Log results (visible in -vvv output)
        addGas; mulGas; invGas;
    }

    function test_benchEqEval_8vars() public view {
        testContract.benchmarkEqEval(8);
    }

    function test_benchEqEval_16vars() public view {
        testContract.benchmarkEqEval(16);
    }

    function test_benchSumcheck_8rounds() public view {
        testContract.benchmarkSumcheck(8);
    }

    function test_benchSumcheck_12rounds() public view {
        testContract.benchmarkSumcheck(12);
    }

    function test_benchSumcheck_16rounds() public view {
        testContract.benchmarkSumcheck(16);
    }

    // Gas estimates removed — WHIR verification gas depends on proof size, not O(2^n).
}
