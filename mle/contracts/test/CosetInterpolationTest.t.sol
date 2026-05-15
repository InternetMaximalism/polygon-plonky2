// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.25;

import {Test} from "forge-std/Test.sol";
import {Plonky2GateEvaluator} from "../src/Plonky2GateEvaluator.sol";
import {CosetInterpolationVectors} from "./CosetInterpolationVectors.sol";

/// @dev External wrapper so `vm.expectRevert` can intercept reverts that
///      originate inside the `internal` library function. Foundry's
///      cheatcode operates on the next external call, not on inlined
///      library code.
contract CosetInterpolationHarness {
    function eval(
        uint256[] memory wires,
        uint256 subgroupBits,
        uint256 degree,
        uint256 filter,
        uint256[] memory acc
    ) external pure returns (uint256[] memory) {
        Plonky2GateEvaluator._evalCosetInterpolation(
            wires, subgroupBits, degree, filter, acc
        );
        return acc;
    }
}

/// @title CosetInterpolationTest
///
/// @notice Bit-exact equivalence test: for every supported
///         `(subgroup_bits, degree)` combination, run
///         `Plonky2GateEvaluator._evalCosetInterpolation` against random
///         wires and compare each base-field constraint value to what
///         `CosetInterpolationGate::eval_unfiltered_base_one` produced
///         on the Rust side. Any mismatch fails the test.
///
/// @dev    Test vectors come from `mle/tests/dump_coset_test_vectors.rs`.
///         Regenerate them whenever the gate's constraint formula
///         changes or the Goldilocks domain encoding shifts (the dumper
///         is the single source of truth — see
///         `tasks/coset_interpolation_port.md` §6 verification matrix).
contract CosetInterpolationTest is Test {
    CosetInterpolationHarness internal harness;

    function setUp() public {
        harness = new CosetInterpolationHarness();
    }

    /// Run every dumped `(bits, degree)` vector through the Solidity gate
    /// evaluator with `filter = 1` and assert bit-exact equality.
    function test_bitExactMatch_filterOne() public pure {
        uint256[2][] memory cs = CosetInterpolationVectors.combos();
        for (uint256 i = 0; i < cs.length; i++) {
            uint256 bits = cs[i][0];
            uint256 degree = cs[i][1];
            (uint256[] memory wires, uint256[] memory expected) =
                _loadVector(bits, degree);
            _checkOne(bits, degree, wires, expected, /*filter=*/ 1);
        }
    }

    /// `filter = 0` must zero every constraint (multiplicative
    /// no-contribution). This is the property the dispatcher relies on
    /// when it `continue`s past a filtered-out row.
    function test_filterZero_zeroesAll() public pure {
        uint256[2][] memory cs = CosetInterpolationVectors.combos();
        for (uint256 i = 0; i < cs.length; i++) {
            uint256 bits = cs[i][0];
            uint256 degree = cs[i][1];
            (uint256[] memory wires, uint256[] memory expected) =
                _loadVector(bits, degree);
            uint256[] memory acc = new uint256[](expected.length);
            Plonky2GateEvaluator._evalCosetInterpolation(
                wires, bits, degree, /*filter=*/ 0, acc
            );
            for (uint256 k = 0; k < acc.length; k++) {
                assertEq(acc[k], 0, "filter=0 must not contribute");
            }
        }
    }

    /// Same as `test_bitExactMatch_filterOne` but with a random non-trivial
    /// filter to exercise the multiplicative accumulation. The expected
    /// value at each slot becomes `filter · expected[i] mod p`.
    function test_bitExactMatch_filterRandom() public pure {
        uint256 p = 0xFFFFFFFF00000001;
        uint256 filter = uint256(keccak256("coset-filter")) % p;
        uint256[2][] memory cs = CosetInterpolationVectors.combos();
        for (uint256 i = 0; i < cs.length; i++) {
            uint256 bits = cs[i][0];
            uint256 degree = cs[i][1];
            (uint256[] memory wires, uint256[] memory expected) =
                _loadVector(bits, degree);
            // Scale expected by filter.
            for (uint256 k = 0; k < expected.length; k++) {
                expected[k] = mulmod(filter, expected[k], p);
            }
            _checkOne(bits, degree, wires, expected, filter);
        }
    }

    /// Verify that unsupported `subgroup_bits` revert at the constants
    /// library entry. We exercise `bits = 5` (larger than supported).
    function test_unsupportedSubgroupBits_revert() public {
        // Wire array must be at least 2·N + 7 + 4·numInt long; with bits=5
        // (N=32) and degree=4 → numInt = 10, length ≥ 113. Allocate plenty.
        uint256[] memory wires = new uint256[](256);
        uint256[] memory acc = new uint256[](256);
        // bits = 5 → would need SUBGROUP_5 which doesn't exist.
        vm.expectRevert(bytes("CosetInterpolation: subgroup_bits not supported"));
        harness.eval(wires, 5, 4, 1, acc);
    }

    function test_degreeBelowTwo_revert() public {
        uint256[] memory wires = new uint256[](16);
        uint256[] memory acc = new uint256[](16);
        vm.expectRevert(bytes("CosetInterpolation: degree must be >= 2"));
        harness.eval(wires, 2, 1, 1, acc);
    }

    // --- internals ------------------------------------------------------

    /// Common harness: call the gate evaluator on `wires` with `filter`,
    /// then assert each `acc[k]` matches the precomputed Rust expected.
    function _checkOne(
        uint256 bits,
        uint256 degree,
        uint256[] memory wires,
        uint256[] memory expected,
        uint256 filter
    ) private pure {
        uint256[] memory acc = new uint256[](expected.length);
        Plonky2GateEvaluator._evalCosetInterpolation(
            wires, bits, degree, filter, acc
        );
        for (uint256 k = 0; k < expected.length; k++) {
            // Helpful failure context: encode (bits, degree, slot) into the
            // failure message so a bad slot doesn't look the same across
            // vectors.
            string memory ctx = string(abi.encodePacked(
                "mismatch bits=", _toStr(bits),
                " deg=", _toStr(degree),
                " slot=", _toStr(k)
            ));
            assertEq(acc[k], expected[k], ctx);
        }
    }

    /// Dispatch from `(bits, degree)` to the right auto-generated vector.
    /// Adding a new vector requires re-running the Rust dumper and adding
    /// a branch here. We intentionally enumerate exhaustively so a
    /// missing vector surfaces as a `revert` rather than a silent skip.
    function _loadVector(uint256 bits, uint256 degree)
        private
        pure
        returns (uint256[] memory wires, uint256[] memory expected)
    {
        // Mapping: dumper uses `max_degree` as the second key but the
        // effective `gate.degree()` may differ. Match by effective degree
        // since that is what the dispatcher passes through `param2`.
        if (bits == 1 && degree == 2) return CosetInterpolationVectors.vector_k1_d2();
        if (bits == 2 && degree == 2) return CosetInterpolationVectors.vector_k2_d2();
        if (bits == 2 && degree == 3) return CosetInterpolationVectors.vector_k2_d3();
        if (bits == 3 && degree == 2) return CosetInterpolationVectors.vector_k3_d2();
        if (bits == 3 && degree == 4) return CosetInterpolationVectors.vector_k3_d4();
        if (bits == 4 && degree == 4) return CosetInterpolationVectors.vector_k4_d4();
        if (bits == 4 && degree == 6) return CosetInterpolationVectors.vector_k4_d6();
        revert("CosetInterpolationTest: vector not found for (bits, degree)");
    }

    function _toStr(uint256 v) private pure returns (string memory) {
        if (v == 0) return "0";
        uint256 j = v;
        uint256 len = 0;
        while (j != 0) {
            j /= 10;
            len++;
        }
        bytes memory bstr = new bytes(len);
        uint256 k = len;
        while (v != 0) {
            k--;
            bstr[k] = bytes1(uint8(48 + (v % 10)));
            v /= 10;
        }
        return string(bstr);
    }
}
