// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.25;

import {GoldilocksField as F} from "./GoldilocksField.sol";
import {PoseidonGate} from "./PoseidonGate.sol";
import {PoseidonConstants} from "./PoseidonConstants.sol";

/// @title Plonky2GateEvaluator — minimal port (Issue R2-#1)
///
/// Supports the 4 simple gate types that appear in mul-chain fixtures:
///   ArithmeticGate (num_ops × [c0·w0·w1 + c1·w2 − w3]),
///   ConstantGate (num_consts × [const_i − w_i]),
///   PublicInputGate (4 × [w_i − PI_hash[i]]),
///   NoopGate (no constraints).
///
/// PoseidonGate, CosetInterpolationGate, ReducingGate, LookupGate, …
/// are intentionally NOT ported. Fixtures that activate those gates at
/// any row will fail Solidity verification with a completeness (not
/// soundness) error — the Rust prover remains trusted to include their
/// contribution; if the Solidity evaluator returns a smaller sum the
/// terminal check mismatch causes rejection.
///
/// For `large_mul` and `huge_mul` fixtures, selector[0] is constant 3
/// (ArithmeticGate) and selector[1] is constant UNUSED: every gate
/// except ArithmeticGate has filter = 0 at the sumcheck output point,
/// so only ArithmeticGate actually contributes to the sum.
library Plonky2GateEvaluator {
    using F for uint256;

    uint256 internal constant UNUSED_SELECTOR = 0xFFFFFFFF; // u32::MAX

    // Gate IDs (matches the Rust `common_data.gates.iter().map(|g| g.0.id())`
    // *sorted ascending by gate.degree()*). Fixture must use this ordering.
    uint8 internal constant GATE_NOOP = 0;
    uint8 internal constant GATE_CONSTANT = 1;
    uint8 internal constant GATE_PUBLIC_INPUT = 2;
    uint8 internal constant GATE_ARITHMETIC = 3;
    uint8 internal constant GATE_POSEIDON = 4;
    uint8 internal constant GATE_POSEIDON_MDS = 5;
    uint8 internal constant GATE_ARITHMETIC_EXT = 6;
    uint8 internal constant GATE_MUL_EXT = 7;
    uint8 internal constant GATE_EXPONENTIATION = 8;
    uint8 internal constant GATE_BASE_SUM = 9;
    uint8 internal constant GATE_REDUCING = 10;
    uint8 internal constant GATE_REDUCING_EXT = 11;
    uint8 internal constant GATE_RANDOM_ACCESS = 12;
    uint8 internal constant GATE_COSET_INTERPOLATION = 13;

    /// @dev Ext2 multiplier: X^2 = 7 in F::Extension over Goldilocks.
    uint256 internal constant EXT2_W = 7;

    /// @dev Circuit-specific gate info. Mirror of Plonky2's selectors_info +
    /// per-gate parameters extracted from `gate.id()` string.
    struct GateInfo {
        uint8 gateId;
        uint8 selectorIndex;
        uint8 groupStart;
        uint8 groupEnd;
        uint8 gateRowIndex;
        uint16 numConstraints;
        /// Primary param (see fixture.rs GateInfoFixture for the mapping).
        uint16 numOrConsts;
        /// Secondary param (BaseSum: B; RandomAccess: num_copies; else 0).
        uint16 param2;
        /// Tertiary param (RandomAccess: num_extra_constants; else 0).
        uint16 param3;
    }

    /// @dev Evaluate Σ_j α^j · filter_j · gate_j.eval(w, c) over the
    /// supported gate types, flatten via `ext_challenge`, return the
    /// base-field `flat` value.
    ///
    /// SECURITY: the returned value is exactly what the Φ_gate terminal
    /// check compares against the sumcheck final evaluation, modulo
    /// `eq(τ, r)`. The lookup argument, if any, is NOT handled (consistent
    /// with the Rust verifier which also errors on `!common_data.luts.is_empty()`).
    ///
    /// Params:
    ///  - wires: MLE(W_k)(r) for k = 0..num_wires-1
    ///  - preprocessed: [selectors || gate_constants || sigmas] at r. Only the first
    ///    `numConstants` entries are used here (sigmas are ignored).
    ///  - alpha, extChallenge: Fiat-Shamir challenges.
    ///  - publicInputsHash: 4-element Poseidon digest of the public inputs.
    ///  - gates: sorted (asc by degree) list of gates present in common_data.
    ///  - numSelectors: common_data.selectors_info.num_selectors().
    ///  - numConstants: common_data.num_constants.
    ///  - numGateConstraints: common_data.num_gate_constraints.
    function evalCombinedFlat(
        uint256[] calldata wiresCd,
        uint256[] calldata preprocessedCd,
        uint256 alpha,
        uint256 extChallenge,
        uint256[4] memory publicInputsHash,
        GateInfo[] calldata gatesCd,
        uint256 numSelectors,
        uint256 numConstants,
        uint256 numGateConstraints
    ) internal pure returns (uint256 flat) {
        // The inner gate helpers were written against memory arrays. We copy
        // once here (instead of at every call site) so the dispatcher below
        // can reuse the memory arrays across all gate calls.
        uint256[] memory wires = _cdToMem(wiresCd);
        uint256[] memory preprocessed = _cdToMem(preprocessedCd);
        GateInfo[] memory gates = _gatesCdToMem(gatesCd);
        // Component 0: ext component c0 of the combined constraint.
        // Component 1: ext component c1.
        // For D=2, combined_ext.to_basefield_array() = [c0, c1].
        // We assemble (c0, c1) as if in F::Extension, combining per-gate contributions
        // (base-field only since in this minimal scope every supported gate returns
        // a base-field value — the full Ext3 recomposition is only needed for
        // extension-field gates, which we do not port).
        //
        // flat = c0 + extChallenge·c1
        uint256 c0 = 0;
        uint256 c1 = 0;

        uint256[] memory perIdxAccum = new uint256[](numGateConstraints);
        // Running index into the α-powers → we accumulate per constraint slot.
        // Each gate's eval produces gate.num_constraints() entries; they write
        // into perIdxAccum[0..gate.num_constraints()] (added, not overwriting,
        // matching `evaluate_gate_constraints` which does `constraints[i] += c`).
        for (uint256 g = 0; g < gates.length; g++) {
            GateInfo memory gi = gates[g];
            uint256 selectorVal = preprocessed[gi.selectorIndex];
            uint256 filter = _computeFilter(
                gi.gateRowIndex,
                gi.groupStart,
                gi.groupEnd,
                selectorVal,
                numSelectors > 1
            );
            if (filter == 0) {
                continue;
            }

            // Gate-specific eval. The gate's view of local_constants has the
            // first `numSelectors` entries stripped (see Gate::eval_filtered
            // in plonky2 — `vars.remove_prefix(num_selectors)`).
            if (gi.gateId == GATE_ARITHMETIC) {
                _evalArithmetic(
                    wires,
                    preprocessed,
                    numSelectors,
                    gi.numOrConsts,
                    filter,
                    perIdxAccum
                );
            } else if (gi.gateId == GATE_CONSTANT) {
                _evalConstant(
                    wires,
                    preprocessed,
                    numSelectors,
                    gi.numOrConsts,
                    filter,
                    perIdxAccum
                );
            } else if (gi.gateId == GATE_PUBLIC_INPUT) {
                _evalPublicInput(wires, publicInputsHash, filter, perIdxAccum);
            } else if (gi.gateId == GATE_NOOP) {
                continue;
            } else if (gi.gateId == GATE_POSEIDON) {
                PoseidonGate.evalConstraints(wires, filter, perIdxAccum);
            } else if (gi.gateId == GATE_POSEIDON_MDS) {
                _evalPoseidonMds(wires, filter, perIdxAccum);
            } else if (gi.gateId == GATE_ARITHMETIC_EXT) {
                _evalArithmeticExt(
                    wires,
                    preprocessed,
                    numSelectors,
                    gi.numOrConsts,
                    filter,
                    perIdxAccum
                );
            } else if (gi.gateId == GATE_MUL_EXT) {
                _evalMulExt(
                    wires,
                    preprocessed,
                    numSelectors,
                    gi.numOrConsts,
                    filter,
                    perIdxAccum
                );
            } else if (gi.gateId == GATE_BASE_SUM) {
                _evalBaseSum(wires, gi.numOrConsts, gi.param2, filter, perIdxAccum);
            } else if (gi.gateId == GATE_REDUCING) {
                _evalReducing(wires, gi.numOrConsts, filter, perIdxAccum);
            } else if (gi.gateId == GATE_REDUCING_EXT) {
                _evalReducingExt(wires, gi.numOrConsts, filter, perIdxAccum);
            } else if (gi.gateId == GATE_RANDOM_ACCESS) {
                _evalRandomAccess(
                    wires,
                    preprocessed,
                    numSelectors,
                    gi.numOrConsts, // bits
                    gi.param2,      // num_copies
                    gi.param3,      // num_extra_constants
                    filter,
                    perIdxAccum
                );
            } else {
                // Unsupported gate (ExponentiationGate, CosetInterpolationGate,
                // LookupGate, …). SECURITY: if filter != 0, we revert to signal
                // a completeness failure. Never silently accepts.
                revert("unsupported gate with non-zero filter");
            }
        }

        // Combine via α-powers and accumulate into c0. c1 remains 0 in the
        // minimal port because all supported gates produce base-field
        // constraints (see comment above).
        assembly {
            let p := 0xFFFFFFFF00000001
            let ptr := add(perIdxAccum, 0x20)
            let alphaPow := 1
            for { let i := 0 } lt(i, numGateConstraints) { i := add(i, 1) } {
                c0 := addmod(c0, mulmod(alphaPow, mload(add(ptr, mul(i, 0x20))), p), p)
                alphaPow := mulmod(alphaPow, alpha, p)
            }
        }

        // flat = c0 + extChallenge · c1 = c0 (c1 = 0).
        flat = c0.add(extChallenge.mul(c1));
    }

    /// @dev Efficient calldata → memory copies for the outer dispatcher.
    function _cdToMem(uint256[] calldata src) private pure returns (uint256[] memory dst) {
        uint256 len = src.length;
        dst = new uint256[](len);
        assembly {
            calldatacopy(add(dst, 0x20), src.offset, mul(len, 0x20))
        }
    }

    function _gatesCdToMem(GateInfo[] calldata src) private pure returns (GateInfo[] memory dst) {
        // Struct array has per-element memory pointers; a single calldatacopy
        // would corrupt layout. Element-wise copy.
        uint256 len = src.length;
        dst = new GateInfo[](len);
        for (uint256 i = 0; i < len; i++) dst[i] = src[i];
    }

    /// @dev Plonky2 filter polynomial (see plonky2/src/gates/gate.rs:326).
    /// filter(s) = Π_{i ∈ groupRange, i != row}(i − s) · (manySel ? (UNUSED − s) : 1)
    function _computeFilter(
        uint256 row,
        uint256 groupStart,
        uint256 groupEnd,
        uint256 s,
        bool manySel
    ) private pure returns (uint256 result) {
        result = 1;
        for (uint256 i = groupStart; i < groupEnd; i++) {
            if (i == row) continue;
            uint256 factor = F.sub(i, s);
            result = result.mul(factor);
        }
        if (manySel) {
            uint256 factor = F.sub(UNUSED_SELECTOR, s);
            result = result.mul(factor);
        }
    }

    /// @dev ArithmeticGate (Yul). constraint_i = output − (const_0·mul_0·mul_1 + const_1·addend).
    function _evalArithmetic(
        uint256[] memory wires,
        uint256[] memory preprocessed,
        uint256 numSelectors,
        uint256 numOps,
        uint256 filter,
        uint256[] memory acc
    ) private pure {
        assembly {
            let p := 0xFFFFFFFF00000001
            let preBase := add(preprocessed, 0x20)
            let c0 := mload(add(preBase, mul(numSelectors, 0x20)))
            let c1 := mload(add(preBase, mul(add(numSelectors, 1), 0x20)))
            let wPtr := add(wires, 0x20)
            let aPtr := add(acc, 0x20)
            for { let i := 0 } lt(i, numOps) { i := add(i, 1) } {
                let base := add(wPtr, mul(mul(i, 4), 0x20))
                let m0 := mload(base)
                let m1 := mload(add(base, 0x20))
                let addend := mload(add(base, 0x40))
                let output := mload(add(base, 0x60))
                let computed := addmod(
                    mulmod(c0, mulmod(m0, m1, p), p),
                    mulmod(c1, addend, p),
                    p
                )
                let diff := addmod(output, sub(p, computed), p)
                let slot := add(aPtr, mul(i, 0x20))
                mstore(slot, addmod(mload(slot), mulmod(filter, diff, p), p))
            }
        }
    }

    /// @dev ConstantGate (Yul). constraint_i = const_i − wire_i.
    function _evalConstant(
        uint256[] memory wires,
        uint256[] memory preprocessed,
        uint256 numSelectors,
        uint256 numConsts,
        uint256 filter,
        uint256[] memory acc
    ) private pure {
        assembly {
            let p := 0xFFFFFFFF00000001
            let preBase := add(add(preprocessed, 0x20), mul(numSelectors, 0x20))
            let wPtr := add(wires, 0x20)
            let aPtr := add(acc, 0x20)
            for { let i := 0 } lt(i, numConsts) { i := add(i, 1) } {
                let c := mload(add(preBase, mul(i, 0x20)))
                let w := mload(add(wPtr, mul(i, 0x20)))
                let diff := addmod(c, sub(p, w), p)
                let slot := add(aPtr, mul(i, 0x20))
                mstore(slot, addmod(mload(slot), mulmod(filter, diff, p), p))
            }
        }
    }

    /// @dev PublicInputGate (Yul). constraint_i = wire_i − public_inputs_hash[i].
    function _evalPublicInput(
        uint256[] memory wires,
        uint256[4] memory pih,
        uint256 filter,
        uint256[] memory acc
    ) private pure {
        assembly {
            let p := 0xFFFFFFFF00000001
            let wPtr := add(wires, 0x20)
            let aPtr := add(acc, 0x20)
            for { let i := 0 } lt(i, 4) { i := add(i, 1) } {
                let w := mload(add(wPtr, mul(i, 0x20)))
                let h := mload(add(pih, mul(i, 0x20)))
                let diff := addmod(w, sub(p, h), p)
                let slot := add(aPtr, mul(i, 0x20))
                mstore(slot, addmod(mload(slot), mulmod(filter, diff, p), p))
            }
        }
    }

    // ───────────────────────────────────────────────────────────────────────
    //  Extension-field gates.
    //
    //  In our Φ_gate terminal check, each wire MLE evaluation is a base-field
    //  value lifted to F::Extension as (w, 0). Because Ext2 multiplication
    //  satisfies (a, 0) * (b, 0) = (a·b, 0), the c1 component stays zero
    //  through any polynomial combination of lifted wires — so ExtensionAlgebra
    //  computations degenerate to base-field arithmetic on the c0 components.
    //
    //  The `_c0` and `_c1` quantities below refer to the two components of
    //  each ExtensionAlgebra element (the algebra basis is 1, t with t^2 = 7),
    //  not the two components of each F::Extension coefficient.
    // ───────────────────────────────────────────────────────────────────────

    /// @dev PoseidonMdsGate: apply the Poseidon MDS circulant + diagonal matrix
    /// to 12 ExtensionAlgebra inputs. 24 constraints = 12 × D (D=2).
    /// Input wires: 0..24 (2 per ExtAlgebra element). Output wires: 24..48.
    function _evalPoseidonMds(
        uint256[] memory wires,
        uint256 filter,
        uint256[] memory acc
    ) private pure {
        uint256 p = F.P;
        uint256 constraintIdx = 0;
        for (uint256 r = 0; r < 12; r++) {
            uint256 c0 = 0;
            uint256 c1 = 0;
            for (uint256 i = 0; i < 12; i++) {
                uint256 srcR = (i + r) % 12;
                uint256 circ = PoseidonConstants.mdsCirc(i);
                assembly {
                    let v0 := mload(add(add(wires, 0x20), mul(mul(srcR, 2), 0x20)))
                    let v1 := mload(add(add(wires, 0x20), mul(add(mul(srcR, 2), 1), 0x20)))
                    c0 := addmod(c0, mulmod(v0, circ, p), p)
                    c1 := addmod(c1, mulmod(v1, circ, p), p)
                }
            }
            uint256 diag = PoseidonConstants.mdsDiag(r);
            {
                uint256 v0 = wires[2 * r];
                uint256 v1 = wires[2 * r + 1];
                assembly {
                    c0 := addmod(c0, mulmod(v0, diag, p), p)
                    c1 := addmod(c1, mulmod(v1, diag, p), p)
                }
            }

            uint256 out0 = wires[24 + 2 * r];
            uint256 out1 = wires[24 + 2 * r + 1];
            uint256 diff0 = F.sub(out0, c0);
            uint256 diff1 = F.sub(out1, c1);
            acc[constraintIdx] = acc[constraintIdx].add(filter.mul(diff0));
            constraintIdx++;
            acc[constraintIdx] = acc[constraintIdx].add(filter.mul(diff1));
            constraintIdx++;
        }
    }

    /// @dev ArithmeticExtensionGate: for i in 0..num_ops,
    ///   output_ext = const_0 · (mult0_ext × mult1_ext) + const_1 · addend_ext
    /// where each ext is an ExtensionAlgebra element (2 base wires).
    /// Wires per op: 4·D = 8. Constraints per op: D = 2.
    function _evalArithmeticExt(
        uint256[] memory wires,
        uint256[] memory preprocessed,
        uint256 numSelectors,
        uint256 numOps,
        uint256 filter,
        uint256[] memory acc
    ) private pure {
        uint256 const0 = preprocessed[numSelectors];
        uint256 const1 = preprocessed[numSelectors + 1];
        uint256 p = F.P;
        uint256 constraintIdx = 0;
        for (uint256 i = 0; i < numOps; i++) {
            uint256 m0_0 = wires[8 * i];
            uint256 m0_1 = wires[8 * i + 1];
            uint256 m1_0 = wires[8 * i + 2];
            uint256 m1_1 = wires[8 * i + 3];
            uint256 ad_0 = wires[8 * i + 4];
            uint256 ad_1 = wires[8 * i + 5];
            uint256 out0 = wires[8 * i + 6];
            uint256 out1 = wires[8 * i + 7];

            // ext_algebra multiply: (a, b)·(c, d) = (a·c + W·b·d, a·d + b·c)
            uint256 mul_c0;
            uint256 mul_c1;
            assembly {
                mul_c0 := addmod(mulmod(m0_0, m1_0, p), mulmod(EXT2_W, mulmod(m0_1, m1_1, p), p), p)
                mul_c1 := addmod(mulmod(m0_0, m1_1, p), mulmod(m0_1, m1_0, p), p)
            }

            uint256 comp_c0;
            uint256 comp_c1;
            assembly {
                comp_c0 := addmod(mulmod(const0, mul_c0, p), mulmod(const1, ad_0, p), p)
                comp_c1 := addmod(mulmod(const0, mul_c1, p), mulmod(const1, ad_1, p), p)
            }

            uint256 diff0 = F.sub(out0, comp_c0);
            uint256 diff1 = F.sub(out1, comp_c1);
            acc[constraintIdx] = acc[constraintIdx].add(filter.mul(diff0));
            constraintIdx++;
            acc[constraintIdx] = acc[constraintIdx].add(filter.mul(diff1));
            constraintIdx++;
        }
    }

    /// @dev MulExtensionGate: for i in 0..num_ops,
    ///   output_ext = const_0 · (mult0_ext × mult1_ext)
    /// Wires per op: 3·D = 6. Constraints per op: D = 2.
    function _evalMulExt(
        uint256[] memory wires,
        uint256[] memory preprocessed,
        uint256 numSelectors,
        uint256 numOps,
        uint256 filter,
        uint256[] memory acc
    ) private pure {
        uint256 const0 = preprocessed[numSelectors];
        uint256 p = F.P;
        uint256 constraintIdx = 0;
        for (uint256 i = 0; i < numOps; i++) {
            uint256 m0_0 = wires[6 * i];
            uint256 m0_1 = wires[6 * i + 1];
            uint256 m1_0 = wires[6 * i + 2];
            uint256 m1_1 = wires[6 * i + 3];
            uint256 out0 = wires[6 * i + 4];
            uint256 out1 = wires[6 * i + 5];

            uint256 mul_c0;
            uint256 mul_c1;
            assembly {
                mul_c0 := addmod(mulmod(m0_0, m1_0, p), mulmod(EXT2_W, mulmod(m0_1, m1_1, p), p), p)
                mul_c1 := addmod(mulmod(m0_0, m1_1, p), mulmod(m0_1, m1_0, p), p)
            }
            uint256 comp_c0;
            uint256 comp_c1;
            assembly {
                comp_c0 := mulmod(const0, mul_c0, p)
                comp_c1 := mulmod(const0, mul_c1, p)
            }

            uint256 diff0 = F.sub(out0, comp_c0);
            uint256 diff1 = F.sub(out1, comp_c1);
            acc[constraintIdx] = acc[constraintIdx].add(filter.mul(diff0));
            constraintIdx++;
            acc[constraintIdx] = acc[constraintIdx].add(filter.mul(diff1));
            constraintIdx++;
        }
    }

    /// @dev BaseSumGate<B> (Yul). constraints = [computed_sum - wire_sum]
    /// followed by Π_{k=0..B} (limb[i] - k) for each limb.
    function _evalBaseSum(
        uint256[] memory wires,
        uint256 numLimbs,
        uint256 base,
        uint256 filter,
        uint256[] memory acc
    ) private pure {
        assembly {
            let p := 0xFFFFFFFF00000001
            let wPtr := add(wires, 0x20)
            let aPtr := add(acc, 0x20)
            let wireSum := mload(wPtr)

            // Horner computed_sum, iterating limbs in reverse.
            let computedSum := 0
            for { let i := numLimbs } gt(i, 0) { i := sub(i, 1) } {
                let limb := mload(add(wPtr, mul(i, 0x20)))
                computedSum := addmod(mulmod(computedSum, base, p), limb, p)
            }
            let diff := addmod(computedSum, sub(p, wireSum), p)
            mstore(aPtr, addmod(mload(aPtr), mulmod(filter, diff, p), p))

            // Per-limb ∏_{k=0..B} (limb - k).
            for { let i := 0 } lt(i, numLimbs) { i := add(i, 1) } {
                let limb := mload(add(wPtr, mul(add(i, 1), 0x20)))
                let prod := 1
                for { let k := 0 } lt(k, base) { k := add(k, 1) } {
                    let factor := addmod(limb, sub(p, k), p)
                    prod := mulmod(prod, factor, p)
                }
                let slot := add(aPtr, mul(add(i, 1), 0x20))
                mstore(slot, addmod(mload(slot), mulmod(filter, prod, p), p))
            }
        }
    }

    /// @dev Reducing state to shuttle through the loop without exceeding stack.
    struct ReducingState {
        uint256 a0;
        uint256 a1;
    }

    /// @dev ReducingGate: constraints_i = (acc · alpha + coeff[i] - accs[i]).
    /// acc/alpha/accs are ExtAlgebra (2 wires). coeff[i] is a single base wire.
    function _evalReducing(
        uint256[] memory wires,
        uint256 numCoeffs,
        uint256 filter,
        uint256[] memory acc
    ) private pure {
        uint256 startAccs = 3 * 2 + numCoeffs; // 3·D + num_coeffs
        ReducingState memory st = ReducingState({a0: wires[4], a1: wires[5]});

        uint256 cIdx = 0;
        for (uint256 i = 0; i < numCoeffs; i++) {
            (uint256 accWire0, uint256 accWire1) =
                _reducingAccWires(wires, startAccs, i, numCoeffs);
            cIdx = _reducingStep(
                st,
                wires[2], // alpha0
                wires[3], // alpha1
                wires[6 + i], // coeff
                accWire0,
                accWire1,
                filter,
                acc,
                cIdx,
                false
            );
        }
    }

    function _reducingAccWires(
        uint256[] memory wires,
        uint256 startAccs,
        uint256 i,
        uint256 numCoeffs
    ) private pure returns (uint256 w0, uint256 w1) {
        if (i + 1 == numCoeffs) {
            w0 = wires[0];
            w1 = wires[1];
        } else {
            w0 = wires[startAccs + 2 * i];
            w1 = wires[startAccs + 2 * i + 1];
        }
    }

    /// @dev Single Reducing / ReducingExtension step. coeffIsExt selects
    /// whether coeff0 is a scalar (coeff, 0) or full ExtAlgebra (coeff0, coeff1).
    function _reducingStep(
        ReducingState memory st,
        uint256 alpha0,
        uint256 alpha1,
        uint256 coeff0,
        uint256 accWire0,
        uint256 accWire1,
        uint256 filter,
        uint256[] memory acc,
        uint256 cIdx,
        bool /*coeffIsExt — coeff1 is handled in _reducingExtStep */
    ) private pure returns (uint256) {
        uint256 p = F.P;
        uint256 a0 = st.a0;
        uint256 a1 = st.a1;
        uint256 mul_c0;
        uint256 mul_c1;
        assembly {
            mul_c0 := addmod(mulmod(a0, alpha0, p), mulmod(EXT2_W, mulmod(a1, alpha1, p), p), p)
            mul_c1 := addmod(mulmod(a0, alpha1, p), mulmod(a1, alpha0, p), p)
        }
        uint256 c0 = F.sub(mul_c0.add(coeff0), accWire0);
        uint256 c1 = F.sub(mul_c1, accWire1);
        acc[cIdx] = acc[cIdx].add(filter.mul(c0));
        cIdx++;
        acc[cIdx] = acc[cIdx].add(filter.mul(c1));
        cIdx++;
        st.a0 = accWire0;
        st.a1 = accWire1;
        return cIdx;
    }

    /// @dev ReducingExtensionGate: coeff[i] is also ExtAlgebra (2 wires).
    function _evalReducingExt(
        uint256[] memory wires,
        uint256 numCoeffs,
        uint256 filter,
        uint256[] memory acc
    ) private pure {
        uint256 startAccs = 3 * 2 + numCoeffs * 2; // 3·D + num_coeffs·D
        ReducingState memory st = ReducingState({a0: wires[4], a1: wires[5]});

        uint256 cIdx = 0;
        for (uint256 i = 0; i < numCoeffs; i++) {
            (uint256 accWire0, uint256 accWire1) =
                _reducingAccWires(wires, startAccs, i, numCoeffs);
            cIdx = _reducingExtStep(
                st,
                wires[2], // alpha0
                wires[3], // alpha1
                wires[6 + 2 * i],     // coeff0
                wires[6 + 2 * i + 1], // coeff1
                accWire0,
                accWire1,
                filter,
                acc,
                cIdx
            );
        }
    }

    /// @dev Single ReducingExtension step (ExtAlgebra coeff).
    function _reducingExtStep(
        ReducingState memory st,
        uint256 alpha0,
        uint256 alpha1,
        uint256 coeff0,
        uint256 coeff1,
        uint256 accWire0,
        uint256 accWire1,
        uint256 filter,
        uint256[] memory acc,
        uint256 cIdx
    ) private pure returns (uint256) {
        uint256 p = F.P;
        uint256 a0 = st.a0;
        uint256 a1 = st.a1;
        uint256 mul_c0;
        uint256 mul_c1;
        assembly {
            mul_c0 := addmod(mulmod(a0, alpha0, p), mulmod(EXT2_W, mulmod(a1, alpha1, p), p), p)
            mul_c1 := addmod(mulmod(a0, alpha1, p), mulmod(a1, alpha0, p), p)
        }
        uint256 c0 = F.sub(mul_c0.add(coeff0), accWire0);
        uint256 c1 = F.sub(mul_c1.add(coeff1), accWire1);
        acc[cIdx] = acc[cIdx].add(filter.mul(c0));
        cIdx++;
        acc[cIdx] = acc[cIdx].add(filter.mul(c1));
        cIdx++;
        st.a0 = accWire0;
        st.a1 = accWire1;
        return cIdx;
    }

    /// @dev RandomAccessGate: indexed list access with bit decomposition.
    /// Per copy:
    ///   - bits: binary check b*(b-1)=0 (bits constraints)
    ///   - reconstructed_index - access_index = 0 (1)
    ///   - folded list[0] - claimed_element = 0 (1)
    /// Plus num_extra_constants constants-to-wires checks.
    function _evalRandomAccess(
        uint256[] memory wires,
        uint256[] memory preprocessed,
        uint256 numSelectors,
        uint256 bits,
        uint256 numCopies,
        uint256 numExtraConstants,
        uint256 filter,
        uint256[] memory acc
    ) private pure {
        uint256 vecSize = 1 << bits;
        uint256 numRoutedWires = (2 + vecSize) * numCopies + numExtraConstants;
        uint256 cIdx = 0;
        for (uint256 copy = 0; copy < numCopies; copy++) {
            cIdx = _evalRandomAccessCopy(
                wires,
                copy,
                bits,
                vecSize,
                numRoutedWires,
                filter,
                acc,
                cIdx
            );
        }
        for (uint256 i = 0; i < numExtraConstants; i++) {
            uint256 c = preprocessed[numSelectors + i];
            uint256 w = wires[(2 + vecSize) * numCopies + i];
            uint256 diff = F.sub(c, w);
            acc[cIdx] = acc[cIdx].add(filter.mul(diff));
            cIdx++;
        }
    }

    /// @dev Extracted per-copy evaluation to keep stack frames small.
    function _evalRandomAccessCopy(
        uint256[] memory wires,
        uint256 copy,
        uint256 bits,
        uint256 vecSize,
        uint256 numRoutedWires,
        uint256 filter,
        uint256[] memory acc,
        uint256 cIdx
    ) private pure returns (uint256) {
        uint256 p = F.P;
        uint256 copyBase = (2 + vecSize) * copy;
        uint256 accessIndex = wires[copyBase];
        uint256 claimedElement = wires[copyBase + 1];

        // Load bit wires for this copy.
        uint256[] memory bitVals = new uint256[](bits);
        for (uint256 i = 0; i < bits; i++) {
            bitVals[i] = wires[numRoutedWires + copy * bits + i];
        }

        // Boolean check for each bit: b*(b-1) = 0.
        for (uint256 i = 0; i < bits; i++) {
            uint256 b = bitVals[i];
            uint256 bMinus1 = F.sub(b, 1);
            uint256 bs = b.mul(bMinus1);
            acc[cIdx] = acc[cIdx].add(filter.mul(bs));
            cIdx++;
        }

        // reconstructed_index = Σ_i bit[i] · 2^i  (little-endian)
        uint256 recon = 0;
        for (uint256 i = bits; i > 0; i--) {
            uint256 b = bitVals[i - 1];
            assembly {
                recon := addmod(addmod(recon, recon, p), b, p)
            }
        }
        uint256 idxDiff = F.sub(recon, accessIndex);
        acc[cIdx] = acc[cIdx].add(filter.mul(idxDiff));
        cIdx++;

        // Fold the list with bits (ascending: bit 0 first).
        // Each fold halves the list: pair (x, y) -> x + b*(y - x).
        uint256[] memory listItems = new uint256[](vecSize);
        for (uint256 i = 0; i < vecSize; i++) {
            listItems[i] = wires[copyBase + 2 + i];
        }
        uint256 curLen = vecSize;
        for (uint256 bi = 0; bi < bits; bi++) {
            uint256 b = bitVals[bi];
            uint256 half = curLen / 2;
            for (uint256 j = 0; j < half; j++) {
                uint256 x = listItems[2 * j];
                uint256 y = listItems[2 * j + 1];
                uint256 diff = F.sub(y, x);
                listItems[j] = x.add(b.mul(diff));
            }
            curLen = half;
        }

        // Final: listItems[0] - claimed_element = 0
        uint256 finalDiff = F.sub(listItems[0], claimedElement);
        acc[cIdx] = acc[cIdx].add(filter.mul(finalDiff));
        cIdx++;

        return cIdx;
    }
}
