// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.25;

import {GoldilocksField as F} from "./GoldilocksField.sol";
import {PoseidonGate} from "./PoseidonGate.sol";
import {PoseidonConstants} from "./PoseidonConstants.sol";
import {CosetInterpolationConstants} from "./CosetInterpolationConstants.sol";

/// @title Plonky2GateEvaluator — Solidity port of Plonky2's gate constraint
///         evaluation, used by the MLE verifier's Φ_gate sumcheck terminal.
///
/// SUPPORTED GATES (gate_id → constraint family):
///     0  NoopGate              — no constraints
///     1  ConstantGate          — num_consts × [const_i − w_i]
///     2  PublicInputGate       — 4 × [w_i − PI_hash[i]]
///     3  ArithmeticGate        — num_ops × [c0·w0·w1 + c1·w2 − w3]
///     4  PoseidonGate          — full 12-state Poseidon-Goldilocks permutation
///                                (round constants + MDS + S-box; see PoseidonGate.sol)
///     5  PoseidonMdsGate       — MDS-only variant of PoseidonGate
///     6  ArithmeticExtensionGate — extension-field arithmetic ops
///     7  MulExtensionGate      — extension-field multiplications
///     9  BaseSumGate           — base-B limb decomposition checks
///    10  ReducingGate          — Horner-style reduction (base field)
///    11  ReducingExtensionGate — Horner-style reduction (extension field)
///    12  RandomAccessGate      — multiplexer w/ binary selectors
///    13  CosetInterpolationGate — barycentric Lagrange interpolation over a
///                                  two-adic coset (used by recursive FRI verifier)
///
/// UNSUPPORTED GATES (any row with filter ≠ 0 reverts explicitly — never
/// silently accepted):
///     8  ExponentiationGate    — not yet ported; recursion circuits may emit it
///        LookupGate / LookupTableGate — only used if the inner circuit has
///                                       lookup tables (out of scope for the
///                                       recursive verifier fixture today)
///
/// Per-fixture wire interpretation, plus how `numOrConsts` / `param2` / `param3`
/// map to each gate's parameters, is documented on the `GateInfo` struct
/// below and on each `_evalXxx` helper.
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
        GateInfo[] calldata gates,
        uint256 numSelectors,
        uint256 numConstants,
        uint256 numGateConstraints
    ) external pure returns (uint256 flat) {
        // The inner gate helpers were written against memory arrays. We copy
        // wire / preprocessed arrays once (amortizing across all gate dispatches)
        // but iterate `gates` directly in calldata — the dispatcher only needs
        // to read primitive fields which are cheap `calldataload`s and avoid a
        // full `GateInfo[]`-to-memory copy.
        uint256[] memory wires = _cdToMem(wiresCd);
        uint256[] memory preprocessed = _cdToMem(preprocessedCd);
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
            GateInfo calldata gi = gates[g];
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
            } else if (gi.gateId == GATE_COSET_INTERPOLATION) {
                _evalCosetInterpolation(
                    wires,
                    gi.numOrConsts, // subgroup_bits
                    gi.param2,      // degree
                    filter,
                    perIdxAccum
                );
            } else {
                // Unsupported gate (ExponentiationGate, LookupGate / LookupTableGate).
                // SECURITY: if filter != 0, we revert to signal a completeness
                // failure. Never silently accepts.
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

    /// @dev Plonky2 filter polynomial (see plonky2/src/gates/gate.rs:326).
    /// filter(s) = Π_{i ∈ groupRange, i != row}(i − s) · (manySel ? (UNUSED − s) : 1)
    ///
    /// Yul-optimized: inlines `F.sub` / `F.mul`, drops the Solidity wrapper
    /// call overhead. `s` is assumed canonical (enforced upstream as a
    /// preprocessed MLE evaluation at `r_gate_v2` after C2 canonicalization);
    /// `i` is a small integer (< UNUSED_SELECTOR = 2^32-1 < P).
    function _computeFilter(
        uint256 row,
        uint256 groupStart,
        uint256 groupEnd,
        uint256 s,
        bool manySel
    ) private pure returns (uint256 result) {
        assembly {
            let p := 0xFFFFFFFF00000001
            // `s_red`: defensive reduction even though caller canonicalizes.
            let sRed := mod(s, p)
            let negS := sub(p, sRed) // fits in word since sRed < p.
            let r := 1
            for { let i := groupStart } lt(i, groupEnd) { i := add(i, 1) } {
                if iszero(eq(i, row)) {
                    // factor = (i - s) mod p.  i < P since groupStart/End < 2^8.
                    // addmod(i, p - sRed, p) = (i - s) mod p.
                    let factor := addmod(i, negS, p)
                    r := mulmod(r, factor, p)
                }
            }
            if manySel {
                // factor = (UNUSED_SELECTOR - s) mod p.
                let factor := addmod(0xFFFFFFFF, negS, p)
                r := mulmod(r, factor, p)
            }
            result := r
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
                // SECURITY (C2, phase3_c2_threat_model.md §6.2): defensive
                // self-reduction of prover-supplied wire before field negation.
                // Without `mod(w, p)`, a non-canonical `w = v + k·P` would make
                // `sub(p, w)` underflow 2^256 and inject K = 2^256 mod P into
                // `diff`, enabling a subset-sum attack on `flat`. Caller-side
                // enforcement in MleVerifier also canonicalizes, so this is
                // defense-in-depth.
                let diff := addmod(c, sub(p, mod(w, p)), p)
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
                // SECURITY (C2, phase3_c2_threat_model.md §6.2): self-reduce
                // publicInputsHash entry; caller should also canonicalize but
                // we stay robust if that check is ever removed.
                let diff := addmod(w, sub(p, mod(h, p)), p)
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
    /// Yul-ified: one assembly block for the whole 12×12 MDS sweep. Reads
    /// MDS constants once into locals, then pure Yul loops.
    function _evalPoseidonMds(
        uint256[] memory wires,
        uint256 filter,
        uint256[] memory acc
    ) private pure {
        // Pre-load MDS constants into a local memory buffer so inner loops
        // can mload by offset (mirrors the pattern in PoseidonGate).
        bytes memory mdsCirc = PoseidonConstants.MDS_CIRC;
        bytes memory mdsDiag = PoseidonConstants.MDS_DIAG;
        assembly {
            let p := 0xFFFFFFFF00000001
            let wPtr := add(wires, 0x20)
            let aPtr := add(acc, 0x20)
            let circBase := add(mdsCirc, 0x20)
            let diagBase := add(mdsDiag, 0x20)
            let constraintIdx := 0
            for { let r := 0 } lt(r, 12) { r := add(r, 1) } {
                let c0 := 0
                let c1 := 0
                for { let i := 0 } lt(i, 12) { i := add(i, 1) } {
                    let srcR := mod(add(i, r), 12)
                    let circ := shr(192, mload(add(circBase, mul(i, 8))))
                    let v0 := mload(add(wPtr, mul(mul(srcR, 2), 0x20)))
                    let v1 := mload(add(wPtr, mul(add(mul(srcR, 2), 1), 0x20)))
                    c0 := addmod(c0, mulmod(v0, circ, p), p)
                    c1 := addmod(c1, mulmod(v1, circ, p), p)
                }
                {
                    let diag := shr(192, mload(add(diagBase, mul(r, 8))))
                    let v0 := mload(add(wPtr, mul(mul(r, 2), 0x20)))
                    let v1 := mload(add(wPtr, mul(add(mul(r, 2), 1), 0x20)))
                    c0 := addmod(c0, mulmod(v0, diag, p), p)
                    c1 := addmod(c1, mulmod(v1, diag, p), p)
                }
                let out0 := mload(add(wPtr, mul(add(24, mul(r, 2)), 0x20)))
                let out1 := mload(add(wPtr, mul(add(25, mul(r, 2)), 0x20)))
                let diff0 := addmod(out0, sub(p, mod(c0, p)), p)
                let diff1 := addmod(out1, sub(p, mod(c1, p)), p)
                let slot0 := add(aPtr, mul(constraintIdx, 0x20))
                mstore(slot0, addmod(mload(slot0), mulmod(filter, diff0, p), p))
                let slot1 := add(aPtr, mul(add(constraintIdx, 1), 0x20))
                mstore(slot1, addmod(mload(slot1), mulmod(filter, diff1, p), p))
                constraintIdx := add(constraintIdx, 2)
            }
        }
    }

    /// @dev ArithmeticExtensionGate: for i in 0..num_ops,
    ///   output_ext = const_0 · (mult0_ext × mult1_ext) + const_1 · addend_ext
    /// where each ext is an ExtensionAlgebra element (2 base wires).
    /// Wires per op: 4·D = 8. Constraints per op: D = 2.
    /// Yul-ified: single assembly block, no Solidity wrapper calls.
    function _evalArithmeticExt(
        uint256[] memory wires,
        uint256[] memory preprocessed,
        uint256 numSelectors,
        uint256 numOps,
        uint256 filter,
        uint256[] memory acc
    ) private pure {
        assembly {
            let p := 0xFFFFFFFF00000001
            let wPtr := add(wires, 0x20)
            let aPtr := add(acc, 0x20)
            let preBase := add(add(preprocessed, 0x20), mul(numSelectors, 0x20))
            let const0 := mload(preBase)
            let const1 := mload(add(preBase, 0x20))
            let constraintIdx := 0
            for { let i := 0 } lt(i, numOps) { i := add(i, 1) } {
                let base := add(wPtr, mul(mul(i, 8), 0x20))
                let m0_0 := mload(base)
                let m0_1 := mload(add(base, 0x20))
                let m1_0 := mload(add(base, 0x40))
                let m1_1 := mload(add(base, 0x60))
                let ad_0 := mload(add(base, 0x80))
                let ad_1 := mload(add(base, 0xa0))
                let out0 := mload(add(base, 0xc0))
                let out1 := mload(add(base, 0xe0))
                // (m0_0, m0_1)·(m1_0, m1_1) in Ext2:
                let mul_c0 := addmod(mulmod(m0_0, m1_0, p), mulmod(EXT2_W, mulmod(m0_1, m1_1, p), p), p)
                let mul_c1 := addmod(mulmod(m0_0, m1_1, p), mulmod(m0_1, m1_0, p), p)
                let comp_c0 := addmod(mulmod(const0, mul_c0, p), mulmod(const1, ad_0, p), p)
                let comp_c1 := addmod(mulmod(const0, mul_c1, p), mulmod(const1, ad_1, p), p)
                let diff0 := addmod(out0, sub(p, mod(comp_c0, p)), p)
                let diff1 := addmod(out1, sub(p, mod(comp_c1, p)), p)
                let s0 := add(aPtr, mul(constraintIdx, 0x20))
                mstore(s0, addmod(mload(s0), mulmod(filter, diff0, p), p))
                let s1 := add(aPtr, mul(add(constraintIdx, 1), 0x20))
                mstore(s1, addmod(mload(s1), mulmod(filter, diff1, p), p))
                constraintIdx := add(constraintIdx, 2)
            }
        }
    }

    /// @dev MulExtensionGate: for i in 0..num_ops,
    ///   output_ext = const_0 · (mult0_ext × mult1_ext)
    /// Wires per op: 3·D = 6. Constraints per op: D = 2.
    /// Yul-ified.
    function _evalMulExt(
        uint256[] memory wires,
        uint256[] memory preprocessed,
        uint256 numSelectors,
        uint256 numOps,
        uint256 filter,
        uint256[] memory acc
    ) private pure {
        assembly {
            let p := 0xFFFFFFFF00000001
            let wPtr := add(wires, 0x20)
            let aPtr := add(acc, 0x20)
            let const0 := mload(add(add(preprocessed, 0x20), mul(numSelectors, 0x20)))
            let constraintIdx := 0
            for { let i := 0 } lt(i, numOps) { i := add(i, 1) } {
                let base := add(wPtr, mul(mul(i, 6), 0x20))
                let m0_0 := mload(base)
                let m0_1 := mload(add(base, 0x20))
                let m1_0 := mload(add(base, 0x40))
                let m1_1 := mload(add(base, 0x60))
                let out0 := mload(add(base, 0x80))
                let out1 := mload(add(base, 0xa0))
                let mul_c0 := addmod(mulmod(m0_0, m1_0, p), mulmod(EXT2_W, mulmod(m0_1, m1_1, p), p), p)
                let mul_c1 := addmod(mulmod(m0_0, m1_1, p), mulmod(m0_1, m1_0, p), p)
                let comp_c0 := mulmod(const0, mul_c0, p)
                let comp_c1 := mulmod(const0, mul_c1, p)
                let diff0 := addmod(out0, sub(p, mod(comp_c0, p)), p)
                let diff1 := addmod(out1, sub(p, mod(comp_c1, p)), p)
                let s0 := add(aPtr, mul(constraintIdx, 0x20))
                mstore(s0, addmod(mload(s0), mulmod(filter, diff0, p), p))
                let s1 := add(aPtr, mul(add(constraintIdx, 1), 0x20))
                mstore(s1, addmod(mload(s1), mulmod(filter, diff1, p), p))
                constraintIdx := add(constraintIdx, 2)
            }
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
            // SECURITY (C2): self-reduce `wireSum` before field negation.
            let diff := addmod(computedSum, sub(p, mod(wireSum, p)), p)
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

    /// @dev Working state of the Plonky2 `partial_interpolate` recurrence,
    ///      held in memory so we can pass it by reference between
    ///      helper calls without exhausting the EVM stack.
    ///
    ///      The recurrence (see `coset_interpolation.rs::partial_interpolate`):
    ///        for each (x_j, w_j, val_j) in current chunk:
    ///          term = sep - x_j            (Ext-Ext subtraction; sep = shifted_eval_pt)
    ///          weighted_val = val_j · w_j  (Ext scalar mul by base-field weight)
    ///          eval' = eval · term + weighted_val · prod
    ///          prod' = prod · term
    ///
    ///      Every Ext value is stored as a `(a0, a1)` pair representing
    ///      `a0 + a1 · X` with `X² = EXT2_W = 7` over Goldilocks.
    struct CosetState {
        uint256 evalA;
        uint256 evalB;
        uint256 prodA;
        uint256 prodB;
        uint256 sepA;
        uint256 sepB;
    }

    /// @dev Bundle of loop-invariant arguments for the per-intermediate
    ///      iteration. Boxed into a struct so we can pass it by reference
    ///      (single stack slot) and stay below Yul's stack limit.
    struct _CosetLoopArgs {
        uint256 subgroupBits;
        uint256 degree;
        uint256 N;
        uint256 numInt;
        uint256 startInt;
        uint256 i;
        uint256 filter;
    }

    /// @dev Handle one intermediate `i`:
    ///      1. Read `intermediate_eval[i]` / `intermediate_prod[i]` from wires.
    ///      2. Emit the two constraint pairs (eval diff / prod diff) into `acc`.
    ///      3. Reseed `(eval, prod)` with those intermediates.
    ///      4. Run `partial_interpolate` over the next domain chunk.
    ///      Returns the updated `cIdx` (advanced by 4).
    function _cosetCheckIntermediateAndAdvance(
        CosetState memory st,
        uint256[] memory wires,
        uint256[] memory acc,
        uint256 cIdx,
        _CosetLoopArgs memory args
    ) private pure returns (uint256) {
        uint256 ieA = wires[args.startInt + 2 * args.i];
        uint256 ieB = wires[args.startInt + 2 * args.i + 1];
        uint256 ipA = wires[args.startInt + 2 * args.numInt + 2 * args.i];
        uint256 ipB = wires[args.startInt + 2 * args.numInt + 2 * args.i + 1];

        // eval diff + prod diff (4 base-field constraint slots).
        _cosetEmitExtDiff(acc, cIdx, args.filter, ieA, ieB, st.evalA, st.evalB);
        _cosetEmitExtDiff(acc, cIdx + 2, args.filter, ipA, ipB, st.prodA, st.prodB);

        // Reseed and advance.
        st.evalA = ieA;
        st.evalB = ieB;
        st.prodA = ipA;
        st.prodB = ipB;

        uint256 startIdx = 1 + (args.degree - 1) * (args.i + 1);
        uint256 endIdx = startIdx + (args.degree - 1);
        if (endIdx > args.N) {
            endIdx = args.N;
        }
        _cosetRunChunk(st, wires, args.subgroupBits, startIdx, endIdx);

        return cIdx + 4;
    }

    /// @dev Emit `filter · (lhs - rhs)` for both Ext components into
    ///      `acc[cIdx]` and `acc[cIdx+1]`. Used for every Ext constraint
    ///      pair in this gate (shift consistency, intermediates, final).
    ///
    /// SECURITY (defense-in-depth, audit M1): self-reduce every operand
    /// with `mod(..., p)` before `sub(p, rhs)`. This matches the explicit
    /// `// SECURITY (C2)…` pattern used by every other gate in this file
    /// (`_evalConstant`, `_evalPublicInput`, `_evalArithmeticExt`, …) to
    /// neutralise the `K = 2^256 mod P` injection attack at the gate
    /// boundary, in case `MleVerifier._requireCanonicalProofInputs`
    /// upstream ever fails to canonicalize a wire — a regression there
    /// otherwise becomes an in-coset soundness break. The cost is one
    /// extra `mod` per Ext component (negligible relative to the
    /// surrounding `mulmod`s).
    function _cosetEmitExtDiff(
        uint256[] memory acc,
        uint256 cIdx,
        uint256 filter,
        uint256 lhsA,
        uint256 lhsB,
        uint256 rhsA,
        uint256 rhsB
    ) private pure {
        uint256 p = F.P;
        uint256 dA;
        uint256 dB;
        assembly ("memory-safe") {
            // Self-reduce wire reads before the modular sub.
            let lA := mod(lhsA, p)
            let lB := mod(lhsB, p)
            let rA := mod(rhsA, p)
            let rB := mod(rhsB, p)
            dA := addmod(lA, sub(p, rA), p)
            dB := addmod(lB, sub(p, rB), p)
        }
        acc[cIdx] = addmod(acc[cIdx], mulmod(filter, dA, p), p);
        acc[cIdx + 1] = addmod(acc[cIdx + 1], mulmod(filter, dB, p), p);
    }

    /// @dev Run `partial_interpolate` over `wires[1 + 2·startIdx .. 1 + 2·endIdx)`,
    ///      using `subgroupBits` (to look up domain/weights) and the
    ///      `shifted_evaluation_point` already stored in `st`. Mutates `st`.
    ///      Factoring this loop into its own function bounds the stack pressure
    ///      inside `_evalCosetInterpolation` (Solidity / Yul stack-too-deep
    ///      otherwise; `via_ir` alone is not enough for this gate).
    function _cosetRunChunk(
        CosetState memory st,
        uint256[] memory wires,
        uint256 subgroupBits,
        uint256 startIdx,
        uint256 endIdx
    ) private pure {
        for (uint256 j = startIdx; j < endIdx; j++) {
            uint256 xj = CosetInterpolationConstants.subgroupElement(subgroupBits, j);
            uint256 wj = CosetInterpolationConstants.weight(subgroupBits, j);
            uint256 valA = wires[1 + 2 * j];
            uint256 valB = wires[1 + 2 * j + 1];
            _cosetPartialStep(st, xj, wj, valA, valB);
        }
    }

    /// @dev Single step of `partial_interpolate`: advance `(eval, prod)` by
    ///      one domain-point/value pair. See `CosetState` for the formula.
    ///
    ///      SECURITY: this exactly mirrors the inner loop body of
    ///      `coset_interpolation.rs::partial_interpolate`. Any deviation
    ///      causes the Solidity-evaluated constraint value to disagree
    ///      with the Rust prover's witness, breaking completeness (honest
    ///      proofs rejected). Bit-for-bit equivalence is enforced by the
    ///      Foundry test `Plonky2GateEvaluatorCosetInterpolation.t.sol`.
    function _cosetPartialStep(
        CosetState memory st,
        uint256 xj,
        uint256 wj,
        uint256 valA,
        uint256 valB
    ) private pure {
        uint256 p = F.P;
        assembly ("memory-safe") {
            // Load state pointers.
            let evalA := mload(st)
            let evalB := mload(add(st, 0x20))
            let prodA := mload(add(st, 0x40))
            let prodB := mload(add(st, 0x60))
            let sepA := mload(add(st, 0x80))
            let sepB := mload(add(st, 0xa0))

            // term = sep - (x_j, 0) = (sepA - x_j, sepB)
            let t0 := addmod(sepA, sub(p, xj), p)
            let t1 := sepB

            // weighted_val = val · w (component-wise base-field mul).
            let wvA := mulmod(valA, wj, p)
            let wvB := mulmod(valB, wj, p)

            // Ext2 mul (a0 + a1·X)·(b0 + b1·X)
            //   = (a0·b0 + W·a1·b1, a0·b1 + a1·b0), with W = 7.

            // eval · term
            let etA := addmod(
                mulmod(evalA, t0, p),
                mulmod(EXT2_W, mulmod(evalB, t1, p), p),
                p
            )
            let etB := addmod(
                mulmod(evalA, t1, p),
                mulmod(evalB, t0, p),
                p
            )

            // weighted_val · prod
            let wpA := addmod(
                mulmod(wvA, prodA, p),
                mulmod(EXT2_W, mulmod(wvB, prodB, p), p),
                p
            )
            let wpB := addmod(
                mulmod(wvA, prodB, p),
                mulmod(wvB, prodA, p),
                p
            )

            // next_eval = eval · term + weighted_val · prod
            let newEvalA := addmod(etA, wpA, p)
            let newEvalB := addmod(etB, wpB, p)

            // next_prod = prod · term
            let newProdA := addmod(
                mulmod(prodA, t0, p),
                mulmod(EXT2_W, mulmod(prodB, t1, p), p),
                p
            )
            let newProdB := addmod(
                mulmod(prodA, t1, p),
                mulmod(prodB, t0, p),
                p
            )

            mstore(st, newEvalA)
            mstore(add(st, 0x20), newEvalB)
            mstore(add(st, 0x40), newProdA)
            mstore(add(st, 0x60), newProdB)
            // sepA / sepB unchanged.
        }
    }

    /// @dev `CosetInterpolationGate::eval_unfiltered_base_one` port.
    ///
    /// Wire layout (after the dispatcher strips `numSelectors` constants —
    /// CosetInterpolation has `num_constants() == 0`, so the wire array is
    /// the gate's full local-wires slice unchanged):
    ///
    ///   wires[0]                                    = shift (base-field scalar)
    ///   wires[1 + 2·i .. 1 + 2·(i+1))               = values[i] for i in 0..N   (Ext)
    ///   wires[1 + 2·N .. 1 + 2·(N+1))               = evaluation_point          (Ext)
    ///   wires[1 + 2·(N+1) .. 1 + 2·(N+2))           = evaluation_value          (Ext)
    ///   startInt = 1 + 2·(N+2) = 2·N + 5
    ///   wires[startInt + 2·i .. startInt + 2·(i+1)) = intermediate_eval[i] for i in 0..numInt
    ///   wires[startInt + 2·numInt + 2·i .. +2)      = intermediate_prod[i] for i in 0..numInt
    ///   wires[startInt + 4·numInt .. +2)            = shifted_evaluation_point  (Ext)
    ///
    /// where N = 2^subgroup_bits and numInt = (N - 2) / (degree - 1).
    ///
    /// Constraint sequence written into `acc` (each Ext diff → 2 base-field entries):
    ///
    ///   acc[0..2):                    evaluation_point - shift · shifted_eval_pt
    ///   for i in 0..numInt:
    ///     acc[2+4·i .. 2+4·i+2):      intermediate_eval[i]  - computed_eval[i]
    ///     acc[2+4·i+2 .. 2+4·i+4):    intermediate_prod[i]  - computed_prod[i]
    ///   acc[2+4·numInt .. +2):        evaluation_value      - computed_eval_final
    ///
    /// SECURITY: param validation is intentionally strict. `subgroupBits ∉ {1,2,3,4,5}`
    /// (the currently-supported set; see `mle/tests/dump_coset_constants.rs`
    /// `SUPPORTED_BITS`) reverts via `CosetInterpolationConstants.{subgroupElement,weight}`
    /// because those helpers carry the canonical revert. `degree < 2` would
    /// underflow `degree - 1` so we explicitly reject it. `degree > N` is
    /// rejected to prevent the chunk loop reading past the constants table.
    // INTERNAL visibility (not private) so the Foundry test harness in
    // `test/CosetInterpolationTest.t.sol` can invoke this directly and
    // verify bit-exact equivalence with the Rust gate evaluator. The
    // production caller is always the dispatcher above.
    function _evalCosetInterpolation(
        uint256[] memory wires,
        uint256 subgroupBits,
        uint256 degree,
        uint256 filter,
        uint256[] memory acc
    ) internal pure {
        // INVARIANT I3 (tasks/coset_interpolation_port.md §4.1): degree >= 2.
        require(degree >= 2, "CosetInterpolation: degree must be >= 2");

        uint256 N = uint256(1) << subgroupBits;
        require(N >= 2, "CosetInterpolation: subgroup must have >= 2 points");
        // Defense-in-depth (audit L1): a malformed gate descriptor with
        // `degree > N` would let the initial chunk loop run past the
        // checked-in subgroup table. Honest `with_max_degree` ensures
        // `degree ≤ N` by construction; guarding here surfaces drift
        // between the fixture generator and the on-chain constants.
        require(degree <= N, "CosetInterpolation: degree > subgroup size");

        // INVARIANT I2 / A1: the constants library reverts on unsupported
        // `subgroupBits`. Touch it eagerly so we surface the error before
        // doing any work on the wires.
        // (`weight(_, 0)` doubles as both a sanity check and a constant load.)
        CosetInterpolationConstants.weight(subgroupBits, 0);

        uint256 numInt = (N - 2) / (degree - 1);
        uint256 startInt = 2 * N + 5;
        uint256 shiftedEvalIdx = startInt + 4 * numInt;

        uint256 p = F.P;

        // Constraint pair 1: evaluation_point - shift · shifted_evaluation_point.
        // `shift` is base-field; scalar-mul on Ext = component-wise mul.
        {
            uint256 shift = wires[0];
            uint256 sepA = wires[shiftedEvalIdx];
            uint256 sepB = wires[shiftedEvalIdx + 1];
            _cosetEmitExtDiff(
                acc,
                0,
                filter,
                wires[1 + 2 * N],
                wires[1 + 2 * N + 1],
                mulmod(shift, sepA, p),
                mulmod(shift, sepB, p)
            );
        }

        // Seed the recurrence with (eval, prod) = (0, 1) and run
        // `partial_interpolate` over `domain[0..degree]`.
        CosetState memory st = CosetState({
            evalA: 0,
            evalB: 0,
            prodA: 1,
            prodB: 0,
            sepA: wires[shiftedEvalIdx],
            sepB: wires[shiftedEvalIdx + 1]
        });

        _cosetRunChunk(st, wires, subgroupBits, 0, degree);

        // For each intermediate: two constraint pairs (eval diff, prod diff),
        // then advance the recurrence over the next chunk.
        uint256 cIdx = 2;
        for (uint256 i = 0; i < numInt; i++) {
            cIdx = _cosetCheckIntermediateAndAdvance(
                st,
                wires,
                acc,
                cIdx,
                _CosetLoopArgs({
                    subgroupBits: subgroupBits,
                    degree: degree,
                    N: N,
                    numInt: numInt,
                    startInt: startInt,
                    i: i,
                    filter: filter
                })
            );
        }

        // C₃: evaluation_value - computed_eval_final.
        _cosetEmitExtDiff(
            acc,
            cIdx,
            filter,
            wires[1 + 2 * (N + 1)],
            wires[1 + 2 * (N + 1) + 1],
            st.evalA,
            st.evalB
        );
    }
}
