// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.25;

import {PoseidonConstants} from "./PoseidonConstants.sol";

/// @title PoseidonGate — Plonky2 Poseidon-12 gate constraints (Yul-optimized).
/// @notice Mirrors `plonky2::gates::poseidon::PoseidonGate::eval_unfiltered` for
/// the Goldilocks field. Produces 123 base-field constraint values at a random
/// point `r_gate_v2`, accumulating `filter * constraint_i` into the caller's
/// accumulator slot `acc[i]`.
///
/// Optimizations vs. the naïve port:
///  - State kept in contiguous memory (12 × 32-byte slots) instead of solidity
///    uint256[12] with copy-back-and-forth on every layer.
///  - MDS constants MDS_CIRC[0..12] and MDS_DIAG[0] cached in local variables
///    at function entry (re-reading from `PoseidonConstants.readU64` ~1200× per
///    MDS sweep is expensive).
///  - Round constants for the current round loaded in a single 12-value block
///    per round instead of 12 separate library calls.
///  - S-box `x^7` inlined as 4 mulmod ops inside tight assembly loops.
///  - Constraint accumulation writes `acc[i]` directly in assembly (skip
///    Solidity bounds check + wrapper mulmod/addmod).
///  - `_mdsPartialLayerFast` and `_mdsPartialLayerInit` unrolled + in-place.
///
/// All uint64 Poseidon constants live in `PoseidonConstants.sol` as packed
/// big-endian `bytes` blobs. We take a direct memory pointer to each blob's
/// data region at function entry and read via `shr(192, mload(ptr+offset))`.
library PoseidonGate {
    uint256 internal constant P = 0xFFFFFFFF00000001;
    uint256 internal constant SPONGE_WIDTH = 12;
    uint256 internal constant HALF_N_FULL_ROUNDS = 4;
    uint256 internal constant N_PARTIAL_ROUNDS = 22;

    // Wire layout (matches plonky2/src/gates/poseidon.rs).
    uint256 internal constant WIRE_SWAP = 24;
    uint256 internal constant START_DELTA = 25;
    uint256 internal constant START_FULL_0 = 29;
    uint256 internal constant START_PARTIAL = 65;
    uint256 internal constant START_FULL_1 = 87;

    /// @dev 123 constraints total. Layout:
    ///   [0]           swap binary check
    ///   [1..5)        delta consistency (4)
    ///   [5..41)       first-set full-round S-box input consistency (36 = 12×3)
    ///   [41..63)      partial-round S-box input consistency (22)
    ///   [63..111)     second-set full-round S-box input consistency (48 = 12×4)
    ///   [111..123)    output consistency (12)
    function evalConstraints(
        uint256[] memory w,
        uint256 filter,
        uint256[] memory acc
    ) internal pure {
        // Pull direct memory pointers to the packed big-endian blobs so inner
        // loops can `mload(ptr+offset)` without function-call or bounds-check
        // overhead. Each blob is `bytes memory`: 32-byte length prefix then
        // the payload we want.
        bytes memory allRC = PoseidonConstants.ALL_ROUND_CONSTANTS;
        bytes memory mdsCirc = PoseidonConstants.MDS_CIRC;
        bytes memory mdsDiag = PoseidonConstants.MDS_DIAG;
        bytes memory pfrc = PoseidonConstants.FAST_PARTIAL_FIRST_ROUND_CONSTANT;
        bytes memory prc = PoseidonConstants.FAST_PARTIAL_ROUND_CONSTANTS;
        bytes memory prvs = PoseidonConstants.FAST_PARTIAL_ROUND_VS;
        bytes memory prwh = PoseidonConstants.FAST_PARTIAL_ROUND_W_HATS;
        bytes memory pim = PoseidonConstants.FAST_PARTIAL_ROUND_INITIAL_MATRIX;

        // MDS_CIRC[0..12] + MDS_DIAG[0]: store contiguously in a 13-slot
        // scratch buffer so inner loops can mload via a single pointer
        // (cheaper than carrying 13 stack locals through nested calls).
        uint256[] memory mdsBuf = new uint256[](13);
        uint256 mdsPtr;
        assembly {
            mdsPtr := add(mdsBuf, 0x20)
            let cp := add(mdsCirc, 0x20)
            mstore(mdsPtr,            shr(192, mload(cp)))
            mstore(add(mdsPtr, 0x20), shr(192, mload(add(cp, 8))))
            mstore(add(mdsPtr, 0x40), shr(192, mload(add(cp, 16))))
            mstore(add(mdsPtr, 0x60), shr(192, mload(add(cp, 24))))
            mstore(add(mdsPtr, 0x80), shr(192, mload(add(cp, 32))))
            mstore(add(mdsPtr, 0xa0), shr(192, mload(add(cp, 40))))
            mstore(add(mdsPtr, 0xc0), shr(192, mload(add(cp, 48))))
            mstore(add(mdsPtr, 0xe0), shr(192, mload(add(cp, 56))))
            mstore(add(mdsPtr, 0x100), shr(192, mload(add(cp, 64))))
            mstore(add(mdsPtr, 0x120), shr(192, mload(add(cp, 72))))
            mstore(add(mdsPtr, 0x140), shr(192, mload(add(cp, 80))))
            mstore(add(mdsPtr, 0x160), shr(192, mload(add(cp, 88))))
            mstore(add(mdsPtr, 0x180), shr(192, mload(add(mdsDiag, 0x20))))
        }

        // Allocate a contiguous 12-slot scratch for the Poseidon state.
        // Layout: state[i] at offset 0x20*i (i ∈ 0..12).
        uint256[] memory stateArr = new uint256[](12);
        uint256 statePtr;
        assembly {
            statePtr := add(stateArr, 0x20)
        }

        // Also need a second 12-slot buffer for MDS output accumulators.
        uint256[] memory scratchArr = new uint256[](12);
        uint256 scratchPtr;
        assembly {
            scratchPtr := add(scratchArr, 0x20)
        }

        // 0..5: swap + delta constraints, also build initial state.
        _evalSwapDelta(w, filter, acc, statePtr);

        // Phase structure delegated to helpers to keep stack usage bounded.
        uint256 nextIdx = _firstFullRounds(w, filter, acc, statePtr, scratchPtr, mdsPtr, allRC);
        _partialFirstConstantLayer(statePtr, pfrc);
        _mdsPartialLayerInit(statePtr, scratchPtr, pim);
        nextIdx = _partialRounds(w, filter, acc, statePtr, scratchPtr, mdsPtr, prc, prvs, prwh, nextIdx);
        nextIdx = _secondFullRounds(w, filter, acc, statePtr, scratchPtr, mdsPtr, allRC, nextIdx);
        _outputConstraints(w, filter, acc, statePtr, nextIdx);
    }

    /// @dev First HALF_N_FULL_ROUNDS full rounds with S-box input constraints
    /// starting from round 1.
    function _firstFullRounds(
        uint256[] memory w,
        uint256 filter,
        uint256[] memory acc,
        uint256 statePtr,
        uint256 scratchPtr,
        uint256 mdsPtr,
        bytes memory allRC
    ) private pure returns (uint256 nextIdx) {
        uint256 wPtr;
        uint256 accPtr;
        assembly {
            wPtr := add(w, 0x20)
            accPtr := add(acc, 0x20)
        }
        nextIdx = 5;
        uint256 roundCtr = 0;
        for (uint256 r = 0; r < HALF_N_FULL_ROUNDS; r++) {
            _addConstantLayer(statePtr, allRC, roundCtr);
            if (r != 0) {
                uint256 startSbox = START_FULL_0 + 12 * (r - 1);
                nextIdx = _pushConsumeSboxInputs(statePtr, wPtr, startSbox, filter, accPtr, nextIdx);
            }
            _sboxLayer(statePtr);
            _mdsLayerInline(statePtr, scratchPtr, mdsPtr);
            roundCtr++;
        }
    }

    /// @dev N_PARTIAL_ROUNDS partial rounds with a constraint per round.
    function _partialRounds(
        uint256[] memory w,
        uint256 filter,
        uint256[] memory acc,
        uint256 statePtr,
        uint256 scratchPtr,
        uint256 mdsPtr,
        bytes memory prc,
        bytes memory prvs,
        bytes memory prwh,
        uint256 nextIdx
    ) private pure returns (uint256) {
        uint256 accPtr;
        assembly {
            accPtr := add(acc, 0x20)
        }
        // m00 = MDS_CIRC[0] + MDS_DIAG[0]
        uint256 m00;
        assembly {
            m00 := addmod(mload(mdsPtr), mload(add(mdsPtr, 0x180)), P)
        }
        for (uint256 r = 0; r < N_PARTIAL_ROUNDS - 1; r++) {
            uint256 sboxIn = w[START_PARTIAL + r];
            nextIdx = _pushPartialConstraint(statePtr, sboxIn, filter, accPtr, nextIdx);
            // state[0] = sbox_monomial(sboxIn) + FAST_PARTIAL_ROUND_CONSTANTS[r]
            assembly {
                let x := sboxIn
                let x2 := mulmod(x, x, P)
                let x4 := mulmod(x2, x2, P)
                let x7 := mulmod(mulmod(x, x2, P), x4, P)
                let rc := shr(192, mload(add(add(prc, 0x20), mul(r, 8))))
                mstore(statePtr, addmod(x7, rc, P))
            }
            _mdsPartialLayerFast(statePtr, scratchPtr, prvs, prwh, r, m00);
        }
        // Final partial round (no following round constant add).
        uint256 sboxInFinal = w[START_PARTIAL + N_PARTIAL_ROUNDS - 1];
        nextIdx = _pushPartialConstraint(statePtr, sboxInFinal, filter, accPtr, nextIdx);
        assembly {
            let x := sboxInFinal
            let x2 := mulmod(x, x, P)
            let x4 := mulmod(x2, x2, P)
            let x7 := mulmod(mulmod(x, x2, P), x4, P)
            mstore(statePtr, x7)
        }
        _mdsPartialLayerFast(statePtr, scratchPtr, prvs, prwh, N_PARTIAL_ROUNDS - 1, m00);
        return nextIdx;
    }

    /// @dev Second set of full rounds (with S-box input constraints at every round).
    function _secondFullRounds(
        uint256[] memory w,
        uint256 filter,
        uint256[] memory acc,
        uint256 statePtr,
        uint256 scratchPtr,
        uint256 mdsPtr,
        bytes memory allRC,
        uint256 nextIdx
    ) private pure returns (uint256) {
        uint256 wPtr;
        uint256 accPtr;
        assembly {
            wPtr := add(w, 0x20)
            accPtr := add(acc, 0x20)
        }
        uint256 roundCtr = HALF_N_FULL_ROUNDS + N_PARTIAL_ROUNDS;
        for (uint256 r = 0; r < HALF_N_FULL_ROUNDS; r++) {
            _addConstantLayer(statePtr, allRC, roundCtr);
            uint256 startSbox = START_FULL_1 + 12 * r;
            nextIdx = _pushConsumeSboxInputs(statePtr, wPtr, startSbox, filter, accPtr, nextIdx);
            _sboxLayer(statePtr);
            _mdsLayerInline(statePtr, scratchPtr, mdsPtr);
            roundCtr++;
        }
        return nextIdx;
    }

    /// @dev Output consistency: state[i] - wire_output(i) for i ∈ 0..12.
    function _outputConstraints(
        uint256[] memory w,
        uint256 filter,
        uint256[] memory acc,
        uint256 statePtr,
        uint256 nextIdx
    ) private pure {
        assembly {
            let p := P
            let wPtr := add(w, 0x20)
            let accPtr := add(acc, 0x20)
            for { let i := 0 } lt(i, 12) { i := add(i, 1) } {
                let stI := mload(add(statePtr, mul(i, 0x20)))
                let outI := mload(add(wPtr, mul(add(i, 12), 0x20)))
                let diff := addmod(stI, sub(p, outI), p)
                let slot := add(accPtr, mul(add(nextIdx, i), 0x20))
                mstore(slot, addmod(mload(slot), mulmod(filter, diff, p), p))
            }
        }
    }

    /// @dev Constraints 0..5 (swap binary + 4 delta) and initial state load.
    function _evalSwapDelta(
        uint256[] memory w,
        uint256 filter,
        uint256[] memory acc,
        uint256 statePtr
    ) private pure {
        uint256 swap = w[WIRE_SWAP];
        assembly {
            let p := P
            let accPtr := add(acc, 0x20)
            let wPtr := add(w, 0x20)
            // Constraint 0: swap * (swap - 1)
            let s1 := addmod(swap, sub(p, 1), p)
            let v0 := mulmod(swap, s1, p)
            mstore(accPtr, addmod(mload(accPtr), mulmod(filter, v0, p), p))
            // Constraints 1..5: swap*(rhs-lhs) - delta_i
            // Also write state[0..8] = [input[i] + delta_i, input[i+4] - delta_i].
            for { let i := 0 } lt(i, 4) { i := add(i, 1) } {
                let lhs := mload(add(wPtr, mul(i, 0x20)))
                let rhs := mload(add(wPtr, mul(add(i, 4), 0x20)))
                let deltaI := mload(add(wPtr, mul(add(i, START_DELTA), 0x20)))
                let rmL := addmod(rhs, sub(p, lhs), p)
                let tmp := mulmod(swap, rmL, p)
                let diff := addmod(tmp, sub(p, deltaI), p)
                let slot := add(accPtr, mul(add(i, 1), 0x20))
                mstore(slot, addmod(mload(slot), mulmod(filter, diff, p), p))
                mstore(add(statePtr, mul(i, 0x20)), addmod(lhs, deltaI, p))
                mstore(add(statePtr, mul(add(i, 4), 0x20)), addmod(rhs, sub(p, deltaI), p))
            }
            // state[8..12] = wire_input(8..12)
            for { let i := 8 } lt(i, 12) { i := add(i, 1) } {
                mstore(add(statePtr, mul(i, 0x20)), mload(add(wPtr, mul(i, 0x20))))
            }
        }
    }

    /// @dev Push 12 constraints `state[i] - sbox_in_i`, overwriting
    /// state[i] with sbox_in_i on the way out.
    function _pushConsumeSboxInputs(
        uint256 statePtr,
        uint256 wPtr,
        uint256 startSbox,
        uint256 filter,
        uint256 accPtr,
        uint256 nextIdx
    ) private pure returns (uint256) {
        assembly {
            let p := P
            let f := filter
            for { let i := 0 } lt(i, 12) { i := add(i, 1) } {
                let stSlot := add(statePtr, mul(i, 0x20))
                let stV := mload(stSlot)
                let sboxIn := mload(add(wPtr, mul(add(startSbox, i), 0x20)))
                let diff := addmod(stV, sub(p, sboxIn), p)
                let contribute := mulmod(f, diff, p)
                let accSlot := add(accPtr, mul(add(nextIdx, i), 0x20))
                mstore(accSlot, addmod(mload(accSlot), contribute, p))
                // state[i] = sbox_in
                mstore(stSlot, sboxIn)
            }
        }
        unchecked { return nextIdx + 12; }
    }

    /// @dev Single partial-round sbox-input constraint: state[0] - sbox_in.
    function _pushPartialConstraint(
        uint256 statePtr,
        uint256 sboxIn,
        uint256 filter,
        uint256 accPtr,
        uint256 nextIdx
    ) private pure returns (uint256) {
        assembly {
            let p := P
            let st0 := mload(statePtr)
            let diff := addmod(st0, sub(p, sboxIn), p)
            let contribute := mulmod(filter, diff, p)
            let slot := add(accPtr, mul(nextIdx, 0x20))
            mstore(slot, addmod(mload(slot), contribute, p))
        }
        unchecked { return nextIdx + 1; }
    }

    /// @dev state[i] += ALL_ROUND_CONSTANTS[12*round_ctr + i] for i ∈ 0..12.
    function _addConstantLayer(uint256 statePtr, bytes memory allRC, uint256 roundCtr) private pure {
        assembly {
            let base := add(add(allRC, 0x20), mul(roundCtr, 96)) // 12*8 bytes per round
            let p := P
            for { let i := 0 } lt(i, 12) { i := add(i, 1) } {
                let rc := shr(192, mload(add(base, mul(i, 8))))
                let slot := add(statePtr, mul(i, 0x20))
                mstore(slot, addmod(mload(slot), rc, p))
            }
        }
    }

    /// @dev state[i] := state[i]^7 for i ∈ 0..12. In-place.
    function _sboxLayer(uint256 statePtr) private pure {
        assembly {
            let p := P
            for { let i := 0 } lt(i, 12) { i := add(i, 1) } {
                let slot := add(statePtr, mul(i, 0x20))
                let x := mload(slot)
                let x2 := mulmod(x, x, p)
                let x4 := mulmod(x2, x2, p)
                let x7 := mulmod(mulmod(x, x2, p), x4, p)
                mstore(slot, x7)
            }
        }
    }

    /// @dev MDS layer using cached MDS_CIRC + MDS_DIAG[0] from `mdsPtr`.
    /// result[r] = Σ_i state[(i+r) % 12] * CIRC[i]   (+ s0*DIAG[0] if r==0)
    /// Loop over r with an inner loop over i (avoids the 24-variable stack
    /// pressure of a fully-unrolled 12×12 version).
    function _mdsLayerInline(
        uint256 statePtr,
        uint256 scratchPtr,
        uint256 mdsPtr
    ) private pure {
        assembly {
            let p := P
            // Outer loop over row r.
            for { let r := 0 } lt(r, 12) { r := add(r, 1) } {
                let acc := 0
                // Inner dot product.
                for { let i := 0 } lt(i, 12) { i := add(i, 1) } {
                    let circ := mload(add(mdsPtr, mul(i, 0x20)))
                    // state index = (i + r) mod 12
                    let idx := addmod(i, r, 12) // cheap: all < 24
                    let s := mload(add(statePtr, mul(idx, 0x20)))
                    acc := addmod(acc, mulmod(s, circ, p), p)
                }
                // Only DIAG[0] is non-zero; add it to row 0 only.
                if iszero(r) {
                    acc := addmod(acc, mulmod(mload(statePtr), mload(add(mdsPtr, 0x180)), p), p)
                }
                mstore(add(scratchPtr, mul(r, 0x20)), acc)
            }
            // Copy scratch back to state in one sweep.
            for { let i := 0 } lt(i, 12) { i := add(i, 1) } {
                mstore(add(statePtr, mul(i, 0x20)), mload(add(scratchPtr, mul(i, 0x20))))
            }
        }
    }

    /// @dev state[i] += FAST_PARTIAL_FIRST_ROUND_CONSTANT[i] for i ∈ 0..12.
    function _partialFirstConstantLayer(uint256 statePtr, bytes memory pfrc) private pure {
        assembly {
            let p := P
            let base := add(pfrc, 0x20)
            for { let i := 0 } lt(i, 12) { i := add(i, 1) } {
                let c := shr(192, mload(add(base, mul(i, 8))))
                let slot := add(statePtr, mul(i, 0x20))
                mstore(slot, addmod(mload(slot), c, p))
            }
        }
    }

    /// @dev result[0] = state[0]; result[c] = Σ_r state[r] * M[r-1][c-1].
    function _mdsPartialLayerInit(uint256 statePtr, uint256 scratchPtr, bytes memory pim) private pure {
        assembly {
            let p := P
            // Zero scratch.
            mstore(scratchPtr, mload(statePtr)) // result[0] = state[0]
            for { let i := 1 } lt(i, 12) { i := add(i, 1) } {
                mstore(add(scratchPtr, mul(i, 0x20)), 0)
            }
            let matBase := add(pim, 0x20)
            // For r ∈ [1,12): for c ∈ [1,12): scratch[c] += state[r] * M[r-1][c-1]
            for { let r := 1 } lt(r, 12) { r := add(r, 1) } {
                let stR := mload(add(statePtr, mul(r, 0x20)))
                if stR {
                    let rowBase := add(matBase, mul(sub(r, 1), 88)) // 11 entries × 8 bytes
                    for { let c := 1 } lt(c, 12) { c := add(c, 1) } {
                        let t := shr(192, mload(add(rowBase, mul(sub(c, 1), 8))))
                        let sl := add(scratchPtr, mul(c, 0x20))
                        mstore(sl, addmod(mload(sl), mulmod(stR, t, p), p))
                    }
                }
            }
            // Copy scratch back to state.
            for { let i := 0 } lt(i, 12) { i := add(i, 1) } {
                mstore(add(statePtr, mul(i, 0x20)), mload(add(scratchPtr, mul(i, 0x20))))
            }
        }
    }

    /// @dev Fast partial MDS layer for partial round `r`.
    ///   d = state[0] * M_00 + Σ_{i=1..12} state[i] * W_HATS[r][i-1]
    ///   result[0] = d
    ///   result[i] = state[0] * VS[r][i-1] + state[i]  for i ∈ [1,12)
    function _mdsPartialLayerFast(
        uint256 statePtr,
        uint256 scratchPtr,
        bytes memory prvs,
        bytes memory prwh,
        uint256 r,
        uint256 m00
    ) private pure {
        assembly {
            let p := P
            let s0 := mload(statePtr)
            let d := mulmod(s0, m00, p)
            let whBase := add(add(prwh, 0x20), mul(r, 88))
            for { let i := 1 } lt(i, 12) { i := add(i, 1) } {
                let t := shr(192, mload(add(whBase, mul(sub(i, 1), 8))))
                let stI := mload(add(statePtr, mul(i, 0x20)))
                d := addmod(d, mulmod(stI, t, p), p)
            }
            mstore(scratchPtr, d)
            let vsBase := add(add(prvs, 0x20), mul(r, 88))
            for { let i := 1 } lt(i, 12) { i := add(i, 1) } {
                let t := shr(192, mload(add(vsBase, mul(sub(i, 1), 8))))
                let stI := mload(add(statePtr, mul(i, 0x20)))
                mstore(add(scratchPtr, mul(i, 0x20)), addmod(mulmod(s0, t, p), stI, p))
            }
            // Copy scratch back.
            for { let i := 0 } lt(i, 12) { i := add(i, 1) } {
                mstore(add(statePtr, mul(i, 0x20)), mload(add(scratchPtr, mul(i, 0x20))))
            }
        }
    }
}
