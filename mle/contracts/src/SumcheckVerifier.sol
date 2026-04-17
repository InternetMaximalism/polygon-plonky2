// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.25;

import {GoldilocksField as F} from "./GoldilocksField.sol";
import {TranscriptLib} from "./TranscriptLib.sol";

/// @title SumcheckVerifier
/// @notice Verifies sumcheck proofs for both zero-check (eq·C) and plain (Σh) protocols.
/// @dev All field arithmetic uses Yul via the GoldilocksField library.
///      The verifier checks that g_i(0) + g_i(1) = claim_i for each round,
///      derives challenges from the transcript, and returns the final evaluation point.
library SumcheckVerifier {
    using F for uint256;

    /// @dev A round polynomial represented by evaluations at {0, 1, ..., degree}.
    struct RoundPoly {
        uint256[] evals; // evals[j] = g_i(j) for j = 0..degree
    }

    /// @dev A sumcheck proof: one round polynomial per variable.
    struct SumcheckProof {
        RoundPoly[] roundPolys;
    }

    /// @notice Verify a sumcheck proof.
    /// @param proof The sumcheck proof (round polynomials).
    /// @param claimedSum The claimed value Σ f(b) or Σ eq(τ,b)·C(b).
    /// @param numVars Number of sumcheck variables (= number of rounds).
    /// @param transcript Fiat-Shamir transcript (must match prover state).
    /// @return challenges The random challenges r_0, ..., r_{n-1}.
    /// @return finalEval The final claimed evaluation g_{n-1}(r_{n-1}).
    function verify(
        SumcheckProof memory proof,
        uint256 claimedSum,
        uint256 numVars,
        uint256 maxDegree,
        TranscriptLib.Transcript memory transcript
    ) internal pure returns (uint256[] memory challenges, uint256 finalEval) {
        require(proof.roundPolys.length == numVars, "Wrong number of rounds");
        require(maxDegree >= 1, "maxDegree must be >= 1");

        challenges = new uint256[](numVars);
        uint256 currentClaim = claimedSum;
        uint256 maxEvals = maxDegree + 1;

        for (uint256 i = 0; i < numVars; i++) {
            uint256[] memory evals = proof.roundPolys[i].evals;
            require(evals.length >= 2, "Round poly too short");
            // SECURITY (Issue #8): enforce upper bound on round-poly degree.
            require(evals.length <= maxEvals, "Round poly degree too high");

            // Check: g_i(0) + g_i(1) == currentClaim
            uint256 sum;
            assembly {
                // evals is a memory array: first word is length, then elements
                let evalsPtr := add(evals, 0x20)
                let e0 := mload(evalsPtr)
                let e1 := mload(add(evalsPtr, 0x20))
                // addmod(e0, e1, P)
                sum := addmod(e0, e1, 0xFFFFFFFF00000001)
            }
            require(sum == currentClaim, "Round check failed");

            // Absorb round polynomial into transcript
            TranscriptLib.domainSeparate(transcript, "sumcheck-round");
            TranscriptLib.absorbFieldVec(transcript, evals);

            // Squeeze challenge
            uint256 r_i = TranscriptLib.squeezeChallenge(transcript);
            challenges[i] = r_i;

            // Compute next claim: g_i(r_i) via Lagrange interpolation over {0,...,d}
            currentClaim = _evaluateRoundPoly(evals, r_i);
        }

        finalEval = currentClaim;
    }

    /// @notice Evaluate a round polynomial at a field element using barycentric
    /// Lagrange interpolation over integer nodes {0, 1, ..., d-1}.
    /// @dev Batch-inverts all (point − j) differences in a single Fermat
    /// exponentiation (saves ~(d−1) × 256 mulmod per round-poly evaluation
    /// relative to the per-i inverse approach).
    function _evaluateRoundPoly(uint256[] memory evals, uint256 point)
        private
        pure
        returns (uint256 result)
    {
        uint256 d = evals.length;

        // Node-collision shortcut (hot path for point = 0 or 1 in corner cases).
        if (point < d) {
            return evals[point];
        }

        assembly {
            let p := 0xFFFFFFFF00000001
            let evalsPtr := add(evals, 0x20)

            // Scratch regions inside the free-memory area:
            //   diffs[0..d]      : point − j
            //   diffsInv[0..d]   : inverse of diffs[i]
            //   denoms[0..d]     : Π_{j≠i} (i − j)
            let scratch := mload(0x40)
            let diffs := scratch
            let diffsInv := add(scratch, mul(d, 0x20))
            let denoms := add(scratch, mul(d, 0x40))
            mstore(0x40, add(scratch, mul(d, 0x60)))

            // --- 1. diffs[j] = point − j ---
            for { let j := 0 } lt(j, d) { j := add(j, 1) } {
                mstore(add(diffs, mul(j, 0x20)), addmod(point, sub(p, j), p))
            }

            // --- 2. Batch-invert diffs using Montgomery's trick:
            //        prefix scan, single Fermat, backward scan. ---
            // prefix[0] = diffs[0]; prefix[i] = prefix[i-1] * diffs[i]
            // We reuse diffsInv as scratch for prefix products during the
            // forward pass, then overwrite with true inverses backward.
            {
                let run := mload(diffs)
                mstore(diffsInv, run)
                for { let j := 1 } lt(j, d) { j := add(j, 1) } {
                    run := mulmod(run, mload(add(diffs, mul(j, 0x20))), p)
                    mstore(add(diffsInv, mul(j, 0x20)), run)
                }
                // totalInv = inverse of full product via Fermat (x^(p-2)).
                let invProd := 1
                let base := run
                let e := 0xFFFFFFFEFFFFFFFF
                for {} gt(e, 0) {} {
                    if and(e, 1) {
                        invProd := mulmod(invProd, base, p)
                    }
                    base := mulmod(base, base, p)
                    e := shr(1, e)
                }
                // Backward scan: diffsInv[i] = prefix[i-1] * invProd,
                // then invProd *= diffs[i]. Prefix[-1] = 1.
                for { let i := d } gt(i, 0) {} {
                    i := sub(i, 1)
                    let prefixPrev
                    switch i
                    case 0 { prefixPrev := 1 }
                    default { prefixPrev := mload(add(diffsInv, mul(sub(i, 1), 0x20))) }
                    mstore(add(diffsInv, mul(i, 0x20)), mulmod(prefixPrev, invProd, p))
                    invProd := mulmod(invProd, mload(add(diffs, mul(i, 0x20))), p)
                }
            }

            // --- 3. denom[i] = Π_{j≠i} (i − j). For integer nodes {0..d-1}:
            //        denom[i] = (-1)^{d-1-i} · i! · (d-1-i)!
            //        Compute directly to avoid an O(d²) inner loop. ---
            {
                // factorials[k] = k! mod p for k = 0..d-1
                let fact := add(scratch, mul(d, 0x60))
                mstore(0x40, add(fact, mul(d, 0x20)))
                let acc := 1
                mstore(fact, 1)
                for { let k := 1 } lt(k, d) { k := add(k, 1) } {
                    acc := mulmod(acc, k, p)
                    mstore(add(fact, mul(k, 0x20)), acc)
                }
                let dMinus1 := sub(d, 1)
                for { let i := 0 } lt(i, d) { i := add(i, 1) } {
                    let fi := mload(add(fact, mul(i, 0x20)))
                    let fdi := mload(add(fact, mul(sub(dMinus1, i), 0x20)))
                    let den := mulmod(fi, fdi, p)
                    // sign: (-1)^{d-1-i}. If (d-1-i) is odd, negate.
                    if and(sub(dMinus1, i), 1) {
                        den := sub(p, den)
                    }
                    mstore(add(denoms, mul(i, 0x20)), den)
                }
            }

            // --- 4. fullProduct = Π diffs[j] (reconstructed from diffsInv[d-1]
            //        is cheaper: we already squeezed it during inversion but the
            //        value was consumed. Recompute by one scan). ---
            let fullProduct := 1
            for { let j := 0 } lt(j, d) { j := add(j, 1) } {
                fullProduct := mulmod(fullProduct, mload(add(diffs, mul(j, 0x20))), p)
            }

            // --- 5. Sum evals[i] * fullProduct * diffsInv[i] / denom[i].
            //        Batch-invert denoms to reuse the single Fermat exponent. ---
            let denomsInv := add(scratch, mul(d, 0x60))
            mstore(0x40, add(denomsInv, mul(d, 0x20)))
            {
                let run := mload(denoms)
                mstore(denomsInv, run)
                for { let j := 1 } lt(j, d) { j := add(j, 1) } {
                    run := mulmod(run, mload(add(denoms, mul(j, 0x20))), p)
                    mstore(add(denomsInv, mul(j, 0x20)), run)
                }
                let invProd := 1
                let base := run
                let e := 0xFFFFFFFEFFFFFFFF
                for {} gt(e, 0) {} {
                    if and(e, 1) {
                        invProd := mulmod(invProd, base, p)
                    }
                    base := mulmod(base, base, p)
                    e := shr(1, e)
                }
                for { let i := d } gt(i, 0) {} {
                    i := sub(i, 1)
                    let prefixPrev
                    switch i
                    case 0 { prefixPrev := 1 }
                    default { prefixPrev := mload(add(denomsInv, mul(sub(i, 1), 0x20))) }
                    mstore(add(denomsInv, mul(i, 0x20)), mulmod(prefixPrev, invProd, p))
                    invProd := mulmod(invProd, mload(add(denoms, mul(i, 0x20))), p)
                }
            }

            result := 0
            for { let i := 0 } lt(i, d) { i := add(i, 1) } {
                let li := mulmod(
                    fullProduct,
                    mulmod(
                        mload(add(diffsInv, mul(i, 0x20))),
                        mload(add(denomsInv, mul(i, 0x20))),
                        p
                    ),
                    p
                )
                let term := mulmod(mload(add(evalsPtr, mul(i, 0x20))), li, p)
                result := addmod(result, term, p)
            }
        }
    }
}
