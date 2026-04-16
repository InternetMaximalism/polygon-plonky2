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
        TranscriptLib.Transcript memory transcript
    ) internal pure returns (uint256[] memory challenges, uint256 finalEval) {
        require(proof.roundPolys.length == numVars, "Wrong number of rounds");

        challenges = new uint256[](numVars);
        uint256 currentClaim = claimedSum;

        for (uint256 i = 0; i < numVars; i++) {
            uint256[] memory evals = proof.roundPolys[i].evals;
            require(evals.length >= 2, "Round poly too short");

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

    /// @notice Evaluate a round polynomial at a field element using Lagrange interpolation.
    /// @dev Interpolates over integer nodes {0, 1, ..., d} where d = evals.length - 1.
    ///      Uses Yul for all field arithmetic.
    function _evaluateRoundPoly(uint256[] memory evals, uint256 point)
        private
        pure
        returns (uint256 result)
    {
        uint256 d = evals.length;

        // Quick check: if point is one of the integer nodes {0,...,d-1},
        // return the evaluation directly (common case for point = 0 or 1).
        if (point < d) {
            return evals[point];
        }

        assembly {
            let p := 0xFFFFFFFF00000001
            let evalsPtr := add(evals, 0x20)

            // Precompute diffs[j] = (point - j) mod p for j = 0..d-1
            // Store on stack or in scratch memory
            let scratchStart := mload(0x40) // free memory pointer
            for { let j := 0 } lt(j, d) { j := add(j, 1) } {
                let diff := addmod(point, sub(p, mod(j, p)), p)
                mstore(add(scratchStart, mul(j, 0x20)), diff)
            }

            // fullProduct = Π diffs[j]
            let fullProduct := 1
            for { let j := 0 } lt(j, d) { j := add(j, 1) } {
                fullProduct := mulmod(fullProduct, mload(add(scratchStart, mul(j, 0x20))), p)
            }

            // fullProduct == 0 is unreachable here: the `point < d` check at line 86
            // already handles all integer-node cases by returning evals[point] directly.
            // No distinct point x with x >= d can equal any node j in {0..d-1}, so
            // all diffs are nonzero, making fullProduct nonzero. The branch is removed.
            {
                result := 0

                for { let i := 0 } lt(i, d) { i := add(i, 1) } {
                    let diff_i := mload(add(scratchStart, mul(i, 0x20)))

                    // denom = Π_{j≠i} (i - j) mod p
                    let denom := 1
                    for { let j := 0 } lt(j, d) { j := add(j, 1) } {
                        if iszero(eq(j, i)) {
                            // (i - j) mod p
                            let ij := addmod(mod(i, p), sub(p, mod(j, p)), p)
                            denom := mulmod(denom, ij, p)
                        }
                    }

                    // L_i(point) = fullProduct / (diff_i * denom)
                    // Need: inv(diff_i * denom) = inv(diff_i) * inv(denom)
                    // inv via Fermat: x^(p-2) mod p
                    let toInvert := mulmod(diff_i, denom, p)

                    // Inline modular inverse: toInvert^(p-2) mod p
                    let invVal := 1
                    let base := toInvert
                    let e := 0xFFFFFFFEFFFFFFFF // p - 2

                    for {} gt(e, 0) {} {
                        if and(e, 1) {
                            invVal := mulmod(invVal, base, p)
                        }
                        base := mulmod(base, base, p)
                        e := shr(1, e)
                    }

                    let li := mulmod(fullProduct, invVal, p)
                    let term := mulmod(mload(add(evalsPtr, mul(i, 0x20))), li, p)
                    result := addmod(result, term, p)
                }

                // Update free memory pointer
                mstore(0x40, add(scratchStart, mul(d, 0x20)))
            }
        }
    }
}
