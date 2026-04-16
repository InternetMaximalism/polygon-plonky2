// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.25;

/// @title EqPolyLib
/// @notice Evaluates the eq polynomial eq(τ, r) = Π_j (τ_j·r_j + (1-τ_j)(1-r_j)).
/// @dev Uses Yul for gas-efficient field arithmetic.
library EqPolyLib {
    /// @notice Compute eq(tau, r) at a single point.
    /// @param tau The fixed point τ ∈ F^n.
    /// @param r The evaluation point r ∈ F^n.
    /// @return result eq(tau, r) as a field element.
    function eqEval(uint256[] memory tau, uint256[] memory r)
        internal
        pure
        returns (uint256 result)
    {
        require(tau.length == r.length, "Length mismatch");

        assembly {
            let p := 0xFFFFFFFF00000001
            result := 1

            let n := mload(tau)
            let tauPtr := add(tau, 0x20)
            let rPtr := add(r, 0x20)

            for { let j := 0 } lt(j, n) { j := add(j, 1) } {
                let t_j := mload(add(tauPtr, mul(j, 0x20)))
                let r_j := mload(add(rPtr, mul(j, 0x20)))

                // factor = t_j * r_j + (1 - t_j) * (1 - r_j)
                //        = t_j * r_j + 1 - t_j - r_j + t_j * r_j
                //        = 2 * t_j * r_j - t_j - r_j + 1
                let tr := mulmod(t_j, r_j, p)
                let two_tr := addmod(tr, tr, p)
                // 1 - t_j - r_j + 2*t_j*r_j
                let factor := addmod(
                    addmod(1, sub(p, t_j), p),
                    addmod(sub(p, r_j), two_tr, p),
                    p
                )

                result := mulmod(result, factor, p)
            }
        }
    }
}
