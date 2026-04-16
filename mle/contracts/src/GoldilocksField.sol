// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.25;

/// @title GoldilocksField
/// @notice Arithmetic over the Goldilocks prime field p = 2^64 - 2^32 + 1.
/// @dev All operations use Yul for gas efficiency. Field elements are stored
///      as uint256 but MUST be canonical (< P) at all times.
///      p = 18446744069414584321
library GoldilocksField {
    /// @dev The Goldilocks prime: 2^64 - 2^32 + 1
    uint256 internal constant P = 0xFFFFFFFF00000001;

    /// @dev P - 2 (exponent for modular inverse via Fermat)
    uint256 internal constant P_MINUS_2 = 0xFFFFFFFEFFFFFFFF;

    /// @notice Add two field elements: (a + b) mod p
    function add(uint256 a, uint256 b) internal pure returns (uint256 result) {
        assembly {
            result := addmod(a, b, P)
        }
    }

    /// @notice Subtract two field elements: (a - b) mod p
    /// @dev Safe for all uint256 inputs due to addmod handling.
    function sub(uint256 a, uint256 b) internal pure returns (uint256 result) {
        assembly {
            // Reduce b first to avoid underflow in sub(P, b)
            let b_red := mod(b, P)
            result := addmod(a, sub(P, b_red), P)
        }
    }

    /// @notice Multiply two field elements: (a * b) mod p
    function mul(uint256 a, uint256 b) internal pure returns (uint256 result) {
        assembly {
            result := mulmod(a, b, P)
        }
    }

    /// @notice Modular inverse via Fermat's little theorem: a^(p-2) mod p
    /// @dev Reverts if a == 0 (zero has no inverse).
    function inv(uint256 a) internal pure returns (uint256 result) {
        assembly {
            // SECURITY: Zero has no multiplicative inverse.
            if iszero(mod(a, P)) {
                // revert with "Division by zero"
                mstore(0x00, 0x08c379a000000000000000000000000000000000000000000000000000000000)
                mstore(0x04, 0x20)
                mstore(0x24, 16)
                mstore(0x44, "Division by zero")
                revert(0x00, 0x64)
            }

            result := 1
            let base := mod(a, P)
            let e := P_MINUS_2

            for {} gt(e, 0) {} {
                if and(e, 1) {
                    result := mulmod(result, base, P)
                }
                base := mulmod(base, base, P)
                e := shr(1, e)
            }
        }
    }

    /// @notice Modular exponentiation: base^exponent mod p
    function modExp(uint256 base, uint256 exponent) internal pure returns (uint256 result) {
        assembly {
            result := 1
            let b := mod(base, P)
            let e := exponent

            for {} gt(e, 0) {} {
                if and(e, 1) {
                    result := mulmod(result, b, P)
                }
                b := mulmod(b, b, P)
                e := shr(1, e)
            }
        }
    }

    /// @notice Negate a field element: (-a) mod p = (p - a) mod p
    function neg(uint256 a) internal pure returns (uint256 result) {
        assembly {
            let a_red := mod(a, P)
            switch a_red
            case 0 { result := 0 }
            default { result := sub(P, a_red) }
        }
    }

    /// @notice Reduce a uint256 to a canonical Goldilocks field element (< P).
    function reduce(uint256 a) internal pure returns (uint256 result) {
        assembly {
            result := mod(a, P)
        }
    }

    /// @notice Validate that a value is a canonical field element (< P).
    function requireCanonical(uint256 a) internal pure {
        require(a < P, "Not canonical field element");
    }
}
