// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title GoldilocksExt3
/// @notice Cubic extension of Goldilocks field: F_p[x] / (x^3 - 2)
///         where p = 2^64 - 2^32 + 1 (Goldilocks prime)
///
///   Elements are represented as (c0, c1, c2) where element = c0 + c1*x + c2*x^2
///   Multiplication uses x^3 = 2 (NONRESIDUE = 2)
///
///   All arithmetic functions use inline assembly for gas efficiency.
///   Ext3 memory layout: [c0 (32 bytes), c1 (32 bytes), c2 (32 bytes)] at the memory pointer.
library GoldilocksExt3 {
    uint256 internal constant P = 0xFFFFFFFF00000001; // 2^64 - 2^32 + 1

    struct Ext3 {
        uint64 c0;
        uint64 c1;
        uint64 c2;
    }

    function zero() internal pure returns (Ext3 memory r) {
        // default zero-initialized
    }

    function one() internal pure returns (Ext3 memory r) {
        r.c0 = 1;
    }

    function fromBase(uint64 x) internal pure returns (Ext3 memory r) {
        // SECURITY: Reject out-of-range values. uint64 can hold [P, 2^64-1] which are
        // non-canonical representations that bypass isZero checks and corrupt inv().
        require(x < uint64(P), "GoldilocksExt3: value not in field");
        r.c0 = x;
    }

    function isZero(Ext3 memory a) internal pure returns (bool) {
        // SECURITY: Compare modulo P, not bitwise. A value c0 == P is zero in the field
        // but would pass bitwise comparison as non-zero, defeating the guard before inv().
        return a.c0 % uint64(P) == 0 && a.c1 % uint64(P) == 0 && a.c2 % uint64(P) == 0;
    }

    function eq(Ext3 memory a, Ext3 memory b) internal pure returns (bool) {
        // SECURITY: Compare modulo P for field equality, not bitwise.
        return a.c0 % uint64(P) == b.c0 % uint64(P) &&
               a.c1 % uint64(P) == b.c1 % uint64(P) &&
               a.c2 % uint64(P) == b.c2 % uint64(P);
    }

    function add(Ext3 memory a, Ext3 memory b) internal pure returns (Ext3 memory r) {
        assembly {
            let p := 0xFFFFFFFF00000001
            mstore(r, addmod(mload(a), mload(b), p))
            mstore(add(r, 0x20), addmod(mload(add(a, 0x20)), mload(add(b, 0x20)), p))
            mstore(add(r, 0x40), addmod(mload(add(a, 0x40)), mload(add(b, 0x40)), p))
        }
    }

    function sub(Ext3 memory a, Ext3 memory b) internal pure returns (Ext3 memory r) {
        assembly {
            let p := 0xFFFFFFFF00000001
            // SECURITY: Normalize b components to [0, p-1] before negating.
            // Non-canonical b (b >= p) causes sub(p, b) to wrap in 256-bit arithmetic:
            // sub(p, p+k) = 2^256 - k, which is NOT the field negation.
            // Since 2^256 mod p != 0, addmod would then produce a wrong result.
            let b0 := mod(mload(b), p)
            let b1 := mod(mload(add(b, 0x20)), p)
            let b2 := mod(mload(add(b, 0x40)), p)
            mstore(r, addmod(mload(a), sub(p, b0), p))
            mstore(add(r, 0x20), addmod(mload(add(a, 0x20)), sub(p, b1), p))
            mstore(add(r, 0x40), addmod(mload(add(a, 0x40)), sub(p, b2), p))
        }
    }

    function neg(Ext3 memory a) internal pure returns (Ext3 memory r) {
        assembly {
            let p := 0xFFFFFFFF00000001
            // SECURITY: Normalize components to [0, p-1] before negating.
            // A raw value a >= p causes sub(p, a) to wrap in 256-bit arithmetic.
            let a0 := mod(mload(a), p)
            let a1 := mod(mload(add(a, 0x20)), p)
            let a2 := mod(mload(add(a, 0x40)), p)
            mstore(r, mul(iszero(iszero(a0)), sub(p, a0)))
            mstore(add(r, 0x20), mul(iszero(iszero(a1)), sub(p, a1)))
            mstore(add(r, 0x40), mul(iszero(iszero(a2)), sub(p, a2)))
        }
    }

    /// @dev Multiply in F_p[x] / (x^3 - 2)
    ///   c0 = a0*b0 + 2*(a1*b2 + a2*b1)
    ///   c1 = a0*b1 + a1*b0 + 2*a2*b2
    ///   c2 = a0*b2 + a1*b1 + a2*b0
    function mul(Ext3 memory a, Ext3 memory b) internal pure returns (Ext3 memory r) {
        assembly {
            let p := 0xFFFFFFFF00000001
            let a0 := mload(a)
            let a1 := mload(add(a, 0x20))
            let a2 := mload(add(a, 0x40))
            let b0 := mload(b)
            let b1 := mload(add(b, 0x20))
            let b2 := mload(add(b, 0x40))

            // c0 = a0*b0 + 2*(a1*b2 + a2*b1)
            let t1 := addmod(mulmod(a1, b2, p), mulmod(a2, b1, p), p)
            mstore(r, addmod(mulmod(a0, b0, p), mulmod(2, t1, p), p))

            // c1 = a0*b1 + a1*b0 + 2*a2*b2
            let t2 := addmod(mulmod(a0, b1, p), mulmod(a1, b0, p), p)
            mstore(add(r, 0x20), addmod(t2, mulmod(2, mulmod(a2, b2, p), p), p))

            // c2 = a0*b2 + a1*b1 + a2*b0
            mstore(add(r, 0x40), addmod(addmod(mulmod(a0, b2, p), mulmod(a1, b1, p), p), mulmod(a2, b0, p), p))
        }
    }

    /// @dev Scalar multiplication: ext3 * base field element
    function mulScalar(Ext3 memory a, uint64 s) internal pure returns (Ext3 memory r) {
        assembly {
            let p := 0xFFFFFFFF00000001
            let sv := s
            mstore(r, mulmod(mload(a), sv, p))
            mstore(add(r, 0x20), mulmod(mload(add(a, 0x20)), sv, p))
            mstore(add(r, 0x40), mulmod(mload(add(a, 0x40)), sv, p))
        }
    }

    /// @dev Double an element
    function double_(Ext3 memory a) internal pure returns (Ext3 memory r) {
        assembly {
            let p := 0xFFFFFFFF00000001
            let a0 := mload(a)
            let a1 := mload(add(a, 0x20))
            let a2 := mload(add(a, 0x40))
            mstore(r, addmod(a0, a0, p))
            mstore(add(r, 0x20), addmod(a1, a1, p))
            mstore(add(r, 0x40), addmod(a2, a2, p))
        }
    }

    /// @dev Square an element. Specialized formula: 6 mulmod vs 9 in mul().
    ///   c0 = a0^2 + 4*a1*a2       (NONRESIDUE=2, so 2*2=4)
    ///   c1 = 2*a0*a1 + 2*a2^2
    ///   c2 = 2*a0*a2 + a1^2
    function square(Ext3 memory a) internal pure returns (Ext3 memory r) {
        assembly {
            let p := 0xFFFFFFFF00000001
            let a0 := mload(a)
            let a1 := mload(add(a, 0x20))
            let a2 := mload(add(a, 0x40))

            // c0 = a0^2 + 4*a1*a2
            mstore(r, addmod(mulmod(a0, a0, p), mulmod(4, mulmod(a1, a2, p), p), p))

            // c1 = 2*a0*a1 + 2*a2^2
            mstore(add(r, 0x20), addmod(mulmod(2, mulmod(a0, a1, p), p), mulmod(2, mulmod(a2, a2, p), p), p))

            // c2 = 2*a0*a2 + a1^2
            mstore(add(r, 0x40), addmod(mulmod(2, mulmod(a0, a2, p), p), mulmod(a1, a1, p), p))
        }
    }

    /// @dev Multiplicative inverse in F_p[x] / (x^3 - 2).
    ///   α⁻¹ = (1/norm) · (a² - 2bc, 2c² - ab, b² - ac)
    ///   where norm = a·s0 + 2·(c·s1 + b·s2)
    function inv(Ext3 memory a) internal pure returns (Ext3 memory r) {
        assembly {
            let p := 0xFFFFFFFF00000001
            let a0 := mload(a)
            let a1 := mload(add(a, 0x20))
            let a2 := mload(add(a, 0x40))

            // s0 = a0² - 2·a1·a2
            let s0 := addmod(mulmod(a0, a0, p), sub(p, mulmod(2, mulmod(a1, a2, p), p)), p)
            // s1 = 2·a2² - a0·a1
            let s1 := addmod(mulmod(2, mulmod(a2, a2, p), p), sub(p, mulmod(a0, a1, p)), p)
            // s2 = a1² - a0·a2
            let s2 := addmod(mulmod(a1, a1, p), sub(p, mulmod(a0, a2, p)), p)

            // norm = a0·s0 + 2·(a2·s1 + a1·s2)
            let norm := addmod(
                mulmod(a0, s0, p),
                mulmod(2, addmod(mulmod(a2, s1, p), mulmod(a1, s2, p), p), p),
                p
            )

            // normInv = norm^(p-2) mod p via square-and-multiply
            let base := mod(norm, p)
            // SECURITY: Revert if the element is zero. norm == 0 means a == 0, which has
            // no multiplicative inverse. Without this check, inv(0) silently returns (0,0,0),
            // corrupting any subsequent division (e.g. the guard before inv() can be bypassed
            // by passing a non-canonical zero where c0 == P, which isZero() missed pre-fix).
            if iszero(base) { revert(0, 0) }
            let e := sub(p, 2)
            let result := 1
            for {} gt(e, 0) {} {
                if and(e, 1) { result := mulmod(result, base, p) }
                e := shr(1, e)
                base := mulmod(base, base, p)
            }

            mstore(r, mulmod(s0, result, p))
            mstore(add(r, 0x20), mulmod(s1, result, p))
            mstore(add(r, 0x40), mulmod(s2, result, p))
        }
    }

    /// @dev Compute a^(2^n) by repeated squaring
    function expPowerOf2(Ext3 memory a, uint256 n) internal pure returns (Ext3 memory result) {
        result = a;
        for (uint256 i = 0; i < n; i++) {
            result = square(result);
        }
    }

    /// @dev Check equality
    function isEqual(Ext3 memory a, Ext3 memory b) internal pure returns (bool) {
        // SECURITY: Compare modulo P for field equality.
        return a.c0 % uint64(P) == b.c0 % uint64(P) &&
               a.c1 % uint64(P) == b.c1 % uint64(P) &&
               a.c2 % uint64(P) == b.c2 % uint64(P);
    }

    /// @dev Evaluate L_0(x) = (x^n - 1) / (n * (x - 1)) where n = 2^degreeBits
    function evalL0(Ext3 memory x, uint256 degreeBits) internal pure returns (Ext3 memory) {
        // SECURITY: Reject degreeBits >= 64 to prevent uint64 truncation of n.
        // If degreeBits >= 64, uint64(1 << degreeBits) = 0, causing mulScalar to return
        // zero and inv(zero) to silently return zero, making evalL0 return 0 for any x.
        require(degreeBits < 64, "GoldilocksExt3: degreeBits out of range");
        uint64 nScalar = uint64(1) << uint64(degreeBits);
        // SECURITY: Also check that n < P (required for valid scalar field element).
        require(nScalar < uint64(P), "GoldilocksExt3: n exceeds field modulus");
        Ext3 memory xPowN = expPowerOf2(x, degreeBits);
        Ext3 memory numerator = sub(xPowN, one());
        Ext3 memory denominator = mulScalar(sub(x, one()), nScalar);
        return mul(numerator, inv(denominator));
    }

    /// @dev Horner evaluation: terms[0] + alpha*(terms[1] + alpha*(terms[2] + ...))
    function reduceWithPowers(Ext3[] memory terms, Ext3 memory alpha) internal pure returns (Ext3 memory result) {
        if (terms.length == 0) return zero();
        result = zero();
        for (uint256 i = terms.length; i > 0; i--) {
            result = add(mul(result, alpha), terms[i - 1]);
        }
    }

    /// @dev Scalar multiplication with uint256 (truncates to uint64 mod P)
    function mulScalarU256(Ext3 memory a, uint256 s) internal pure returns (Ext3 memory r) {
        assembly {
            let p := 0xFFFFFFFF00000001
            let sv := mod(s, p)
            mstore(r, mulmod(mload(a), sv, p))
            mstore(add(r, 0x20), mulmod(mload(add(a, 0x20)), sv, p))
            mstore(add(r, 0x40), mulmod(mload(add(a, 0x40)), sv, p))
        }
    }

    /// @dev Create Ext3 from uint256 base field element
    function fromBaseU256(uint256 x) internal pure returns (Ext3 memory r) {
        assembly {
            mstore(r, mod(x, 0xFFFFFFFF00000001))
        }
    }

    /// @dev Dot product of two arrays of Ext3 elements
    function dot(Ext3[] memory a, Ext3[] memory b) internal pure returns (Ext3 memory result) {
        assembly {
            let p := 0xFFFFFFFF00000001
            let aLen := mload(a)
            let bLen := mload(b)
            let n := aLen
            if lt(bLen, aLen) { n := bLen }

            let r0 := 0
            let r1 := 0
            let r2 := 0

            let aPtr := add(a, 0x20)
            let bPtr := add(b, 0x20)

            for { let i := 0 } lt(i, n) { i := add(i, 1) } {
                let aElem := mload(add(aPtr, mul(i, 0x20)))
                let bElem := mload(add(bPtr, mul(i, 0x20)))

                let a0 := mload(aElem)
                let a1 := mload(add(aElem, 0x20))
                let a2 := mload(add(aElem, 0x40))
                let b0 := mload(bElem)
                let b1 := mload(add(bElem, 0x20))
                let b2 := mload(add(bElem, 0x40))

                // mul: c0 = a0*b0 + 2*(a1*b2 + a2*b1)
                let t1 := addmod(mulmod(a1, b2, p), mulmod(a2, b1, p), p)
                let mc0 := addmod(mulmod(a0, b0, p), mulmod(2, t1, p), p)
                // c1 = a0*b1 + a1*b0 + 2*a2*b2
                let mc1 := addmod(addmod(mulmod(a0, b1, p), mulmod(a1, b0, p), p), mulmod(2, mulmod(a2, b2, p), p), p)
                // c2 = a0*b2 + a1*b1 + a2*b0
                let mc2 := addmod(addmod(mulmod(a0, b2, p), mulmod(a1, b1, p), p), mulmod(a2, b0, p), p)

                r0 := addmod(r0, mc0, p)
                r1 := addmod(r1, mc1, p)
                r2 := addmod(r2, mc2, p)
            }

            mstore(result, r0)
            mstore(add(result, 0x20), r1)
            mstore(add(result, 0x40), r2)
        }
    }

}
