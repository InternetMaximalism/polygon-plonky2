// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.25;

/// @title TranscriptLib
/// @notice Keccak256-based Fiat-Shamir transcript matching the Rust implementation
///         (mle/src/transcript.rs) byte-for-byte.
/// @dev SECURITY: Every byte absorbed and every challenge squeezed MUST be
///      identical to the Rust prover's transcript. Any divergence breaks
///      Fiat-Shamir binding and allows proof forgery.
library TranscriptLib {
    uint256 internal constant P = 0xFFFFFFFF00000001;
    /// @dev EPSILON = 2^32 - 1, used in Goldilocks reduce96.
    uint256 internal constant EPSILON = 0xFFFFFFFF;

    struct Transcript {
        bytes state;
        uint64 squeezeCounter;
    }

    /// @notice Initialize with protocol domain separation.
    function init(Transcript memory t) internal pure {
        t.state = "";
        t.squeezeCounter = 0;
        domainSeparate(t, "plonky2-mle-v0");
    }

    /// @notice Absorb a domain separation label. Resets squeeze counter.
    function domainSeparate(Transcript memory t, string memory label) internal pure {
        bytes memory labelBytes = bytes(label);
        uint64 len = uint64(labelBytes.length);
        bytes memory lenBytes = _u64ToLE(len);
        t.state = abi.encodePacked(t.state, lenBytes, labelBytes);
        t.squeezeCounter = 0;
    }

    /// @notice Absorb a single Goldilocks field element (must be < P).
    function absorbField(Transcript memory t, uint256 elem) internal pure {
        require(elem < P, "Field element >= P");
        t.state = abi.encodePacked(t.state, _u64ToLE(uint64(elem)));
        t.squeezeCounter = 0;
    }

    /// @notice Absorb a slice of Goldilocks field elements.
    /// @dev Optimized: single allocation instead of N+1 abi.encodePacked calls.
    ///      Appends [length_u64_LE || elem0_u64_LE || ... || elemN_u64_LE] to state.
    function absorbFieldVec(Transcript memory t, uint256[] memory elems) internal pure {
        uint256 n = elems.length;
        // Validate all elements < P first
        for (uint256 i = 0; i < n; i++) {
            require(elems[i] < P, "Field element >= P");
        }
        // Append (1 + n) * 8 bytes to state in a single allocation
        bytes memory oldState = t.state;
        uint256 oldLen = oldState.length;
        uint256 appendLen = (1 + n) * 8; // length prefix + n elements, each 8 bytes
        bytes memory newState = new bytes(oldLen + appendLen);
        assembly {
            // Copy old state
            let src := add(oldState, 0x20)
            let dst := add(newState, 0x20)
            // Copy in 32-byte chunks
            for { let off := 0 } lt(off, oldLen) { off := add(off, 0x20) } {
                mstore(add(dst, off), mload(add(src, off)))
            }
            // Write length prefix as u64 LE
            let writePtr := add(dst, oldLen)
            // Store n as u64 LE (8 bytes) — byte-reverse the low 64 bits
            // u64 LE of n: byte 0 = n & 0xFF, byte 1 = (n >> 8) & 0xFF, ...
            mstore8(writePtr, and(n, 0xff))
            mstore8(add(writePtr, 1), and(shr(8, n), 0xff))
            mstore8(add(writePtr, 2), and(shr(16, n), 0xff))
            mstore8(add(writePtr, 3), and(shr(24, n), 0xff))
            mstore8(add(writePtr, 4), and(shr(32, n), 0xff))
            mstore8(add(writePtr, 5), and(shr(40, n), 0xff))
            mstore8(add(writePtr, 6), and(shr(48, n), 0xff))
            mstore8(add(writePtr, 7), and(shr(56, n), 0xff))
            writePtr := add(writePtr, 8)
            // Write each element as u64 LE
            let elemsData := add(elems, 0x20)
            for { let i := 0 } lt(i, n) { i := add(i, 1) } {
                let val := mload(add(elemsData, mul(i, 0x20)))
                mstore8(writePtr, and(val, 0xff))
                mstore8(add(writePtr, 1), and(shr(8, val), 0xff))
                mstore8(add(writePtr, 2), and(shr(16, val), 0xff))
                mstore8(add(writePtr, 3), and(shr(24, val), 0xff))
                mstore8(add(writePtr, 4), and(shr(32, val), 0xff))
                mstore8(add(writePtr, 5), and(shr(40, val), 0xff))
                mstore8(add(writePtr, 6), and(shr(48, val), 0xff))
                mstore8(add(writePtr, 7), and(shr(56, val), 0xff))
                writePtr := add(writePtr, 8)
            }
        }
        t.state = newState;
        t.squeezeCounter = 0;
    }

    /// @notice Absorb raw bytes. Resets squeeze counter.
    function absorbBytes(Transcript memory t, bytes memory data) internal pure {
        bytes memory lenBytes = _u64ToLE(uint64(data.length));
        t.state = abi.encodePacked(t.state, lenBytes, data);
        t.squeezeCounter = 0;
    }

    /// @notice Squeeze a challenge field element matching the Rust implementation exactly.
    /// @dev Rust algorithm:
    ///   1. hash = keccak256(state || counter_LE_u64)
    ///   2. Split hash into 4 LE u64 limbs: limb0=[0..8], limb1=[8..16], limb2=[16..24], limb3=[24..32]
    ///   3. Horner accumulation (reversed): acc = 0; for limb in [limb3, limb2, limb1, limb0]:
    ///        acc = (acc << 64) | limb     (wrapping u128)
    ///   4. After 4 iterations of wrapping u128: lo = acc as u64 = limb0, hi = (acc >> 64) as u32 = limb1 & 0xFFFFFFFF
    ///   5. Result = reduce96(lo, hi) = lo + hi * EPSILON  (may exceed P, but Goldilocks allows non-canonical)
    ///   6. Final canonical reduction: result mod P
    function squeezeChallenge(Transcript memory t) internal pure returns (uint256 challenge) {
        bytes memory toHash = abi.encodePacked(t.state, _u64ToLE(t.squeezeCounter));
        t.squeezeCounter++;

        assembly {
            let hashVal := keccak256(add(toHash, 0x20), mload(toHash))

            // hashVal is a bytes32 in big-endian (EVM convention).
            // We need to extract LE u64 limbs from the raw keccak output bytes.
            // Keccak output byte[0] is the MSB of the bytes32.
            //
            // Rust reads bytes sequentially: bytes[0..8] → limb0 (LE), bytes[8..16] → limb1 (LE)
            // In Solidity bytes32, byte[0] is at the MSB end.
            // hashVal >> 192 gives the top 8 bytes as a big-endian u64.
            // But Rust reads them as LE u64, so we need to byte-swap.

            // Extract 4 big-endian u64 values from hashVal, then swap to LE interpretation.
            // Byte layout of bytes32 hashVal (BE):
            //   [b0 b1 b2 b3 b4 b5 b6 b7 | b8 b9 ... b15 | b16 ... b23 | b24 ... b31]
            //   MSB                                                                LSB
            //
            // Rust keccak output bytes[i] = b_i. Rust reads:
            //   limb0 = u64::from_le_bytes([b0,b1,b2,b3,b4,b5,b6,b7])
            //   limb1 = u64::from_le_bytes([b8,...,b15])
            //
            // In Solidity, hashVal >> 192 = big-endian interpretation of [b0..b7].
            // To get LE u64 from [b0..b7], we need to byte-reverse.

            // Helper: byte-reverse a 64-bit value
            // swap64(x) reverses the 8 bytes of the lowest 64 bits of x.
            function swap64(x) -> r {
                // Swap bytes: abcdefgh -> hgfedcba
                x := and(x, 0xFFFFFFFFFFFFFFFF)
                x := or(shl(32, and(x, 0x00000000FFFFFFFF)), shr(32, and(x, 0xFFFFFFFF00000000)))
                x := or(shl(16, and(x, 0x0000FFFF0000FFFF)), shr(16, and(x, 0xFFFF0000FFFF0000)))
                x := or(shl(8,  and(x, 0x00FF00FF00FF00FF)), shr(8,  and(x, 0xFF00FF00FF00FF00)))
                r := x
            }

            // Extract big-endian u64s and convert to LE u64s
            let be0 := shr(192, hashVal)           // bytes [0..8]  as BE u64
            let be1 := and(shr(128, hashVal), 0xFFFFFFFFFFFFFFFF)  // bytes [8..16]

            let limb0 := swap64(be0)  // LE interpretation
            let limb1 := swap64(be1)  // LE interpretation

            // Rust Horner on u128 (wrapping): after 4 iterations, due to u128 wrapping,
            // the result is: lo = limb0, hi_full = limb1.
            // Then: hi = limb1 & 0xFFFFFFFF (truncated to u32)
            // result = lo + hi * EPSILON

            let lo := limb0
            let hi := and(limb1, 0xFFFFFFFF)

            // reduce96: lo + hi * EPSILON
            // EPSILON = 2^32 - 1
            let reduced := add(lo, mul(hi, 0xFFFFFFFF))

            // Canonical reduction: if reduced >= P, subtract P
            // P = 0xFFFFFFFF00000001
            // reduced can be at most (2^64 - 1) + (2^32 - 1) * (2^32 - 1)
            //   = 2^64 - 1 + 2^64 - 2^33 + 1 = 2^65 - 2^33
            // So we may need to reduce once or twice.
            // Actually, reduce96 in Rust uses add_no_canonicalize which may return
            // a value in [0, 2^64). The Rust code does NOT fully canonicalize.
            // But then it's stored as GoldilocksField(t2) where t2 can be >= P.
            // When used in field arithmetic, non-canonical values work fine.
            // However, for the transcript comparison, we need the exact same
            // canonical representation. The Rust from_noncanonical_u96 returns
            // a possibly non-canonical value, but it's used in arithmetic where
            // the canonical reduction happens implicitly.
            //
            // For Solidity we need canonical: result mod P.
            challenge := mod(reduced, 0xFFFFFFFF00000001)
        }
    }

    /// @notice Squeeze n challenges.
    function squeezeChallenges(Transcript memory t, uint256 n)
        internal
        pure
        returns (uint256[] memory challenges)
    {
        challenges = new uint256[](n);
        for (uint256 i = 0; i < n; i++) {
            challenges[i] = squeezeChallenge(t);
        }
    }

    /// @dev Encode a uint64 as 8 bytes little-endian.
    function _u64ToLE(uint64 val) private pure returns (bytes memory result) {
        result = new bytes(8);
        assembly {
            let ptr := add(result, 0x20)
            mstore8(ptr, and(val, 0xff))
            mstore8(add(ptr, 1), and(shr(8, val), 0xff))
            mstore8(add(ptr, 2), and(shr(16, val), 0xff))
            mstore8(add(ptr, 3), and(shr(24, val), 0xff))
            mstore8(add(ptr, 4), and(shr(32, val), 0xff))
            mstore8(add(ptr, 5), and(shr(40, val), 0xff))
            mstore8(add(ptr, 6), and(shr(48, val), 0xff))
            mstore8(add(ptr, 7), and(shr(56, val), 0xff))
        }
    }
}
