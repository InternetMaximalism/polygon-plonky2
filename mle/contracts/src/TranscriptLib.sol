// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.25;

/// @title TranscriptLib
/// @notice Keccak256-based Fiat-Shamir transcript matching the Rust implementation
///         (mle/src/transcript.rs) byte-for-byte.
/// @dev SECURITY: Every byte absorbed and every challenge squeezed MUST be
///      identical to the Rust prover's transcript. Any divergence breaks
///      Fiat-Shamir binding and allows proof forgery.
///
///      All absorb/squeeze operations are Yul-optimized to avoid
///      abi.encodePacked memory reallocation overhead.
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
    /// @dev Appends [labelLen_u64_LE || labelBytes] to state.
    function domainSeparate(Transcript memory t, string memory label) internal pure {
        bytes memory oldState = t.state;
        bytes memory labelBytes = bytes(label);
        uint256 labelLen = labelBytes.length;
        uint256 oldLen = oldState.length;
        uint256 newLen = oldLen + 8 + labelLen;
        bytes memory newState = new bytes(newLen);
        assembly {
            let src := add(oldState, 0x20)
            let dst := add(newState, 0x20)
            // Copy old state in 32-byte chunks
            for { let off := 0 } lt(off, oldLen) { off := add(off, 0x20) } {
                mstore(add(dst, off), mload(add(src, off)))
            }
            // Write label length as u64 LE
            let wp := add(dst, oldLen)
            mstore8(wp, and(labelLen, 0xff))
            mstore8(add(wp, 1), and(shr(8, labelLen), 0xff))
            mstore8(add(wp, 2), and(shr(16, labelLen), 0xff))
            mstore8(add(wp, 3), and(shr(24, labelLen), 0xff))
            mstore8(add(wp, 4), and(shr(32, labelLen), 0xff))
            mstore8(add(wp, 5), and(shr(40, labelLen), 0xff))
            mstore8(add(wp, 6), and(shr(48, labelLen), 0xff))
            mstore8(add(wp, 7), and(shr(56, labelLen), 0xff))
            // Copy label bytes
            let lSrc := add(labelBytes, 0x20)
            let lDst := add(wp, 8)
            for { let off := 0 } lt(off, labelLen) { off := add(off, 0x20) } {
                mstore(add(lDst, off), mload(add(lSrc, off)))
            }
        }
        t.state = newState;
        t.squeezeCounter = 0;
    }

    /// @notice Absorb a single Goldilocks field element (must be < P).
    /// @dev Appends [elem_u64_LE] (8 bytes) to state.
    function absorbField(Transcript memory t, uint256 elem) internal pure {
        require(elem < P, "Field element >= P");
        bytes memory oldState = t.state;
        uint256 oldLen = oldState.length;
        bytes memory newState = new bytes(oldLen + 8);
        assembly {
            let src := add(oldState, 0x20)
            let dst := add(newState, 0x20)
            for { let off := 0 } lt(off, oldLen) { off := add(off, 0x20) } {
                mstore(add(dst, off), mload(add(src, off)))
            }
            let wp := add(dst, oldLen)
            mstore8(wp, and(elem, 0xff))
            mstore8(add(wp, 1), and(shr(8, elem), 0xff))
            mstore8(add(wp, 2), and(shr(16, elem), 0xff))
            mstore8(add(wp, 3), and(shr(24, elem), 0xff))
            mstore8(add(wp, 4), and(shr(32, elem), 0xff))
            mstore8(add(wp, 5), and(shr(40, elem), 0xff))
            mstore8(add(wp, 6), and(shr(48, elem), 0xff))
            mstore8(add(wp, 7), and(shr(56, elem), 0xff))
        }
        t.state = newState;
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
        uint256 appendLen = (1 + n) * 8;
        bytes memory newState = new bytes(oldLen + appendLen);
        assembly {
            let src := add(oldState, 0x20)
            let dst := add(newState, 0x20)
            for { let off := 0 } lt(off, oldLen) { off := add(off, 0x20) } {
                mstore(add(dst, off), mload(add(src, off)))
            }
            let wp := add(dst, oldLen)
            // Write array length as u64 LE
            mstore8(wp, and(n, 0xff))
            mstore8(add(wp, 1), and(shr(8, n), 0xff))
            mstore8(add(wp, 2), and(shr(16, n), 0xff))
            mstore8(add(wp, 3), and(shr(24, n), 0xff))
            mstore8(add(wp, 4), and(shr(32, n), 0xff))
            mstore8(add(wp, 5), and(shr(40, n), 0xff))
            mstore8(add(wp, 6), and(shr(48, n), 0xff))
            mstore8(add(wp, 7), and(shr(56, n), 0xff))
            wp := add(wp, 8)
            // Write each element as u64 LE
            let elemsData := add(elems, 0x20)
            for { let i := 0 } lt(i, n) { i := add(i, 1) } {
                let val := mload(add(elemsData, mul(i, 0x20)))
                mstore8(wp, and(val, 0xff))
                mstore8(add(wp, 1), and(shr(8, val), 0xff))
                mstore8(add(wp, 2), and(shr(16, val), 0xff))
                mstore8(add(wp, 3), and(shr(24, val), 0xff))
                mstore8(add(wp, 4), and(shr(32, val), 0xff))
                mstore8(add(wp, 5), and(shr(40, val), 0xff))
                mstore8(add(wp, 6), and(shr(48, val), 0xff))
                mstore8(add(wp, 7), and(shr(56, val), 0xff))
                wp := add(wp, 8)
            }
        }
        t.state = newState;
        t.squeezeCounter = 0;
    }

    /// @notice Absorb raw bytes. Resets squeeze counter.
    /// @dev Appends [dataLen_u64_LE || data] to state.
    function absorbBytes(Transcript memory t, bytes memory data) internal pure {
        bytes memory oldState = t.state;
        uint256 oldLen = oldState.length;
        uint256 dataLen = data.length;
        uint256 newLen = oldLen + 8 + dataLen;
        bytes memory newState = new bytes(newLen);
        assembly {
            let src := add(oldState, 0x20)
            let dst := add(newState, 0x20)
            for { let off := 0 } lt(off, oldLen) { off := add(off, 0x20) } {
                mstore(add(dst, off), mload(add(src, off)))
            }
            // Write data length as u64 LE
            let wp := add(dst, oldLen)
            mstore8(wp, and(dataLen, 0xff))
            mstore8(add(wp, 1), and(shr(8, dataLen), 0xff))
            mstore8(add(wp, 2), and(shr(16, dataLen), 0xff))
            mstore8(add(wp, 3), and(shr(24, dataLen), 0xff))
            mstore8(add(wp, 4), and(shr(32, dataLen), 0xff))
            mstore8(add(wp, 5), and(shr(40, dataLen), 0xff))
            mstore8(add(wp, 6), and(shr(48, dataLen), 0xff))
            mstore8(add(wp, 7), and(shr(56, dataLen), 0xff))
            // Copy data bytes
            let dSrc := add(data, 0x20)
            let dDst := add(wp, 8)
            for { let off := 0 } lt(off, dataLen) { off := add(off, 0x20) } {
                mstore(add(dDst, off), mload(add(dSrc, off)))
            }
        }
        t.state = newState;
        t.squeezeCounter = 0;
    }

    /// @notice Squeeze a challenge field element matching the Rust implementation exactly.
    /// @dev Optimized: computes keccak256(state || counter_LE) in-place without
    ///      allocating a new bytes array. Temporarily writes 8 counter bytes after
    ///      the state data in memory, computes the hash, then restores.
    ///
    ///      Rust algorithm:
    ///        1. hash = keccak256(state || counter_LE_u64)
    ///        2. limb0 = LE u64 from hash[0..8], limb1 = LE u64 from hash[8..16]
    ///        3. result = reduce96(limb0, limb1 & 0xFFFFFFFF) mod P
    function squeezeChallenge(Transcript memory t) internal pure returns (uint256 challenge) {
        assembly {
            // t is a pointer to the Transcript struct in memory
            // t+0x00 -> pointer to state bytes
            // t+0x20 -> squeezeCounter (uint64)
            let statePtr := mload(t)                    // pointer to state bytes array
            let stateLen := mload(statePtr)             // state.length
            let stateData := add(statePtr, 0x20)        // pointer to state data
            let counter := mload(add(t, 0x20))          // squeezeCounter

            // Save the 32 bytes at stateData+stateLen (we'll temporarily overwrite 8 of them)
            let tailPtr := add(stateData, stateLen)
            let saved := mload(tailPtr)

            // Write counter as u64 LE at tailPtr (8 bytes)
            mstore8(tailPtr, and(counter, 0xff))
            mstore8(add(tailPtr, 1), and(shr(8, counter), 0xff))
            mstore8(add(tailPtr, 2), and(shr(16, counter), 0xff))
            mstore8(add(tailPtr, 3), and(shr(24, counter), 0xff))
            mstore8(add(tailPtr, 4), and(shr(32, counter), 0xff))
            mstore8(add(tailPtr, 5), and(shr(40, counter), 0xff))
            mstore8(add(tailPtr, 6), and(shr(48, counter), 0xff))
            mstore8(add(tailPtr, 7), and(shr(56, counter), 0xff))

            // Compute keccak256(stateData, stateLen + 8) in-place
            let hashVal := keccak256(stateData, add(stateLen, 8))

            // Restore the overwritten memory
            mstore(tailPtr, saved)

            // Increment squeezeCounter
            mstore(add(t, 0x20), add(counter, 1))

            // Extract LE u64 limbs and compute challenge
            // swap64: byte-reverse a 64-bit value
            function swap64(x) -> r {
                x := and(x, 0xFFFFFFFFFFFFFFFF)
                x := or(shl(32, and(x, 0x00000000FFFFFFFF)), shr(32, and(x, 0xFFFFFFFF00000000)))
                x := or(shl(16, and(x, 0x0000FFFF0000FFFF)), shr(16, and(x, 0xFFFF0000FFFF0000)))
                x := or(shl(8,  and(x, 0x00FF00FF00FF00FF)), shr(8,  and(x, 0xFF00FF00FF00FF00)))
                r := x
            }

            let limb0 := swap64(shr(192, hashVal))
            let limb1 := swap64(and(shr(128, hashVal), 0xFFFFFFFFFFFFFFFF))

            // reduce96: lo + (hi & 0xFFFFFFFF) * EPSILON
            let reduced := add(limb0, mul(and(limb1, 0xFFFFFFFF), 0xFFFFFFFF))
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
}
