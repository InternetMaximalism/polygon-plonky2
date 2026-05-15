// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.25;

/// @title CosetInterpolationConstants — Plonky2 Goldilocks two-adic
///         subgroups + barycentric weights for `CosetInterpolationGate`.
/// @notice Each entry is u64 (8 bytes, big-endian) packed into a single
///         `bytes` constant; read via `readU64` (same helper as
///         `PoseidonConstants.sol`).
///
/// Source: auto-extracted from `plonky2_field::goldilocks_field`. DO NOT
/// EDIT MANUALLY — regenerate via
///   cargo test --release --test dump_coset_constants \
///       --features std -- --nocapture > \
///       mle/contracts/src/CosetInterpolationConstants.sol
library CosetInterpolationConstants {

    /// Two-adic subgroup of size 2^1 (= 2).
    bytes internal constant SUBGROUP_1 = hex"0000000000000001ffffffff00000000";

    /// Barycentric weights for SUBGROUP_1.
    bytes internal constant WEIGHTS_1 = hex"7fffffff800000017fffffff80000000";

    /// Two-adic subgroup of size 2^2 (= 4).
    bytes internal constant SUBGROUP_2 = hex"00000000000000010001000000000000ffffffff00000000fffeffff00000001";

    /// Barycentric weights for SUBGROUP_2.
    bytes internal constant WEIGHTS_2 = hex"bfffffff4000000100004000000000003fffffffc0000000ffffbfff00000001";

    /// Two-adic subgroup of size 2^3 (= 8).
    bytes internal constant SUBGROUP_3 = hex"000000000000000100000000010000000001000000000000000000ffffffff00ffffffff00000000fffffffeff000001fffeffff00000001fffffeff00000101";

    /// Barycentric weights for SUBGROUP_3.
    bytes internal constant WEIGHTS_3 = hex"dfffffff20000001000000000020000000002000000000000000001fffffffe01fffffffe0000000fffffffeffe00001ffffdfff00000001ffffffdf00000021";

    /// Two-adic subgroup of size 2^4 (= 16).
    bytes internal constant SUBGROUP_4 = hex"000000000000000100000000000010000000000001000000000000100000000000010000000000001000000000000000000000ffffffff00000ffffffff00000ffffffff00000000fffffffefffff001fffffffeff000001ffffffef00000001fffeffff00000001efffffff00000001fffffeff00000101ffefffff00100001";

    /// Barycentric weights for SUBGROUP_4.
    bytes internal constant WEIGHTS_4 = hex"efffffff10000001000000000000010000000000001000000000000100000000000010000000000001000000000000000000000ffffffff00000ffffffff00000ffffffff0000000fffffffeffffff01fffffffefff00001fffffffe00000001ffffefff00000001feffffff00000001ffffffef00000011fffeffff00010001";

    /// Two-adic subgroup of size 2^5 (= 32).
    bytes internal constant SUBGROUP_5 = hex"0000000000000001000000000000004000000000000010000000000000040000000000000100000000000000400000000000001000000000000004000000000000010000000000000040000000000000100000000000000000000003fffffffc000000ffffffff0000003fffffffc000000ffffffff0000003fffffffc000000ffffffff00000000fffffffeffffffc1fffffffefffff001fffffffefffc0001fffffffeff000001fffffffec0000001ffffffef00000001fffffbff00000001fffeffff00000001ffbfffff00000001efffffff00000001fffffffb00000005fffffeff00000101ffffbfff00004001ffefffff00100001fbffffff04000001";

    /// Barycentric weights for SUBGROUP_5.
    bytes internal constant WEIGHTS_5 = hex"f7ffffff080000010000000000000002000000000000008000000000000020000000000000080000000000000200000000000000800000000000002000000000000008000000000000020000000000000080000000000000200000000000000000000007fffffff8000001fffffffe0000007fffffff8000001fffffffe0000007fffffff8000000fffffffefffffffffffffffeffffff81fffffffeffffe001fffffffefff80001fffffffefe000001fffffffe80000001ffffffdf00000001fffff7ff00000001fffdffff00000001ff7fffff00000001dfffffff00000001fffffff700000009fffffdff00000201ffff7fff00008001ffdfffff00200001";

    /// Read the `i`-th u64 from a packed `bytes` blob (8 bytes / entry).
    /// Mirrors `PoseidonConstants.readU64`.
    function readU64(bytes memory blob, uint256 i) internal pure returns (uint256 v) {
        // Defense-in-depth (audit L2): bound-check `i` against the
        // packed-blob length so a buggy caller cannot silently read
        // past the constants table (which `mload` would otherwise pad
        // with zero).
        require(i * 8 + 8 <= blob.length, "CosetInterpolation: index OOB");
        assembly {
            let ptr := add(add(blob, 0x20), mul(i, 8))
            v := shr(192, mload(ptr))
        }
    }

    /// Return the `i`-th element of the two-adic subgroup of size 2^bits.
    /// Reverts if `bits` is outside the supported set or `i >= 2^bits`.
    function subgroupElement(uint256 bits, uint256 i) internal pure returns (uint256) {
        if (bits == 1) return readU64(SUBGROUP_1, i);
        if (bits == 2) return readU64(SUBGROUP_2, i);
        if (bits == 3) return readU64(SUBGROUP_3, i);
        if (bits == 4) return readU64(SUBGROUP_4, i);
        if (bits == 5) return readU64(SUBGROUP_5, i);
        revert("CosetInterpolation: subgroup_bits not supported");
    }

    /// Return the `i`-th barycentric weight for the two-adic subgroup of size 2^bits.
    function weight(uint256 bits, uint256 i) internal pure returns (uint256) {
        if (bits == 1) return readU64(WEIGHTS_1, i);
        if (bits == 2) return readU64(WEIGHTS_2, i);
        if (bits == 3) return readU64(WEIGHTS_3, i);
        if (bits == 4) return readU64(WEIGHTS_4, i);
        if (bits == 5) return readU64(WEIGHTS_5, i);
        revert("CosetInterpolation: subgroup_bits not supported");
    }
}
