//! Dump Plonky2's two-adic subgroups and barycentric weights for the small
//! `subgroup_bits` values supported by `CosetInterpolationGate` in the
//! Solidity verifier.
//!
//! Run with:
//!   cargo test --release --test dump_coset_constants \
//!       --features "std" -- --nocapture
//!
//! The output is a complete `CosetInterpolationConstants.sol` file that can
//! be redirected:
//!   cargo test --release --test dump_coset_constants \
//!       --features "std" -- --nocapture > \
//!       mle/contracts/src/CosetInterpolationConstants.sol
//!
//! SECURITY: this file is the audit surface for `_evalCosetInterpolation`.
//! Any drift between the Rust gate's expected `(domain, weights)` and the
//! Solidity constants is a soundness break. The dumper MUST be the single
//! source of truth — never hand-edit the generated `.sol` file.

use plonky2::field::interpolation::barycentric_weights;
use plonky2::field::types::{Field, PrimeField64};
use plonky2_field::goldilocks_field::GoldilocksField as F;

/// `subgroup_bits` values we generate constants for. Higher values are
/// rejected by the Solidity gate at runtime — extend this array to
/// support more, then regenerate `CosetInterpolationConstants.sol`.
///
/// Why the cap is 5 by default:
///   `CosetInterpolationGate::num_wires() = 2·N + 4·num_intermediates + 9`
///   where `N = 2^subgroup_bits`. The standard recursion config caps
///   `num_wires` at 135, so:
///     bits=5 → 89 wires  ✓ fits standard_recursion_config
///     bits=6 → 169 wires ✗ requires a wider config (uncommon)
///     bits=7 → 337 wires ✗
///   We support up to 5 to cover every recursive setup that uses the
///   default `standard_recursion_config`. Extending to 6+ requires
///   downstream consumers to use a wider config (or to add an explicit
///   `num_wires` argument upstream); regenerating is mechanical.
const SUPPORTED_BITS: &[usize] = &[1, 2, 3, 4, 5];

fn pack(values: &[F]) -> String {
    let mut s = String::new();
    for v in values {
        // SECURITY: emit the *canonical* representative (`to_canonical_u64`)
        // — never `.0`. `GoldilocksField` stores values in non-canonical
        // form up to `2 * ORDER - 1`; the Solidity verifier compares
        // against `< ORDER`. A non-canonical dump would silently produce
        // weights that disagree with `barycentric_weights` after mod p
        // and break the bit-exact constraint match.
        s.push_str(&format!("{:016x}", v.to_canonical_u64()));
    }
    s
}

#[test]
fn dump_constants() {
    println!("// SPDX-License-Identifier: MIT OR Apache-2.0");
    println!("pragma solidity ^0.8.25;");
    println!();
    println!("/// @title CosetInterpolationConstants — Plonky2 Goldilocks two-adic");
    println!("///         subgroups + barycentric weights for `CosetInterpolationGate`.");
    println!("/// @notice Each entry is u64 (8 bytes, big-endian) packed into a single");
    println!("///         `bytes` constant; read via `readU64` (same helper as");
    println!("///         `PoseidonConstants.sol`).");
    println!("///");
    println!("/// Source: auto-extracted from `plonky2_field::goldilocks_field`. DO NOT");
    println!("/// EDIT MANUALLY — regenerate via");
    println!("///   cargo test --release --test dump_coset_constants \\");
    println!("///       --features std -- --nocapture > \\");
    println!("///       mle/contracts/src/CosetInterpolationConstants.sol");
    println!("library CosetInterpolationConstants {{");

    for &bits in SUPPORTED_BITS {
        // Two-adic subgroup: [g^0, g^1, ..., g^(N-1)] where g is the primitive
        // 2^bits-th root of unity in Goldilocks. Matches `F::two_adic_subgroup`.
        let domain = F::two_adic_subgroup(bits);
        // Barycentric weights for Lagrange interpolation over `domain`.
        // The plonky2 gate uses `(x, F::ZERO)` placeholder pairs because
        // `barycentric_weights` operates on `(x, y)` pairs but only `x` is
        // needed for the weights. We replicate that exactly.
        let weights: Vec<F> = barycentric_weights(
            &domain
                .iter()
                .map(|&x| (x, F::ZERO))
                .collect::<Vec<_>>(),
        );
        assert_eq!(domain.len(), 1 << bits, "subgroup length mismatch");
        assert_eq!(weights.len(), 1 << bits, "weights length mismatch");

        println!();
        println!("    /// Two-adic subgroup of size 2^{bits} (= {}).", 1 << bits);
        println!(
            "    bytes internal constant SUBGROUP_{bits} = hex\"{}\";",
            pack(&domain)
        );
        println!();
        println!("    /// Barycentric weights for SUBGROUP_{bits}.");
        println!(
            "    bytes internal constant WEIGHTS_{bits} = hex\"{}\";",
            pack(&weights)
        );
    }

    println!();
    println!("    /// Read the `i`-th u64 from a packed `bytes` blob (8 bytes / entry).");
    println!("    /// Mirrors `PoseidonConstants.readU64`.");
    println!("    function readU64(bytes memory blob, uint256 i) internal pure returns (uint256 v) {{");
    println!("        // Defense-in-depth (audit L2): bound-check `i` against the");
    println!("        // packed-blob length so a buggy caller cannot silently read");
    println!("        // past the constants table (which `mload` would otherwise pad");
    println!("        // with zero).");
    println!("        require(i * 8 + 8 <= blob.length, \"CosetInterpolation: index OOB\");");
    println!("        assembly {{");
    println!("            let ptr := add(add(blob, 0x20), mul(i, 8))");
    println!("            v := shr(192, mload(ptr))");
    println!("        }}");
    println!("    }}");
    println!();
    println!("    /// Return the `i`-th element of the two-adic subgroup of size 2^bits.");
    println!("    /// Reverts if `bits` is outside the supported set or `i >= 2^bits`.");
    println!("    function subgroupElement(uint256 bits, uint256 i) internal pure returns (uint256) {{");
    for &bits in SUPPORTED_BITS {
        println!("        if (bits == {bits}) return readU64(SUBGROUP_{bits}, i);");
    }
    println!("        revert(\"CosetInterpolation: subgroup_bits not supported\");");
    println!("    }}");
    println!();
    println!("    /// Return the `i`-th barycentric weight for the two-adic subgroup of size 2^bits.");
    println!("    function weight(uint256 bits, uint256 i) internal pure returns (uint256) {{");
    for &bits in SUPPORTED_BITS {
        println!("        if (bits == {bits}) return readU64(WEIGHTS_{bits}, i);");
    }
    println!("        revert(\"CosetInterpolation: subgroup_bits not supported\");");
    println!("    }}");
    println!("}}");
}
