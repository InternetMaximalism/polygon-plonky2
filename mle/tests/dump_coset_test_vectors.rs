//! Dump bit-exact `(wires, expected_constraints)` test vectors for
//! `CosetInterpolationGate::eval_unfiltered_base_one` across the
//! `(subgroup_bits, degree)` combinations supported by the Solidity port.
//!
//! Run with:
//!   cargo test --release --test dump_coset_test_vectors \
//!       --features std -- --nocapture
//!
//! Output is plain Solidity source for inclusion in a Foundry test:
//! one helper per `(bits, degree)` pair that returns `(wires, expected)`.
//!
//! SECURITY: a passing Foundry test against these vectors is the proof
//! that the Solidity port matches the Rust reference. If you change
//! `_evalCosetInterpolation`, the only way to be sure you didn't break
//! the soundness invariant `I1` (tasks/coset_interpolation_port.md §4.1)
//! is to re-dump these vectors and re-run the Foundry test.

use plonky2::gates::coset_interpolation::CosetInterpolationGate;
use plonky2::gates::gate::Gate;
use plonky2::gates::util::StridedConstraintConsumer;
use plonky2::hash::hash_types::HashOut;
use plonky2::plonk::vars::EvaluationVarsBase;
use plonky2::util::strided_view::PackedStridedView;
use plonky2_field::goldilocks_field::GoldilocksField;
use plonky2_field::types::{Field, PrimeField64, Sample};
use rand::rngs::StdRng;
use rand::SeedableRng;

type F = GoldilocksField;
const D: usize = 2;

/// Combinations exercised by the test:
/// `(subgroup_bits, max_degree)` ranges over all reasonable values used
/// by plonky2's recursive FRI verifier. We deliberately include the
/// edge cases `subgroup_bits == 1` (smallest possible) and the
/// `max_degree > subgroup_size` clamp.
const COMBOS: &[(usize, usize)] = &[
    (1, 2),
    (2, 2),
    (2, 3),
    (3, 2),
    (3, 4),
    (4, 4),
    (4, 6),
    // subgroup_bits = 5 (32 points) — exercised by recursive proofs whose
    // inner FRI uses arity_bits=4 across multiple folds, plus by any
    // future caller with `reduction_arity_bits = [5, ...]`. The two
    // representative degrees match plonky2's
    // `max_quotient_degree_factor`: 4 (small circuits) and 8 (typical
    // recursion config).
    (5, 4),
    (5, 8),
];

/// Generate a `(wires, expected_constraints)` test vector for one
/// `(subgroup_bits, max_degree)` configuration with a deterministic seed.
fn one_combo(subgroup_bits: usize, max_degree: usize, seed: u64) -> (Vec<F>, Vec<F>) {
    let gate = <CosetInterpolationGate<F, D>>::with_max_degree(subgroup_bits, max_degree);
    let num_wires = gate.num_wires();
    let mut rng = StdRng::seed_from_u64(seed);
    let wires: Vec<F> = (0..num_wires).map(|_| F::sample(&mut rng)).collect();
    let constants: Vec<F> = Vec::new(); // CosetInterpolationGate has num_constants() == 0
    let zero_hash = HashOut::<F>::ZERO;

    let vars = EvaluationVarsBase {
        local_constants: PackedStridedView::new(&constants[..], 1, 0),
        local_wires: PackedStridedView::new(&wires[..], 1, 0),
        public_inputs_hash: &zero_hash,
    };

    // Reference computation. `eval_unfiltered_base_one` returns Ext elements;
    // each Ext = `[base, base]` flattened to consecutive base-field constraints.
    let mut buf = vec![F::ZERO; gate.num_constraints()];
    {
        let consumer = StridedConstraintConsumer::new(&mut buf[..], 1, 0);
        gate.eval_unfiltered_base_one(vars, consumer);
    }

    (wires, buf)
}

fn fmt_field(x: F) -> String {
    // SECURITY: canonical representative only — see dump_coset_constants.rs
    // for the same rationale.
    format!("0x{:016x}", x.to_canonical_u64())
}

fn dump_solidity(combos: &[(usize, usize)]) {
    println!("// SPDX-License-Identifier: MIT OR Apache-2.0");
    println!("pragma solidity ^0.8.25;");
    println!();
    println!("/// AUTO-GENERATED — do not hand-edit.");
    println!("/// Regenerate via:");
    println!("///   cargo test --release --test dump_coset_test_vectors \\");
    println!("///       --features std -- --nocapture > \\");
    println!("///       mle/contracts/test/CosetInterpolationVectors.sol");
    println!("///");
    println!("/// Each `vector_kK_degD()` returns:");
    println!("///   wires:    the gate's local-wires slice (random Goldilocks elements,");
    println!("///             not necessarily satisfying the constraints — the point is");
    println!("///             bit-exact match between the Rust evaluator and the");
    println!("///             Solidity port, not constraint validity).");
    println!("///   expected: the per-constraint base-field values that");
    println!("///             `CosetInterpolationGate::eval_unfiltered_base_one`");
    println!("///             writes (length = `4 · (num_intermediates + 1)`).");
    println!("library CosetInterpolationVectors {{");

    for &(bits, deg) in combos {
        let (wires, expected) = one_combo(bits, deg, ((bits * 100) + deg) as u64);
        let gate = <CosetInterpolationGate<F, D>>::with_max_degree(bits, deg);
        println!();
        println!(
            "    /// subgroup_bits = {}, max_degree (constructor arg) = {} (effective degree = {})",
            bits,
            deg,
            gate.degree()
        );
        println!(
            "    function vector_k{}_d{}() internal pure returns (uint256[] memory, uint256[] memory) {{",
            bits, deg
        );
        println!(
            "        uint256[] memory wires = new uint256[]({});",
            wires.len()
        );
        for (i, w) in wires.iter().enumerate() {
            println!("        wires[{}] = {};", i, fmt_field(*w));
        }
        println!(
            "        uint256[] memory expected = new uint256[]({});",
            expected.len()
        );
        for (i, e) in expected.iter().enumerate() {
            println!("        expected[{}] = {};", i, fmt_field(*e));
        }
        println!("        return (wires, expected);");
        println!("    }}");
    }
    println!();
    // Effective degree info so the test can pick the right constructor arg.
    println!("    /// (subgroup_bits, effective_degree) for each vector.");
    println!("    function combos() internal pure returns (uint256[2][] memory cs) {{");
    println!("        cs = new uint256[2][]({});", combos.len());
    for (i, &(bits, deg)) in combos.iter().enumerate() {
        let gate = <CosetInterpolationGate<F, D>>::with_max_degree(bits, deg);
        println!(
            "        cs[{}] = [uint256({}), uint256({})];",
            i,
            bits,
            gate.degree()
        );
    }
    println!("    }}");
    println!("}}");
}

#[test]
fn dump() {
    dump_solidity(COMBOS);
}
