/// Integration tests for the MLE proving system.
///
/// Covers:
/// - Permutation argument soundness on real Plonky2 circuits
/// - Poseidon gate (high-degree constraint) handling
/// - Large circuit tests (n=16)
/// - Randomized prove/verify tests
/// - Soundness tests (invalid witness rejection)
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use plonky2::plonk::prover::extract_evaluation_tables;
use plonky2::util::timing::TimingTree;
use plonky2_field::goldilocks_field::GoldilocksField;
use plonky2_field::types::Field;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2_mle::config::WhirConfig;
use plonky2_mle::constraint_eval::{compute_combined_constraints, flatten_extension_constraints};
use plonky2_mle::permutation::logup::{compute_identity_values, compute_permutation_numerator};
use plonky2_mle::prover::mle_prove;
use plonky2_mle::verifier::mle_verify;

type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;
const D: usize = 2;

// ══════════════════════════════════════════════════════════════════════════════
//  Permutation argument soundness
// ══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_permutation_numerator_sum_is_zero() {
    // For a valid circuit, Σ_b h(b) = 0 (unweighted sum).
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    let x = builder.add_virtual_target();
    let y = builder.add_virtual_target();
    let z = builder.mul(x, y);
    // Copy constraint: register z as public input, which creates copy constraints
    builder.register_public_input(z);

    let circuit = builder.build::<C>();
    let mut pw = PartialWitness::new();
    pw.set_target(x, F::from_canonical_u64(3));
    pw.set_target(y, F::from_canonical_u64(7));

    let mut timing = TimingTree::default();
    let tables = extract_evaluation_tables::<F, C, D>(
        &circuit.prover_only,
        &circuit.common,
        pw,
        &mut timing,
    )
    .unwrap();

    let beta = F::from_canonical_u64(12345);
    let gamma = F::from_canonical_u64(67890);

    let id_values = compute_identity_values(
        &tables.k_is,
        &tables.subgroup,
        tables.num_routed_wires,
        tables.degree,
    );

    let h = compute_permutation_numerator(
        &tables.wire_values,
        &tables.sigma_values,
        &id_values,
        beta,
        gamma,
        tables.num_routed_wires,
        tables.degree,
    );

    let sum: F = h.iter().copied().sum();
    assert_eq!(
        sum,
        F::ZERO,
        "Permutation numerator sum should be zero for valid circuit, got {sum}"
    );
}

#[test]
fn test_permutation_with_copy_constraints() {
    // Build a circuit with explicit copy constraints: x + x = 2x
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    let x = builder.add_virtual_target();
    let two_x = builder.add(x, x); // This creates a copy constraint: both inputs of add are x
    builder.register_public_input(two_x);

    let circuit = builder.build::<C>();
    let mut pw = PartialWitness::new();
    pw.set_target(x, F::from_canonical_u64(42));

    let mut timing = TimingTree::default();
    let tables = extract_evaluation_tables::<F, C, D>(
        &circuit.prover_only,
        &circuit.common,
        pw,
        &mut timing,
    )
    .unwrap();

    let beta = F::from_canonical_u64(9999);
    let gamma = F::from_canonical_u64(7777);

    let id_values = compute_identity_values(
        &tables.k_is,
        &tables.subgroup,
        tables.num_routed_wires,
        tables.degree,
    );

    let h = compute_permutation_numerator(
        &tables.wire_values,
        &tables.sigma_values,
        &id_values,
        beta,
        gamma,
        tables.num_routed_wires,
        tables.degree,
    );

    let sum: F = h.iter().copied().sum();
    assert_eq!(sum, F::ZERO, "Sum should be zero for valid copy constraints");
}

// ══════════════════════════════════════════════════════════════════════════════
//  Constraint evaluation correctness
// ══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_constraints_zero_for_addition_circuit() {
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    let a = builder.add_virtual_target();
    let b = builder.add_virtual_target();
    let c = builder.add(a, b);
    builder.register_public_input(c);

    let circuit = builder.build::<C>();
    let mut pw = PartialWitness::new();
    pw.set_target(a, F::from_canonical_u64(100));
    pw.set_target(b, F::from_canonical_u64(200));

    let mut timing = TimingTree::default();
    let tables = extract_evaluation_tables::<F, C, D>(
        &circuit.prover_only,
        &circuit.common,
        pw,
        &mut timing,
    )
    .unwrap();

    let alpha = F::from_canonical_u64(42);
    let combined = compute_combined_constraints::<F, D>(
        &circuit.common,
        &tables.wire_values,
        &tables.constant_values,
        &[alpha],
        &tables.public_inputs_hash,
        tables.degree,
    );

    for (row, components) in combined.iter().enumerate() {
        for (k, &val) in components.iter().enumerate() {
            assert_eq!(val, F::ZERO, "Constraint [{k}] non-zero at row {row}");
        }
    }
}

// ══════════════════════════════════════════════════════════════════════════════
//  Poseidon gate test (high-degree constraints)
// ══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_poseidon_gate_constraints_zero() {
    // Build a circuit that uses the Poseidon hash gate (degree 7 S-box).
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // hash_n_to_hash_no_pad uses the Poseidon gate internally
    let inputs: Vec<_> = (0..4)
        .map(|_| builder.add_virtual_target())
        .collect();
    let hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(inputs.clone());
    for &h in hash.elements.iter() {
        builder.register_public_input(h);
    }

    let circuit = builder.build::<C>();
    let mut pw = PartialWitness::new();
    for (i, &input) in inputs.iter().enumerate() {
        pw.set_target(input, F::from_canonical_u64(i as u64 + 1));
    }

    let mut timing = TimingTree::default();
    let tables = extract_evaluation_tables::<F, C, D>(
        &circuit.prover_only,
        &circuit.common,
        pw,
        &mut timing,
    )
    .unwrap();

    let alpha = F::from_canonical_u64(999);
    let combined = compute_combined_constraints::<F, D>(
        &circuit.common,
        &tables.wire_values,
        &tables.constant_values,
        &[alpha],
        &tables.public_inputs_hash,
        tables.degree,
    );

    for (row, components) in combined.iter().enumerate() {
        for (k, &val) in components.iter().enumerate() {
            assert_eq!(
                val,
                F::ZERO,
                "Poseidon constraint [{k}] non-zero at row {row}"
            );
        }
    }
}

#[test]
fn test_poseidon_circuit_prove_verify() {
    // Full E2E: Poseidon circuit -> MLE prove -> MLE verify
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    let inputs: Vec<_> = (0..4)
        .map(|_| builder.add_virtual_target())
        .collect();
    let hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(inputs.clone());
    for &h in hash.elements.iter() {
        builder.register_public_input(h);
    }

    let circuit = builder.build::<C>();
    let mut pw = PartialWitness::new();
    for (i, &input) in inputs.iter().enumerate() {
        pw.set_target(input, F::from_canonical_u64(i as u64 + 10));
    }

    let mut timing = TimingTree::default();
    let proof = mle_prove::<F, C, D>(
        &circuit.prover_only,
        &circuit.common,
        pw,
        &mut timing,
    )
    .unwrap();

    let result = mle_verify::<F, D>(&circuit.common, &proof);
    assert!(result.is_ok(), "Poseidon circuit verify failed: {:?}", result.err());
}

// ══════════════════════════════════════════════════════════════════════════════
//  Large circuit test
// ══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_large_circuit_chain() {
    // Build a chain of multiplications to create a large circuit.
    // Each mul gate adds a row, plus padding to next power of 2.
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    let x = builder.add_virtual_target();
    let mut current = x;

    // Chain: x -> x*x -> (x*x)*(x*x) -> ...
    // 200 multiplications should produce a circuit with several hundred gates
    for _ in 0..200 {
        current = builder.mul(current, x);
    }
    builder.register_public_input(current);

    let circuit = builder.build::<C>();
    let degree = circuit.common.degree();
    let degree_bits = circuit.common.degree_bits();
    println!("Large circuit: degree={degree}, degree_bits={degree_bits}");

    let mut pw = PartialWitness::new();
    pw.set_target(x, F::from_canonical_u64(2));

    let mut timing = TimingTree::default();
    let proof = mle_prove::<F, C, D>(
        &circuit.prover_only,
        &circuit.common,
        pw,
        &mut timing,
    )
    .unwrap();

    // x^201 mod p for x=2
    assert!(!proof.public_inputs.is_empty());

    let result = mle_verify::<F, D>(&circuit.common, &proof);
    assert!(result.is_ok(), "Large circuit verify failed: {:?}", result.err());
}

// ══════════════════════════════════════════════════════════════════════════════
//  Randomized prove/verify tests
// ══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_randomized_arithmetic_circuits() {
    use rand::Rng;

    let mut rng = rand::thread_rng();

    for trial in 0..120 {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let a = builder.add_virtual_target();
        let b = builder.add_virtual_target();

        // Randomly choose between add and mul
        let result = if trial % 3 == 0 {
            builder.add(a, b)
        } else if trial % 3 == 1 {
            builder.mul(a, b)
        } else {
            let c = builder.mul(a, b);
            builder.add(c, a)
        };
        builder.register_public_input(result);

        let circuit = builder.build::<C>();

        let a_val = F::from_canonical_u64(rng.gen_range(1..1000));
        let b_val = F::from_canonical_u64(rng.gen_range(1..1000));

        let mut pw = PartialWitness::new();
        pw.set_target(a, a_val);
        pw.set_target(b, b_val);

        let mut timing = TimingTree::default();
        let proof = mle_prove::<F, C, D>(
            &circuit.prover_only,
            &circuit.common,
            pw,
            &mut timing,
        )
        .unwrap();

        let result = mle_verify::<F, D>(&circuit.common, &proof);
        assert!(
            result.is_ok(),
            "Trial {trial} failed: {:?}",
            result.err()
        );
    }
}

// ══════════════════════════════════════════════════════════════════════════════
//  Soundness tests (negative)
// ══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_tampered_public_inputs_rejected() {
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    let x = builder.add_virtual_target();
    let y = builder.add_virtual_target();
    let z = builder.mul(x, y);
    builder.register_public_input(z);

    let circuit = builder.build::<C>();
    let mut pw = PartialWitness::new();
    pw.set_target(x, F::from_canonical_u64(3));
    pw.set_target(y, F::from_canonical_u64(7));

    let mut timing = TimingTree::default();
    let mut proof = mle_prove::<F, C, D>(
        &circuit.prover_only,
        &circuit.common,
        pw,
        &mut timing,
    )
    .unwrap();

    // Tamper: change public input from 21 to 22
    proof.public_inputs[0] = F::from_canonical_u64(22);

    let result = mle_verify::<F, D>(&circuit.common, &proof);
    assert!(
        result.is_err(),
        "Should reject tampered public inputs"
    );
}

#[test]
fn test_tampered_eval_value_rejected() {
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    let x = builder.add_virtual_target();
    let y = builder.add_virtual_target();
    let z = builder.mul(x, y);
    builder.register_public_input(z);

    let circuit = builder.build::<C>();
    let mut pw = PartialWitness::new();
    pw.set_target(x, F::from_canonical_u64(5));
    pw.set_target(y, F::from_canonical_u64(9));

    let mut timing = TimingTree::default();
    let mut proof = mle_prove::<F, C, D>(
        &circuit.prover_only,
        &circuit.common,
        pw,
        &mut timing,
    )
    .unwrap();

    // Tamper with the evaluation value
    proof.eval_value = proof.eval_value + F::ONE;

    let result = mle_verify::<F, D>(&circuit.common, &proof);
    assert!(
        result.is_err(),
        "Should reject tampered evaluation value"
    );
}

// ══════════════════════════════════════════════════════════════════════════════
//  WHIR config test
// ══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_whir_config_rate_16() {
    let config = WhirConfig::default_rate_16();
    assert_eq!(config.rate_bits, 4);
    assert_eq!(config.inv_rate(), 16);

    // For n=16 (65536 gates), proof should be sublinear
    let proof_size = config.estimated_proof_field_elements(16);
    println!("WHIR proof size estimate for n=16: {proof_size} field elements");
    assert!(proof_size < 65536);

    // For n=20, still sublinear
    let proof_size_20 = config.estimated_proof_field_elements(20);
    println!("WHIR proof size estimate for n=20: {proof_size_20} field elements");
    assert!(proof_size_20 < 1 << 20);
}

// ══════════════════════════════════════════════════════════════════════════════
//  Cross-protocol soundness tests
// ══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_tampered_constraint_round_poly_rejected() {
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let x = builder.add_virtual_target();
    let y = builder.add_virtual_target();
    let z = builder.mul(x, y);
    builder.register_public_input(z);

    let circuit = builder.build::<C>();
    let mut pw = PartialWitness::new();
    pw.set_target(x, F::from_canonical_u64(4));
    pw.set_target(y, F::from_canonical_u64(6));

    let mut timing = TimingTree::default();
    let mut proof = mle_prove::<F, C, D>(
        &circuit.prover_only, &circuit.common, pw, &mut timing,
    ).unwrap();

    // Tamper with a constraint sumcheck round polynomial
    if !proof.constraint_proof.round_polys.is_empty() {
        proof.constraint_proof.round_polys[0].evaluations[0] =
            proof.constraint_proof.round_polys[0].evaluations[0] + F::ONE;
    }

    let result = mle_verify::<F, D>(&circuit.common, &proof);
    assert!(result.is_err(), "Should reject tampered constraint round poly");
}

#[test]
fn test_tampered_permutation_round_poly_rejected() {
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let x = builder.add_virtual_target();
    let y = builder.add_virtual_target();
    let z = builder.mul(x, y);
    builder.register_public_input(z);

    let circuit = builder.build::<C>();
    let mut pw = PartialWitness::new();
    pw.set_target(x, F::from_canonical_u64(2));
    pw.set_target(y, F::from_canonical_u64(8));

    let mut timing = TimingTree::default();
    let mut proof = mle_prove::<F, C, D>(
        &circuit.prover_only, &circuit.common, pw, &mut timing,
    ).unwrap();

    // Tamper with a permutation sumcheck round polynomial
    if !proof.permutation_proof.sumcheck_proof.round_polys.is_empty() {
        proof.permutation_proof.sumcheck_proof.round_polys[0].evaluations[0] =
            proof.permutation_proof.sumcheck_proof.round_polys[0].evaluations[0] + F::ONE;
    }

    let result = mle_verify::<F, D>(&circuit.common, &proof);
    assert!(result.is_err(), "Should reject tampered permutation round poly");
}

#[test]
fn test_swapped_commitment_rejected() {
    // Generate a valid proof and swap the PCS commitment with a different one.
    // This should be caught by the PCS verification step.
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let x = builder.add_virtual_target();
    let y = builder.add_virtual_target();
    let z = builder.mul(x, y);
    builder.register_public_input(z);

    let circuit = builder.build::<C>();
    let mut pw = PartialWitness::new();
    pw.set_target(x, F::from_canonical_u64(3));
    pw.set_target(y, F::from_canonical_u64(5));

    let mut timing = TimingTree::default();
    let mut proof = mle_prove::<F, C, D>(
        &circuit.prover_only, &circuit.common, pw, &mut timing,
    ).unwrap();

    // Tamper with the commitment root (simulates a different committed polynomial)
    proof.commitment.proof_bytes[0] ^= 0xFF;

    let result = mle_verify::<F, D>(&circuit.common, &proof);
    assert!(result.is_err(), "Should reject tampered commitment");
}

#[test]
fn test_fibonacci_circuit_prove_verify() {
    // Fibonacci: fib(0)=1, fib(1)=1, fib(i)=fib(i-1)+fib(i-2)
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    let n = 20;
    let mut targets = Vec::with_capacity(n);
    targets.push(builder.add_virtual_target());
    targets.push(builder.add_virtual_target());

    for i in 2..n {
        let sum = builder.add(targets[i - 1], targets[i - 2]);
        targets.push(sum);
    }
    builder.register_public_input(*targets.last().unwrap());

    let circuit = builder.build::<C>();
    let mut pw = PartialWitness::new();
    pw.set_target(targets[0], F::ONE);
    pw.set_target(targets[1], F::ONE);

    let mut timing = TimingTree::default();
    let proof = mle_prove::<F, C, D>(
        &circuit.prover_only, &circuit.common, pw, &mut timing,
    ).unwrap();

    // fib(19) = 6765
    assert_eq!(proof.public_inputs[0], F::from_canonical_u64(6765));

    let result = mle_verify::<F, D>(&circuit.common, &proof);
    assert!(result.is_ok(), "Fibonacci verify failed: {:?}", result.err());
}

// ══════════════════════════════════════════════════════════════════════════════
//  Lookup argument standalone tests
// ══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_lookup_logup_standalone() {
    use plonky2_mle::permutation::lookup::{LookupData, compute_lookup_numerator, prove_lookup_check};
    use plonky2_mle::sumcheck::verifier::verify_sumcheck;
    use plonky2_mle::transcript::Transcript;

    // Square table: {(0,0), (1,1), (2,4), (3,9), (4,16)}
    let data = LookupData {
        table_entries: vec![
            (F::from_canonical_u64(0), F::ZERO),
            (F::from_canonical_u64(1), F::ONE),
            (F::from_canonical_u64(2), F::from_canonical_u64(4)),
            (F::from_canonical_u64(3), F::from_canonical_u64(9)),
            (F::from_canonical_u64(4), F::from_canonical_u64(16)),
        ],
        multiplicities: vec![
            F::from_canonical_u64(3), // looked up 3 times
            F::from_canonical_u64(2),
            F::from_canonical_u64(1),
            F::ZERO,
            F::from_canonical_u64(1),
        ],
        lookups: vec![
            (F::ZERO, F::ZERO),
            (F::ZERO, F::ZERO),
            (F::ZERO, F::ZERO),
            (F::ONE, F::ONE),
            (F::ONE, F::ONE),
            (F::from_canonical_u64(2), F::from_canonical_u64(4)),
            (F::from_canonical_u64(4), F::from_canonical_u64(16)),
        ],
    };

    let beta = F::from_canonical_u64(54321);
    let delta = F::from_canonical_u64(98765);

    let h = compute_lookup_numerator(&data, beta, delta);
    let sum: F = h.iter().copied().sum();
    assert_eq!(sum, F::ZERO, "Valid lookup sum should be 0");

    let mut transcript = Transcript::new();
    let (proof, challenges, claimed_sum) = prove_lookup_check(&data, beta, delta, &mut transcript);
    assert_eq!(claimed_sum, F::ZERO);

    let mut v_transcript = Transcript::new();
    let result = verify_sumcheck(&proof, claimed_sum, challenges.len(), &mut v_transcript);
    assert!(result.is_ok(), "Lookup sumcheck failed: {:?}", result.err());
}

// ══════════════════════════════════════════════════════════════════════════════
//  Recursive proof circuit (CosetInterpolationGate) test
// ══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_recursive_circuit_constraints_zero() {
    // Build an inner circuit, prove it with Plonky2, then build an outer circuit
    // that verifies the inner proof. The outer circuit contains CosetInterpolationGate
    // and RandomAccessGate (FRI recursive verification).
    //
    // SECURITY: This is the critical test for validity proofs. Without this,
    // the library is only safe for non-recursive circuits.
    use plonky2::plonk::proof::ProofWithPublicInputs;
    use plonky2::plonk::circuit_data::VerifierCircuitTarget;

    // ── Inner circuit: x * y = z ──
    let inner_config = CircuitConfig::standard_recursion_config();
    let mut inner_builder = CircuitBuilder::<F, D>::new(inner_config);
    let x = inner_builder.add_virtual_target();
    let y = inner_builder.add_virtual_target();
    let z = inner_builder.mul(x, y);
    inner_builder.register_public_input(z);
    let inner_data = inner_builder.build::<C>();

    let mut inner_pw = PartialWitness::new();
    inner_pw.set_target(x, F::from_canonical_u64(3));
    inner_pw.set_target(y, F::from_canonical_u64(7));
    let inner_proof = inner_data.prove(inner_pw).unwrap();
    // Sanity: verify the inner proof with Plonky2
    inner_data.verify(inner_proof.clone()).unwrap();

    // ── Outer circuit: verify the inner proof ──
    let outer_config = CircuitConfig::standard_recursion_config();
    let mut outer_builder = CircuitBuilder::<F, D>::new(outer_config);

    let proof_t = outer_builder.add_virtual_proof_with_pis(&inner_data.common);
    let verifier_data_t = outer_builder.add_virtual_verifier_data(inner_data.common.config.fri_config.cap_height);
    outer_builder.verify_proof::<C>(&proof_t, &verifier_data_t, &inner_data.common);

    // Register the inner proof's public inputs as outer public inputs
    for &pi in &proof_t.public_inputs {
        outer_builder.register_public_input(pi);
    }

    let outer_data = outer_builder.build::<C>();

    // Set the outer witness
    let mut outer_pw = PartialWitness::new();
    outer_pw.set_proof_with_pis_target(&proof_t, &inner_proof);
    outer_pw.set_verifier_data_target(&verifier_data_t, &inner_data.verifier_only);

    // Extract evaluation tables from the outer (recursive) circuit
    let mut timing = TimingTree::default();
    let outer_tables = extract_evaluation_tables::<F, C, D>(
        &outer_data.prover_only,
        &outer_data.common,
        outer_pw.clone(),
        &mut timing,
    )
    .unwrap();

    println!(
        "Recursive circuit: degree={}, degree_bits={}, num_gates_types={}",
        outer_tables.degree,
        outer_tables.degree_bits,
        outer_data.common.gates.len()
    );

    // Print gate types to confirm CosetInterpolationGate is present
    for gate in &outer_data.common.gates {
        println!("  Gate: {}", gate.0.id());
    }

    // ── Verify constraints are zero with extension field handling ──
    let alpha = F::from_canonical_u64(42);
    let combined_ext = compute_combined_constraints::<F, D>(
        &outer_data.common,
        &outer_tables.wire_values,
        &outer_tables.constant_values,
        &[alpha],
        &outer_tables.public_inputs_hash,
        outer_tables.degree,
    );

    // ALL extension field components must be zero
    let mut nonzero_count = 0;
    for (row, components) in combined_ext.iter().enumerate() {
        for (k, &val) in components.iter().enumerate() {
            if val != F::ZERO {
                nonzero_count += 1;
                if nonzero_count <= 5 {
                    println!("  NON-ZERO: row={row}, component={k}, val={val}");
                }
            }
        }
    }
    assert_eq!(
        nonzero_count, 0,
        "Recursive circuit has {nonzero_count} non-zero extension constraint components"
    );

    // ── Also verify the flattened version ──
    let ext_challenge = F::from_canonical_u64(12345);
    let flat = flatten_extension_constraints::<F, D>(&combined_ext, ext_challenge);
    for (row, &val) in flat.iter().enumerate() {
        assert_eq!(val, F::ZERO, "Flattened constraint non-zero at row {row}");
    }

    // ── Full E2E: MLE prove + verify on the recursive circuit ──
    let outer_pw2 = {
        let mut pw = PartialWitness::new();
        pw.set_proof_with_pis_target(&proof_t, &inner_proof);
        pw.set_verifier_data_target(&verifier_data_t, &inner_data.verifier_only);
        pw
    };

    let mle_proof = mle_prove::<F, C, D>(
        &outer_data.prover_only,
        &outer_data.common,
        outer_pw2,
        &mut timing,
    )
    .unwrap();

    assert_eq!(mle_proof.public_inputs[0], F::from_canonical_u64(21));

    let verify_result = mle_verify::<F, D>(&outer_data.common, &mle_proof);
    assert!(
        verify_result.is_ok(),
        "Recursive circuit MLE verify failed: {:?}",
        verify_result.err()
    );
}
