/// E2E transcript trace test.
///
/// Runs the FULL MLE prover flow for a real circuit, recording the transcript
/// state at every major checkpoint. Outputs hex-encoded state bytes and
/// challenges at each step for comparison with the Solidity verifier.
///
/// This test catches divergences that simple test vectors miss, because it
/// exercises the actual proof generation flow with real field values.
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use plonky2::plonk::prover::extract_evaluation_tables;
use plonky2::util::timing::TimingTree;
use plonky2_field::goldilocks_field::GoldilocksField;
use plonky2_field::types::{Field, PrimeField64};
use plonky2_mle::commitment::merkle_pcs::MerklePCS;
use plonky2_mle::commitment::traits::MultilinearPCS;
use plonky2_mle::constraint_eval::{compute_combined_constraints, flatten_extension_constraints};
use plonky2_mle::dense_mle::{row_major_to_mles, tables_to_mles, DenseMultilinearExtension};
use plonky2_mle::eq_poly;
use plonky2_mle::sumcheck::prover::{compute_claimed_sum, prove_sumcheck_product};
use plonky2_mle::transcript::Transcript;

type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;
const D: usize = 2;

fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Print a transcript checkpoint for Solidity comparison.
fn checkpoint(label: &str, transcript: &Transcript) {
    let state = transcript.state_bytes();
    let counter = transcript.current_squeeze_counter();
    let hash = transcript.peek_next_hash();
    println!("  CHECKPOINT [{label}]:");
    println!("    state_len: {}", state.len());
    println!(
        "    state_tail_32: {}",
        hex(&state[state.len().saturating_sub(32)..])
    );
    println!("    squeeze_counter: {counter}");
    println!("    next_hash: {}", hex(&hash));
}

#[test]
fn test_e2e_transcript_trace() {
    println!("\n============================================================");
    println!("  E2E TRANSCRIPT TRACE (for Solidity interop debugging)");
    println!("============================================================\n");

    // ── Build circuit: x * y = z ──
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
    let tables = extract_evaluation_tables::<F, C, D>(
        &circuit.prover_only,
        &circuit.common,
        pw,
        &mut timing,
    )
    .unwrap();

    let degree = tables.degree;
    let degree_bits = tables.degree_bits;
    let num_routed_wires = tables.num_routed_wires;

    println!("Circuit: degree={degree}, degree_bits={degree_bits}, num_wires={}, num_routed_wires={num_routed_wires}, num_constants={}", tables.num_wires, circuit.common.num_constants);
    println!(
        "Public inputs: {:?}",
        tables
            .public_inputs
            .iter()
            .map(|f| f.to_canonical_u64())
            .collect::<Vec<_>>()
    );
    println!();

    // ── Replay the prover's transcript step by step ──
    let mut transcript = Transcript::new();
    checkpoint("after_init", &transcript);

    // Step 1: circuit + public inputs
    transcript.domain_separate("circuit");
    transcript.absorb_field_vec(&tables.public_inputs);
    checkpoint("after_public_inputs", &transcript);

    // Step 2: batch-commit
    transcript.domain_separate("batch-commit");
    let batch_r: F = transcript.squeeze_challenge();
    println!("  batch_r = {}", batch_r.to_canonical_u64());
    checkpoint("after_batch_r", &transcript);

    // Build MLEs and commit
    let wire_mles = tables_to_mles(&tables.wire_values);
    let const_mles = row_major_to_mles(&tables.constant_values, circuit.common.num_constants);
    let sigma_mles = row_major_to_mles(&tables.sigma_values, num_routed_wires);

    let mut all_mles: Vec<&DenseMultilinearExtension<F>> = Vec::new();
    for m in &wire_mles {
        all_mles.push(m);
    }
    for m in &const_mles {
        all_mles.push(m);
    }
    for m in &sigma_mles {
        all_mles.push(m);
    }
    let num_polys = all_mles.len();

    let mut batched_evals = vec![F::ZERO; 1 << degree_bits];
    let mut r_pow = F::ONE;
    for mle in &all_mles {
        for (j, &eval) in mle.evaluations.iter().enumerate() {
            if j < batched_evals.len() {
                batched_evals[j] = batched_evals[j] + r_pow * eval;
            }
        }
        r_pow = r_pow * batch_r;
    }
    let batched_mle = DenseMultilinearExtension::new(batched_evals);

    let pcs = MerklePCS::new(16);
    let (commitment, _commit_state) = pcs.commit(&batched_mle);
    println!("  commitment_root = {}", hex(&commitment.root));

    transcript.absorb_bytes(&commitment.root);
    checkpoint("after_commitment", &transcript);

    // Step 3: challenges
    transcript.domain_separate("challenges");
    let beta: F = transcript.squeeze_challenge();
    let gamma: F = transcript.squeeze_challenge();
    let alpha: F = transcript.squeeze_challenge();
    let tau: Vec<F> = transcript.squeeze_challenges(degree_bits);
    let tau_perm: Vec<F> = transcript.squeeze_challenges(degree_bits);

    println!("  beta  = {}", beta.to_canonical_u64());
    println!("  gamma = {}", gamma.to_canonical_u64());
    println!("  alpha = {}", alpha.to_canonical_u64());
    println!(
        "  tau   = {:?}",
        tau.iter().map(|f| f.to_canonical_u64()).collect::<Vec<_>>()
    );
    println!(
        "  tau_perm = {:?}",
        tau_perm
            .iter()
            .map(|f| f.to_canonical_u64())
            .collect::<Vec<_>>()
    );
    checkpoint("after_challenges", &transcript);

    // Step 4: Permutation check
    transcript.domain_separate("permutation");
    checkpoint("before_perm_sumcheck", &transcript);

    let (perm_sumcheck, perm_challenges, perm_claimed_sum) =
        plonky2_mle::permutation::logup::prove_permutation_check(
            &tables.wire_values,
            &tables.sigma_values,
            &tables.k_is,
            &tables.subgroup,
            num_routed_wires,
            degree,
            beta,
            gamma,
            &tau_perm,
            &mut transcript,
        );

    println!(
        "  perm_claimed_sum = {}",
        perm_claimed_sum.to_canonical_u64()
    );
    println!("  perm_rounds = {}", perm_sumcheck.round_polys.len());
    for (i, rp) in perm_sumcheck.round_polys.iter().enumerate() {
        if i < 3 || i == perm_sumcheck.round_polys.len() - 1 {
            println!(
                "  perm_round[{i}] evals = {:?}",
                rp.evaluations
                    .iter()
                    .map(|f| f.to_canonical_u64())
                    .collect::<Vec<_>>()
            );
        }
    }
    println!(
        "  perm_challenges[0..3] = {:?}",
        perm_challenges
            .iter()
            .take(3)
            .map(|f| f.to_canonical_u64())
            .collect::<Vec<_>>()
    );
    checkpoint("after_perm_sumcheck", &transcript);

    // Compute perm final eval
    let perm_h = plonky2_mle::permutation::logup::compute_permutation_numerator(
        &tables.wire_values,
        &tables.sigma_values,
        &plonky2_mle::permutation::logup::compute_identity_values(
            &tables.k_is,
            &tables.subgroup,
            num_routed_wires,
            degree,
        ),
        beta,
        gamma,
        num_routed_wires,
        degree,
    );
    let mut perm_h_padded = perm_h;
    perm_h_padded.resize(1 << degree_bits, F::ZERO);
    let perm_h_mle = DenseMultilinearExtension::new(perm_h_padded);
    let pcs_perm_eval = perm_h_mle.evaluate(&perm_challenges);
    println!(
        "  pcs_perm_numerator_eval = {}",
        pcs_perm_eval.to_canonical_u64()
    );

    // Verify: perm final eval from sumcheck should match
    let perm_final_from_sumcheck = perm_sumcheck
        .round_polys
        .last()
        .unwrap()
        .evaluate(*perm_challenges.last().unwrap());
    println!(
        "  perm_final_from_sumcheck = {}",
        perm_final_from_sumcheck.to_canonical_u64()
    );
    assert_eq!(
        perm_final_from_sumcheck, pcs_perm_eval,
        "Perm final eval mismatch between sumcheck output and MLE evaluation!"
    );

    // Step 5: Extension combine
    let has_lookup = !circuit.common.luts.is_empty();
    if has_lookup {
        transcript.domain_separate("lookup");
        let _: F = transcript.squeeze_challenge();
        let _: F = transcript.squeeze_challenge();
    }

    let combined_ext = compute_combined_constraints::<F, D>(
        &circuit.common,
        &tables.wire_values,
        &tables.constant_values,
        &[alpha],
        &tables.public_inputs_hash,
        degree,
    );

    transcript.domain_separate("extension-combine");
    let ext_challenge: F = transcript.squeeze_challenge();
    println!("  ext_challenge = {}", ext_challenge.to_canonical_u64());
    checkpoint("after_ext_combine", &transcript);

    let combined_constraints = flatten_extension_constraints::<F, D>(&combined_ext, ext_challenge);
    let mut padded_constraints = combined_constraints;
    padded_constraints.resize(1 << degree_bits, F::ZERO);

    // Step 6: Zero-check sumcheck
    transcript.domain_separate("zero-check");
    let eq_table = eq_poly::eq_evals(&tau);
    let claimed_sum = compute_claimed_sum(&eq_table, &padded_constraints);
    println!(
        "  constraint_claimed_sum = {}",
        claimed_sum.to_canonical_u64()
    );

    let mut eq_mle = DenseMultilinearExtension::new(eq_table);
    let mut constraint_mle = DenseMultilinearExtension::new(padded_constraints.clone());

    checkpoint("before_constraint_sumcheck", &transcript);

    let (constraint_proof, sumcheck_challenges) =
        prove_sumcheck_product(&mut eq_mle, &mut constraint_mle, 2, &mut transcript);

    println!(
        "  constraint_rounds = {}",
        constraint_proof.round_polys.len()
    );
    for (i, rp) in constraint_proof.round_polys.iter().enumerate() {
        if i < 3 || i == constraint_proof.round_polys.len() - 1 {
            println!(
                "  constraint_round[{i}] evals = {:?}",
                rp.evaluations
                    .iter()
                    .map(|f| f.to_canonical_u64())
                    .collect::<Vec<_>>()
            );
        }
    }
    println!(
        "  sumcheck_challenges[0..3] = {:?}",
        sumcheck_challenges
            .iter()
            .take(3)
            .map(|f| f.to_canonical_u64())
            .collect::<Vec<_>>()
    );

    // Compute oracle values
    let constraint_mle_for_eval = DenseMultilinearExtension::new(
        flatten_extension_constraints::<F, D>(&combined_ext, ext_challenge)
            .into_iter()
            .chain(std::iter::repeat(F::ZERO))
            .take(1 << degree_bits)
            .collect(),
    );
    let pcs_constraint_eval = constraint_mle_for_eval.evaluate(&sumcheck_challenges);
    println!(
        "  pcs_constraint_eval = {}",
        pcs_constraint_eval.to_canonical_u64()
    );

    // Verify final eval
    let eq_at_r = eq_poly::eq_eval(&tau, &sumcheck_challenges);
    let expected_final = eq_at_r * pcs_constraint_eval;
    let actual_final = constraint_proof
        .round_polys
        .last()
        .unwrap()
        .evaluate(*sumcheck_challenges.last().unwrap());
    println!("  eq_at_r = {}", eq_at_r.to_canonical_u64());
    println!(
        "  expected_final (eq*C) = {}",
        expected_final.to_canonical_u64()
    );
    println!(
        "  actual_final (sumcheck) = {}",
        actual_final.to_canonical_u64()
    );
    assert_eq!(
        expected_final, actual_final,
        "Constraint final eval mismatch!"
    );

    checkpoint("after_constraint_sumcheck", &transcript);

    println!("\n  num_polys = {num_polys}");
    println!("  has_lookup = {has_lookup}");
    println!("\n  === PROOF SUMMARY ===");
    println!("  commitment_root: {}", hex(&commitment.root));
    println!(
        "  perm_claimed_sum: {}",
        perm_claimed_sum.to_canonical_u64()
    );
    println!(
        "  pcs_perm_numerator_eval: {}",
        pcs_perm_eval.to_canonical_u64()
    );
    println!(
        "  pcs_constraint_eval: {}",
        pcs_constraint_eval.to_canonical_u64()
    );
    println!("  batch_r: {}", batch_r.to_canonical_u64());
    println!("  alpha: {}", alpha.to_canonical_u64());
    println!("  beta: {}", beta.to_canonical_u64());
    println!("  gamma: {}", gamma.to_canonical_u64());

    println!("\n  === ALL CHECKS PASSED ===\n");
}
