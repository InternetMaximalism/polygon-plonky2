/// Integrated MLE prover combining all sub-protocols.
///
/// Architecture: Combined sumcheck (constraint + permutation) with single output
/// point r. Two WHIR proofs:
///   1. Main split-commit: preprocessed + witness polynomials (committed before challenges)
///   2. Auxiliary single-vector: C̃ + h̃ batched (committed after challenges, before sumcheck)
///
/// All evaluations are at the single combined sumcheck output point r.
use anyhow::Result;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::circuit_data::{CommonCircuitData, EvaluationTables, ProverOnlyCircuitData};
use plonky2::plonk::config::{GenericConfig, Hasher};
use plonky2::plonk::prover::extract_evaluation_tables;
use plonky2::util::timing::TimingTree;
use plonky2_field::extension::Extendable;
use plonky2_field::types::Field as PlonkyField;

use crate::commitment::whir_pcs::{plonky2_vec_to_ark, WhirPCS, WHIR_SESSION_SPLIT};
use crate::constraint_eval::{compute_combined_constraints, flatten_extension_constraints};
use crate::dense_mle::{row_major_to_mles, tables_to_mles, DenseMultilinearExtension};
use crate::eq_poly;
use crate::proof::{MleProof, MleVerificationKey};
use crate::sumcheck::prover::prove_sumcheck_combined;
use crate::transcript::Transcript;

/// Derive the deterministic batching scalar for preprocessed polynomials.
///
/// SECURITY: This must produce the same value during setup and proving for the
/// same circuit. It is derived solely from the circuit_digest (verifying key hash)
/// using a dedicated mini-transcript with its own domain separation.
pub fn derive_preprocessed_batch_r<F: RichField>(circuit_digest: &[F]) -> F {
    let mut t = Transcript::new();
    t.domain_separate("preprocessed-batch-r");
    t.absorb_field_vec(circuit_digest);
    t.squeeze_challenge()
}

/// Build the batched preprocessed MLE from constants and sigmas.
fn build_preprocessed_batch<'a, F: RichField>(
    const_mles: &'a [DenseMultilinearExtension<F>],
    sigma_mles: &'a [DenseMultilinearExtension<F>],
    batch_r: F,
    degree_bits: usize,
) -> (
    DenseMultilinearExtension<F>,
    Vec<&'a DenseMultilinearExtension<F>>,
) {
    let mut preprocessed_mles: Vec<&DenseMultilinearExtension<F>> = Vec::new();
    for m in const_mles {
        preprocessed_mles.push(m);
    }
    for m in sigma_mles {
        preprocessed_mles.push(m);
    }

    let mut batched_evals = vec![F::ZERO; 1 << degree_bits];
    let mut r_pow = F::ONE;
    for mle in &preprocessed_mles {
        for (j, &eval) in mle.evaluations.iter().enumerate() {
            if j < batched_evals.len() {
                batched_evals[j] += r_pow * eval;
            }
        }
        r_pow *= batch_r;
    }

    (
        DenseMultilinearExtension::new(batched_evals),
        preprocessed_mles,
    )
}

/// Compute the MLE verification key for a circuit (setup phase).
pub fn mle_setup<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
    prover_data: &ProverOnlyCircuitData<F, C, D>,
    common_data: &CommonCircuitData<F, D>,
) -> MleVerificationKey<F>
where
    C::Hasher: Hasher<F>,
{
    let degree_bits = common_data.degree_bits();
    let num_routed_wires = common_data.config.num_routed_wires;

    let digest_bytes =
        serde_json::to_vec(&prover_data.circuit_digest).expect("circuit_digest serialization");
    let circuit_digest: Vec<F> = {
        let hash_out: plonky2::hash::hash_types::HashOut<F> =
            serde_json::from_slice(&digest_bytes).expect("circuit_digest deserialization");
        hash_out.elements.to_vec()
    };

    let const_mles = row_major_to_mles(&prover_data.constant_evals, common_data.num_constants);
    let sigma_mles = row_major_to_mles(&prover_data.sigmas, num_routed_wires);

    let batch_r_pre = derive_preprocessed_batch_r(&circuit_digest);
    let (preprocessed_batched, _) =
        build_preprocessed_batch(&const_mles, &sigma_mles, batch_r_pre, degree_bits);

    let goldilocks_evals: Vec<plonky2_field::goldilocks_field::GoldilocksField> =
        preprocessed_batched
            .evaluations
            .iter()
            .map(|&f| {
                plonky2_field::goldilocks_field::GoldilocksField::from_canonical_u64(
                    f.to_canonical_u64(),
                )
            })
            .collect();
    let goldilocks_mle = DenseMultilinearExtension::new(goldilocks_evals);

    let whir_pcs = WhirPCS::for_num_vars(degree_bits);
    let preprocessed_commitment_root = whir_pcs.commit_root(&goldilocks_mle);

    MleVerificationKey {
        circuit_digest,
        preprocessed_commitment_root,
        num_constants: common_data.num_constants,
        num_routed_wires,
    }
}

/// Generate an MLE proof for a Plonky2 circuit.
pub fn mle_prove<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
    prover_data: &ProverOnlyCircuitData<F, C, D>,
    common_data: &CommonCircuitData<F, D>,
    inputs: PartialWitness<F>,
    timing: &mut TimingTree,
) -> Result<MleProof<F>>
where
    C::Hasher: Hasher<F>,
    C::InnerHasher: Hasher<F>,
{
    let tables = extract_evaluation_tables::<F, C, D>(prover_data, common_data, inputs, timing)?;

    let digest_bytes =
        serde_json::to_vec(&prover_data.circuit_digest).expect("circuit_digest serialization");
    let circuit_digest: Vec<F> = {
        let hash_out: plonky2::hash::hash_types::HashOut<F> =
            serde_json::from_slice(&digest_bytes).expect("circuit_digest deserialization");
        hash_out.elements.to_vec()
    };

    mle_prove_from_tables::<F, D>(common_data, &tables, &circuit_digest)
}

/// Generate an MLE proof from pre-extracted evaluation tables.
pub fn mle_prove_from_tables<F: RichField + Extendable<D>, const D: usize>(
    common_data: &CommonCircuitData<F, D>,
    tables: &EvaluationTables<F>,
    circuit_digest: &[F],
) -> Result<MleProof<F>> {
    let degree = tables.degree;
    let degree_bits = tables.degree_bits;
    let num_routed_wires = tables.num_routed_wires;

    eprintln!("[prover] degree_bits={degree_bits}, degree={degree}");

    // ═══════════════════════════════════════════════════════════════════
    // Phase 1: Commit preprocessed + witness
    // ═══════════════════════════════════════════════════════════════════
    let mut transcript = Transcript::new();
    transcript.domain_separate("circuit");
    transcript.absorb_field_vec(circuit_digest);
    transcript.absorb_field_vec(&tables.public_inputs);

    let _t = std::time::Instant::now();
    let wire_mles = tables_to_mles(&tables.wire_values);
    let const_mles = row_major_to_mles(&tables.constant_values, common_data.num_constants);
    let sigma_mles = row_major_to_mles(&tables.sigma_values, num_routed_wires);
    eprintln!("[prover] build MLEs: {:?}", _t.elapsed());

    let whir_pcs = WhirPCS::for_num_vars(degree_bits);

    // Preprocessed batch + commit root
    let _t = std::time::Instant::now();
    let batch_r_pre: F = derive_preprocessed_batch_r(circuit_digest);
    let (preprocessed_batched, preprocessed_mles) =
        build_preprocessed_batch(&const_mles, &sigma_mles, batch_r_pre, degree_bits);

    let pre_goldilocks_evals: Vec<plonky2_field::goldilocks_field::GoldilocksField> =
        preprocessed_batched
            .evaluations
            .iter()
            .map(|&f| {
                plonky2_field::goldilocks_field::GoldilocksField::from_canonical_u64(
                    f.to_canonical_u64(),
                )
            })
            .collect();
    let pre_ark_evals = plonky2_vec_to_ark(&pre_goldilocks_evals);

    let pre_goldilocks_mle = DenseMultilinearExtension::new(pre_goldilocks_evals);
    let pre_root = whir_pcs.commit_root(&pre_goldilocks_mle);

    transcript.absorb_bytes(&pre_root);
    transcript.domain_separate("batch-commit-witness");
    let batch_r_wit: F = transcript.squeeze_challenge();

    // Witness batch
    let mut wit_batched_evals = vec![F::ZERO; 1 << degree_bits];
    let mut r_pow = F::ONE;
    for mle in &wire_mles {
        for (j, &eval) in mle.evaluations.iter().enumerate() {
            if j < wit_batched_evals.len() {
                wit_batched_evals[j] += r_pow * eval;
            }
        }
        r_pow *= batch_r_wit;
    }
    let wit_goldilocks_evals: Vec<plonky2_field::goldilocks_field::GoldilocksField> =
        wit_batched_evals
            .iter()
            .map(|&f| {
                plonky2_field::goldilocks_field::GoldilocksField::from_canonical_u64(
                    f.to_canonical_u64(),
                )
            })
            .collect();
    let wit_ark_evals = plonky2_vec_to_ark(&wit_goldilocks_evals);

    // Split commit preprocessed + witness (phase 1 — before challenges)
    let mut commit_data =
        whir_pcs.commit_split(&[&pre_ark_evals, &wit_ark_evals], WHIR_SESSION_SPLIT);
    assert_eq!(pre_root, commit_data.roots[0]);
    let witness_root = commit_data.roots[1].clone();
    transcript.absorb_bytes(&witness_root);
    eprintln!("[prover] phase1 commit: {:?}", _t.elapsed());

    // ═══════════════════════════════════════════════════════════════════
    // Phase 2: Derive challenges + compute C̃ and h̃
    // ═══════════════════════════════════════════════════════════════════
    transcript.domain_separate("challenges");
    let beta: F = transcript.squeeze_challenge();
    let gamma: F = transcript.squeeze_challenge();
    let alpha: F = transcript.squeeze_challenge();
    let tau: Vec<F> = transcript.squeeze_challenges(degree_bits);
    let tau_perm: Vec<F> = transcript.squeeze_challenges(degree_bits);

    // Compute C̃ (constraint MLE)
    let _t = std::time::Instant::now();
    let combined_ext = compute_combined_constraints::<F, D>(
        common_data,
        &tables.wire_values,
        &tables.constant_values,
        &[alpha],
        &tables.public_inputs_hash,
        degree,
    );
    transcript.domain_separate("extension-combine");
    let ext_challenge: F = transcript.squeeze_challenge();
    let mut padded_constraints =
        flatten_extension_constraints::<F, D>(&combined_ext, ext_challenge);
    padded_constraints.resize(1 << degree_bits, F::ZERO);

    // Compute h̃ (permutation numerator MLE)
    let id_values = crate::permutation::logup::compute_identity_values(
        &tables.k_is,
        &tables.subgroup,
        num_routed_wires,
        degree,
    );
    let perm_h = crate::permutation::logup::compute_permutation_numerator(
        &tables.wire_values,
        &tables.sigma_values,
        &id_values,
        beta,
        gamma,
        num_routed_wires,
        degree,
    );
    let mut perm_h_padded = perm_h;
    perm_h_padded.resize(1 << degree_bits, F::ZERO);
    eprintln!("[prover] phase2 constraints+perm: {:?}", _t.elapsed());

    // ═══════════════════════════════════════════════════════════════════
    // Phase 3: Auxiliary commitment (C̃ + h̃ batched)
    //
    // SECURITY: C̃ and h̃ depend on challenges (alpha, beta, gamma) derived
    // AFTER the main commitment. A second commitment round makes their
    // evaluations WHIR-bound, closing the oracle gap.
    // ═══════════════════════════════════════════════════════════════════
    let _t = std::time::Instant::now();
    transcript.domain_separate("aux-commit");
    let batch_r_aux: F = transcript.squeeze_challenge();

    // P_aux(x) = C̃(x) + batch_r_aux · h̃(x)
    let mut aux_batched_evals = vec![F::ZERO; 1 << degree_bits];
    for (j, &c_val) in padded_constraints.iter().enumerate() {
        aux_batched_evals[j] += c_val;
    }
    for (j, &h_val) in perm_h_padded.iter().enumerate() {
        if j < aux_batched_evals.len() {
            aux_batched_evals[j] += batch_r_aux * h_val;
        }
    }

    // Convert auxiliary to arkworks field
    let aux_ark_evals = plonky2_vec_to_ark(
        &aux_batched_evals
            .iter()
            .map(|&f| {
                plonky2_field::goldilocks_field::GoldilocksField::from_canonical_u64(
                    f.to_canonical_u64(),
                )
            })
            .collect::<Vec<_>>(),
    );

    // Add auxiliary to the SAME WHIR session (phased commit — vector 2)
    // SECURITY: commit_additional uses the same WHIR ProverState, ensuring
    // cross-term OOD binding with preprocessed and witness vectors.
    let aux_root = whir_pcs.commit_additional(&mut commit_data, &aux_ark_evals);
    transcript.absorb_bytes(&aux_root);
    eprintln!("[prover] phase3 aux commit (phased): {:?}", _t.elapsed());

    // ═══════════════════════════════════════════════════════════════════
    // Phase 4: Derive combination scalar μ + lookups
    // ═══════════════════════════════════════════════════════════════════
    transcript.domain_separate("combined-sumcheck");
    let mu: F = transcript.squeeze_challenge();

    // SECURITY: Lookup argument is not yet implemented. Fail-fast to prevent
    // silently accepting circuits with lookup tables (which would be unsound).
    let has_lookup = !common_data.luts.is_empty();
    anyhow::ensure!(
        !has_lookup,
        "Lookup tables not yet supported in MLE prover ({} LUTs present)",
        common_data.luts.len()
    );
    let lookup_proofs = Vec::new();

    // ═══════════════════════════════════════════════════════════════════
    // Phase 5: Combined sumcheck
    //   Σ_b [eq(τ,b)·C̃(b) + μ·eq(τ_perm,b)·h̃(b)] = 0
    // Single sumcheck → single output point r
    // ═══════════════════════════════════════════════════════════════════
    let _t = std::time::Instant::now();
    let eq_table = eq_poly::eq_evals(&tau);

    let mut eq_mle = DenseMultilinearExtension::new(eq_table);
    let mut constraint_mle = DenseMultilinearExtension::new(padded_constraints.clone());
    let mut h_mle = DenseMultilinearExtension::new(perm_h_padded.clone());

    // Max degree: eq(τ,·)·C(·) has degree 2 per variable (product of two multilinear),
    // μ·h(·) has degree 1 per variable (scaled multilinear). Combined: degree 2.
    let max_constraint_degree = 2;
    let (combined_proof, sumcheck_challenges) = prove_sumcheck_combined(
        &mut eq_mle,
        &mut constraint_mle,
        &mut h_mle,
        mu,
        max_constraint_degree,
        &mut transcript,
    );
    eprintln!("[prover] phase5 combined sumcheck: {:?}", _t.elapsed());

    // ═══════════════════════════════════════════════════════════════════
    // Phase 6: Evaluate at sumcheck output point r
    // ═══════════════════════════════════════════════════════════════════
    let _t = std::time::Instant::now();

    // Individual evals from main commitment
    let preprocessed_individual_evals: Vec<F> = preprocessed_mles
        .iter()
        .map(|m| m.evaluate(&sumcheck_challenges))
        .collect();
    let witness_individual_evals: Vec<F> = wire_mles
        .iter()
        .map(|m| m.evaluate(&sumcheck_challenges))
        .collect();

    // Auxiliary oracle evals at r
    let constraint_mle_eval = DenseMultilinearExtension::new(padded_constraints);
    let perm_h_mle_eval = DenseMultilinearExtension::new(perm_h_padded);
    let aux_constraint_eval = constraint_mle_eval.evaluate(&sumcheck_challenges);
    let aux_perm_eval = perm_h_mle_eval.evaluate(&sumcheck_challenges);
    let aux_eval_value = aux_constraint_eval + batch_r_aux * aux_perm_eval;

    // Batched main evaluations
    let mut preprocessed_eval_value = F::ZERO;
    let mut r_pow = F::ONE;
    for &eval in &preprocessed_individual_evals {
        preprocessed_eval_value += r_pow * eval;
        r_pow *= batch_r_pre;
    }
    let mut witness_eval_value = F::ZERO;
    let mut r_pow = F::ONE;
    for &eval in &witness_individual_evals {
        witness_eval_value += r_pow * eval;
        r_pow *= batch_r_wit;
    }
    eprintln!("[prover] phase6 evals: {:?}", _t.elapsed());

    // ═══════════════════════════════════════════════════════════════════
    // Phase 7: WHIR prove — main split at r, auxiliary at r
    // ═══════════════════════════════════════════════════════════════════
    let _t = std::time::Instant::now();
    let r_gl: Vec<plonky2_field::goldilocks_field::GoldilocksField> = sumcheck_challenges
        .iter()
        .map(|&f| {
            plonky2_field::goldilocks_field::GoldilocksField::from_canonical_u64(
                f.to_canonical_u64(),
            )
        })
        .collect();

    // Single WHIR proof for all 3 vectors at r (phased split-commit)
    // commit_data now contains [preprocessed, witness, auxiliary]
    let (whir_eval_proof, whir_per_point_evals) =
        whir_pcs.prove_split_with_eval(commit_data, &[&r_gl]);
    // whir_per_point_evals[0] = [P_pre(r), P_wit(r), P_aux(r)]
    let pre_eval_ext3 = whir_per_point_evals[0][0];
    let wit_eval_ext3 = whir_per_point_evals[0][1];
    let aux_whir_eval_ext3 = whir_per_point_evals[0][2];

    eprintln!("[prover] phase7 WHIR prove: {:?}", _t.elapsed());

    // ═══════════════════════════════════════════════════════════════════
    // Phase 8: Proof assembly
    // ═══════════════════════════════════════════════════════════════════
    transcript.domain_separate("pcs-eval");

    Ok(MleProof {
        circuit_digest: circuit_digest.to_vec(),
        // Main WHIR PCS
        whir_eval_proof,
        preprocessed_root: pre_root,
        witness_root,
        // Preprocessed batch at r
        preprocessed_eval_value,
        preprocessed_batch_r: batch_r_pre,
        preprocessed_individual_evals,
        preprocessed_whir_eval_ext3: pre_eval_ext3,
        // Witness batch at r
        witness_eval_value,
        witness_batch_r: batch_r_wit,
        witness_individual_evals,
        witness_whir_eval_ext3: wit_eval_ext3,
        // Auxiliary polynomial (3rd vector in same WHIR proof)
        aux_commitment_root: aux_root,
        aux_batch_r: batch_r_aux,
        aux_constraint_eval,
        aux_perm_eval,
        aux_eval_value,
        aux_whir_eval_ext3,
        // Sumcheck output
        sumcheck_challenges: sumcheck_challenges.clone(),
        // Combined sumcheck
        combined_proof,
        lookup_proofs,
        // Public data
        public_inputs: tables.public_inputs.clone(),
        public_inputs_hash: tables.public_inputs_hash,
        alpha,
        beta,
        gamma,
        tau,
        tau_perm,
        mu,
        num_wires: tables.num_wires,
        num_routed_wires,
        num_constants: common_data.num_constants,
    })
}

#[cfg(test)]
mod tests {
    use plonky2::iop::witness::WitnessWrite;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;
    use plonky2_field::goldilocks_field::GoldilocksField;
    use plonky2_field::types::Field;

    use super::*;

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    #[test]
    fn test_mle_prove_simple_circuit() {
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
        let proof =
            mle_prove::<F, C, D>(&circuit.prover_only, &circuit.common, pw, &mut timing).unwrap();

        assert_eq!(proof.public_inputs[0], F::from_canonical_u64(21));
        assert!(!proof.witness_individual_evals.is_empty());
        assert!(!proof.preprocessed_individual_evals.is_empty());
    }
}
