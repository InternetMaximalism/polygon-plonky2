/// Integrated MLE prover combining all sub-protocols.
///
/// Takes a Plonky2 circuit + witness and produces an MLE proof using:
/// 1. MLE construction from raw evaluation tables
/// 2. Merkle PCS commitment (batched)
/// 3. Fiat-Shamir (Keccak) for all challenges
/// 4. Zero-check sumcheck for gate constraints
/// 5. Log-derivative permutation check
/// 6. PCS evaluation proof
use anyhow::Result;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::circuit_data::{CommonCircuitData, EvaluationTables, ProverOnlyCircuitData};
use plonky2::plonk::config::{GenericConfig, Hasher};
use plonky2::plonk::prover::extract_evaluation_tables;
use plonky2::util::timing::TimingTree;
use plonky2_field::extension::Extendable;

use crate::commitment::merkle_pcs::MerklePCS;
use crate::commitment::traits::MultilinearPCS;
use crate::constraint_eval::compute_combined_constraints;
use crate::dense_mle::{row_major_to_mles, tables_to_mles, DenseMultilinearExtension};
use crate::eq_poly;
use crate::permutation::logup::PermutationProof;
use crate::permutation::lookup::{self, LookupProof};
use crate::proof::MleProof;
use crate::sumcheck::prover::{compute_claimed_sum, prove_sumcheck_product};
use crate::transcript::Transcript;

/// Generate an MLE proof for a Plonky2 circuit.
///
/// This is the main entry point for the MLE proving system.
pub fn mle_prove<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    prover_data: &ProverOnlyCircuitData<F, C, D>,
    common_data: &CommonCircuitData<F, D>,
    inputs: PartialWitness<F>,
    timing: &mut TimingTree,
) -> Result<MleProof<F>>
where
    C::Hasher: Hasher<F>,
    C::InnerHasher: Hasher<F>,
{
    // Step 1: Extract raw evaluation tables from Plonky2
    let tables = extract_evaluation_tables::<F, C, D>(prover_data, common_data, inputs, timing)?;

    mle_prove_from_tables::<F, D>(common_data, &tables)
}

/// Generate an MLE proof from pre-extracted evaluation tables.
///
/// This allows decoupling the witness generation (Plonky2-specific) from the
/// MLE proof generation (generic).
pub fn mle_prove_from_tables<F: RichField + Extendable<D>, const D: usize>(
    common_data: &CommonCircuitData<F, D>,
    tables: &EvaluationTables<F>,
) -> Result<MleProof<F>> {
    let degree = tables.degree;
    let degree_bits = tables.degree_bits;
    let _num_wires = tables.num_wires;
    let num_routed_wires = tables.num_routed_wires;

    // Step 2: Initialize transcript with circuit identity
    let mut transcript = Transcript::new();
    transcript.domain_separate("circuit");
    // Absorb public inputs into transcript
    transcript.absorb_field_vec(&tables.public_inputs);

    // Step 3: Build MLEs from evaluation tables
    let wire_mles = tables_to_mles(&tables.wire_values);
    let const_mles = row_major_to_mles(&tables.constant_values, common_data.num_constants);
    let sigma_mles = row_major_to_mles(&tables.sigma_values, num_routed_wires);

    // Collect all MLEs for batching
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

    // Step 4: Batch MLEs and commit via PCS
    transcript.domain_separate("batch-commit");
    let batch_r: F = transcript.squeeze_challenge();

    // Build batched polynomial: P(x) = Σ_i batch_r^i · poly_i(x)
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
    let (commitment, commit_state) = pcs.commit(&batched_mle);

    // Absorb commitment into transcript
    transcript.absorb_bytes(&commitment.root);

    // Step 5: Derive challenges
    transcript.domain_separate("challenges");
    let beta: F = transcript.squeeze_challenge();
    let gamma: F = transcript.squeeze_challenge();
    let alpha: F = transcript.squeeze_challenge();
    let tau: Vec<F> = transcript.squeeze_challenges(degree_bits);
    let tau_perm: Vec<F> = transcript.squeeze_challenges(degree_bits);

    // Step 6: Permutation check
    transcript.domain_separate("permutation");
    let (perm_sumcheck, perm_challenges, perm_claimed_sum) =
        crate::permutation::logup::prove_permutation_check(
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

    // Step 6b: Lookup argument (if circuit has lookup tables)
    let has_lookup = !common_data.luts.is_empty();
    let lookup_proofs = if has_lookup {
        transcript.domain_separate("lookup");
        let delta_lookup: F = transcript.squeeze_challenge();
        let beta_lookup: F = transcript.squeeze_challenge();

        // For the prototype, extract lookup data from wire values.
        // A full implementation would use the LookupGate/LookupTableGate wire layout.
        // Currently we support circuits without lookups in the E2E path;
        // the lookup extraction from raw wire values needs gate-row mapping
        // which requires CommonCircuitData.gates access.
        // TODO: Implement full lookup data extraction from evaluation tables.
        Vec::new()
    } else {
        Vec::new()
    };

    // Step 7: Compute combined gate constraints
    let combined_constraints = compute_combined_constraints::<F, D>(
        common_data,
        &tables.wire_values,
        &tables.constant_values,
        &[alpha],
        &tables.public_inputs_hash,
        degree,
    );

    // Pad to power of 2
    let mut padded_constraints = combined_constraints;
    padded_constraints.resize(1 << degree_bits, F::ZERO);

    // Step 8: Zero-check sumcheck
    transcript.domain_separate("zero-check");
    let eq_table = eq_poly::eq_evals(&tau);
    let _claimed_sum = compute_claimed_sum(&eq_table, &padded_constraints);

    let mut eq_mle = DenseMultilinearExtension::new(eq_table);
    let mut constraint_mle = DenseMultilinearExtension::new(padded_constraints);

    let (constraint_proof, sumcheck_challenges) =
        prove_sumcheck_product(&mut eq_mle, &mut constraint_mle, 2, &mut transcript);

    // Step 9: Evaluate all individual MLEs at the sumcheck point
    let mut individual_evals = Vec::with_capacity(num_polys);
    for mle in &all_mles {
        individual_evals.push(mle.evaluate(&sumcheck_challenges));
    }

    // Recompute batched evaluation for PCS opening
    let mut batched_eval = F::ZERO;
    let mut r_pow = F::ONE;
    for &eval in &individual_evals {
        batched_eval = batched_eval + r_pow * eval;
        r_pow = r_pow * batch_r;
    }

    // Step 10: PCS evaluation proof
    transcript.domain_separate("pcs-eval");
    let eval_proof = pcs.open(
        &commit_state,
        &batched_mle,
        &sumcheck_challenges,
        batched_eval,
        &mut transcript,
    );

    Ok(MleProof {
        commitment,
        constraint_proof,
        permutation_proof: PermutationProof {
            sumcheck_proof: perm_sumcheck,
            challenges: perm_challenges,
            claimed_sum: perm_claimed_sum,
        },
        lookup_proofs,
        eval_proof,
        eval_value: batched_eval,
        public_inputs: tables.public_inputs.clone(),
        batch_r,
        num_polys,
        individual_evals,
        alpha,
        beta,
        gamma,
        tau,
        tau_perm,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::iop::witness::WitnessWrite;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;
    use plonky2_field::goldilocks_field::GoldilocksField;
    use plonky2_field::types::Field;

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
        pw.set_target(x, F::from_canonical_u64(3)).unwrap();
        pw.set_target(y, F::from_canonical_u64(7)).unwrap();

        let mut timing = TimingTree::default();
        let proof = mle_prove::<F, C, D>(
            &circuit.prover_only,
            &circuit.common,
            pw,
            &mut timing,
        )
        .unwrap();

        assert_eq!(proof.public_inputs[0], F::from_canonical_u64(21));
        assert!(!proof.individual_evals.is_empty());
    }
}
