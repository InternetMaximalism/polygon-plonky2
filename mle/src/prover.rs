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
use plonky2_field::types::{Field as PlonkyField, PrimeField64};

use crate::commitment::whir_pcs::WhirPCS;
use crate::constraint_eval::{compute_combined_constraints, flatten_extension_constraints};
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

    // SECURITY: Extract circuit_digest (verifying key hash) to bind the proof
    // to a specific Plonky2 circuit. This is the first thing absorbed into the
    // Fiat-Shamir transcript, matching the standard Plonky2 verifier.
    // HashOut<F> has 4 field elements accessible via .elements.
    // circuit_digest is <<C as GenericConfig<D>>::Hasher as Hasher<F>>::Hash
    // which is HashOut<F> for PoseidonGoldilocksConfig. We serialize it to
    // bytes and parse back as field elements for transcript absorption.
    let digest_bytes = serde_json::to_vec(&prover_data.circuit_digest)
        .expect("circuit_digest serialization");
    // Parse the JSON array [elem0, elem1, elem2, elem3] back to F elements
    let circuit_digest: Vec<F> = {
        let hash_out: plonky2::hash::hash_types::HashOut<F> =
            serde_json::from_slice(&digest_bytes).expect("circuit_digest deserialization");
        hash_out.elements.to_vec()
    };

    mle_prove_from_tables::<F, D>(common_data, &tables, &circuit_digest)
}

/// Generate an MLE proof from pre-extracted evaluation tables.
///
/// This allows decoupling the witness generation (Plonky2-specific) from the
/// MLE proof generation (generic).
pub fn mle_prove_from_tables<F: RichField + Extendable<D>, const D: usize>(
    common_data: &CommonCircuitData<F, D>,
    tables: &EvaluationTables<F>,
    circuit_digest: &[F],
) -> Result<MleProof<F>> {
    let degree = tables.degree;
    let degree_bits = tables.degree_bits;
    let _num_wires = tables.num_wires;
    let num_routed_wires = tables.num_routed_wires;

    let _prover_start = std::time::Instant::now();
    eprintln!("[prover] degree_bits={degree_bits}, degree={degree}");

    // Step 2: Initialize transcript with circuit identity
    // SECURITY: Absorb circuit_digest first to bind this proof to the specific
    // Plonky2 circuit (verifying key). Without this, an attacker could forge a
    // proof for a trivial circuit and claim it verifies the target circuit.
    let mut transcript = Transcript::new();
    transcript.domain_separate("circuit");
    transcript.absorb_field_vec(circuit_digest);
    // Absorb public inputs into transcript
    transcript.absorb_field_vec(&tables.public_inputs);

    // Step 3: Build MLEs from evaluation tables
    let _t = std::time::Instant::now();
    let wire_mles = tables_to_mles(&tables.wire_values);
    let const_mles = row_major_to_mles(&tables.constant_values, common_data.num_constants);
    let sigma_mles = row_major_to_mles(&tables.sigma_values, num_routed_wires);
    eprintln!("[prover] step3 build MLEs: {:?}", _t.elapsed());

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
    let _t = std::time::Instant::now();
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
    eprintln!("[prover] step4 batch MLEs: {:?}", _t.elapsed());

    // Step 4b: WHIR commit + eval proof
    let _t = std::time::Instant::now();
    // WHIR handles its own transcript internally (spongefish).
    // We absorb the WHIR commitment root into our Keccak transcript
    // to bind the two transcript systems.
    //
    // WHIR operates over arkworks Field64 (same Goldilocks prime).
    // Convert evaluations via canonical u64 representation.
    let goldilocks_evals: Vec<plonky2_field::goldilocks_field::GoldilocksField> = batched_mle
        .evaluations
        .iter()
        .map(|&f| {
            plonky2_field::goldilocks_field::GoldilocksField::from_canonical_u64(
                f.to_canonical_u64()
            )
        })
        .collect();
    let goldilocks_mle = DenseMultilinearExtension::new(goldilocks_evals);

    let whir_pcs = WhirPCS::for_num_vars(degree_bits);
    let (whir_commitment, whir_proof, whir_eval_ext3) = whir_pcs.prove_at_point(
        &goldilocks_mle, None, None,
    );

    eprintln!("[prover] step4b WHIR prove: {:?}", _t.elapsed());

    // Absorb WHIR commitment (proof hash) into our transcript
    let commitment_bytes = &whir_commitment.proof_bytes[..32.min(whir_commitment.proof_bytes.len())];
    transcript.absorb_bytes(commitment_bytes);

    // Step 5: Derive challenges
    transcript.domain_separate("challenges");
    let beta: F = transcript.squeeze_challenge();
    let gamma: F = transcript.squeeze_challenge();
    let alpha: F = transcript.squeeze_challenge();
    let tau: Vec<F> = transcript.squeeze_challenges(degree_bits);
    let tau_perm: Vec<F> = transcript.squeeze_challenges(degree_bits);

    // Step 6: Permutation check
    let _t = std::time::Instant::now();
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

    eprintln!("[prover] step6 permutation: {:?}", _t.elapsed());

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

    let _t = std::time::Instant::now();
    // Step 7: Compute combined gate constraints (extension field)
    // SECURITY: Gate constraints live in F::Extension (D=2 components).
    // ALL components must be zero for the constraint to be satisfied.
    // We flatten the D components into a single base-field value per row
    // using a fresh Fiat-Shamir challenge for the extension combination.
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

    let combined_constraints = flatten_extension_constraints::<F, D>(&combined_ext, ext_challenge);

    eprintln!("[prover] step7 constraints: {:?}", _t.elapsed());

    // Pad to power of 2
    let mut padded_constraints = combined_constraints;
    padded_constraints.resize(1 << degree_bits, F::ZERO);

    // Step 8: Zero-check sumcheck
    let _t = std::time::Instant::now();
    transcript.domain_separate("zero-check");
    let eq_table = eq_poly::eq_evals(&tau);
    let _claimed_sum = compute_claimed_sum(&eq_table, &padded_constraints);

    let mut eq_mle = DenseMultilinearExtension::new(eq_table);
    let mut constraint_mle = DenseMultilinearExtension::new(padded_constraints);

    let (constraint_proof, sumcheck_challenges) =
        prove_sumcheck_product(&mut eq_mle, &mut constraint_mle, 2, &mut transcript);

    eprintln!("[prover] step8 zero-check sumcheck: {:?}", _t.elapsed());

    // Step 9: Evaluate all individual MLEs at the sumcheck point
    let _t = std::time::Instant::now();
    let mut individual_evals = Vec::with_capacity(num_polys);
    for mle in &all_mles {
        individual_evals.push(mle.evaluate(&sumcheck_challenges));
    }

    // Step 9b: Compute PCS-bound oracle values for the Solidity verifier.
    //
    // pcs_constraint_eval: the flattened constraint polynomial C(r) at the
    // sumcheck output point r. The Solidity verifier checks:
    //   constraintFinalEval == eq(τ, r) · pcs_constraint_eval
    //
    // This is computed from the (already flattened) constraint MLE evaluated at r.
    // We use the original padded_constraints (before sumcheck consumed it).
    let constraint_mle_for_eval = DenseMultilinearExtension::new(
        flatten_extension_constraints::<F, D>(&combined_ext, ext_challenge)
            .into_iter()
            .chain(std::iter::repeat(F::ZERO))
            .take(1 << degree_bits)
            .collect(),
    );
    let pcs_constraint_eval = constraint_mle_for_eval.evaluate(&sumcheck_challenges);

    // pcs_perm_numerator_eval: h(r_perm) at the permutation sumcheck output point.
    // The permutation sumcheck produced perm_challenges as its output point.
    // We recompute h as an MLE and evaluate it at perm_challenges.
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
    let perm_h_mle = DenseMultilinearExtension::new(perm_h_padded);
    let pcs_perm_numerator_eval = perm_h_mle.evaluate(&perm_challenges);

    // Recompute batched evaluation for PCS opening
    let mut batched_eval = F::ZERO;
    let mut r_pow = F::ONE;
    for &eval in &individual_evals {
        batched_eval = batched_eval + r_pow * eval;
        r_pow = r_pow * batch_r;
    }

    eprintln!("[prover] step9 individual evals + pcs: {:?}", _t.elapsed());

    // Step 10: WHIR evaluation proof is already generated in step 4b.
    // The WHIR proof covers both commitment and evaluation.
    transcript.domain_separate("pcs-eval");

    Ok(MleProof {
        circuit_digest: circuit_digest.to_vec(),
        commitment: whir_commitment,
        constraint_proof,
        permutation_proof: PermutationProof {
            sumcheck_proof: perm_sumcheck,
            challenges: perm_challenges,
            claimed_sum: perm_claimed_sum,
        },
        lookup_proofs,
        eval_proof: whir_proof,
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
        pcs_constraint_eval,
        pcs_perm_numerator_eval,
        num_wires: tables.num_wires,
        num_routed_wires,
        num_constants: common_data.num_constants,
        whir_eval_ext3,
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
        pw.set_target(x, F::from_canonical_u64(3));
        pw.set_target(y, F::from_canonical_u64(7));

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
