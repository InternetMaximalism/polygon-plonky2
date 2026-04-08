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

use crate::commitment::whir_pcs::{WhirPCS, WHIR_SESSION_PREPROCESSED, WHIR_SESSION_WITNESS};
use crate::constraint_eval::{compute_combined_constraints, flatten_extension_constraints};
use crate::dense_mle::{row_major_to_mles, tables_to_mles, DenseMultilinearExtension};
use crate::eq_poly;
use crate::permutation::logup::PermutationProof;
use crate::permutation::lookup::{self, LookupProof};
use crate::proof::{MleProof, MleVerificationKey};
use crate::sumcheck::prover::{compute_claimed_sum, prove_sumcheck_product};
use crate::transcript::Transcript;

/// Derive the deterministic batching scalar for preprocessed polynomials.
///
/// SECURITY: This must produce the same value during setup and proving for the
/// same circuit. It is derived solely from the circuit_digest (verifying key hash)
/// using a dedicated mini-transcript with its own domain separation.
/// The value is public — security comes from the WHIR commitment binding, not
/// from batch_r secrecy.
pub fn derive_preprocessed_batch_r<F: RichField>(circuit_digest: &[F]) -> F {
    let mut t = Transcript::new();
    t.domain_separate("preprocessed-batch-r");
    t.absorb_field_vec(circuit_digest);
    t.squeeze_challenge()
}

/// Build the batched preprocessed MLE from constants and sigmas.
///
/// Returns (batched_mle, preprocessed_mles) where preprocessed_mles are
/// [const_0, ..., const_C, sigma_0, ..., sigma_R].
fn build_preprocessed_batch<'a, F: RichField>(
    const_mles: &'a [DenseMultilinearExtension<F>],
    sigma_mles: &'a [DenseMultilinearExtension<F>],
    batch_r: F,
    degree_bits: usize,
) -> (DenseMultilinearExtension<F>, Vec<&'a DenseMultilinearExtension<F>>) {
    // INTENTIONALLY SIMPLE: Collect preprocessed MLEs in fixed order
    // (constants first, then sigmas) matching the batch decomposition
    // expected by the verifier.
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
                batched_evals[j] = batched_evals[j] + r_pow * eval;
            }
        }
        r_pow = r_pow * batch_r;
    }

    (DenseMultilinearExtension::new(batched_evals), preprocessed_mles)
}

/// Compute the MLE verification key for a circuit (setup phase).
///
/// This is called once per circuit after `CircuitBuilder::build()`.
/// The VK contains the WHIR commitment root for the preprocessed polynomials
/// (constants + sigmas), which is used by the verifier to ensure the prover
/// cannot substitute fabricated preprocessed data.
///
/// SECURITY: The preprocessed_commitment_root in the returned VK binds the
/// verifier to the specific gate selectors, constant values, and permutation
/// routing of this circuit. An attacker using different constants/sigmas would
/// produce a different Merkle root, causing verification to fail.
pub fn mle_setup<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    prover_data: &ProverOnlyCircuitData<F, C, D>,
    common_data: &CommonCircuitData<F, D>,
) -> MleVerificationKey<F>
where
    C::Hasher: Hasher<F>,
{
    let degree_bits = common_data.degree_bits();
    let num_routed_wires = common_data.config.num_routed_wires;

    // Extract circuit_digest
    let digest_bytes = serde_json::to_vec(&prover_data.circuit_digest)
        .expect("circuit_digest serialization");
    let circuit_digest: Vec<F> = {
        let hash_out: plonky2::hash::hash_types::HashOut<F> =
            serde_json::from_slice(&digest_bytes).expect("circuit_digest deserialization");
        hash_out.elements.to_vec()
    };

    // Build preprocessed MLEs from prover_data
    // constant_evals is row-major [row][col], sigmas is row-major [row][col]
    let const_mles = row_major_to_mles(&prover_data.constant_evals, common_data.num_constants);
    let sigma_mles = row_major_to_mles(&prover_data.sigmas, num_routed_wires);

    // Batch preprocessed polynomials with deterministic batch_r
    let batch_r_pre = derive_preprocessed_batch_r(&circuit_digest);
    let (preprocessed_batched, _) = build_preprocessed_batch(
        &const_mles, &sigma_mles, batch_r_pre, degree_bits,
    );

    // Convert to Goldilocks and compute WHIR commitment root
    let goldilocks_evals: Vec<plonky2_field::goldilocks_field::GoldilocksField> =
        preprocessed_batched.evaluations.iter()
            .map(|&f| plonky2_field::goldilocks_field::GoldilocksField::from_canonical_u64(
                f.to_canonical_u64(),
            ))
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

    let whir_pcs = WhirPCS::for_num_vars(degree_bits);

    // Step 4a: Preprocessed batch (constants + sigmas) + WHIR commitment
    // SECURITY: The preprocessed polynomial is committed with a deterministic batch_r
    // derived from circuit_digest. The commitment root must match the VK, preventing
    // an attacker from substituting fabricated constants/sigmas.
    let _t = std::time::Instant::now();
    let batch_r_pre: F = derive_preprocessed_batch_r(circuit_digest);
    let (preprocessed_batched, preprocessed_mles) = build_preprocessed_batch(
        &const_mles, &sigma_mles, batch_r_pre, degree_bits,
    );

    // Convert to Goldilocks and WHIR prove
    let pre_goldilocks_evals: Vec<plonky2_field::goldilocks_field::GoldilocksField> =
        preprocessed_batched.evaluations.iter()
            .map(|&f| plonky2_field::goldilocks_field::GoldilocksField::from_canonical_u64(
                f.to_canonical_u64(),
            ))
            .collect();
    let pre_goldilocks_mle = DenseMultilinearExtension::new(pre_goldilocks_evals);
    let (pre_commitment, pre_eval_proof, pre_eval_ext3) =
        whir_pcs.prove_at_point_with_session(
            &pre_goldilocks_mle, None, WHIR_SESSION_PREPROCESSED,
        );
    eprintln!("[prover] step4a preprocessed WHIR: {:?}", _t.elapsed());

    // Absorb preprocessed commitment root into transcript
    let pre_root = &pre_commitment.proof_bytes[..32.min(pre_commitment.proof_bytes.len())];
    transcript.absorb_bytes(pre_root);

    // Step 4b: Witness batch (wires) + WHIR commitment
    let _t = std::time::Instant::now();
    transcript.domain_separate("batch-commit-witness");
    let batch_r_wit: F = transcript.squeeze_challenge();

    // Build batched witness polynomial: P_wit(x) = Σ_i batch_r_wit^i · wire_i(x)
    let mut wit_batched_evals = vec![F::ZERO; 1 << degree_bits];
    let mut r_pow = F::ONE;
    for mle in &wire_mles {
        for (j, &eval) in mle.evaluations.iter().enumerate() {
            if j < wit_batched_evals.len() {
                wit_batched_evals[j] = wit_batched_evals[j] + r_pow * eval;
            }
        }
        r_pow = r_pow * batch_r_wit;
    }
    let wit_batched_mle = DenseMultilinearExtension::new(wit_batched_evals);

    // Convert to Goldilocks and WHIR prove
    let wit_goldilocks_evals: Vec<plonky2_field::goldilocks_field::GoldilocksField> =
        wit_batched_mle.evaluations.iter()
            .map(|&f| plonky2_field::goldilocks_field::GoldilocksField::from_canonical_u64(
                f.to_canonical_u64(),
            ))
            .collect();
    let wit_goldilocks_mle = DenseMultilinearExtension::new(wit_goldilocks_evals);
    let (wit_commitment, wit_eval_proof, wit_eval_ext3) =
        whir_pcs.prove_at_point_with_session(
            &wit_goldilocks_mle, None, WHIR_SESSION_WITNESS,
        );
    eprintln!("[prover] step4b witness WHIR: {:?}", _t.elapsed());

    // Absorb witness commitment root into transcript
    let wit_root = &wit_commitment.proof_bytes[..32.min(wit_commitment.proof_bytes.len())];
    transcript.absorb_bytes(wit_root);

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

    // Step 9: Evaluate individual MLEs at the sumcheck point, split by commitment
    let _t = std::time::Instant::now();

    // Preprocessed evaluations: [const_0(r), ..., const_C(r), sigma_0(r), ..., sigma_R(r)]
    let mut preprocessed_individual_evals = Vec::with_capacity(preprocessed_mles.len());
    for mle in &preprocessed_mles {
        preprocessed_individual_evals.push(mle.evaluate(&sumcheck_challenges));
    }

    // Witness evaluations: [wire_0(r), ..., wire_W(r)]
    let mut witness_individual_evals = Vec::with_capacity(wire_mles.len());
    for mle in &wire_mles {
        witness_individual_evals.push(mle.evaluate(&sumcheck_challenges));
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

    // Recompute batched evaluations for each commitment
    let mut preprocessed_eval_value = F::ZERO;
    let mut r_pow = F::ONE;
    for &eval in &preprocessed_individual_evals {
        preprocessed_eval_value = preprocessed_eval_value + r_pow * eval;
        r_pow = r_pow * batch_r_pre;
    }

    let mut witness_eval_value = F::ZERO;
    let mut r_pow = F::ONE;
    for &eval in &witness_individual_evals {
        witness_eval_value = witness_eval_value + r_pow * eval;
        r_pow = r_pow * batch_r_wit;
    }

    eprintln!("[prover] step9 individual evals + pcs: {:?}", _t.elapsed());

    // Step 10: WHIR evaluation proofs are already generated in steps 4a/4b.
    transcript.domain_separate("pcs-eval");

    Ok(MleProof {
        circuit_digest: circuit_digest.to_vec(),
        // Preprocessed PCS
        preprocessed_commitment: pre_commitment,
        preprocessed_eval_proof: pre_eval_proof,
        preprocessed_eval_value,
        preprocessed_batch_r: batch_r_pre,
        preprocessed_individual_evals,
        preprocessed_whir_eval_ext3: pre_eval_ext3,
        // Witness PCS
        witness_commitment: wit_commitment,
        witness_eval_proof: wit_eval_proof,
        witness_eval_value,
        witness_batch_r: batch_r_wit,
        witness_individual_evals,
        witness_whir_eval_ext3: wit_eval_ext3,
        // Sub-protocol proofs
        constraint_proof,
        permutation_proof: PermutationProof {
            sumcheck_proof: perm_sumcheck,
            challenges: perm_challenges,
            claimed_sum: perm_claimed_sum,
        },
        lookup_proofs,
        // Public data
        public_inputs: tables.public_inputs.clone(),
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
        assert!(!proof.witness_individual_evals.is_empty());
        assert!(!proof.preprocessed_individual_evals.is_empty());
    }
}
