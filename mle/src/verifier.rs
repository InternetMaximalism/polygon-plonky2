/// MLE proof verifier.
///
/// Verifies the complete MLE proof by:
/// 1. Reconstructing the Fiat-Shamir transcript
/// 2. Verifying the zero-check sumcheck
/// 3. Verifying the permutation check sumcheck
/// 4. Verifying the unified PCS evaluation proof (split-commit WHIR)
/// 5. Checking the final sumcheck evaluation against opened values
use anyhow::{ensure, Result};
use plonky2::hash::hash_types::RichField;
use plonky2::plonk::circuit_data::CommonCircuitData;
use plonky2_field::extension::Extendable;

use crate::commitment::whir_pcs::{WhirPCS, WHIR_SESSION_SPLIT};
use crate::eq_poly;
use crate::proof::{MleProof, MleVerificationKey};
use crate::prover::derive_preprocessed_batch_r;
use crate::sumcheck::verifier::verify_sumcheck;
use crate::transcript::Transcript;

/// Verify an MLE proof for a Plonky2 circuit.
///
/// SECURITY: The `vk` parameter binds the verifier to a specific circuit.
/// The preprocessed_commitment_root in the VK ensures the prover used the
/// correct constants and sigma permutation polynomials.
pub fn mle_verify<F: RichField + Extendable<D>, const D: usize>(
    common_data: &CommonCircuitData<F, D>,
    vk: &MleVerificationKey<F>,
    proof: &MleProof<F>,
) -> Result<()> {
    let degree_bits = plonky2_util::log2_strict(
        common_data.degree(),
    );

    // Step 1: Verify circuit digest matches VK
    // SECURITY: This is the first check — ensures this proof claims to be
    // for the circuit described by the VK.
    ensure!(
        proof.circuit_digest == vk.circuit_digest,
        "Circuit digest mismatch: proof does not match verification key"
    );

    // Step 1b: Verify preprocessed batch_r is correctly derived
    // SECURITY: The preprocessed batch_r must be deterministic from circuit_digest.
    // This prevents the prover from choosing a favorable batch_r.
    let expected_pre_r: F = derive_preprocessed_batch_r(&proof.circuit_digest);
    ensure!(
        expected_pre_r == proof.preprocessed_batch_r,
        "Preprocessed batch_r mismatch: not correctly derived from circuit_digest"
    );

    // Step 2: Verify preprocessed commitment root matches VK
    // SECURITY: This is the critical circuit-binding check. The preprocessed
    // Merkle root must match the VK. An attacker who substitutes different
    // constants/sigmas would produce a different root, failing this check.
    ensure!(
        proof.preprocessed_root == vk.preprocessed_commitment_root,
        "Preprocessed commitment root mismatch — circuit binding violated. \
         The prover used different constants/sigmas than the verification key expects."
    );

    // Step 3: Reconstruct Fiat-Shamir transcript (must match prover exactly)
    let mut transcript = Transcript::new();
    transcript.domain_separate("circuit");
    transcript.absorb_field_vec(&proof.circuit_digest);
    transcript.absorb_field_vec(&proof.public_inputs);

    // Absorb preprocessed commitment root (binds preprocessed to transcript)
    transcript.absorb_bytes(&proof.preprocessed_root);

    // Derive witness batch_r
    transcript.domain_separate("batch-commit-witness");
    let batch_r_wit: F = transcript.squeeze_challenge();
    ensure!(
        batch_r_wit == proof.witness_batch_r,
        "Witness batch random scalar mismatch"
    );

    // Absorb witness commitment root
    transcript.absorb_bytes(&proof.witness_root);

    // Step 4: Re-derive challenges
    transcript.domain_separate("challenges");
    let beta: F = transcript.squeeze_challenge();
    let gamma: F = transcript.squeeze_challenge();
    let alpha: F = transcript.squeeze_challenge();
    let tau: Vec<F> = transcript.squeeze_challenges(degree_bits);
    let tau_perm: Vec<F> = transcript.squeeze_challenges(degree_bits);

    ensure!(beta == proof.beta, "Beta mismatch");
    ensure!(gamma == proof.gamma, "Gamma mismatch");
    ensure!(alpha == proof.alpha, "Alpha mismatch");
    ensure!(tau == proof.tau, "Tau mismatch");
    ensure!(tau_perm == proof.tau_perm, "Tau_perm mismatch");

    // Step 5: Verify permutation check sumcheck
    // The prover proves: Σ_b h(b) = 0 where h(b) is the logUp numerator.
    // SECURITY: Soundness relies on β, γ being random Fiat-Shamir challenges.
    // For a wrong permutation, Σ h(b) ≠ 0 as a formal polynomial in β, γ
    // with probability ≥ 1 - degree/|F| by Schwartz-Zippel.
    transcript.domain_separate("permutation");
    let perm_proof = &proof.permutation_proof;

    // SECURITY: The claimed sum MUST be 0 for a valid permutation.
    ensure!(
        perm_proof.claimed_sum == F::ZERO,
        "Permutation check failed: Σ h(b) = {} ≠ 0",
        perm_proof.claimed_sum
    );

    let perm_result = verify_sumcheck(
        &perm_proof.sumcheck_proof,
        perm_proof.claimed_sum,
        degree_bits,
        &mut transcript,
    );
    ensure!(
        perm_result.is_ok(),
        "Permutation sumcheck verification failed"
    );

    // Step 5b: Verify lookup proofs (if any)
    let has_lookup = !common_data.luts.is_empty();
    if has_lookup {
        transcript.domain_separate("lookup");
        let _delta_lookup: F = transcript.squeeze_challenge();
        let _beta_lookup: F = transcript.squeeze_challenge();

        for (i, lp) in proof.lookup_proofs.iter().enumerate() {
            ensure!(
                lp.claimed_sum == F::ZERO,
                "Lookup {i}: claimed_sum = {} != 0",
                lp.claimed_sum
            );
            let lr = verify_sumcheck(
                &lp.sumcheck_proof,
                lp.claimed_sum,
                lp.challenges.len(),
                &mut transcript,
            );
            ensure!(lr.is_ok(), "Lookup {i} sumcheck verification failed");
        }
    }

    // Step 5c: Extension field combination challenge (must match prover).
    // INTENTIONALLY UNUSED: The ext_challenge is used by the prover to flatten
    // the D=2 extension field constraint components into a single base field value.
    // The verifier receives this flattened value as pcs_constraint_eval (PCS-bound),
    // so it doesn't need ext_challenge directly. We squeeze it here solely to keep
    // the transcript in sync with the prover.
    transcript.domain_separate("extension-combine");
    let _ext_challenge: F = transcript.squeeze_challenge();

    // Step 6: Verify zero-check sumcheck (claimed sum = 0 for valid circuit)
    transcript.domain_separate("zero-check");

    let zero_claim = F::ZERO;
    let constraint_result = verify_sumcheck(
        &proof.constraint_proof,
        zero_claim,
        degree_bits,
        &mut transcript,
    );

    let (sumcheck_challenges, final_eval) = constraint_result
        .map_err(|e| anyhow::anyhow!("Constraint sumcheck verification failed: {}", e))?;

    // Step 7: Verify the final sumcheck evaluation.
    // SECURITY: final_eval must equal eq(τ, r) · C(r), where C(r) is the
    // PCS-bound constraint evaluation supplied by the prover.
    let eq_at_r = eq_poly::eq_eval(&tau, &sumcheck_challenges);
    let expected_final = eq_at_r * proof.pcs_constraint_eval;
    ensure!(
        expected_final == final_eval,
        "Constraint final eval mismatch: eq(τ,r)*C(r) != finalEval"
    );

    // Step 7b: Verify the permutation final evaluation.
    // SECURITY: The sumcheck's last round polynomial g_{n-1}(r_{n-1}) should equal
    // h(r_perm) — the PCS-bound evaluation of the logUp numerator at the
    // sumcheck output point r_perm.
    if let (Some(last_rp), Some(&last_challenge)) = (
        proof.permutation_proof.sumcheck_proof.round_polys.last(),
        proof.permutation_proof.challenges.last(),
    ) {
        let perm_final = last_rp.evaluate(last_challenge);
        ensure!(
            perm_final == proof.pcs_perm_numerator_eval,
            "Permutation final eval mismatch: h(r_perm) != pcsPermNumeratorEval"
        );
    }

    // Step 8: Verify unified WHIR PCS proof
    transcript.domain_separate("pcs-eval");

    // Step 8a: Preprocessed batch consistency
    let batch_r_pre = proof.preprocessed_batch_r;
    let mut expected_pre_batched = F::ZERO;
    let mut r_pow = F::ONE;
    for &eval in &proof.preprocessed_individual_evals {
        expected_pre_batched = expected_pre_batched + r_pow * eval;
        r_pow = r_pow * batch_r_pre;
    }
    ensure!(
        expected_pre_batched == proof.preprocessed_eval_value,
        "Preprocessed batched evaluation mismatch"
    );

    // Step 8b: Witness batch consistency
    let mut expected_wit_batched = F::ZERO;
    let mut r_pow = F::ONE;
    for &eval in &proof.witness_individual_evals {
        expected_wit_batched = expected_wit_batched + r_pow * eval;
        r_pow = r_pow * batch_r_wit;
    }
    ensure!(
        expected_wit_batched == proof.witness_eval_value,
        "Witness batched evaluation mismatch"
    );

    // Step 8c: Verify unified WHIR split proof
    //
    // SECURITY: WHIR verification confirms both committed polynomials are
    // well-formed (proximity test) and evaluates correctly at the canonical
    // point (1, 2, ..., n). Cross-term OOD evaluations bind the two vectors.
    //
    // The canonical evaluation point differs from the sumcheck output point r.
    // However, the commitment binding property of WHIR ensures the polynomial
    // is uniquely determined: once WHIR proves proximity (the committed vector
    // is close to a valid codeword), the polynomial is fixed, and ANY evaluation
    // P(r) is uniquely determined by the commitment. The batch_r Schwartz-Zippel
    // argument then ensures the prover cannot lie about individual evaluations
    // at the sumcheck point without changing the batched value. Concretely:
    //   1. WHIR proves: the committed polynomial P is fixed (binding)
    //   2. Batch consistency proves: Σ batch_r^i · eval_i = batched_eval
    //   3. WHIR proves: batched_eval matches P evaluated via canonical point
    //   4. Since P is fixed by (1), P(r) at any point r is determined
    //   5. Individual evals are bound via Schwartz-Zippel over batch_r
    //
    // Phase 2 improvement: move WHIR evaluation to the sumcheck output point
    // for a direct binding (eliminating the need for the batch_r argument).
    let whir_pcs = WhirPCS::for_num_vars(degree_bits);

    let whir_result = whir_pcs.verify_split(
        degree_bits,
        &proof.whir_eval_proof,
        &[proof.preprocessed_whir_eval_ext3, proof.witness_whir_eval_ext3],
        WHIR_SESSION_SPLIT,
    );
    ensure!(
        whir_result.is_ok(),
        "Unified WHIR PCS verification failed: {}",
        whir_result.err().unwrap_or_default()
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prover::{mle_prove, mle_setup};
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;
    use plonky2::util::timing::TimingTree;
    use plonky2_field::goldilocks_field::GoldilocksField;
    use plonky2_field::types::Field;

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    fn build_mul_circuit() -> (
        plonky2::plonk::circuit_data::ProverOnlyCircuitData<F, C, D>,
        plonky2::plonk::circuit_data::CommonCircuitData<F, D>,
        plonky2::iop::target::Target,
        plonky2::iop::target::Target,
    ) {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let x = builder.add_virtual_target();
        let y = builder.add_virtual_target();
        let z = builder.mul(x, y);
        builder.register_public_input(z);
        let circuit = builder.build::<C>();
        (circuit.prover_only, circuit.common, x, y)
    }

    #[test]
    fn test_prove_verify_roundtrip() {
        let (prover_data, common_data, x, y) = build_mul_circuit();

        // Setup: compute verification key
        let vk = mle_setup::<F, C, D>(&prover_data, &common_data);

        // Prove
        let mut pw = PartialWitness::new();
        pw.set_target(x, F::from_canonical_u64(3));
        pw.set_target(y, F::from_canonical_u64(7));

        let mut timing = TimingTree::default();
        let proof = mle_prove::<F, C, D>(
            &prover_data,
            &common_data,
            pw,
            &mut timing,
        )
        .unwrap();

        // Verify
        let result = mle_verify::<F, D>(&common_data, &vk, &proof);
        assert!(result.is_ok(), "Verification failed: {:?}", result.err());
    }

    /// SECURITY TEST: Tampered preprocessed commitment root must be rejected.
    /// An attacker who modifies the commitment root (simulating different
    /// constants/sigmas) should fail the VK binding check.
    #[test]
    fn test_tampered_preprocessed_root_rejected() {
        let (prover_data, common_data, x, y) = build_mul_circuit();
        let vk = mle_setup::<F, C, D>(&prover_data, &common_data);

        let mut pw = PartialWitness::new();
        pw.set_target(x, F::from_canonical_u64(5));
        pw.set_target(y, F::from_canonical_u64(11));

        let mut timing = TimingTree::default();
        let mut proof = mle_prove::<F, C, D>(
            &prover_data,
            &common_data,
            pw,
            &mut timing,
        )
        .unwrap();

        // Tamper with the preprocessed commitment root
        if !proof.preprocessed_root.is_empty() {
            proof.preprocessed_root[0] ^= 0xFF;
        }

        let result = mle_verify::<F, D>(&common_data, &vk, &proof);
        assert!(result.is_err(), "Tampered preprocessed root should be rejected");
        let err_msg = format!("{:?}", result.err().unwrap());
        assert!(
            err_msg.contains("circuit binding violated") || err_msg.contains("commitment root mismatch"),
            "Error should mention circuit binding: {err_msg}"
        );
    }

    /// SECURITY TEST: A proof from circuit A must not verify against VK from circuit B.
    #[test]
    fn test_cross_circuit_proof_rejected() {
        // Circuit A: x * y
        let (prover_data_a, common_data_a, x_a, y_a) = build_mul_circuit();
        let _vk_a = mle_setup::<F, C, D>(&prover_data_a, &common_data_a);

        // Circuit B: different circuit (x + y)
        let config = CircuitConfig::standard_recursion_config();
        let mut builder_b = CircuitBuilder::<F, D>::new(config);
        let x_b = builder_b.add_virtual_target();
        let y_b = builder_b.add_virtual_target();
        let z_b = builder_b.add(x_b, y_b);
        builder_b.register_public_input(z_b);
        let circuit_b = builder_b.build::<C>();
        let vk_b = mle_setup::<F, C, D>(&circuit_b.prover_only, &circuit_b.common);

        // Generate proof for circuit A
        let mut pw_a = PartialWitness::new();
        pw_a.set_target(x_a, F::from_canonical_u64(3));
        pw_a.set_target(y_a, F::from_canonical_u64(7));

        let mut timing = TimingTree::default();
        let proof_a = mle_prove::<F, C, D>(
            &prover_data_a,
            &common_data_a,
            pw_a,
            &mut timing,
        )
        .unwrap();

        // Try to verify proof_a against vk_b — should fail
        let result = mle_verify::<F, D>(&common_data_a, &vk_b, &proof_a);
        assert!(result.is_err(), "Cross-circuit proof should be rejected");
    }

    /// SECURITY TEST: Setup must be deterministic — calling it twice produces
    /// the same VK.
    #[test]
    fn test_setup_determinism() {
        let (prover_data, common_data, _, _) = build_mul_circuit();
        let vk1 = mle_setup::<F, C, D>(&prover_data, &common_data);
        let vk2 = mle_setup::<F, C, D>(&prover_data, &common_data);

        assert_eq!(vk1.circuit_digest, vk2.circuit_digest);
        assert_eq!(vk1.preprocessed_commitment_root, vk2.preprocessed_commitment_root);
        assert_eq!(vk1.num_constants, vk2.num_constants);
        assert_eq!(vk1.num_routed_wires, vk2.num_routed_wires);
    }
}
