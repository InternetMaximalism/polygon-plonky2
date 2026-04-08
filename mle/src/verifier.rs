/// MLE proof verifier.
///
/// Verifies the complete MLE proof by:
/// 1. Reconstructing the Fiat-Shamir transcript
/// 2. Verifying the zero-check sumcheck
/// 3. Verifying the permutation check sumcheck
/// 4. Verifying the PCS evaluation proof
/// 5. Checking the final sumcheck evaluation against opened values
use anyhow::{ensure, Result};
use plonky2::hash::hash_types::RichField;
use plonky2::plonk::circuit_data::CommonCircuitData;
use plonky2_field::extension::Extendable;
use plonky2_field::types::Field;

use crate::commitment::whir_pcs::WhirPCS;
use crate::eq_poly;
use crate::proof::MleProof;
use crate::sumcheck::verifier::verify_sumcheck;
use crate::transcript::Transcript;

/// Verify an MLE proof for a Plonky2 circuit.
pub fn mle_verify<F: RichField + Extendable<D>, const D: usize>(
    common_data: &CommonCircuitData<F, D>,
    proof: &MleProof<F>,
) -> Result<()> {
    let degree_bits = plonky2_util::log2_strict(
        common_data.degree(),
    );

    // Step 1: Reconstruct transcript (must match prover exactly)
    // SECURITY: Absorb circuit_digest first to verify this proof is for the
    // expected circuit. The circuit_digest is a hash of the verifying key
    // (constants, sigmas, circuit topology).
    let mut transcript = Transcript::new();
    transcript.domain_separate("circuit");
    transcript.absorb_field_vec(&proof.circuit_digest);
    transcript.absorb_field_vec(&proof.public_inputs);

    // Step 2: Derive batch_r
    transcript.domain_separate("batch-commit");
    let batch_r: F = transcript.squeeze_challenge();
    ensure!(
        batch_r == proof.batch_r,
        "Batch random scalar mismatch"
    );

    // Absorb commitment
    let commitment_bytes = &proof.commitment.proof_bytes[..32.min(proof.commitment.proof_bytes.len())];
    transcript.absorb_bytes(commitment_bytes);

    // Step 3: Re-derive challenges
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

    // Step 4: Verify permutation check sumcheck
    transcript.domain_separate("permutation");
    let perm_proof = &proof.permutation_proof;

    // Verify the permutation check: Σ_b h(b) = 0 via plain sumcheck.
    // SECURITY: The claimed sum MUST be 0 for a valid permutation.
    // The logUp terms telescope across permutation cycles, giving Σ h(b) = 0.
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

    // Step 4b: Verify lookup proofs (if any)
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

    // Step 4c: Extension field combination challenge (must match prover)
    transcript.domain_separate("extension-combine");
    let _ext_challenge: F = transcript.squeeze_challenge();

    // Step 5: Verify zero-check sumcheck (claimed sum = 0 for valid circuit)
    transcript.domain_separate("zero-check");

    // The claimed sum should be 0 for a valid zero-check
    let zero_claim = F::ZERO;
    let constraint_result = verify_sumcheck(
        &proof.constraint_proof,
        zero_claim,
        degree_bits,
        &mut transcript,
    );

    let (sumcheck_challenges, final_eval) = constraint_result
        .map_err(|e| anyhow::anyhow!("Constraint sumcheck verification failed: {}", e))?;

    // Step 6: Verify the final sumcheck evaluation.
    // SECURITY: final_eval must equal eq(τ, r) · C(r), where C(r) is the
    // PCS-bound constraint evaluation supplied by the prover.
    let eq_at_r = eq_poly::eq_eval(&tau, &sumcheck_challenges);
    let expected_final = eq_at_r * proof.pcs_constraint_eval;
    ensure!(
        expected_final == final_eval,
        "Constraint final eval mismatch: eq(τ,r)*C(r) != finalEval"
    );

    // Step 6b: Verify the permutation final evaluation.
    // SECURITY: The permutation sumcheck's final eval must equal h(r_perm),
    // the PCS-bound permutation numerator evaluation.
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

    // Step 7: Verify PCS evaluation proof
    transcript.domain_separate("pcs-eval");

    // Recompute batched evaluation from individual evals
    let mut expected_batched = F::ZERO;
    let mut r_pow = F::ONE;
    for &eval in &proof.individual_evals {
        expected_batched = expected_batched + r_pow * eval;
        r_pow = r_pow * batch_r;
    }
    ensure!(
        expected_batched == proof.eval_value,
        "Batched evaluation mismatch"
    );

    // Verify WHIR proof: the commitment + evaluation proof with eval binding.
    // SECURITY: The evaluation point is the sumcheck output point, which is
    // Fiat-Shamir derived. WHIR's FinalClaim verifies that the committed
    // polynomial evaluates to eval_value at sumcheck_challenges.
    let whir_pcs = WhirPCS::for_num_vars(degree_bits);
    // SECURITY: Verify WHIR proof with evaluation binding at the canonical point.
    // The prover used prove_at_point() which binds the commitment to an evaluation.
    // We pass the Ext3 evaluation value from the proof for FinalClaim verification.
    let whir_result = whir_pcs.verify(
        degree_bits,
        &proof.eval_proof,
        None,  // canonical point (matching prover's None)
        Some(proof.whir_eval_ext3),
    );
    ensure!(
        whir_result.is_ok(),
        "WHIR PCS verification failed: {}",
        whir_result.err().unwrap_or_default()
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prover::mle_prove;
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

    #[test]
    fn test_prove_verify_roundtrip() {
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

        // Verify
        let result = mle_verify::<F, D>(&circuit.common, &proof);
        assert!(result.is_ok(), "Verification failed: {:?}", result.err());
    }
}
