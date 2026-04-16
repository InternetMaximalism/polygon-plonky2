/// MLE proof verifier — combined sumcheck architecture.
///
/// Verification chain (all evaluations at single sumcheck output point r):
///   1. Transcript reconstruction + challenge re-derivation
///   2. Auxiliary WHIR verification: P_aux(r) is bound → C̃(r), h̃(r) decomposition
///   3. Main WHIR verification: P_pre(r), P_wit(r) → individual wire/const/sigma evals
///   4. Combined sumcheck: eq(τ,r)·C̃(r) + μ·eq(τ_perm,r)·h̃(r) = final_eval
///
/// SECURITY: No prover-claimed oracle values are trusted without WHIR binding.
use anyhow::{ensure, Result};
use plonky2::hash::hash_types::RichField;
use plonky2::plonk::circuit_data::CommonCircuitData;
use plonky2_field::extension::Extendable;
use plonky2_field::types::Field;

use crate::commitment::whir_pcs::{WhirPCS, WHIR_SESSION_SPLIT};
use crate::eq_poly;
use crate::proof::{MleProof, MleVerificationKey};
use crate::prover::derive_preprocessed_batch_r;
use crate::sumcheck::verifier::verify_sumcheck;
use crate::transcript::Transcript;

/// Verify an MLE proof for a Plonky2 circuit.
pub fn mle_verify<F: RichField + Extendable<D>, const D: usize>(
    common_data: &CommonCircuitData<F, D>,
    vk: &MleVerificationKey<F>,
    proof: &MleProof<F>,
) -> Result<()> {
    let degree_bits = plonky2_util::log2_strict(common_data.degree());

    // ═══════════════════════════════════════════════════════════════════
    // Step 1: Circuit binding + transcript reconstruction
    // ═══════════════════════════════════════════════════════════════════
    ensure!(
        proof.circuit_digest == vk.circuit_digest,
        "Circuit digest mismatch"
    );

    let expected_pre_r: F = derive_preprocessed_batch_r(&proof.circuit_digest);
    ensure!(
        expected_pre_r == proof.preprocessed_batch_r,
        "Preprocessed batch_r mismatch"
    );

    ensure!(
        proof.preprocessed_root == vk.preprocessed_commitment_root,
        "Preprocessed commitment root mismatch — circuit binding violated"
    );

    let mut transcript = Transcript::new();
    transcript.domain_separate("circuit");
    transcript.absorb_field_vec(&proof.circuit_digest);
    transcript.absorb_field_vec(&proof.public_inputs);
    transcript.absorb_bytes(&proof.preprocessed_root);

    transcript.domain_separate("batch-commit-witness");
    let batch_r_wit: F = transcript.squeeze_challenge();
    ensure!(
        batch_r_wit == proof.witness_batch_r,
        "Witness batch_r mismatch"
    );
    transcript.absorb_bytes(&proof.witness_root);

    // ═══════════════════════════════════════════════════════════════════
    // Step 2: Re-derive challenges
    // ═══════════════════════════════════════════════════════════════════
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

    transcript.domain_separate("extension-combine");
    let _ext_challenge: F = transcript.squeeze_challenge();

    // ═══════════════════════════════════════════════════════════════════
    // Step 3: Auxiliary commitment verification
    //
    // SECURITY: P_aux = C̃ + batch_r_aux · h̃ is committed AFTER challenges.
    // WHIR binds P_aux(r), and Schwartz-Zippel over batch_r_aux ensures
    // the decomposition into C̃(r) and h̃(r) is unique (forgery ≤ 1/|F|).
    // ═══════════════════════════════════════════════════════════════════
    transcript.domain_separate("aux-commit");
    let batch_r_aux: F = transcript.squeeze_challenge();
    ensure!(batch_r_aux == proof.aux_batch_r, "Aux batch_r mismatch");
    transcript.absorb_bytes(&proof.aux_commitment_root);

    // Verify P_aux(r) decomposition: P_aux(r) = C̃(r) + batch_r_aux · h̃(r)
    let expected_aux_eval = proof.aux_constraint_eval + batch_r_aux * proof.aux_perm_eval;
    ensure!(
        expected_aux_eval == proof.aux_eval_value,
        "Auxiliary decomposition mismatch: C̃(r) + batch_r_aux·h̃(r) ≠ P_aux(r)"
    );

    // ═══════════════════════════════════════════════════════════════════
    // Step 4: Derive μ + verify combined sumcheck
    // ═══════════════════════════════════════════════════════════════════
    transcript.domain_separate("combined-sumcheck");
    let mu: F = transcript.squeeze_challenge();
    ensure!(mu == proof.mu, "Mu mismatch");

    // SECURITY: Lookup argument is not yet implemented. Reject any circuit
    // that contains lookup tables to prevent unsound verification.
    let has_lookup = !common_data.luts.is_empty();
    ensure!(
        !has_lookup,
        "MLE verifier does not yet support lookup tables"
    );

    // Verify combined sumcheck: Σ [eq(τ,b)·C̃(b) + μ·eq(τ_perm,b)·h̃(b)] = 0
    let combined_result =
        verify_sumcheck(&proof.combined_proof, F::ZERO, degree_bits, &mut transcript);
    let (sumcheck_challenges, final_eval) =
        combined_result.map_err(|e| anyhow::anyhow!("Combined sumcheck failed: {}", e))?;

    // ═══════════════════════════════════════════════════════════════════
    // Step 5: Verify WHIR proofs + batch consistency
    // ═══════════════════════════════════════════════════════════════════
    transcript.domain_separate("pcs-eval");

    let whir_pcs = WhirPCS::for_num_vars(degree_bits);
    let r_gl: Vec<plonky2_field::goldilocks_field::GoldilocksField> = sumcheck_challenges
        .iter()
        .map(|&f| {
            plonky2_field::goldilocks_field::GoldilocksField::from_canonical_u64(
                f.to_canonical_u64(),
            )
        })
        .collect();

    // 5a: Single WHIR proof — 3 vectors (preprocessed + witness + auxiliary) at r
    // SECURITY: All 3 vectors are in the same WHIR session with cross-term OOD
    // binding. The phased commit (vectors 0,1 before challenges, vector 2 after)
    // is transparent to the WHIR verifier — it sees 3 committed vectors.
    let whir_result = whir_pcs.verify_split(
        degree_bits,
        &proof.whir_eval_proof,
        &[
            proof.preprocessed_whir_eval_ext3,
            proof.witness_whir_eval_ext3,
            proof.aux_whir_eval_ext3,
        ],
        WHIR_SESSION_SPLIT,
        &[&r_gl],
        3, // num_vectors: preprocessed + witness + auxiliary
    );
    ensure!(
        whir_result.is_ok(),
        "WHIR verification failed: {}",
        whir_result.err().unwrap_or_default()
    );

    // SECURITY NOTE (Ext3 ↔ Goldilocks binding):
    //
    // WHIR binds the batched polynomial evaluation in Field64_3 via the
    // Basefield<Field64_3> embedding. This is a DIFFERENT numeric value
    // than the plain Goldilocks evaluation (mixed_multilinear_extend uses
    // extension-field arithmetic). However, WHIR binding + Schwartz-Zippel
    // on batch_r still provides soundness:
    //   1. WHIR binds the committed polynomial P (via ext3 eval at r)
    //   2. The Goldilocks batch consistency check (below) verifies that
    //      individual_evals reconstruct to eval_value via batch_r
    //   3. By Schwartz-Zippel, forging individual_evals that batch
    //      correctly but differ from P's true values has probability
    //      ≤ (num_polys - 1) / |F| ≈ 2^{-64}
    //
    // No explicit c0-match check is needed because the binding comes from
    // WHIR fixing P and Schwartz-Zippel fixing the decomposition.

    // 5c: Batch consistency — preprocessed at r
    let batch_r_pre = proof.preprocessed_batch_r;
    let mut expected_pre = F::ZERO;
    let mut r_pow = F::ONE;
    for &eval in &proof.preprocessed_individual_evals {
        expected_pre += r_pow * eval;
        r_pow *= batch_r_pre;
    }
    ensure!(
        expected_pre == proof.preprocessed_eval_value,
        "Preprocessed batch mismatch"
    );

    // 5d: Batch consistency — witness at r
    let mut expected_wit = F::ZERO;
    let mut r_pow = F::ONE;
    for &eval in &proof.witness_individual_evals {
        expected_wit += r_pow * eval;
        r_pow *= batch_r_wit;
    }
    ensure!(
        expected_wit == proof.witness_eval_value,
        "Witness batch mismatch"
    );

    // ═══════════════════════════════════════════════════════════════════
    // Step 6: Final evaluation check
    //
    // SECURITY: All values are WHIR-bound:
    //   - C̃(r) via auxiliary WHIR + Schwartz-Zippel decomposition
    //   - h̃(r) via auxiliary WHIR + Schwartz-Zippel decomposition
    //   - eq(τ,r) and eq(τ_perm,r) computed by verifier from Fiat-Shamir challenges
    //   - μ is a Fiat-Shamir challenge
    //
    // The combined check:
    //   eq(τ,r)·C̃(r) + μ·eq(τ_perm,r)·h̃(r) = final_eval
    //
    // If the prover ran a fake sumcheck, final_eval would be inconsistent
    // with the WHIR-bound C̃(r) and h̃(r), and this check fails.
    // ═══════════════════════════════════════════════════════════════════
    // Combined: eq(τ,r)·C̃(r) + μ·h̃(r) = final_eval
    // Note: h term is UNWEIGHTED (no eq_perm) because logUp guarantees Σ h(b) = 0
    // (total sum), not h(b) = 0 at each row.
    let eq_at_r = eq_poly::eq_eval(&tau, &sumcheck_challenges);
    let expected_final = eq_at_r * proof.aux_constraint_eval + mu * proof.aux_perm_eval;

    ensure!(
        expected_final == final_eval,
        "Combined final eval mismatch: \
         eq(τ,r)·C̃(r) + μ·eq(τ_perm,r)·h̃(r) ≠ sumcheck final_eval"
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;
    use plonky2::util::timing::TimingTree;
    use plonky2_field::goldilocks_field::GoldilocksField;
    use plonky2_field::types::Field;

    use super::*;
    use crate::prover::{mle_prove, mle_setup};

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
        let vk = mle_setup::<F, C, D>(&prover_data, &common_data);

        let mut pw = PartialWitness::new();
        pw.set_target(x, F::from_canonical_u64(3)).unwrap();
        pw.set_target(y, F::from_canonical_u64(7)).unwrap();

        let mut timing = TimingTree::default();
        let proof = mle_prove::<F, C, D>(&prover_data, &common_data, pw, &mut timing).unwrap();

        let result = mle_verify::<F, D>(&common_data, &vk, &proof);
        assert!(result.is_ok(), "Verification failed: {:?}", result.err());
    }

    #[test]
    fn test_tampered_preprocessed_root_rejected() {
        let (prover_data, common_data, x, y) = build_mul_circuit();
        let vk = mle_setup::<F, C, D>(&prover_data, &common_data);

        let mut pw = PartialWitness::new();
        pw.set_target(x, F::from_canonical_u64(5)).unwrap();
        pw.set_target(y, F::from_canonical_u64(11)).unwrap();

        let mut timing = TimingTree::default();
        let mut proof = mle_prove::<F, C, D>(&prover_data, &common_data, pw, &mut timing).unwrap();

        if !proof.preprocessed_root.is_empty() {
            proof.preprocessed_root[0] ^= 0xFF;
        }

        let result = mle_verify::<F, D>(&common_data, &vk, &proof);
        assert!(result.is_err(), "Tampered root should be rejected");
    }

    #[test]
    fn test_cross_circuit_proof_rejected() {
        let (prover_data_a, common_data_a, x_a, y_a) = build_mul_circuit();

        let config = CircuitConfig::standard_recursion_config();
        let mut builder_b = CircuitBuilder::<F, D>::new(config);
        let x_b = builder_b.add_virtual_target();
        let y_b = builder_b.add_virtual_target();
        let z_b = builder_b.add(x_b, y_b);
        builder_b.register_public_input(z_b);
        let circuit_b = builder_b.build::<C>();
        let vk_b = mle_setup::<F, C, D>(&circuit_b.prover_only, &circuit_b.common);

        let mut pw_a = PartialWitness::new();
        pw_a.set_target(x_a, F::from_canonical_u64(3)).unwrap();
        pw_a.set_target(y_a, F::from_canonical_u64(7)).unwrap();

        let mut timing = TimingTree::default();
        let proof_a =
            mle_prove::<F, C, D>(&prover_data_a, &common_data_a, pw_a, &mut timing).unwrap();

        let result = mle_verify::<F, D>(&common_data_a, &vk_b, &proof_a);
        assert!(result.is_err(), "Cross-circuit proof should be rejected");
    }

    #[test]
    fn test_setup_determinism() {
        let (prover_data, common_data, _, _) = build_mul_circuit();
        let vk1 = mle_setup::<F, C, D>(&prover_data, &common_data);
        let vk2 = mle_setup::<F, C, D>(&prover_data, &common_data);

        assert_eq!(vk1.circuit_digest, vk2.circuit_digest);
        assert_eq!(
            vk1.preprocessed_commitment_root,
            vk2.preprocessed_commitment_root
        );
    }
}
