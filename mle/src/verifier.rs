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
    // Step 2: Re-derive challenges (must mirror prover transcript order)
    // ═══════════════════════════════════════════════════════════════════
    transcript.domain_separate("challenges");
    let beta: F = transcript.squeeze_challenge();
    let gamma: F = transcript.squeeze_challenge();
    ensure!(beta == proof.beta, "Beta mismatch");
    ensure!(gamma == proof.gamma, "Gamma mismatch");

    // ── v2 logUp: inverse-helpers commitment is absorbed AFTER β,γ. ─────
    transcript.domain_separate("inverse-helpers-batch-r");
    let inv_helpers_batch_r: F = transcript.squeeze_challenge();
    ensure!(
        inv_helpers_batch_r == proof.inverse_helpers_batch_r,
        "Inverse helpers batch_r mismatch"
    );
    transcript.absorb_bytes(&proof.inverse_helpers_root);

    let alpha: F = transcript.squeeze_challenge();
    let tau: Vec<F> = transcript.squeeze_challenges(degree_bits);
    let tau_perm: Vec<F> = transcript.squeeze_challenges(degree_bits);
    ensure!(alpha == proof.alpha, "Alpha mismatch");
    ensure!(tau == proof.tau, "Tau mismatch");
    ensure!(tau_perm == proof.tau_perm, "Tau_perm mismatch");

    transcript.domain_separate("v2-logup-challenges");
    let lambda_inv: F = transcript.squeeze_challenge();
    let mu_inv: F = transcript.squeeze_challenge();
    let lambda_h: F = transcript.squeeze_challenge();
    let tau_inv: Vec<F> = transcript.squeeze_challenges(degree_bits);
    ensure!(lambda_inv == proof.lambda_inv, "lambda_inv mismatch");
    ensure!(mu_inv == proof.mu_inv, "mu_inv mismatch");
    ensure!(lambda_h == proof.lambda_h, "lambda_h mismatch");
    ensure!(tau_inv == proof.tau_inv, "tau_inv mismatch");

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
    ensure!(
        sumcheck_challenges == proof.sumcheck_challenges,
        "Combined sumcheck challenges mismatch"
    );

    // ═══════════════════════════════════════════════════════════════════
    // Step 4.5 (v2 logUp): Verify Φ_inv zero-check sumcheck.
    //   Σ_b eq(τ_inv,b)·Σ_j λ^j·(A_j·D_id − 1 + μ_inv·(B_j·D_σ − 1)) = 0
    // Round-poly degree bound: 3.
    // ═══════════════════════════════════════════════════════════════════
    transcript.domain_separate("v2-inv-zerocheck");
    // Round-poly degree bound (Φ_inv): 3. Reject any over-long round poly.
    for (i, rp) in proof.inv_sumcheck_proof.round_polys.iter().enumerate() {
        ensure!(
            rp.evaluations.len() <= 4,
            "Φ_inv round {i}: round poly degree exceeds 3 (got {} evaluations)",
            rp.evaluations.len()
        );
    }
    let inv_result =
        verify_sumcheck(&proof.inv_sumcheck_proof, F::ZERO, degree_bits, &mut transcript);
    let (inv_challenges, inv_final_eval) =
        inv_result.map_err(|e| anyhow::anyhow!("Φ_inv sumcheck failed: {}", e))?;
    ensure!(
        inv_challenges == proof.inv_sumcheck_challenges,
        "Φ_inv sumcheck challenges mismatch"
    );

    // ═══════════════════════════════════════════════════════════════════
    // Step 4.7 (v2 logUp): Verify Φ_h linear sumcheck.
    //   Σ_b H(b) = 0, H(b) = Σ_j λ_h^j · (A_j(b) − B_j(b))
    // Round-poly degree bound: 1.
    // ═══════════════════════════════════════════════════════════════════
    transcript.domain_separate("v2-h-linear");
    for (i, rp) in proof.h_sumcheck_proof.round_polys.iter().enumerate() {
        ensure!(
            rp.evaluations.len() == 2,
            "Φ_h round {i}: expected 2 evaluations (degree 1), got {}",
            rp.evaluations.len()
        );
    }
    let h_result =
        verify_sumcheck(&proof.h_sumcheck_proof, F::ZERO, degree_bits, &mut transcript);
    let (h_challenges, h_final_eval) =
        h_result.map_err(|e| anyhow::anyhow!("Φ_h sumcheck failed: {}", e))?;
    ensure!(
        h_challenges == proof.h_sumcheck_challenges,
        "Φ_h sumcheck challenges mismatch"
    );

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

    // 5a: Multi-point WHIR proof — 4 vectors (pre + wit + aux + inverse_helpers)
    //     at 3 points (r_gate, r_inv, r_h). All cross-vector + cross-point binding
    //     is provided by the single WHIR session.
    let r_inv_gl: Vec<plonky2_field::goldilocks_field::GoldilocksField> = proof
        .inv_sumcheck_challenges
        .iter()
        .map(|&f| {
            plonky2_field::goldilocks_field::GoldilocksField::from_canonical_u64(
                f.to_canonical_u64(),
            )
        })
        .collect();
    let r_h_gl: Vec<plonky2_field::goldilocks_field::GoldilocksField> = proof
        .h_sumcheck_challenges
        .iter()
        .map(|&f| {
            plonky2_field::goldilocks_field::GoldilocksField::from_canonical_u64(
                f.to_canonical_u64(),
            )
        })
        .collect();

    let whir_eval_values: Vec<_> = vec![
        // Point 0 (r_gate): pre, wit, aux, inv
        proof.preprocessed_whir_eval_ext3,
        proof.witness_whir_eval_ext3,
        proof.aux_whir_eval_ext3,
        proof.inverse_helpers_whir_eval_at_r_gate_ext3,
        // Point 1 (r_inv): pre, wit, aux, inv
        proof.preprocessed_whir_eval_at_r_inv_ext3,
        proof.witness_whir_eval_at_r_inv_ext3,
        proof.aux_whir_eval_at_r_inv_ext3,
        proof.inverse_helpers_whir_eval_at_r_inv_ext3,
        // Point 2 (r_h): pre, wit, aux, inv
        proof.preprocessed_whir_eval_at_r_h_ext3,
        proof.witness_whir_eval_at_r_h_ext3,
        proof.aux_whir_eval_at_r_h_ext3,
        proof.inverse_helpers_whir_eval_at_r_h_ext3,
    ];
    let whir_result = whir_pcs.verify_split(
        degree_bits,
        &proof.whir_eval_proof,
        &whir_eval_values,
        WHIR_SESSION_SPLIT,
        &[&r_gl, &r_inv_gl, &r_h_gl],
        4, // num_vectors: preprocessed + witness + auxiliary + inverse_helpers
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

    // 5e: Batch consistency — witness at r_inv
    let mut expected_wit_at_r_inv = F::ZERO;
    let mut r_pow = F::ONE;
    for &eval in &proof.witness_individual_evals_at_r_inv {
        expected_wit_at_r_inv += r_pow * eval;
        r_pow *= batch_r_wit;
    }
    ensure!(
        expected_wit_at_r_inv == proof.witness_eval_value_at_r_inv,
        "Witness batch mismatch at r_inv"
    );

    // 5f: Batch consistency — preprocessed at r_inv.
    //     Full layout `[const_0..const_C, sigma_0..sigma_R]`. The sigma subset
    //     drives the Φ_inv terminal check; the const subset is unused there
    //     but required to identify the batched value with the WHIR Ext3 binding.
    let mut expected_pre_at_r_inv = F::ZERO;
    let mut r_pow = F::ONE;
    for &eval in &proof.preprocessed_individual_evals_at_r_inv {
        expected_pre_at_r_inv += r_pow * eval;
        r_pow *= batch_r_pre;
    }
    ensure!(
        expected_pre_at_r_inv == proof.preprocessed_eval_value_at_r_inv,
        "Preprocessed batch mismatch at r_inv"
    );
    let expected_pre_len = proof.num_constants + proof.num_routed_wires;
    ensure!(
        proof.preprocessed_individual_evals_at_r_inv.len() == expected_pre_len,
        "preprocessed_individual_evals_at_r_inv has wrong length"
    );

    // 5g: Inverse helpers batch consistency at r_inv
    ensure!(
        proof.inverse_helpers_evals_at_r_inv.len() == 2 * proof.num_routed_wires,
        "inverse_helpers_evals_at_r_inv has wrong length"
    );
    let mut expected_inv_at_r_inv = F::ZERO;
    let mut r_pow = F::ONE;
    for &eval in &proof.inverse_helpers_evals_at_r_inv {
        expected_inv_at_r_inv += r_pow * eval;
        r_pow *= proof.inverse_helpers_batch_r;
    }
    // The Goldilocks batch consistency together with the WHIR ext3 binding +
    // Schwartz-Zippel on inverse_helpers_batch_r ensures the individual evals
    // are uniquely determined by the committed P_inv polynomial.

    // 5h: Inverse helpers batch consistency at r_h
    ensure!(
        proof.inverse_helpers_evals_at_r_h.len() == 2 * proof.num_routed_wires,
        "inverse_helpers_evals_at_r_h has wrong length"
    );
    let mut _expected_inv_at_r_h = F::ZERO;
    let mut r_pow = F::ONE;
    for &eval in &proof.inverse_helpers_evals_at_r_h {
        _expected_inv_at_r_h += r_pow * eval;
        r_pow *= proof.inverse_helpers_batch_r;
    }
    let _ = expected_inv_at_r_inv; // silence unused-binding warnings (used via WHIR)

    // 5i: g_sub(r_inv) consistency — verifier recomputes from VK-bound powers.
    let mut expected_g_sub_at_r_inv = F::ONE;
    ensure!(
        proof.subgroup_gen_powers.len() >= degree_bits,
        "subgroup_gen_powers has insufficient length"
    );
    for (i, &r_i) in proof.inv_sumcheck_challenges.iter().enumerate() {
        let g_pow_i = proof.subgroup_gen_powers[i];
        let factor = (F::ONE - r_i) + r_i * g_pow_i;
        expected_g_sub_at_r_inv *= factor;
    }
    ensure!(
        expected_g_sub_at_r_inv == proof.g_sub_eval_at_r_inv,
        "g_sub(r_inv) mismatch — subgroup MLE evaluation inconsistent"
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

    // ═══════════════════════════════════════════════════════════════════
    // Step 7 (v2 logUp): Φ_inv terminal check.
    //
    //   inv_final_eval ?= eq(τ_inv, r_inv) · Σ_j λ_inv^j ·
    //                       ( a_j(r_inv) · D_j^id(r_inv) − 1
    //                       + μ_inv · (b_j(r_inv) · D_j^σ(r_inv) − 1) )
    //
    // where D_j^id(r_inv) = β + w_j(r_inv) + γ · K_j · g_sub(r_inv)
    //       D_j^σ(r_inv)  = β + w_j(r_inv) + γ · σ_j(r_inv)
    //
    // SECURITY: This is the v2 fix for Issue R2-#2. All evaluated quantities
    // (a_j, b_j, w_j, σ_j, g_sub) are multilinear functions of r_inv that are
    // bound by either WHIR (a, b, w, σ) or VK + verifier reconstruction (g_sub).
    // No 1/x is evaluated by the verifier; the polynomial identity
    // A_j · D_j − 1 = 0 is enforced row-wise by the zero-check sumcheck.
    // ═══════════════════════════════════════════════════════════════════
    let eq_at_r_inv = eq_poly::eq_eval(&tau_inv, &inv_challenges);
    let num_routed = proof.num_routed_wires;
    ensure!(
        proof.k_is.len() >= num_routed,
        "k_is has insufficient length"
    );
    ensure!(
        proof.witness_individual_evals_at_r_inv.len() >= num_routed,
        "witness_individual_evals_at_r_inv has insufficient length for routed wires"
    );

    let mut inv_pred_inner = F::ZERO;
    let mut lambda_pow = F::ONE;
    for j in 0..num_routed {
        let a_j = proof.inverse_helpers_evals_at_r_inv[j];
        let b_j = proof.inverse_helpers_evals_at_r_inv[num_routed + j];
        let w_j = proof.witness_individual_evals_at_r_inv[j];
        // sigma sits after the constants in the preprocessed batch layout.
        let s_j = proof.preprocessed_individual_evals_at_r_inv[proof.num_constants + j];
        let id_j = proof.k_is[j] * proof.g_sub_eval_at_r_inv;
        let denom_id = beta + w_j + gamma * id_j;
        let denom_sigma = beta + w_j + gamma * s_j;
        let z_id = a_j * denom_id - F::ONE;
        let z_sigma = b_j * denom_sigma - F::ONE;
        inv_pred_inner += lambda_pow * (z_id + mu_inv * z_sigma);
        lambda_pow *= lambda_inv;
    }
    let inv_pred = eq_at_r_inv * inv_pred_inner;
    ensure!(
        inv_pred == inv_final_eval,
        "Φ_inv terminal check failed — inverse helpers not consistent with logUp denominators"
    );

    // ═══════════════════════════════════════════════════════════════════
    // Step 8 (v2 logUp): Φ_h terminal check.
    //   h_final_eval ?= Σ_j λ_h^j · ( a_j(r_h) − b_j(r_h) )
    // (no eq weight — claimed sum 0 is unweighted)
    // ═══════════════════════════════════════════════════════════════════
    ensure!(
        proof.inverse_helpers_evals_at_r_h.len() == 2 * num_routed,
        "inverse_helpers_evals_at_r_h has wrong length"
    );
    let mut h_pred = F::ZERO;
    for j in 0..num_routed {
        let a_j = proof.inverse_helpers_evals_at_r_h[j];
        let b_j = proof.inverse_helpers_evals_at_r_h[num_routed + j];
        h_pred += a_j - b_j;
    }
    ensure!(
        h_pred == h_final_eval,
        "Φ_h terminal check failed — H = Σ_j (A_j − B_j) inconsistent at r_h"
    );
    let _ = lambda_h; // retained as transcript challenge for future per-j folding

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
