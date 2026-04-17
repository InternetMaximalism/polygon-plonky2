/// Proof structure for the MLE-native proving system.
///
/// Architecture: Combined sumcheck (constraint + permutation) with single
/// output point r. Two WHIR proofs:
///   1. Main split-commit: preprocessed + witness polynomials
///   2. Auxiliary single-vector: C̃ + h̃ (constraint + permutation MLEs)
///
/// All evaluations are at the single sumcheck output point r, providing
/// direct WHIR binding for individual_evals, C̃(r), and h̃(r).
use plonky2_field::types::Field;
use whir::algebra::fields::Field64_3;

use crate::commitment::whir_pcs::WhirEvalProof;
use crate::permutation::lookup::LookupProof;
use crate::sumcheck::types::SumcheckProof;

/// Verification key for the MLE proving system.
///
/// Contains the WHIR commitment root for the preprocessed polynomials
/// (constants + sigmas), computed once during circuit setup.
///
/// SECURITY: The preprocessed_commitment_root binds the verifier to a specific
/// set of gate selectors, constant values, and permutation routing. Without this,
/// an attacker could substitute fabricated constants/sigmas that trivially satisfy
/// all constraints.
#[derive(Clone, Debug)]
pub struct MleVerificationKey<F: Field> {
    /// Circuit digest (verifying key hash) — 4 Goldilocks field elements.
    pub circuit_digest: Vec<F>,
    /// WHIR commitment root for the batched preprocessed polynomial.
    pub preprocessed_commitment_root: Vec<u8>,
    /// Number of constant columns in the circuit.
    pub num_constants: usize,
    /// Number of routed wire columns (sigma permutation columns).
    pub num_routed_wires: usize,
}

/// A complete MLE proof for a Plonky2 circuit.
///
/// SECURITY: All polynomial evaluations at the sumcheck output point r are
/// WHIR-bound. The verification chain:
///   1. Main WHIR binds P_pre(r), P_wit(r) → individual wire/const/sigma evals
///   2. Auxiliary WHIR binds P_aux(r) → C̃(r) and h̃(r) via batch decomposition
///   3. Combined sumcheck: eq(τ,r)·C̃(r) + μ·eq(τ_perm,r)·h̃(r) = final_eval
///   4. Verifier checks final_eval matches sumcheck output
///
/// No prover-claimed oracle values are trusted without WHIR binding.
#[derive(Clone, Debug)]
pub struct MleProof<F: Field> {
    /// Circuit digest (verifying key hash) — 4 Goldilocks field elements.
    pub circuit_digest: Vec<F>,

    // ── Main WHIR PCS (preprocessed + witness) ─────────────────────────
    /// Single WHIR evaluation proof covering both preprocessed and witness.
    pub whir_eval_proof: WhirEvalProof,
    /// Preprocessed commitment root (32 bytes, for VK binding check).
    pub preprocessed_root: Vec<u8>,
    /// Witness commitment root (32 bytes).
    pub witness_root: Vec<u8>,

    // ── Preprocessed batch evaluation at r ──────────────────────────────
    pub preprocessed_eval_value: F,
    pub preprocessed_batch_r: F,
    /// Individual evals at r: [const_0..const_C, sigma_0..sigma_R].
    pub preprocessed_individual_evals: Vec<F>,
    pub preprocessed_whir_eval_ext3: Field64_3,

    // ── Witness batch evaluation at r ───────────────────────────────────
    pub witness_eval_value: F,
    pub witness_batch_r: F,
    /// Individual evals at r: [wire_0..wire_W].
    pub witness_individual_evals: Vec<F>,
    pub witness_whir_eval_ext3: Field64_3,

    // ── Auxiliary polynomial (C̃ + h̃, 3rd vector in same WHIR proof) ───
    /// SECURITY: The auxiliary polynomial P_aux = C̃ + batch_r_aux · h̃ is the
    /// 3rd vector in the same WHIR split-commit proof. WHIR cross-term OOD
    /// binding + Schwartz-Zippel over batch_r_aux ensures C̃(r) and h̃(r) are
    /// uniquely determined (forgery probability ≤ 1/|F| ≈ 2^{-64}).
    pub aux_commitment_root: Vec<u8>,
    pub aux_batch_r: F,
    /// C̃(r) — constraint MLE evaluation at r, WHIR-bound.
    pub aux_constraint_eval: F,
    /// h̃(r) — permutation numerator MLE evaluation at r, WHIR-bound.
    pub aux_perm_eval: F,
    /// Auxiliary batched evaluation at r: P_aux(r) = C̃(r) + batch_r_aux · h̃(r).
    pub aux_eval_value: F,
    pub aux_whir_eval_ext3: Field64_3,

    // ── Sumcheck output ────────────────────────────────────────────────
    /// Combined sumcheck output point r.
    pub sumcheck_challenges: Vec<F>,

    // ── Combined sumcheck proof ────────────────────────────────────────
    /// Single sumcheck proof for: eq(τ,b)·C(b) + μ·eq(τ_perm,b)·h(b) = 0.
    pub combined_proof: SumcheckProof<F>,
    /// Lookup proofs (one per lookup table, empty if no lookups).
    pub lookup_proofs: Vec<LookupProof<F>>,

    // ── Public data ────────────────────────────────────────────────────
    pub public_inputs: Vec<F>,
    pub public_inputs_hash: plonky2::hash::hash_types::HashOut<F>,
    /// Fiat-Shamir challenges.
    pub alpha: F,
    pub beta: F,
    pub gamma: F,
    pub tau: Vec<F>,
    pub tau_perm: Vec<F>,
    /// Combined sumcheck combination scalar.
    pub mu: F,
    /// Circuit dimensions.
    pub num_wires: usize,
    pub num_routed_wires: usize,
    pub num_constants: usize,

    // ── Permutation argument context (Issue #2) ────────────────────────
    /// Coset shifts k_is from Plonky2's permutation routing
    /// (id[row][col] = k_is[col] * subgroup[row]). VK-bound public data.
    pub k_is: Vec<F>,
    /// Powers g^{2^i} of the multiplicative subgroup generator g,
    /// for i = 0..degree_bits. Used to evaluate the subgroup MLE at the
    /// sumcheck point r via Π_i ((1 - r_i) + r_i · g^{2^i}). VK-bound public data.
    pub subgroup_gen_powers: Vec<F>,

    // ═══════════════════════════════════════════════════════════════════
    // v2 logUp soundness fix — Issue R2-#2 (paper §4.2)
    //
    // Auxiliary inverse helpers A_j(b) = 1/D_j^id(b), B_j(b) = 1/D_j^σ(b)
    // are committed via WHIR (commit_additional, after β,γ are squeezed)
    // and bound via two sumchecks:
    //   Φ_inv: zero-check on A_j·D_j^id − 1 = 0 and B_j·D_j^σ − 1 = 0  (deg 3)
    //   Φ_h:   linear sumcheck on H = Σ_j λ_h^j (A_j − B_j),  claimed sum = 0
    //
    // The terminal checks reconstruct predictions from PCS-bound values
    // a_j(r_inv), b_j(r_inv), w_j(r_inv), σ_j(r_inv), g_sub(r_inv) for Φ_inv,
    // and a_j(r_h), b_j(r_h) for Φ_h. No 1/x is evaluated by the verifier.
    // ═══════════════════════════════════════════════════════════════════
    /// Commitment root for the inverse-helper batched MLE
    /// `P_inv = A_0 + r_inv_batch · A_1 + … + r_inv_batch^{2W_R-1} · B_{W_R-1}`.
    /// Committed *after* (β, γ) are squeezed.
    pub inverse_helpers_root: Vec<u8>,
    /// Schwartz-Zippel batching scalar for the inverse-helper batched MLE.
    pub inverse_helpers_batch_r: F,
    /// Φ_inv sumcheck challenge point (length = degree_bits).
    pub inv_sumcheck_challenges: Vec<F>,
    /// Φ_inv sumcheck proof (round polys of degree ≤ 3).
    pub inv_sumcheck_proof: SumcheckProof<F>,
    /// Φ_h sumcheck challenge point (length = degree_bits).
    pub h_sumcheck_challenges: Vec<F>,
    /// Φ_h sumcheck proof (round polys of degree 1).
    pub h_sumcheck_proof: SumcheckProof<F>,
    /// Fiat-Shamir challenges for the v2 logUp protocol.
    pub lambda_inv: F,
    pub mu_inv: F,
    pub lambda_h: F,
    pub tau_inv: Vec<F>,
    /// Inverse helper individual evals at r_inv (length = 2 · num_routed_wires,
    /// laid out as `[a_0, a_1, …, a_{W_R-1}, b_0, …, b_{W_R-1}]`).
    pub inverse_helpers_evals_at_r_inv: Vec<F>,
    /// Inverse helper individual evals at r_h (same layout).
    pub inverse_helpers_evals_at_r_h: Vec<F>,
    /// Inverse helper batched WHIR evaluation at r_inv (Ext3).
    pub inverse_helpers_whir_eval_at_r_inv_ext3: Field64_3,
    /// Inverse helper batched WHIR evaluation at r_h (Ext3).
    pub inverse_helpers_whir_eval_at_r_h_ext3: Field64_3,
    /// Witness individual evals at r_inv (needed for Φ_inv terminal check).
    pub witness_individual_evals_at_r_inv: Vec<F>,
    /// Full preprocessed individual evals at r_inv (needed for batch
    /// consistency with `preprocessed_eval_value_at_r_inv` ↔ WHIR Ext3 eval).
    /// Layout `[const_0 .. const_{C-1}, sigma_0 .. sigma_{R-1}]`.
    /// The sigma subset (indices `[num_constants..num_constants+num_routed]`)
    /// feeds the Φ_inv terminal check; the const subset is unused there but
    /// required by the batch identity Σ batch_r_pre^i · eval_i.
    pub preprocessed_individual_evals_at_r_inv: Vec<F>,
    /// Subgroup MLE g_sub(r_inv) — verifier recomputes this from
    /// `subgroup_gen_powers` and checks consistency.
    pub g_sub_eval_at_r_inv: F,
    /// Witness batched WHIR evaluation at r_inv (Ext3) — proves the
    /// `witness_individual_evals_at_r_inv` are PCS-bound.
    pub witness_whir_eval_at_r_inv_ext3: Field64_3,
    /// Preprocessed batched WHIR evaluation at r_inv (Ext3) — proves
    /// `sigma_individual_evals_at_r_inv` (and unused const evals) PCS-bound.
    pub preprocessed_whir_eval_at_r_inv_ext3: Field64_3,
    /// Witness batch eval (Goldilocks) at r_inv, for batch consistency.
    pub witness_eval_value_at_r_inv: F,
    /// Preprocessed batch eval (Goldilocks) at r_inv, for batch consistency.
    pub preprocessed_eval_value_at_r_inv: F,
    /// Auxiliary batched WHIR evaluation at r_inv (Ext3). Not used by the
    /// terminal check but produced by the multi-point WHIR proof.
    pub aux_whir_eval_at_r_inv_ext3: Field64_3,
    /// Auxiliary, witness, preprocessed WHIR evals at r_h (Ext3). Used to
    /// satisfy the multi-point WHIR contract; only inverse-helper values are
    /// consumed by Φ_h terminal check.
    pub aux_whir_eval_at_r_h_ext3: Field64_3,
    pub witness_whir_eval_at_r_h_ext3: Field64_3,
    pub preprocessed_whir_eval_at_r_h_ext3: Field64_3,
    /// Inverse-helpers WHIR eval at r_gate (Ext3). Not used by terminal checks
    /// but required to satisfy the multi-point WHIR verification contract.
    pub inverse_helpers_whir_eval_at_r_gate_ext3: Field64_3,
}
