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
}
