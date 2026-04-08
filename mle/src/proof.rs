/// Proof structure for the MLE-native proving system.
use plonky2_field::types::Field;
use whir::algebra::fields::Field64_3;

use crate::commitment::whir_pcs::{WhirCommitment, WhirEvalProof};
use crate::permutation::logup::PermutationProof;
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
    /// This is the first 32 bytes of the WHIR proof for the constants+sigmas
    /// polynomial, and is deterministic for a given circuit.
    pub preprocessed_commitment_root: Vec<u8>,
    /// Number of constant columns in the circuit.
    pub num_constants: usize,
    /// Number of routed wire columns (sigma permutation columns).
    pub num_routed_wires: usize,
}

/// A complete MLE proof for a Plonky2 circuit.
#[derive(Clone, Debug)]
pub struct MleProof<F: Field> {
    /// Circuit digest (verifying key hash) — 4 Goldilocks field elements.
    /// SECURITY: Binds this proof to a specific Plonky2 circuit. Without this,
    /// an attacker could generate a proof for a trivial circuit and present it
    /// as valid for the target circuit.
    pub circuit_digest: Vec<F>,

    // ── Preprocessed PCS (constants + sigmas) ────────────────────────────
    /// WHIR commitment to the batched preprocessed polynomial.
    /// SECURITY: The first 32 bytes (commitment root) must match the VK.
    pub preprocessed_commitment: WhirCommitment,
    /// WHIR evaluation proof for the preprocessed polynomial.
    pub preprocessed_eval_proof: WhirEvalProof,
    /// Batched evaluation value for the preprocessed polynomial.
    pub preprocessed_eval_value: F,
    /// Batching scalar for preprocessed polys (deterministic, from circuit_digest).
    pub preprocessed_batch_r: F,
    /// Individual evaluations at sumcheck point: [const_0..const_C, sigma_0..sigma_R].
    pub preprocessed_individual_evals: Vec<F>,
    /// WHIR evaluation in Ext3 for preprocessed polynomial.
    pub preprocessed_whir_eval_ext3: Field64_3,

    // ── Witness PCS (wires) ──────────────────────────────────────────────
    /// WHIR commitment to the batched witness polynomial.
    pub witness_commitment: WhirCommitment,
    /// WHIR evaluation proof for the witness polynomial.
    pub witness_eval_proof: WhirEvalProof,
    /// Batched evaluation value for the witness polynomial.
    pub witness_eval_value: F,
    /// Batching scalar for witness polys (Fiat-Shamir derived).
    pub witness_batch_r: F,
    /// Individual evaluations at sumcheck point: [wire_0..wire_W].
    pub witness_individual_evals: Vec<F>,
    /// WHIR evaluation in Ext3 for witness polynomial.
    pub witness_whir_eval_ext3: Field64_3,

    // ── Sub-protocol proofs ──────────────────────────────────────────────
    /// Zero-check sumcheck proof for gate constraints.
    pub constraint_proof: SumcheckProof<F>,
    /// Permutation check proof.
    pub permutation_proof: PermutationProof<F>,
    /// Lookup proofs (one per lookup table, empty if no lookups).
    pub lookup_proofs: Vec<LookupProof<F>>,

    // ── Public data ──────────────────────────────────────────────────────
    /// Public inputs.
    pub public_inputs: Vec<F>,
    /// Challenges used (for verifier reference / debugging).
    pub alpha: F,
    pub beta: F,
    pub gamma: F,
    pub tau: Vec<F>,
    pub tau_perm: Vec<F>,
    /// PCS-bound constraint evaluation C(r) at the sumcheck output point.
    /// Computed by the prover as the flattened extension-field combined constraint.
    /// The Solidity verifier checks: constraintFinalEval == eq(τ, r) · pcs_constraint_eval.
    pub pcs_constraint_eval: F,
    /// PCS-bound permutation numerator h(r_perm) at the permutation sumcheck output point.
    /// The Solidity verifier checks: permFinalEval == pcs_perm_numerator_eval.
    pub pcs_perm_numerator_eval: F,
    /// Circuit dimensions for verifier decomposition of individual_evals.
    pub num_wires: usize,
    pub num_routed_wires: usize,
    pub num_constants: usize,
}
