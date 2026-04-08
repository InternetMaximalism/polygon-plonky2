/// Proof structure for the MLE-native proving system.
use plonky2_field::types::Field;
use whir::algebra::fields::Field64_3;

use crate::commitment::whir_pcs::{WhirCommitment, WhirEvalProof};
use crate::permutation::logup::PermutationProof;
use crate::permutation::lookup::LookupProof;
use crate::sumcheck::types::SumcheckProof;

/// A complete MLE proof for a Plonky2 circuit.
#[derive(Clone, Debug)]
pub struct MleProof<F: Field> {
    /// Circuit digest (verifying key hash) — 4 Goldilocks field elements.
    /// SECURITY: Binds this proof to a specific Plonky2 circuit. Without this,
    /// an attacker could generate a proof for a trivial circuit and present it
    /// as valid for the target circuit.
    pub circuit_digest: Vec<F>,
    /// WHIR commitment to the batched MLE polynomial.
    pub commitment: WhirCommitment,
    /// Zero-check sumcheck proof for gate constraints.
    pub constraint_proof: SumcheckProof<F>,
    /// Permutation check proof.
    pub permutation_proof: PermutationProof<F>,
    /// Lookup proofs (one per lookup table, empty if no lookups).
    pub lookup_proofs: Vec<LookupProof<F>>,
    /// WHIR evaluation proof at the sumcheck output point.
    pub eval_proof: WhirEvalProof,
    /// The claimed evaluation value at the sumcheck point.
    pub eval_value: F,
    /// Public inputs.
    pub public_inputs: Vec<F>,
    /// The batching random scalar (for verifier to decompose the batch).
    pub batch_r: F,
    /// Number of polynomials in the batch.
    pub num_polys: usize,
    /// Individual evaluation values at the sumcheck point (for constraint check).
    pub individual_evals: Vec<F>,
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
    /// WHIR evaluation value in Ext3 (for verifier to pass to WHIR verify).
    /// Computed by the prover via WHIR's mixed_multilinear_extend.
    pub whir_eval_ext3: Field64_3,
}
