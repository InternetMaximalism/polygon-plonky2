/// Proof structure for the MLE-native proving system.
use plonky2_field::types::Field;

use crate::commitment::merkle_pcs::{MerkleCommitment, MerkleEvalProof};
use crate::permutation::logup::PermutationProof;
use crate::permutation::lookup::LookupProof;
use crate::sumcheck::types::SumcheckProof;

/// A complete MLE proof for a Plonky2 circuit.
#[derive(Clone, Debug)]
pub struct MleProof<F: Field> {
    /// Commitment to the batched MLE polynomial.
    pub commitment: MerkleCommitment,
    /// Zero-check sumcheck proof for gate constraints.
    pub constraint_proof: SumcheckProof<F>,
    /// Permutation check proof.
    pub permutation_proof: PermutationProof<F>,
    /// Lookup proofs (one per lookup table, empty if no lookups).
    pub lookup_proofs: Vec<LookupProof<F>>,
    /// PCS evaluation proof at the sumcheck output point.
    pub eval_proof: MerkleEvalProof<F>,
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
}
