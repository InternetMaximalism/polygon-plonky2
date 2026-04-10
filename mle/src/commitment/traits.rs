/// Trait for multilinear polynomial commitment schemes.
///
/// This abstraction allows swapping between Merkle-based PCS (fallback)
/// and WHIR (target) without changing the prover/verifier interface.
use plonky2_field::types::Field;

use crate::dense_mle::DenseMultilinearExtension;
use crate::transcript::Transcript;

/// A multilinear polynomial commitment scheme.
pub trait MultilinearPCS<F: Field> {
    /// Opaque commitment data (e.g., Merkle root).
    type Commitment: Clone + core::fmt::Debug;
    /// Auxiliary data the prover retains for opening (e.g., full Merkle tree).
    type CommitState;
    /// Proof of evaluation at a point.
    type EvalProof: Clone + core::fmt::Debug;

    /// Commit to a multilinear polynomial.
    fn commit(&self, poly: &DenseMultilinearExtension<F>) -> (Self::Commitment, Self::CommitState);

    /// Produce an evaluation proof: prove that `poly(point) = value`.
    fn open(
        &self,
        state: &Self::CommitState,
        poly: &DenseMultilinearExtension<F>,
        point: &[F],
        value: F,
        transcript: &mut Transcript,
    ) -> Self::EvalProof;

    /// Verify an evaluation proof.
    fn verify(
        &self,
        commitment: &Self::Commitment,
        point: &[F],
        value: F,
        proof: &Self::EvalProof,
        transcript: &mut Transcript,
    ) -> bool;
}
