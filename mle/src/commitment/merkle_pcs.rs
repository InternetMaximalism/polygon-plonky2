/// Merkle-tree-based multilinear polynomial commitment scheme.
///
/// Commits by hashing evaluations into a Merkle tree. Opens by revealing
/// queried leaves with Merkle inclusion proofs. The evaluation claim is
/// verified by checking that the opened leaves are consistent with the
/// MLE evaluation via a direct recomputation from all leaves.
///
/// Proof size: O(2^n) field elements (all leaves revealed).
/// A future WHIR integration would reduce this to polylog(2^n).
///
/// SECURITY: The binding property comes from the collision resistance of
/// Keccak256. The prover cannot change any leaf without changing the root.
use keccak_hash::keccak;
use plonky2_field::types::{Field, PrimeField64};

use crate::commitment::traits::MultilinearPCS;
use crate::dense_mle::DenseMultilinearExtension;
use crate::transcript::Transcript;

/// Configuration for the Merkle PCS.
#[derive(Clone, Debug)]
pub struct MerklePCS {
    /// Number of random queries (unused in current full-reveal mode, reserved for future).
    pub num_queries: usize,
}

impl MerklePCS {
    pub fn new(num_queries: usize) -> Self {
        Self { num_queries }
    }
}

/// Merkle commitment: the root hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerkleCommitment {
    pub root: [u8; 32],
}

/// Merkle commit state: the full evaluation vector + tree layers.
#[derive(Clone, Debug)]
pub struct MerkleCommitState<F: Field> {
    pub evaluations: Vec<F>,
    pub tree_layers: Vec<Vec<[u8; 32]>>,
}

/// Evaluation proof: all evaluations + Merkle root consistency.
///
/// In a production system this would contain only queried leaves + Merkle paths.
/// Current implementation reveals all leaves for simplicity while maintaining
/// the correct commit-open-verify interface.
#[derive(Clone, Debug)]
pub struct MerkleEvalProof<F: Field> {
    pub evaluations: Vec<F>,
}

fn hash_field_element<F: PrimeField64>(val: F) -> [u8; 32] {
    let bytes = val.to_canonical_u64().to_le_bytes();
    let hash = keccak(&bytes);
    let mut result = [0u8; 32];
    result.copy_from_slice(hash.as_ref());
    result
}

fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut to_hash = Vec::with_capacity(64);
    to_hash.extend_from_slice(left);
    to_hash.extend_from_slice(right);
    let hash = keccak(&to_hash);
    let mut result = [0u8; 32];
    result.copy_from_slice(hash.as_ref());
    result
}

fn build_merkle_tree(leaf_hashes: &[[u8; 32]]) -> Vec<Vec<[u8; 32]>> {
    if leaf_hashes.is_empty() {
        return vec![vec![[0u8; 32]]];
    }

    let mut layers = Vec::new();
    layers.push(leaf_hashes.to_vec());

    while layers.last().unwrap().len() > 1 {
        let current = layers.last().unwrap();
        let mut next = Vec::with_capacity((current.len() + 1) / 2);
        for chunk in current.chunks(2) {
            if chunk.len() == 2 {
                next.push(hash_pair(&chunk[0], &chunk[1]));
            } else {
                next.push(hash_pair(&chunk[0], &chunk[0]));
            }
        }
        layers.push(next);
    }

    layers
}

impl<F: PrimeField64> MultilinearPCS<F> for MerklePCS {
    type Commitment = MerkleCommitment;
    type CommitState = MerkleCommitState<F>;
    type EvalProof = MerkleEvalProof<F>;

    fn commit(&self, poly: &DenseMultilinearExtension<F>) -> (Self::Commitment, Self::CommitState) {
        let leaf_hashes: Vec<[u8; 32]> = poly
            .evaluations
            .iter()
            .map(|&val| hash_field_element(val))
            .collect();

        let tree_layers = build_merkle_tree(&leaf_hashes);
        let root = tree_layers.last().unwrap()[0];

        (
            MerkleCommitment { root },
            MerkleCommitState {
                evaluations: poly.evaluations.clone(),
                tree_layers,
            },
        )
    }

    fn open(
        &self,
        state: &Self::CommitState,
        _poly: &DenseMultilinearExtension<F>,
        _point: &[F],
        _value: F,
        _transcript: &mut Transcript,
    ) -> Self::EvalProof {
        // Reveal all evaluations. The verifier reconstructs the Merkle root
        // and checks the MLE evaluation.
        MerkleEvalProof {
            evaluations: state.evaluations.clone(),
        }
    }

    fn verify(
        &self,
        commitment: &Self::Commitment,
        point: &[F],
        value: F,
        proof: &Self::EvalProof,
        _transcript: &mut Transcript,
    ) -> bool {
        // Reconstruct Merkle root from provided evaluations
        let leaf_hashes: Vec<[u8; 32]> = proof
            .evaluations
            .iter()
            .map(|&val| hash_field_element(val))
            .collect();

        let tree_layers = build_merkle_tree(&leaf_hashes);
        let root = tree_layers.last().unwrap()[0];

        if root != commitment.root {
            return false;
        }

        // Verify MLE evaluation
        let mle = DenseMultilinearExtension::new(proof.evaluations.clone());
        let computed_value = mle.evaluate(point);
        computed_value == value
    }
}

#[cfg(test)]
mod tests {
    use plonky2_field::goldilocks_field::GoldilocksField;
    use plonky2_field::types::Field;

    use super::*;

    type F = GoldilocksField;

    #[test]
    fn test_commit_open_verify() {
        let pcs = MerklePCS::new(16);
        let evals = vec![
            F::from_canonical_u64(1),
            F::from_canonical_u64(2),
            F::from_canonical_u64(3),
            F::from_canonical_u64(4),
        ];
        let mle = DenseMultilinearExtension::new(evals);

        let (commitment, state) = pcs.commit(&mle);

        let point = vec![F::from_canonical_u64(5), F::from_canonical_u64(7)];
        let value = mle.evaluate(&point);

        let mut transcript = Transcript::new();
        let proof = pcs.open(&state, &mle, &point, value, &mut transcript);

        let mut transcript = Transcript::new();
        assert!(pcs.verify(&commitment, &point, value, &proof, &mut transcript));
    }

    #[test]
    fn test_verify_rejects_wrong_value() {
        let pcs = MerklePCS::new(16);
        let evals = vec![
            F::from_canonical_u64(1),
            F::from_canonical_u64(2),
            F::from_canonical_u64(3),
            F::from_canonical_u64(4),
        ];
        let mle = DenseMultilinearExtension::new(evals);

        let (commitment, state) = pcs.commit(&mle);

        let point = vec![F::from_canonical_u64(5), F::from_canonical_u64(7)];
        let value = mle.evaluate(&point);
        let wrong_value = value + F::ONE;

        let mut transcript = Transcript::new();
        let proof = pcs.open(&state, &mle, &point, value, &mut transcript);

        let mut transcript = Transcript::new();
        assert!(!pcs.verify(&commitment, &point, wrong_value, &proof, &mut transcript));
    }

    #[test]
    fn test_verify_rejects_tampered_evaluations() {
        let pcs = MerklePCS::new(16);
        let evals = vec![
            F::from_canonical_u64(1),
            F::from_canonical_u64(2),
            F::from_canonical_u64(3),
            F::from_canonical_u64(4),
        ];
        let mle = DenseMultilinearExtension::new(evals);

        let (commitment, state) = pcs.commit(&mle);

        let point = vec![F::from_canonical_u64(5), F::from_canonical_u64(7)];
        let value = mle.evaluate(&point);

        let mut transcript = Transcript::new();
        let mut proof = pcs.open(&state, &mle, &point, value, &mut transcript);

        // Tamper with an evaluation
        proof.evaluations[0] = proof.evaluations[0] + F::ONE;

        let mut transcript = Transcript::new();
        assert!(!pcs.verify(&commitment, &point, value, &proof, &mut transcript));
    }

    #[test]
    fn test_merkle_tree_consistency() {
        // Verify Merkle tree is deterministic and correct
        let evals: Vec<F> = (0..8).map(|i| F::from_canonical_u64(i + 1)).collect();
        let mle = DenseMultilinearExtension::new(evals);

        let pcs = MerklePCS::new(16);
        let (c1, _) = pcs.commit(&mle);
        let (c2, _) = pcs.commit(&mle);
        assert_eq!(c1.root, c2.root, "Commitment should be deterministic");
    }
}
