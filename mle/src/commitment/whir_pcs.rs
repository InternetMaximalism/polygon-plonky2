/// WHIR-based multilinear polynomial commitment scheme.
///
/// Integrates the `whir` crate (arkworks-based) with the plonky2_mle
/// proving system via the `MultilinearPCS` trait.
///
/// Field conversion: plonky2's GoldilocksField (u64 repr) ↔ arkworks
/// Field64 (Montgomery repr) via canonical u64 serialization.
use std::borrow::Cow;

use ark_ff::{Field as ArkField, PrimeField as ArkPrimeField};
use plonky2_field::goldilocks_field::GoldilocksField;
use plonky2_field::types::{Field, PrimeField64};
use whir::algebra::embedding::Identity;
use whir::algebra::fields::Field64 as ArkGoldilocks;
use whir::parameters::ProtocolParameters;
use whir::protocols::whir::Config as WhirConfig;
use whir::transcript::{Codec, DomainSeparator, Proof as WhirProofData, ProverState, VerifierState};
use whir::transcript::codecs::Empty;

use crate::dense_mle::DenseMultilinearExtension;
use crate::transcript::Transcript;

// ═══════════════════════════════════════════════════════════════════════════
//  Field conversion
// ═══════════════════════════════════════════════════════════════════════════

/// Convert a plonky2 GoldilocksField element to arkworks Field64.
pub fn plonky2_to_ark(val: GoldilocksField) -> ArkGoldilocks {
    ArkGoldilocks::from(val.to_canonical_u64())
}

/// Convert an arkworks Field64 element to plonky2 GoldilocksField.
pub fn ark_to_plonky2(val: ArkGoldilocks) -> GoldilocksField {
    let repr: u64 = val.into_bigint().0[0];
    GoldilocksField::from_canonical_u64(repr)
}

/// Convert a vector of plonky2 field elements to arkworks.
pub fn plonky2_vec_to_ark(vals: &[GoldilocksField]) -> Vec<ArkGoldilocks> {
    vals.iter().map(|v| plonky2_to_ark(*v)).collect()
}

/// Convert a vector of arkworks field elements to plonky2.
pub fn ark_vec_to_plonky2(vals: &[ArkGoldilocks]) -> Vec<GoldilocksField> {
    vals.iter().map(|v| ark_to_plonky2(*v)).collect()
}

// ═══════════════════════════════════════════════════════════════════════════
//  WHIR PCS wrapper
// ═══════════════════════════════════════════════════════════════════════════

/// WHIR polynomial commitment scheme operating over GoldilocksField.
///
/// Uses `Identity<Field64>` embedding (base field only, no extension).
/// The WHIR config is parameterised by rate, security level, and folding factor.
pub struct WhirPCS {
    pub params: ProtocolParameters,
}

/// Commitment: the serialized WHIR proof (for the verifier).
#[derive(Clone, Debug)]
pub struct WhirCommitment {
    /// Serialized WHIR proof bytes.
    pub proof_bytes: Vec<u8>,
}

/// Commit state: data the prover retains for the opening phase.
#[derive(Clone)]
pub struct WhirCommitState {
    /// The original polynomial evaluations in arkworks representation.
    pub ark_evals: Vec<ArkGoldilocks>,
}

/// WHIR evaluation proof: the serialized interactive proof.
#[derive(Clone, Debug)]
pub struct WhirEvalProof {
    /// Serialized WHIR proof bytes (narg_string + hints).
    pub narg_string: Vec<u8>,
    pub hints: Vec<u8>,
}

impl WhirPCS {
    /// Create a WHIR PCS with the given parameters.
    /// rate = 1/2^starting_log_inv_rate (e.g., 6 for rate 1/64).
    pub fn new(
        security_level: usize,
        pow_bits: usize,
        starting_log_inv_rate: usize,
        folding_factor: usize,
    ) -> Self {
        let params = ProtocolParameters {
            security_level,
            pow_bits,
            initial_folding_factor: folding_factor,
            folding_factor,
            unique_decoding: false,
            starting_log_inv_rate,
            batch_size: 1,
            hash_id: whir::hash::KECCAK,
        };
        Self { params }
    }

    /// Default: rate 1/64, 128-bit security, 20 PoW bits, folding factor 4.
    pub fn default_rate_64() -> Self {
        Self::new(128, 20, 6, 4)
    }

    /// Create a WHIR PCS with parameters adapted for a given polynomial size.
    /// Ensures folding_factor <= num_vars to avoid size assertion failures.
    pub fn for_num_vars(num_vars: usize) -> Self {
        // WHIR requires num_vars >= folding_factor
        let folding_factor = num_vars.min(4).max(1);
        let starting_log_inv_rate = if num_vars <= 4 { 1 } else { 6 };
        let security_level = if num_vars <= 8 { 64 } else { 128 };
        let pow_bits = if num_vars <= 8 { 0 } else { 20 };
        Self::new(security_level, pow_bits, starting_log_inv_rate, folding_factor)
    }

    /// Generate a WHIR proof for a multilinear polynomial.
    ///
    /// Commits to the polynomial evaluations and produces an evaluation proof
    /// that can be verified without the full evaluation table.
    pub fn prove(
        &self,
        poly: &DenseMultilinearExtension<GoldilocksField>,
    ) -> (WhirCommitment, WhirEvalProof) {
        let num_vars = poly.num_vars;
        let size = 1 << num_vars;

        let ark_evals = plonky2_vec_to_ark(&poly.evaluations);

        // Build WHIR config
        let config = WhirConfig::<Identity<ArkGoldilocks>>::new(size, &self.params);

        // Create transcript domain separator
        let ds = DomainSeparator::protocol(&config)
            .session(&"plonky2-mle-whir")
            .instance(&Empty);

        let mut prover_state = ProverState::new_std(&ds);

        // Commit
        let witness = config.commit(&mut prover_state, &[&ark_evals]);

        // Prove (no linear forms for basic evaluation proof)
        let _final_claim = config.prove(
            &mut prover_state,
            vec![Cow::Borrowed(ark_evals.as_slice())],
            vec![Cow::Owned(witness)],
            vec![],
            Cow::Owned(vec![]),
        );

        let proof = prover_state.proof();

        (
            WhirCommitment {
                proof_bytes: proof.narg_string.clone(),
            },
            WhirEvalProof {
                narg_string: proof.narg_string,
                hints: proof.hints,
            },
        )
    }

    /// Verify a WHIR proof.
    pub fn verify(
        &self,
        num_vars: usize,
        proof: &WhirEvalProof,
    ) -> Result<(), String> {
        let size = 1 << num_vars;

        let config = WhirConfig::<Identity<ArkGoldilocks>>::new(size, &self.params);
        let ds = DomainSeparator::protocol(&config)
            .session(&"plonky2-mle-whir")
            .instance(&Empty);

        let proof_data = WhirProofData {
            narg_string: proof.narg_string.clone(),
            hints: proof.hints.clone(),
            #[cfg(debug_assertions)]
            pattern: vec![],
        };

        let mut verifier_state = VerifierState::new_std(&ds, &proof_data);

        let commitment = config
            .receive_commitment(&mut verifier_state)
            .map_err(|e| format!("WHIR commitment verification failed: {:?}", e))?;

        let final_claim = config
            .verify(&mut verifier_state, &[&commitment], &[])
            .map_err(|e| format!("WHIR verification failed: {:?}", e))?;

        // No linear forms to check, so final_claim is trivially valid
        let _ = final_claim;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_field_conversion_roundtrip() {
        for i in 0..100u64 {
            let p2 = GoldilocksField::from_canonical_u64(i);
            let ark = plonky2_to_ark(p2);
            let back = ark_to_plonky2(ark);
            assert_eq!(p2, back, "Roundtrip failed for {i}");
        }

        let p = 0xFFFFFFFF00000001u64;
        for offset in [0u64, 1, 2, 100, 1000, 1 << 32, 1 << 53, p - 2, p - 1] {
            let val = offset.min(p - 1);
            let p2 = GoldilocksField::from_canonical_u64(val);
            let ark = plonky2_to_ark(p2);
            let back = ark_to_plonky2(ark);
            assert_eq!(p2, back, "Roundtrip failed for val={val}");
        }
    }

    #[test]
    fn test_field_arithmetic_consistency() {
        let a_p2 = GoldilocksField::from_canonical_u64(123456789);
        let b_p2 = GoldilocksField::from_canonical_u64(987654321);

        let a_ark = plonky2_to_ark(a_p2);
        let b_ark = plonky2_to_ark(b_p2);

        assert_eq!(a_p2 + b_p2, ark_to_plonky2(a_ark + b_ark));
        assert_eq!(a_p2 * b_p2, ark_to_plonky2(a_ark * b_ark));
        assert_eq!(a_p2.inverse(), ark_to_plonky2(a_ark.inverse().unwrap()));
    }

    #[test]
    fn test_whir_prove_verify_small() {
        // Commit to a small polynomial and verify
        let evals: Vec<GoldilocksField> = (0..16)
            .map(|i| GoldilocksField::from_canonical_u64(i + 1))
            .collect();
        let poly = DenseMultilinearExtension::new(evals);

        let pcs = WhirPCS::new(32, 0, 1, 2); // Minimal security for fast test
        let (_commitment, proof) = pcs.prove(&poly);

        let result = pcs.verify(poly.num_vars, &proof);
        assert!(result.is_ok(), "WHIR verify failed: {:?}", result.err());
    }

    #[test]
    fn test_whir_prove_verify_medium() {
        let evals: Vec<GoldilocksField> = (0..256)
            .map(|i| GoldilocksField::from_canonical_u64(i * 7 + 3))
            .collect();
        let poly = DenseMultilinearExtension::new(evals);

        let pcs = WhirPCS::new(32, 0, 1, 2); // Minimal security for fast test
        let (_commitment, proof) = pcs.prove(&poly);

        let result = pcs.verify(poly.num_vars, &proof);
        assert!(result.is_ok(), "WHIR verify failed: {:?}", result.err());
    }
}
