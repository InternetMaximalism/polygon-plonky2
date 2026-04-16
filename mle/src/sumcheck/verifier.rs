/// Sumcheck verifier for the zero-check protocol.
use plonky2_field::types::Field;

use crate::sumcheck::types::SumcheckProof;
use crate::transcript::Transcript;

/// Verify a sumcheck proof.
///
/// # Arguments
/// - `proof`: The sumcheck proof (round polynomials).
/// - `claimed_sum`: The claimed value `Σ eq(τ,b) · C(b)` (should be 0 for zero-check).
/// - `num_vars`: Number of variables `n`.
/// - `transcript`: Fiat-Shamir transcript (must be in the same state as the prover's).
///
/// # Returns
/// `Ok((challenges, final_eval))` if the sumcheck structure is valid, where:
/// - `challenges`: The random challenges `r_0, ..., r_{n-1}`.
/// - `final_eval`: The final claimed evaluation `g_{n-1}(r_{n-1})`.
///
/// The caller must additionally verify that `final_eval == eq(τ, r) · C(r)` using
/// a polynomial commitment opening.
pub fn verify_sumcheck<F: Field + plonky2_field::types::PrimeField64>(
    proof: &SumcheckProof<F>,
    claimed_sum: F,
    num_vars: usize,
    transcript: &mut Transcript,
) -> Result<(Vec<F>, F), SumcheckVerifyError> {
    if proof.round_polys.len() != num_vars {
        return Err(SumcheckVerifyError::WrongNumberOfRounds {
            expected: num_vars,
            got: proof.round_polys.len(),
        });
    }

    let mut current_claim = claimed_sum;
    let mut challenges = Vec::with_capacity(num_vars);

    for (i, round_poly) in proof.round_polys.iter().enumerate() {
        // Check: g_i(0) + g_i(1) == current_claim
        let sum = round_poly.evaluations[0] + round_poly.evaluations[1];
        if sum != current_claim {
            return Err(SumcheckVerifyError::RoundCheckFailed { round: i });
        }

        // Absorb round polynomial (must match prover's transcript)
        transcript.domain_separate("sumcheck-round");
        transcript.absorb_field_vec(&round_poly.evaluations);

        // Squeeze challenge
        let r_i: F = transcript.squeeze_challenge();
        challenges.push(r_i);

        // Next claim = g_i(r_i)
        current_claim = round_poly.evaluate(r_i);
    }

    Ok((challenges, current_claim))
}

/// Errors from sumcheck verification.
#[derive(Debug, Clone)]
pub enum SumcheckVerifyError {
    WrongNumberOfRounds { expected: usize, got: usize },
    RoundCheckFailed { round: usize },
}

impl core::fmt::Display for SumcheckVerifyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::WrongNumberOfRounds { expected, got } => {
                write!(
                    f,
                    "Wrong number of sumcheck rounds: expected {expected}, got {got}"
                )
            }
            Self::RoundCheckFailed { round } => {
                write!(f, "Sumcheck round {round} failed: g(0)+g(1) != claim")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use plonky2_field::goldilocks_field::GoldilocksField;

    use super::*;
    use crate::dense_mle::DenseMultilinearExtension;
    use crate::eq_poly;
    use crate::sumcheck::prover::{compute_claimed_sum, prove_sumcheck_product};

    type F = GoldilocksField;

    #[test]
    fn test_prove_verify_roundtrip() {
        let n = 4;
        let size = 1 << n;
        let tau: Vec<F> = (0..n)
            .map(|i| F::from_canonical_u64(i as u64 * 3 + 2))
            .collect();

        let constraint_table: Vec<F> = (0..size)
            .map(|i| F::from_canonical_u64(i as u64 * 5 + 7))
            .collect();

        let eq_table = eq_poly::eq_evals(&tau);
        let claimed_sum = compute_claimed_sum(&eq_table, &constraint_table);

        // Prover
        let mut eq_mle = DenseMultilinearExtension::new(eq_table.clone());
        let mut c_mle = DenseMultilinearExtension::new(constraint_table.clone());
        let mut prover_transcript = Transcript::new();
        prover_transcript.domain_separate("test-sumcheck");
        let (proof, prover_challenges) =
            prove_sumcheck_product(&mut eq_mle, &mut c_mle, 2, &mut prover_transcript);

        // Verifier
        let mut verifier_transcript = Transcript::new();
        verifier_transcript.domain_separate("test-sumcheck");
        let (verifier_challenges, final_eval) =
            verify_sumcheck(&proof, claimed_sum, n, &mut verifier_transcript).unwrap();

        assert_eq!(prover_challenges, verifier_challenges);

        // Final check: final_eval == eq(τ, r) · C(r)
        let eq_at_r = eq_poly::eq_eval(&tau, &verifier_challenges);
        let c_at_r =
            DenseMultilinearExtension::new(constraint_table).evaluate(&verifier_challenges);
        assert_eq!(final_eval, eq_at_r * c_at_r);
    }

    #[test]
    fn test_verify_rejects_tampered_round_poly() {
        let n = 3;
        let size = 1 << n;
        let tau: Vec<F> = (0..n)
            .map(|i| F::from_canonical_u64(i as u64 + 10))
            .collect();
        let constraint_table: Vec<F> = (0..size)
            .map(|i| F::from_canonical_u64(i as u64 + 1))
            .collect();

        let eq_table = eq_poly::eq_evals(&tau);
        let claimed_sum = compute_claimed_sum(&eq_table, &constraint_table);

        let mut eq_mle = DenseMultilinearExtension::new(eq_table);
        let mut c_mle = DenseMultilinearExtension::new(constraint_table);
        let mut prover_transcript = Transcript::new();
        let (mut proof, _) =
            prove_sumcheck_product(&mut eq_mle, &mut c_mle, 2, &mut prover_transcript);

        // Tamper with the first round polynomial
        proof.round_polys[0].evaluations[0] += F::ONE;

        let mut verifier_transcript = Transcript::new();
        let result = verify_sumcheck(&proof, claimed_sum, n, &mut verifier_transcript);
        assert!(result.is_err());
    }
}
