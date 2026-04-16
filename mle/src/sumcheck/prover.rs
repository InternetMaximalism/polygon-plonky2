/// Sumcheck prover for the zero-check protocol:
///   `Σ_{b ∈ {0,1}^n} eq(τ, b) · C(b) = 0`
///
/// where `C(b)` is the combined gate constraint polynomial evaluated at row `b`.
use plonky2_field::types::Field;

use crate::dense_mle::DenseMultilinearExtension;
use crate::sumcheck::types::{RoundPolynomial, SumcheckProof};
use crate::transcript::Transcript;

/// Run the sumcheck prover for a product of two MLEs: `Σ_b f(b) · g(b) = claimed_sum`.
///
/// Both MLEs are consumed (mutated via bind_variable_in_place).
///
/// # Arguments
/// - `f_mle`, `g_mle`: Two MLEs whose product is summed.
/// - `max_degree`: Maximum degree of `f(X)·g(X)` per variable (typically 2).
/// - `transcript`: Fiat-Shamir transcript.
///
/// # Returns
/// `(proof, challenges)`.
pub fn prove_sumcheck_product<F: Field + plonky2_field::types::PrimeField64>(
    f_mle: &mut DenseMultilinearExtension<F>,
    g_mle: &mut DenseMultilinearExtension<F>,
    max_degree: usize,
    transcript: &mut Transcript,
) -> (SumcheckProof<F>, Vec<F>) {
    let n = f_mle.num_vars;
    assert_eq!(g_mle.num_vars, n);

    let mut round_polys = Vec::with_capacity(n);
    let mut challenges = Vec::with_capacity(n);

    for _round in 0..n {
        let half = f_mle.evaluations.len() / 2;
        let mut evals = vec![F::ZERO; max_degree + 1];

        for j in 0..half {
            let f_lo = f_mle.evaluations[2 * j];
            let f_hi = f_mle.evaluations[2 * j + 1];
            let g_lo = g_mle.evaluations[2 * j];
            let g_hi = g_mle.evaluations[2 * j + 1];

            for (d, eval) in evals.iter_mut().enumerate() {
                let t = F::from_canonical_usize(d);
                let one_minus_t = F::ONE - t;
                let f_t = one_minus_t * f_lo + t * f_hi;
                let g_t = one_minus_t * g_lo + t * g_hi;
                *eval += f_t * g_t;
            }
        }

        let round_poly = RoundPolynomial::new(evals.clone());

        transcript.domain_separate("sumcheck-round");
        transcript.absorb_field_vec(&evals);

        let r_i: F = transcript.squeeze_challenge();
        challenges.push(r_i);

        f_mle.bind_variable_in_place(r_i);
        g_mle.bind_variable_in_place(r_i);

        round_polys.push(round_poly);
    }

    (SumcheckProof { round_polys }, challenges)
}

/// Run the sumcheck prover for a combined constraint+permutation polynomial:
///   `Σ_b [eq(τ, b) · C(b) + μ · h(b)] = 0`
///
/// where `Σ eq(τ,b)·C(b) = 0` (zero-check) and `Σ h(b) = 0` (logUp).
///
/// This merges the constraint zero-check and permutation check into a single
/// sumcheck, halving the number of sumcheck rounds (n instead of 2n) and
/// producing a single output point r where all evaluations are needed.
///
/// NOTE: The permutation term uses h(b) UNWEIGHTED (not eq(τ_perm,b)·h(b)),
/// because logUp guarantees Σ h(b) = 0 (total sum) but NOT h(b) = 0 at each row.
/// The eq-weighted constraint term handles the zero-check (C must be zero at each row).
///
/// # Arguments
/// - `eq_constraint_mle`: eq(τ, ·) MLE
/// - `constraint_mle`: C(·) MLE (flattened constraint polynomial)
/// - `h_mle`: h(·) MLE (logUp permutation numerator)
/// - `mu`: Fiat-Shamir combination scalar
/// - `max_degree`: Maximum degree per variable (2 for product of multilinear polynomials)
/// - `transcript`: Fiat-Shamir transcript
///
/// SECURITY: μ is derived after all MLEs are determined. A prover who tries to
/// cancel constraint violations against permutation imbalances must predict μ,
/// which by Schwartz-Zippel has probability ≤ deg/|F| ≈ 2^{-64}.
pub fn prove_sumcheck_combined<F: Field + plonky2_field::types::PrimeField64>(
    eq_constraint_mle: &mut DenseMultilinearExtension<F>,
    constraint_mle: &mut DenseMultilinearExtension<F>,
    h_mle: &mut DenseMultilinearExtension<F>,
    mu: F,
    max_degree: usize,
    transcript: &mut Transcript,
) -> (SumcheckProof<F>, Vec<F>) {
    let n = eq_constraint_mle.num_vars;
    assert_eq!(constraint_mle.num_vars, n);
    assert_eq!(h_mle.num_vars, n);

    let mut round_polys = Vec::with_capacity(n);
    let mut challenges = Vec::with_capacity(n);

    for _round in 0..n {
        let half = eq_constraint_mle.evaluations.len() / 2;
        let mut evals = vec![F::ZERO; max_degree + 1];

        for j in 0..half {
            // Constraint term: eq(τ, ·) · C(·)
            let ec_lo = eq_constraint_mle.evaluations[2 * j];
            let ec_hi = eq_constraint_mle.evaluations[2 * j + 1];
            let c_lo = constraint_mle.evaluations[2 * j];
            let c_hi = constraint_mle.evaluations[2 * j + 1];

            // Permutation term: μ · h(·) (unweighted)
            let h_lo = h_mle.evaluations[2 * j];
            let h_hi = h_mle.evaluations[2 * j + 1];

            for (d, eval) in evals.iter_mut().enumerate() {
                let t = F::from_canonical_usize(d);
                let one_minus_t = F::ONE - t;

                let ec_t = one_minus_t * ec_lo + t * ec_hi;
                let c_t = one_minus_t * c_lo + t * c_hi;
                let h_t = one_minus_t * h_lo + t * h_hi;

                // Combined: eq(τ,t) · C(t) + μ · h(t)
                *eval += ec_t * c_t + mu * h_t;
            }
        }

        let round_poly = RoundPolynomial::new(evals.clone());

        transcript.domain_separate("sumcheck-round");
        transcript.absorb_field_vec(&evals);

        let r_i: F = transcript.squeeze_challenge();
        challenges.push(r_i);

        eq_constraint_mle.bind_variable_in_place(r_i);
        constraint_mle.bind_variable_in_place(r_i);
        h_mle.bind_variable_in_place(r_i);

        round_polys.push(round_poly);
    }

    (SumcheckProof { round_polys }, challenges)
}

/// Run the sumcheck prover for a single MLE: `Σ_b f(b) = claimed_sum`.
///
/// This uses the identity `Σ f(b) = Σ eq(1,...,1, b)·f(b)` ... no, that's wrong.
/// For a plain sum, the round polynomial is:
///   `g_i(X) = Σ_{b'} f(X, b')` where b' ranges over remaining variables.
/// This is degree 1 in X (since f is multilinear).
pub fn prove_sumcheck_plain<F: Field + plonky2_field::types::PrimeField64>(
    f_mle: &mut DenseMultilinearExtension<F>,
    transcript: &mut Transcript,
) -> (SumcheckProof<F>, Vec<F>) {
    let n = f_mle.num_vars;

    let mut round_polys = Vec::with_capacity(n);
    let mut challenges = Vec::with_capacity(n);

    for _round in 0..n {
        let half = f_mle.evaluations.len() / 2;

        // g(X) = Σ_{b'} f(X, b')
        // g(0) = Σ_{b'} f(0, b') = Σ_j f_mle[2j]
        // g(1) = Σ_{b'} f(1, b') = Σ_j f_mle[2j+1]
        let mut g0 = F::ZERO;
        let mut g1 = F::ZERO;
        for j in 0..half {
            g0 += f_mle.evaluations[2 * j];
            g1 += f_mle.evaluations[2 * j + 1];
        }

        // Degree 1 polynomial: evals at 0 and 1
        let round_poly = RoundPolynomial::new(vec![g0, g1]);

        transcript.domain_separate("sumcheck-round");
        transcript.absorb_field_vec(&[g0, g1]);

        let r_i: F = transcript.squeeze_challenge();
        challenges.push(r_i);

        f_mle.bind_variable_in_place(r_i);

        round_polys.push(round_poly);
    }

    (SumcheckProof { round_polys }, challenges)
}

/// Compute `Σ_{b ∈ {0,1}^n} f(b) · g(b)`.
pub fn compute_claimed_sum<F: Field>(f_evals: &[F], g_evals: &[F]) -> F {
    assert_eq!(f_evals.len(), g_evals.len());
    f_evals
        .iter()
        .zip(g_evals.iter())
        .map(|(&f, &g)| f * g)
        .sum()
}

#[cfg(test)]
mod tests {
    use plonky2_field::goldilocks_field::GoldilocksField;
    use plonky2_field::types::Field;

    use super::*;
    use crate::eq_poly;

    type F = GoldilocksField;

    #[test]
    fn test_sumcheck_zero_constraint() {
        // C(b) = 0 for all b → claimed sum = 0, all round polys should be zero.
        let n = 3;
        let size = 1 << n;
        let tau: Vec<F> = (0..n)
            .map(|i| F::from_canonical_u64(i as u64 + 5))
            .collect();

        let eq_table = eq_poly::eq_evals(&tau);
        let constraint_table = vec![F::ZERO; size];

        let mut eq_mle = DenseMultilinearExtension::new(eq_table);
        let mut c_mle = DenseMultilinearExtension::new(constraint_table);
        let mut transcript = Transcript::new();

        let (proof, _challenges) =
            prove_sumcheck_product(&mut eq_mle, &mut c_mle, 2, &mut transcript);

        for rp in &proof.round_polys {
            assert_eq!(rp.evaluations[0], F::ZERO);
            assert_eq!(rp.evaluations[1], F::ZERO);
        }
    }

    #[test]
    fn test_sumcheck_consistency() {
        let n = 3;
        let size = 1 << n;
        let tau: Vec<F> = (0..n)
            .map(|i| F::from_canonical_u64(i as u64 * 7 + 3))
            .collect();

        let constraint_table: Vec<F> = (0..size)
            .map(|i| F::from_canonical_u64(i as u64 * 13 + 1))
            .collect();

        let eq_table = eq_poly::eq_evals(&tau);
        let claimed_sum = compute_claimed_sum(&eq_table, &constraint_table);

        let mut eq_mle = DenseMultilinearExtension::new(eq_table);
        let mut c_mle = DenseMultilinearExtension::new(constraint_table);
        let mut transcript = Transcript::new();

        let (proof, _challenges) =
            prove_sumcheck_product(&mut eq_mle, &mut c_mle, 2, &mut transcript);

        // g_0(0) + g_0(1) == claimed_sum
        let first_sum = proof.round_polys[0].evaluations[0] + proof.round_polys[0].evaluations[1];
        assert_eq!(first_sum, claimed_sum);

        for i in 1..n {
            let prev_eval = proof.round_polys[i - 1].evaluate(_challenges[i - 1]);
            let this_sum =
                proof.round_polys[i].evaluations[0] + proof.round_polys[i].evaluations[1];
            assert_eq!(this_sum, prev_eval);
        }
    }

    #[test]
    fn test_plain_sumcheck() {
        let n = 3;
        let size = 1 << n;
        let table: Vec<F> = (0..size)
            .map(|i| F::from_canonical_u64(i as u64 + 1))
            .collect();
        let claimed_sum: F = table.iter().copied().sum();

        let mut mle = DenseMultilinearExtension::new(table);
        let mut transcript = Transcript::new();
        let (proof, challenges) = prove_sumcheck_plain(&mut mle, &mut transcript);

        // Check round consistency
        let first_sum = proof.round_polys[0].evaluations[0] + proof.round_polys[0].evaluations[1];
        assert_eq!(first_sum, claimed_sum);

        for i in 1..n {
            let prev_eval = proof.round_polys[i - 1].evaluate(challenges[i - 1]);
            let this_sum =
                proof.round_polys[i].evaluations[0] + proof.round_polys[i].evaluations[1];
            assert_eq!(this_sum, prev_eval);
        }
    }
}
