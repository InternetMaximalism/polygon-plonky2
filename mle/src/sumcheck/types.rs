/// Types for the sumcheck protocol.
use plonky2_field::types::Field;

/// A round polynomial in the sumcheck protocol.
///
/// Represented by its evaluations at `0, 1, ..., degree`.
/// The round polynomial `g_i(X)` has degree at most `max_degree`.
#[derive(Clone, Debug)]
pub struct RoundPolynomial<F: Field> {
    /// Evaluations at `0, 1, ..., degree`.
    pub evaluations: Vec<F>,
}

impl<F: Field> RoundPolynomial<F> {
    pub fn new(evaluations: Vec<F>) -> Self {
        Self { evaluations }
    }

    /// The degree of this polynomial (number of evaluations - 1).
    pub fn degree(&self) -> usize {
        self.evaluations.len() - 1
    }

    /// Evaluate at a field element using Lagrange interpolation over {0, 1, ..., d}.
    pub fn evaluate(&self, point: F) -> F {
        lagrange_interpolate_over_integers(&self.evaluations, point)
    }
}

/// Lagrange interpolation over integer nodes {0, 1, ..., d}.
///
/// Given evaluations `evals[i] = f(i)` for `i = 0, ..., d`, compute `f(point)`.
fn lagrange_interpolate_over_integers<F: Field>(evals: &[F], point: F) -> F {
    let d = evals.len();
    if d == 0 {
        return F::ZERO;
    }

    // Precompute (point - j) for all j
    let diffs: Vec<F> = (0..d).map(|j| point - F::from_canonical_usize(j)).collect();

    // Numerator product = Π_{j=0}^{d-1} (point - j)
    let full_product: F = diffs.iter().copied().product();

    let mut result = F::ZERO;
    for i in 0..d {
        if diffs[i] == F::ZERO {
            // point == i, so f(point) = evals[i]
            return evals[i];
        }

        // Barycentric weight: w_i = 1 / Π_{j≠i} (i - j)
        // For integer nodes, Π_{j≠i} (i-j) = Π_{j<i} (i-j) · Π_{j>i} (i-j)
        //   = i! · (-1)^{d-1-i} · (d-1-i)!  (with sign)
        let mut denom = F::ONE;
        for j in 0..d {
            if j != i {
                denom *= F::from_canonical_usize(i) - F::from_canonical_usize(j);
            }
        }

        // L_i(point) = full_product / (diffs[i] * denom)
        let li = full_product * (diffs[i] * denom).inverse();
        result += evals[i] * li;
    }

    result
}

/// Proof data from the sumcheck protocol.
#[derive(Clone, Debug)]
pub struct SumcheckProof<F: Field> {
    /// Round polynomials, one per variable.
    pub round_polys: Vec<RoundPolynomial<F>>,
}

#[cfg(test)]
mod tests {
    use plonky2_field::goldilocks_field::GoldilocksField;

    use super::*;
    type F = GoldilocksField;

    #[test]
    fn test_lagrange_identity() {
        // f(x) = x^2 evaluated at {0,1,2}: [0, 1, 4]
        let evals = vec![F::ZERO, F::ONE, F::from_canonical_u64(4)];
        let poly = RoundPolynomial::new(evals);

        // Check at nodes
        assert_eq!(poly.evaluate(F::ZERO), F::ZERO);
        assert_eq!(poly.evaluate(F::ONE), F::ONE);
        assert_eq!(
            poly.evaluate(F::from_canonical_u64(2)),
            F::from_canonical_u64(4)
        );

        // Check at 3: should give 9
        assert_eq!(
            poly.evaluate(F::from_canonical_u64(3)),
            F::from_canonical_u64(9)
        );
    }

    #[test]
    fn test_round_poly_linear() {
        // f(x) = 2x + 1: f(0)=1, f(1)=3
        let poly = RoundPolynomial::new(vec![F::ONE, F::from_canonical_u64(3)]);
        assert_eq!(
            poly.evaluate(F::from_canonical_u64(5)),
            F::from_canonical_u64(11)
        );
    }
}
