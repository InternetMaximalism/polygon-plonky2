/// Dense multilinear extension over `{0,1}^n`.
///
/// Stores evaluations in lexicographic order of the binary input:
///   `evaluations[i] = f(b_0, ..., b_{n-1})` where `i = Σ b_j · 2^j`.
use plonky2_field::types::Field;

#[derive(Clone, Debug)]
pub struct DenseMultilinearExtension<F: Field> {
    pub num_vars: usize,
    pub evaluations: Vec<F>,
}

impl<F: Field> DenseMultilinearExtension<F> {
    /// Create a new MLE from a vector of evaluations over `{0,1}^n`.
    /// The length must be a power of 2.
    pub fn new(evaluations: Vec<F>) -> Self {
        let num_vars = if evaluations.is_empty() {
            0
        } else {
            plonky2_util::log2_strict(evaluations.len())
        };
        Self {
            num_vars,
            evaluations,
        }
    }

    /// Evaluate the MLE at an arbitrary point `point ∈ F^n` using the standard formula:
    ///   `f(r_0, ..., r_{n-1}) = Σ_{b ∈ {0,1}^n} f(b) · Π_j (b_j · r_j + (1 - b_j)(1 - r_j))`
    ///
    /// Time: O(2^n). Uses the eq-tensor optimization.
    pub fn evaluate(&self, point: &[F]) -> F {
        assert_eq!(point.len(), self.num_vars);
        if self.num_vars == 0 {
            return self.evaluations[0];
        }

        let eq_evals = crate::eq_poly::eq_evals(point);
        self.evaluations
            .iter()
            .zip(eq_evals.iter())
            .map(|(&f_b, &eq_b)| f_b * eq_b)
            .sum()
    }

    /// Bind the first unbound variable (lowest bit) to `val`, halving the table size.
    ///
    /// After calling this with `val`, the MLE represents:
    ///   `f'(x_1, ..., x_{n-1}) = (1-val) · f(0, x_1, ...) + val · f(1, x_1, ...)`
    ///
    /// With our indexing (bit 0 = LSB), variable 0 splits even/odd indices:
    ///   `new[j] = (1-val) · old[2j] + val · old[2j+1]`
    ///
    /// This is the core bookkeeping operation for the sumcheck protocol.
    pub fn bind_variable_in_place(&mut self, val: F) {
        assert!(self.num_vars > 0);
        let half = self.evaluations.len() / 2;
        let one_minus_val = F::ONE - val;
        for j in 0..half {
            self.evaluations[j] =
                one_minus_val * self.evaluations[2 * j] + val * self.evaluations[2 * j + 1];
        }
        self.evaluations.truncate(half);
        self.num_vars -= 1;
    }

    /// Evaluate the partially-bound MLE at `val` for the first variable,
    /// returning a new vector of half the size, without mutating self.
    pub fn evaluate_first_variable(&self, val: F) -> Vec<F> {
        let half = self.evaluations.len() / 2;
        let one_minus_val = F::ONE - val;
        (0..half)
            .map(|j| one_minus_val * self.evaluations[2 * j] + val * self.evaluations[2 * j + 1])
            .collect()
    }

    /// Number of evaluations (= 2^num_vars).
    pub fn len(&self) -> usize {
        self.evaluations.len()
    }

    pub fn is_empty(&self) -> bool {
        self.evaluations.is_empty()
    }
}

/// Convert a column-major wire/constant table into a vec of MLEs.
///
/// `tables[col][row]` → one MLE per column, with `evaluations[row] = tables[col][row]`.
/// If the number of rows is not a power of 2, pads with zeros.
pub fn tables_to_mles<F: Field>(tables: &[Vec<F>]) -> Vec<DenseMultilinearExtension<F>> {
    tables
        .iter()
        .map(|column| {
            let mut evals = column.clone();
            let next_pow2 = evals.len().next_power_of_two();
            evals.resize(next_pow2, F::ZERO);
            DenseMultilinearExtension::new(evals)
        })
        .collect()
}

/// Convert a row-major table into a vec of MLEs (one per column).
///
/// `table[row][col]` → one MLE per column.
pub fn row_major_to_mles<F: Field>(
    table: &[Vec<F>],
    num_cols: usize,
) -> Vec<DenseMultilinearExtension<F>> {
    let num_rows = table.len();
    let next_pow2 = num_rows.next_power_of_two();
    (0..num_cols)
        .map(|col| {
            let mut evals: Vec<F> = table
                .iter()
                .map(|row| if col < row.len() { row[col] } else { F::ZERO })
                .collect();
            evals.resize(next_pow2, F::ZERO);
            DenseMultilinearExtension::new(evals)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use plonky2_field::goldilocks_field::GoldilocksField;
    use plonky2_field::types::Field;

    use super::*;

    type F = GoldilocksField;

    #[test]
    fn test_evaluate_constant() {
        // f(x) = 5 for all x ∈ {0,1}^0
        let mle = DenseMultilinearExtension::new(vec![F::from_canonical_u64(5)]);
        assert_eq!(mle.evaluate(&[]), F::from_canonical_u64(5));
    }

    #[test]
    fn test_evaluate_1var() {
        // f(0) = 3, f(1) = 7
        let mle = DenseMultilinearExtension::new(vec![
            F::from_canonical_u64(3),
            F::from_canonical_u64(7),
        ]);
        // f(0) = 3
        assert_eq!(mle.evaluate(&[F::ZERO]), F::from_canonical_u64(3));
        // f(1) = 7
        assert_eq!(mle.evaluate(&[F::ONE]), F::from_canonical_u64(7));
        // f(0.5) = 0.5*3 + 0.5*7 = 5 ... but in Goldilocks, use (p+1)/2
        let half = F::from_canonical_u64(2).inverse();
        let result = mle.evaluate(&[half]);
        assert_eq!(
            result,
            F::from_canonical_u64(3) * (F::ONE - half) + F::from_canonical_u64(7) * half
        );
    }

    #[test]
    fn test_evaluate_2var() {
        // f(b0, b1) for b0*1 + b1*2:
        // f(0,0)=1, f(1,0)=2, f(0,1)=3, f(1,1)=4
        let mle = DenseMultilinearExtension::new(vec![
            F::from_canonical_u64(1),
            F::from_canonical_u64(2),
            F::from_canonical_u64(3),
            F::from_canonical_u64(4),
        ]);
        assert_eq!(mle.evaluate(&[F::ZERO, F::ZERO]), F::from_canonical_u64(1));
        assert_eq!(mle.evaluate(&[F::ONE, F::ZERO]), F::from_canonical_u64(2));
        assert_eq!(mle.evaluate(&[F::ZERO, F::ONE]), F::from_canonical_u64(3));
        assert_eq!(mle.evaluate(&[F::ONE, F::ONE]), F::from_canonical_u64(4));
    }

    #[test]
    fn test_bind_variable() {
        // f(b0, b1): f(0,0)=1, f(1,0)=2, f(0,1)=3, f(1,1)=4
        let mle = DenseMultilinearExtension::new(vec![
            F::from_canonical_u64(1),
            F::from_canonical_u64(2),
            F::from_canonical_u64(3),
            F::from_canonical_u64(4),
        ]);

        let r0 = F::from_canonical_u64(5);
        let point = vec![r0, F::from_canonical_u64(7)];
        let expected = mle.evaluate(&point);

        // Bind first variable to r0
        let mut bound = mle.clone();
        bound.bind_variable_in_place(r0);
        assert_eq!(bound.num_vars, 1);

        // Now evaluate at r1
        let result = bound.evaluate(&[F::from_canonical_u64(7)]);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_bind_all_variables() {
        let mle = DenseMultilinearExtension::new(vec![
            F::from_canonical_u64(10),
            F::from_canonical_u64(20),
            F::from_canonical_u64(30),
            F::from_canonical_u64(40),
            F::from_canonical_u64(50),
            F::from_canonical_u64(60),
            F::from_canonical_u64(70),
            F::from_canonical_u64(80),
        ]);

        let point = vec![
            F::from_canonical_u64(3),
            F::from_canonical_u64(7),
            F::from_canonical_u64(11),
        ];
        let expected = mle.evaluate(&point);

        let mut bound = mle;
        for &r in &point {
            bound.bind_variable_in_place(r);
        }
        assert_eq!(bound.num_vars, 0);
        assert_eq!(bound.evaluations[0], expected);
    }

    #[test]
    fn test_evaluate_eq_identity() {
        // Property: f(r) = Σ_b f(b) · eq(r, b)
        // This is tested implicitly by evaluate(), but let's verify explicitly.
        let evals = vec![
            F::from_canonical_u64(1),
            F::from_canonical_u64(2),
            F::from_canonical_u64(3),
            F::from_canonical_u64(4),
        ];
        let mle = DenseMultilinearExtension::new(evals.clone());
        let point = vec![F::from_canonical_u64(5), F::from_canonical_u64(9)];

        let eq_table = crate::eq_poly::eq_evals(&point);
        let manual: F = evals
            .iter()
            .zip(eq_table.iter())
            .map(|(&f, &e)| f * e)
            .sum();
        assert_eq!(mle.evaluate(&point), manual);
    }
}
