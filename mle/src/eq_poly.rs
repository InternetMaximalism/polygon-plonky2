/// Evaluation table for the eq polynomial:
///   `eq(τ, b) = Π_{j=0}^{n-1} (τ_j · b_j + (1 - τ_j)(1 - b_j))`
///
/// For a fixed `τ ∈ F^n`, this computes `eq(τ, b)` for all `b ∈ {0,1}^n`.
use plonky2_field::types::Field;

/// Compute the full eq evaluation table of size 2^n.
///
/// `eq_evals(τ)[i] = eq(τ, bits(i))` where `bits(i)` is the binary decomposition
/// with bit j = `(i >> j) & 1`.
///
/// Uses the tensor product structure: O(2^n) time, no divisions.
pub fn eq_evals<F: Field>(tau: &[F]) -> Vec<F> {
    let n = tau.len();
    let size = 1usize << n;
    let mut table = vec![F::ONE; size];

    if n == 0 {
        return table;
    }

    // Build using tensor product: for each variable j, multiply the appropriate
    // factor into each table entry based on bit j of the index.
    // eq(τ, b) = Π_j (τ_j · b_j + (1 - τ_j)(1 - b_j))
    // For b_j = 0: factor = (1 - τ_j)
    // For b_j = 1: factor = τ_j
    for (j, &t_j) in tau.iter().enumerate() {
        let one_minus_t_j = F::ONE - t_j;
        for (i, entry) in table.iter_mut().enumerate() {
            if (i >> j) & 1 == 0 {
                *entry *= one_minus_t_j;
            } else {
                *entry *= t_j;
            }
        }
    }

    table
}

/// Evaluate `eq(τ, r)` at a single point, without building the full table.
/// O(n) time.
pub fn eq_eval<F: Field>(tau: &[F], r: &[F]) -> F {
    assert_eq!(tau.len(), r.len());
    tau.iter()
        .zip(r.iter())
        .map(|(&t, &r_j)| t * r_j + (F::ONE - t) * (F::ONE - r_j))
        .product()
}

#[cfg(test)]
mod tests {
    use plonky2_field::goldilocks_field::GoldilocksField;

    use super::*;

    type F = GoldilocksField;

    #[test]
    fn test_eq_evals_n0() {
        let table = eq_evals::<F>(&[]);
        assert_eq!(table, vec![F::ONE]);
    }

    #[test]
    fn test_eq_evals_n1() {
        let tau = [F::from_canonical_u64(3)];
        let table = eq_evals(&tau);
        // eq(3, 0) = 1 - 3 = -2
        // eq(3, 1) = 3
        assert_eq!(table[0], F::ONE - F::from_canonical_u64(3));
        assert_eq!(table[1], F::from_canonical_u64(3));
    }

    #[test]
    fn test_eq_at_boolean_point() {
        // eq(τ, τ) should be 1 when τ is Boolean
        for b in 0..8u64 {
            let tau: Vec<F> = (0..3)
                .map(|j| if (b >> j) & 1 == 1 { F::ONE } else { F::ZERO })
                .collect();
            let table = eq_evals(&tau);
            // eq(b, b) = 1
            assert_eq!(table[b as usize], F::ONE);
            // All other entries should be 0
            for (i, &entry) in table.iter().enumerate().take(8) {
                if i != b as usize {
                    assert_eq!(entry, F::ZERO);
                }
            }
        }
    }

    #[test]
    fn test_eq_evals_sum_is_one() {
        // For any τ, Σ_b eq(τ, b) = 1
        let tau = vec![
            F::from_canonical_u64(5),
            F::from_canonical_u64(13),
            F::from_canonical_u64(42),
        ];
        let table = eq_evals(&tau);
        let sum: F = table.iter().copied().sum();
        assert_eq!(sum, F::ONE);
    }

    #[test]
    fn test_eq_eval_matches_table() {
        let tau = vec![F::from_canonical_u64(7), F::from_canonical_u64(11)];
        let table = eq_evals(&tau);

        for b in 0..4u64 {
            let r: Vec<F> = (0..2)
                .map(|j| if (b >> j) & 1 == 1 { F::ONE } else { F::ZERO })
                .collect();
            assert_eq!(eq_eval(&tau, &r), table[b as usize]);
        }
    }

    #[test]
    fn test_eq_eval_arbitrary() {
        let tau = vec![F::from_canonical_u64(3), F::from_canonical_u64(7)];
        let r = vec![F::from_canonical_u64(5), F::from_canonical_u64(11)];

        let result = eq_eval(&tau, &r);
        // Manual: (3*5 + (1-3)(1-5)) * (7*11 + (1-7)(1-11))
        let t0 = tau[0] * r[0] + (F::ONE - tau[0]) * (F::ONE - r[0]);
        let t1 = tau[1] * r[1] + (F::ONE - tau[1]) * (F::ONE - r[1]);
        assert_eq!(result, t0 * t1);
    }
}
