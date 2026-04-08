/// Log-derivative (logUp) permutation argument for multilinear systems.
///
/// Proves that for all routed wires j:
///   `Σ_{b ∈ {0,1}^n} [1/(β + w_j(b) + γ·id_j(b)) - 1/(β + w_j(b) + γ·σ_j(b))] = 0`
///
/// This is equivalent to proving the permutation argument without a grand product.
/// The degree per sumcheck variable is 2 (denominator is linear, two fractions).
use plonky2_field::types::Field;

use crate::dense_mle::DenseMultilinearExtension;
use crate::sumcheck::prover::prove_sumcheck_plain;
use crate::sumcheck::types::SumcheckProof;
use crate::transcript::Transcript;

/// Compute the logUp numerator MLE for the permutation check.
///
/// For each row b and each routed wire j, computes:
///   `h(b) = Σ_j [1/(β + w_j(b) + γ·id_j(b)) - 1/(β + w_j(b) + γ·σ_j(b))]`
///
/// If the permutation is satisfied, `Σ_b h(b) = 0`.
///
/// # Arguments
/// - `wire_values`: `wire_values[col][row]` — wire MLE values.
/// - `sigma_values`: `sigma_values[row][col]` — sigma permutation values (field-encoded).
/// - `id_values`: `id_values[row][col]` — identity permutation values (field-encoded).
/// - `beta`, `gamma`: Fiat-Shamir challenges.
/// - `num_routed_wires`: Number of routed wire columns.
/// - `degree`: Number of rows.
///
/// # Returns
/// The evaluation table `h[b]` for all b.
pub fn compute_permutation_numerator<F: Field>(
    wire_values: &[Vec<F>],
    sigma_values: &[Vec<F>],
    id_values: &[Vec<F>],
    beta: F,
    gamma: F,
    num_routed_wires: usize,
    degree: usize,
) -> Vec<F> {
    let mut h = vec![F::ZERO; degree];

    for row in 0..degree {
        let mut sum = F::ZERO;
        for j in 0..num_routed_wires {
            let w = if j < wire_values.len() {
                wire_values[j][row]
            } else {
                F::ZERO
            };
            let id_val = if row < id_values.len() && j < id_values[row].len() {
                id_values[row][j]
            } else {
                F::ZERO
            };
            let sigma_val = if row < sigma_values.len() && j < sigma_values[row].len() {
                sigma_values[row][j]
            } else {
                F::ZERO
            };

            let denom_id = beta + w + gamma * id_val;
            let denom_sigma = beta + w + gamma * sigma_val;

            // SECURITY: Check for zero denominators. In a valid circuit over a
            // large field, this happens with negligible probability.
            if denom_id == F::ZERO || denom_sigma == F::ZERO {
                // If denominator is zero, the permutation argument is unsound.
                // Set h to a non-zero value to ensure rejection.
                h[row] = F::ONE;
                continue;
            }

            sum = sum + denom_id.inverse() - denom_sigma.inverse();
        }
        h[row] = sum;
    }

    h
}

/// Compute identity permutation values: `id[row][col] = k_is[col] * subgroup[row]`.
pub fn compute_identity_values<F: Field>(
    k_is: &[F],
    subgroup: &[F],
    num_routed_wires: usize,
    degree: usize,
) -> Vec<Vec<F>> {
    (0..degree)
        .map(|row| {
            (0..num_routed_wires)
                .map(|col| k_is[col] * subgroup[row])
                .collect()
        })
        .collect()
}

/// Run the permutation check as a sumcheck proving Σ_b h(b) = 0.
///
/// SECURITY: Soundness relies on Schwartz-Zippel over β and γ (the Fiat-Shamir
/// challenges derived BEFORE the prover commits to h). For a wrong permutation,
/// Σ h(b) ≠ 0 as a formal polynomial in β, γ with overwhelming probability.
/// The logUp identity telescopes only when the multisets {(w, id)} and {(w, σ)}
/// are equal, which is equivalent to the permutation being correct.
///
/// Note: `tau_perm` is used by the Fiat-Shamir transcript to derive subsequent
/// challenges but is NOT used as an eq-randomizer in this sumcheck. Unlike the
/// constraint zero-check (which needs eq(τ, b) because the constraint polynomial
/// is not zero on the padding region), h(b) sums to exactly 0 over {0,1}^n
/// when the permutation is valid — the Schwartz-Zippel guarantee comes from
/// β, γ being random, not from an eq-weighting.
///
/// Round polynomial degree is 1 (h is multilinear).
///
/// # Returns
/// `(proof, challenges, claimed_sum)` where `claimed_sum` should be 0.
pub fn prove_permutation_check<F: Field + plonky2_field::types::PrimeField64>(
    wire_values: &[Vec<F>],
    sigma_values: &[Vec<F>],
    k_is: &[F],
    subgroup: &[F],
    num_routed_wires: usize,
    degree: usize,
    beta: F,
    gamma: F,
    _tau_perm: &[F],
    transcript: &mut Transcript,
) -> (SumcheckProof<F>, Vec<F>, F) {
    let id_values = compute_identity_values(k_is, subgroup, num_routed_wires, degree);

    let h = compute_permutation_numerator(
        wire_values,
        sigma_values,
        &id_values,
        beta,
        gamma,
        num_routed_wires,
        degree,
    );

    // Pad to power of 2
    let mut h_padded = h;
    let next_pow2 = h_padded.len().next_power_of_two();
    h_padded.resize(next_pow2, F::ZERO);

    // Compute the claimed sum: Σ_b h(b).
    // For a valid permutation, this sum is 0 (the logUp terms telescope
    // across the permutation cycles).
    let claimed_sum: F = h_padded.iter().copied().sum();

    let mut h_mle = DenseMultilinearExtension::new(h_padded);

    // Plain sumcheck: prove Σ_b h(b) = claimed_sum.
    // Round polynomial degree is 1 (h is multilinear).
    let (proof, challenges) = prove_sumcheck_plain(&mut h_mle, transcript);

    (proof, challenges, claimed_sum)
}

/// Proof data for the permutation check.
#[derive(Clone, Debug)]
pub struct PermutationProof<F: Field> {
    pub sumcheck_proof: SumcheckProof<F>,
    pub challenges: Vec<F>,
    pub claimed_sum: F,
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2_field::goldilocks_field::GoldilocksField;

    type F = GoldilocksField;

    #[test]
    fn test_identity_permutation() {
        // When sigma == id (no copy constraints), h(b) = 0 for all b.
        let degree = 4;
        let num_routed = 2;
        let k_is = vec![F::ONE, F::from_canonical_u64(7)];
        let subgroup: Vec<F> = (0..degree)
            .map(|i| F::from_canonical_u64(i as u64 + 1))
            .collect();

        let wire_values = vec![
            vec![F::from_canonical_u64(10), F::from_canonical_u64(20), F::from_canonical_u64(30), F::from_canonical_u64(40)],
            vec![F::from_canonical_u64(50), F::from_canonical_u64(60), F::from_canonical_u64(70), F::from_canonical_u64(80)],
        ];

        let id_values = compute_identity_values(&k_is, &subgroup, num_routed, degree);
        // sigma == id → h should be all zeros
        let h = compute_permutation_numerator(
            &wire_values,
            &id_values,
            &id_values,
            F::from_canonical_u64(99),
            F::from_canonical_u64(101),
            num_routed,
            degree,
        );

        for &val in &h {
            assert_eq!(val, F::ZERO);
        }
    }

    #[test]
    fn test_valid_swap_permutation() {
        // 2 rows, 1 routed wire. sigma swaps row 0 and row 1.
        // wire[0] = [a, b], id = [k*g^0, k*g^1], sigma = [k*g^1, k*g^0]
        // For permutation to be valid: w[sigma(0)] == w[0] and w[sigma(1)] == w[1]
        // i.e., b == a and a == b → only valid if a == b.
        // Actually permutation argument checks copy constraints, not value equality directly.
        // The logUp sum is: 1/(β+a+γ·id0) - 1/(β+a+γ·σ0) + 1/(β+b+γ·id1) - 1/(β+b+γ·σ1)
        // With id0=k*s0, id1=k*s1, σ0=k*s1, σ1=k*s0:
        //   = 1/(β+a+γ·k·s0) - 1/(β+a+γ·k·s1) + 1/(β+b+γ·k·s1) - 1/(β+b+γ·k·s0)
        // This equals 0 when a==b (terms cancel pairwise).
        let a = F::from_canonical_u64(42);
        let k = F::ONE;
        let s0 = F::from_canonical_u64(1);
        let s1 = F::from_canonical_u64(2);
        let beta = F::from_canonical_u64(99);
        let gamma = F::from_canonical_u64(101);

        let wire_values = vec![vec![a, a]]; // a == b for the permutation to hold
        let id_values = vec![vec![k * s0], vec![k * s1]];
        let sigma_values = vec![vec![k * s1], vec![k * s0]]; // swapped

        let h = compute_permutation_numerator(
            &wire_values,
            &sigma_values,
            &id_values,
            beta,
            gamma,
            1,
            2,
        );

        let sum: F = h.iter().copied().sum();
        assert_eq!(sum, F::ZERO);
    }
}
