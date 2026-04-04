/// Bridge between Plonky2 gate constraints and the MLE sumcheck system.
///
/// Evaluates Plonky2's gate constraints at each row of the evaluation tables
/// and combines them with alpha powers, producing a single combined-constraint
/// MLE suitable for the zero-check sumcheck.
use plonky2::plonk::circuit_data::CommonCircuitData;
use plonky2::plonk::vars::EvaluationVars;
use plonky2::plonk::vanishing_poly::evaluate_gate_constraints;
use plonky2_field::extension::{Extendable, FieldExtension};
use plonky2::hash::hash_types::RichField;

/// Evaluate all gate constraints at every row of the evaluation tables,
/// and combine them with alpha powers into a single scalar per row.
///
/// Returns `combined[row] = Σ_j α^j · constraint_j(wires[row], consts[row])`.
///
/// This is the `C(b)` in the zero-check: `Σ_b eq(τ,b) · C(b) = 0`.
pub fn compute_combined_constraints<F: RichField + Extendable<D>, const D: usize>(
    common_data: &CommonCircuitData<F, D>,
    wire_values: &[Vec<F>],
    constant_values: &[Vec<F>],
    alphas: &[F],
    public_inputs_hash: &plonky2::hash::hash_types::HashOut<F>,
    degree: usize,
) -> Vec<F> {
    let num_gate_constraints = common_data.num_gate_constraints;
    let num_wires = common_data.config.num_wires;
    let num_constants = common_data.num_constants;

    // Precompute alpha powers
    let alpha_powers: Vec<F> = {
        let mut powers = Vec::with_capacity(num_gate_constraints);
        if !alphas.is_empty() {
            // For multiple alpha challenges, we combine them as:
            // α_0^0, α_0^1, ..., α_0^{k-1} where k = num_gate_constraints
            // For simplicity with a single alpha (num_challenges=1):
            let alpha = alphas[0];
            let mut pow = F::ONE;
            for _ in 0..num_gate_constraints {
                powers.push(pow);
                pow = pow * alpha;
            }
        }
        powers
    };

    let mut combined = vec![F::ZERO; degree];

    for row in 0..degree {
        // Build local_wires for this row
        let local_wires: Vec<F::Extension> = (0..num_wires)
            .map(|col| {
                let val = if col < wire_values.len() {
                    wire_values[col][row]
                } else {
                    F::ZERO
                };
                F::Extension::from_basefield(val)
            })
            .collect();

        // Build local_constants for this row
        let local_constants: Vec<F::Extension> = (0..num_constants)
            .map(|col| {
                let val = if row < constant_values.len() && col < constant_values[row].len() {
                    constant_values[row][col]
                } else {
                    F::ZERO
                };
                F::Extension::from_basefield(val)
            })
            .collect();

        let vars = EvaluationVars {
            local_constants: &local_constants,
            local_wires: &local_wires,
            public_inputs_hash,
        };

        let constraint_values = evaluate_gate_constraints(common_data, vars);

        // Combine: C(row) = Σ_j α^j · constraint_j
        let mut combined_val = F::ZERO;
        for (j, &cv) in constraint_values.iter().enumerate() {
            if j < alpha_powers.len() {
                // Extract base field from extension
                let base_val = cv.to_basefield_array()[0];
                combined_val = combined_val + alpha_powers[j] * base_val;
            }
        }

        combined[row] = combined_val;
    }

    combined
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;
    use plonky2::plonk::prover::extract_evaluation_tables;
    use plonky2_field::goldilocks_field::GoldilocksField;
    use plonky2_field::types::Field;
    use plonky2::util::timing::TimingTree;
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    #[test]
    fn test_combined_constraints_are_zero_for_valid_witness() {
        // Build a simple circuit: x * y = z, with x=3, y=5, z=15
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let x = builder.add_virtual_target();
        let y = builder.add_virtual_target();
        let z = builder.mul(x, y);

        builder.register_public_input(x);
        builder.register_public_input(y);
        builder.register_public_input(z);

        let circuit = builder.build::<C>();
        let mut pw = PartialWitness::new();
        pw.set_target(x, F::from_canonical_u64(3)).unwrap();
        pw.set_target(y, F::from_canonical_u64(5)).unwrap();

        let mut timing = TimingTree::default();
        let tables = extract_evaluation_tables::<F, C, D>(
            &circuit.prover_only,
            &circuit.common,
            pw,
            &mut timing,
        )
        .unwrap();

        // Compute combined constraints
        let alpha = F::from_canonical_u64(42);
        let combined = compute_combined_constraints::<F, D>(
            &circuit.common,
            &tables.wire_values,
            &tables.constant_values,
            &[alpha],
            &tables.public_inputs_hash,
            tables.degree,
        );

        // For a valid witness, all constraint evaluations should be zero,
        // so the combined value at every row should be zero.
        for (row, &val) in combined.iter().enumerate() {
            assert_eq!(
                val,
                F::ZERO,
                "Combined constraint at row {row} is non-zero: {val}"
            );
        }
    }
}
