use plonky2::hash::hash_types::RichField;
/// Bridge between Plonky2 gate constraints and the MLE sumcheck system.
///
/// Evaluates Plonky2's gate constraints at each row of the evaluation tables
/// and combines them with alpha powers, producing a combined-constraint
/// MLE suitable for the zero-check sumcheck.
///
/// SECURITY: Gate constraints are evaluated in the extension field F::Extension
/// (degree D=2 for Goldilocks). The combined constraint must capture ALL
/// extension field components, not just the base field projection.
/// Ignoring c1 would allow an attacker to satisfy constraints in the base field
/// while violating them in the extension, breaking soundness for gates that
/// use extension field wires (e.g., CosetInterpolationGate in recursive proofs).
use plonky2::plonk::circuit_data::CommonCircuitData;
use plonky2::plonk::vanishing_poly::evaluate_gate_constraints;
use plonky2::plonk::vars::EvaluationVars;
use plonky2_field::extension::{Extendable, FieldExtension};
use plonky2_field::types::Field;

/// Evaluate all gate constraints at every row of the evaluation tables,
/// and combine them with alpha powers into extension field values per row.
///
/// Returns `combined[row]` as a vector of D field elements (extension field),
/// representing:
///   `C(row) = Σ_j α^j · constraint_j(wires[row], consts[row])`
///
/// where α and constraint values live in F::Extension.
///
/// For the zero-check sumcheck, each extension field component is treated
/// as a separate base-field constraint. The sumcheck proves:
///   `Σ_b eq(τ,b) · C_k(b) = 0`  for each component k ∈ {0, ..., D-1}.
pub fn compute_combined_constraints<F: RichField + Extendable<D>, const D: usize>(
    common_data: &CommonCircuitData<F, D>,
    wire_values: &[Vec<F>],
    constant_values: &[Vec<F>],
    alphas: &[F],
    public_inputs_hash: &plonky2::hash::hash_types::HashOut<F>,
    degree: usize,
) -> Vec<[F; D]> {
    let num_gate_constraints = common_data.num_gate_constraints;
    let num_wires = common_data.config.num_wires;
    let num_constants = common_data.num_constants;

    // Precompute alpha powers in the extension field.
    // SECURITY: α is a base field element lifted to the extension field.
    // The constraint combination Σ α^j · c_j operates entirely in the extension.
    let alpha_ext: F::Extension = if !alphas.is_empty() {
        F::Extension::from_basefield(alphas[0])
    } else {
        F::Extension::ZERO
    };

    let alpha_powers: Vec<F::Extension> = {
        let mut powers = Vec::with_capacity(num_gate_constraints);
        let mut pow = F::Extension::ONE;
        for _ in 0..num_gate_constraints {
            powers.push(pow);
            pow *= alpha_ext;
        }
        powers
    };

    let mut combined: Vec<[F; D]> = vec![[F::ZERO; D]; degree];

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

        // evaluate_gate_constraints handles ALL gate types:
        // ArithmeticGate, ConstantGate, PublicInputGate, PoseidonGate,
        // CosetInterpolationGate, RandomAccessGate, BaseSumGate,
        // ExponentiationGate, LookupGate, etc.
        let constraint_values = evaluate_gate_constraints(common_data, vars);

        // SECURITY: Combine in the extension field, preserving ALL components.
        // Each constraint value cv is in F::Extension (D components).
        // The combined value C(row) = Σ_j α^j · cv_j is also in F::Extension.
        let mut combined_ext = F::Extension::ZERO;
        for (j, &cv) in constraint_values.iter().enumerate() {
            if j < alpha_powers.len() {
                combined_ext += alpha_powers[j] * cv;
            }
        }

        combined[row] = combined_ext.to_basefield_array();
    }

    combined
}

/// Flatten extension field combined constraints into base field for sumcheck.
///
/// The zero-check requires Σ eq(τ,b) · C(b) = 0. Since C(b) is in the extension
/// field (D components), we treat each component as an independent constraint:
///   `Σ eq(τ,b) · C_k(b) = 0`  for k = 0, ..., D-1.
///
/// This returns D separate base-field MLEs, each of which must be zero-checked.
/// Alternatively, they can be random-linearly combined with a fresh challenge.
pub fn flatten_extension_constraints<F: RichField + Extendable<D>, const D: usize>(
    combined: &[[F; D]],
    extension_challenge: F,
) -> Vec<F> {
    combined
        .iter()
        .map(|components| {
            // Combine D components with powers of extension_challenge:
            // flat = c_0 + extension_challenge * c_1 + extension_challenge^2 * c_2 + ...
            let mut result = F::ZERO;
            let mut pow = F::ONE;
            for &c in components.iter() {
                result += pow * c;
                pow *= extension_challenge;
            }
            result
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;
    use plonky2::plonk::prover::extract_evaluation_tables;
    use plonky2::util::timing::TimingTree;
    use plonky2_field::goldilocks_field::GoldilocksField;
    use plonky2_field::types::Field;

    use super::*;

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    #[test]
    fn test_combined_constraints_are_zero_for_valid_witness() {
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

        let alpha = F::from_canonical_u64(42);
        let combined = compute_combined_constraints::<F, D>(
            &circuit.common,
            &tables.wire_values,
            &tables.constant_values,
            &[alpha],
            &tables.public_inputs_hash,
            tables.degree,
        );

        // For a valid witness, ALL extension field components must be zero.
        for (row, components) in combined.iter().enumerate() {
            for (k, &val) in components.iter().enumerate() {
                assert_eq!(
                    val,
                    F::ZERO,
                    "Constraint component {k} at row {row} is non-zero: {val}"
                );
            }
        }
    }

    #[test]
    fn test_poseidon_constraints_extension_field() {
        // Poseidon gate uses extension field wires internally.
        // Verify that ALL extension components are zero.
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        use plonky2::hash::poseidon::PoseidonHash;
        let inputs: Vec<_> = (0..4).map(|_| builder.add_virtual_target()).collect();
        let hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(inputs.clone());
        for &h in hash.elements.iter() {
            builder.register_public_input(h);
        }

        let circuit = builder.build::<C>();
        let mut pw = PartialWitness::new();
        for (i, &input) in inputs.iter().enumerate() {
            pw.set_target(input, F::from_canonical_u64(i as u64 + 1)).unwrap();
        }

        let mut timing = TimingTree::default();
        let tables = extract_evaluation_tables::<F, C, D>(
            &circuit.prover_only,
            &circuit.common,
            pw,
            &mut timing,
        )
        .unwrap();

        let alpha = F::from_canonical_u64(999);
        let combined = compute_combined_constraints::<F, D>(
            &circuit.common,
            &tables.wire_values,
            &tables.constant_values,
            &[alpha],
            &tables.public_inputs_hash,
            tables.degree,
        );

        for (row, components) in combined.iter().enumerate() {
            for (k, &val) in components.iter().enumerate() {
                assert_eq!(
                    val,
                    F::ZERO,
                    "Poseidon constraint [{k}] at row {row}: {val}"
                );
            }
        }
    }

    #[test]
    fn test_flatten_extension_constraints() {
        let combined: Vec<[F; 2]> = vec![
            [F::ZERO, F::ZERO],
            [F::from_canonical_u64(3), F::from_canonical_u64(5)],
        ];

        let challenge = F::from_canonical_u64(7);
        let flat = flatten_extension_constraints::<F, 2>(&combined, challenge);

        assert_eq!(flat[0], F::ZERO); // 0 + 7*0
        assert_eq!(
            flat[1],
            F::from_canonical_u64(3) + F::from_canonical_u64(7) * F::from_canonical_u64(5)
        );
    }
}
