/// Log-derivative lookup argument for Plonky2 lookup gates.
///
/// Proves that every (input, output) pair looked up by LookupGates
/// exists in the corresponding LookupTable, using the logUp formulation:
///
///   Σ_i m_i / (β + t_i) - Σ_j 1 / (β + f_j) = 0
///
/// where:
/// - t_i = table entries (combined as inp + δ·out)
/// - m_i = multiplicity of table entry i
/// - f_j = looked-up values (combined as inp + δ·out)
/// - β, δ are Fiat-Shamir challenges
///
/// This is proved via a plain sumcheck over the combined numerator polynomial.
use plonky2_field::types::Field;

use crate::dense_mle::DenseMultilinearExtension;
use crate::sumcheck::prover::prove_sumcheck_plain;
use crate::sumcheck::types::SumcheckProof;
use crate::transcript::Transcript;

/// Data extracted from Plonky2 for the lookup argument.
#[derive(Clone, Debug)]
pub struct LookupData<F: Field> {
    /// Table entries: (input, output) pairs from LookupTableGate wires.
    pub table_entries: Vec<(F, F)>,
    /// Multiplicities corresponding to each table entry.
    pub multiplicities: Vec<F>,
    /// Looked-up values: (input, output) pairs from LookupGate wires.
    pub lookups: Vec<(F, F)>,
}

/// Compute the lookup numerator polynomial h(b) over the combined domain.
///
/// We organize the data into a single evaluation table of size 2^n:
/// - First `|table|` entries: m_i / (β + t_i)   (table side, positive)
/// - Next `|lookups|` entries: -1 / (β + f_j)    (lookup side, negative)
/// - Remaining entries: 0 (padding)
///
/// For a valid lookup, Σ h(b) = 0.
pub fn compute_lookup_numerator<F: Field>(data: &LookupData<F>, beta: F, delta: F) -> Vec<F> {
    let total = data.table_entries.len() + data.lookups.len();
    let size = total.next_power_of_two().max(1);
    let mut h = vec![F::ZERO; size];

    // Table side: m_i / (β + inp_i + δ·out_i)
    for (i, &(inp, out)) in data.table_entries.iter().enumerate() {
        let combo = inp + delta * out;
        let denom = beta + combo;
        if denom != F::ZERO {
            h[i] = data.multiplicities[i] * denom.inverse();
        }
    }

    // Lookup side: -1 / (β + inp_j + δ·out_j)
    let offset = data.table_entries.len();
    for (j, &(inp, out)) in data.lookups.iter().enumerate() {
        let combo = inp + delta * out;
        let denom = beta + combo;
        if denom != F::ZERO {
            h[offset + j] = -denom.inverse();
        }
    }

    h
}

/// Extract lookup data from Plonky2 evaluation tables.
///
/// Reads LookupTableGate and LookupGate wire values to produce
/// the table entries, multiplicities, and looked-up values.
pub fn extract_lookup_data<F: Field>(
    wire_values: &[Vec<F>],
    common_gates: &[plonky2::gates::gate::GateRef<F, 2>],
    gate_instances: usize,
    _luts: &[plonky2::gates::lookup_table::LookupTable],
) -> Vec<LookupData<F>>
where
    F: plonky2::hash::hash_types::RichField + plonky2_field::extension::Extendable<2>,
{
    // For now, we extract lookup data by examining the wire values
    // at rows where lookup gates are placed. The gate type identification
    // is done via the gate ID string.
    let mut all_data = Vec::new();

    let mut table_entries = Vec::new();
    let mut multiplicities = Vec::new();
    let mut lookups = Vec::new();

    for (gate_idx, gate) in common_gates.iter().enumerate() {
        let gate_id = gate.0.id();

        if gate_id.contains("LookupTableGate") {
            // LookupTableGate: 3 wires per slot (input, output, multiplicity)
            let num_slots = gate.0.num_wires() / 3;
            for row in 0..gate_instances {
                for slot in 0..num_slots {
                    let inp_col = 3 * slot;
                    let out_col = 3 * slot + 1;
                    let mult_col = 3 * slot + 2;

                    if inp_col < wire_values.len() && row < wire_values[inp_col].len() {
                        let inp = wire_values[inp_col][row];
                        let out = wire_values[out_col][row];
                        let mult = wire_values[mult_col][row];
                        if mult != F::ZERO {
                            table_entries.push((inp, out));
                            multiplicities.push(mult);
                        }
                    }
                }
            }
        } else if gate_id.contains("LookupGate") && !gate_id.contains("Table") {
            let num_slots = gate.0.num_wires() / 2;
            for row in 0..gate_instances {
                for slot in 0..num_slots {
                    let inp_col = 2 * slot;
                    let out_col = 2 * slot + 1;

                    if inp_col < wire_values.len() && row < wire_values[inp_col].len() {
                        let inp = wire_values[inp_col][row];
                        let out = wire_values[out_col][row];
                        // Only include non-padding lookups
                        if inp != F::ZERO || out != F::ZERO {
                            lookups.push((inp, out));
                        }
                    }
                }
            }
        }
        let _ = gate_idx; // suppress unused
    }

    if !table_entries.is_empty() || !lookups.is_empty() {
        all_data.push(LookupData {
            table_entries,
            multiplicities,
            lookups,
        });
    }

    all_data
}

/// Prove the lookup argument via plain sumcheck: Σ h(b) = 0.
pub fn prove_lookup_check<F: Field + plonky2_field::types::PrimeField64>(
    data: &LookupData<F>,
    beta: F,
    delta: F,
    transcript: &mut Transcript,
) -> (SumcheckProof<F>, Vec<F>, F) {
    let h = compute_lookup_numerator(data, beta, delta);
    let claimed_sum: F = h.iter().copied().sum();

    let mut h_mle = DenseMultilinearExtension::new(h);
    let (proof, challenges) = prove_sumcheck_plain(&mut h_mle, transcript);

    (proof, challenges, claimed_sum)
}

/// Proof data for the lookup argument.
#[derive(Clone, Debug)]
pub struct LookupProof<F: Field> {
    pub sumcheck_proof: SumcheckProof<F>,
    pub challenges: Vec<F>,
    pub claimed_sum: F,
}

#[cfg(test)]
mod tests {
    use plonky2_field::goldilocks_field::GoldilocksField;

    use super::*;

    type F = GoldilocksField;

    #[test]
    fn test_valid_lookup() {
        // Table: {(0,0), (1,1), (2,4), (3,9)} with multiplicities [1, 2, 1, 0]
        // Lookups: (0,0), (1,1), (1,1), (2,4)
        let data = LookupData {
            table_entries: vec![
                (F::from_canonical_u64(0), F::from_canonical_u64(0)),
                (F::from_canonical_u64(1), F::from_canonical_u64(1)),
                (F::from_canonical_u64(2), F::from_canonical_u64(4)),
                (F::from_canonical_u64(3), F::from_canonical_u64(9)),
            ],
            multiplicities: vec![
                F::from_canonical_u64(1),
                F::from_canonical_u64(2),
                F::from_canonical_u64(1),
                F::from_canonical_u64(0),
            ],
            lookups: vec![
                (F::from_canonical_u64(0), F::from_canonical_u64(0)),
                (F::from_canonical_u64(1), F::from_canonical_u64(1)),
                (F::from_canonical_u64(1), F::from_canonical_u64(1)),
                (F::from_canonical_u64(2), F::from_canonical_u64(4)),
            ],
        };

        let beta = F::from_canonical_u64(12345);
        let delta = F::from_canonical_u64(67890);

        let h = compute_lookup_numerator(&data, beta, delta);
        let sum: F = h.iter().copied().sum();
        assert_eq!(sum, F::ZERO, "Valid lookup should have sum = 0, got {sum}");
    }

    #[test]
    fn test_invalid_lookup_detected() {
        // Table: {(0,0), (1,1)} with multiplicities [1, 0]
        // Lookups: (0,0), (2,4)  -- (2,4) is NOT in the table
        let data = LookupData {
            table_entries: vec![
                (F::from_canonical_u64(0), F::from_canonical_u64(0)),
                (F::from_canonical_u64(1), F::from_canonical_u64(1)),
            ],
            multiplicities: vec![F::from_canonical_u64(1), F::from_canonical_u64(0)],
            lookups: vec![
                (F::from_canonical_u64(0), F::from_canonical_u64(0)),
                (F::from_canonical_u64(2), F::from_canonical_u64(4)),
            ],
        };

        let beta = F::from_canonical_u64(12345);
        let delta = F::from_canonical_u64(67890);

        let h = compute_lookup_numerator(&data, beta, delta);
        let sum: F = h.iter().copied().sum();
        assert_ne!(sum, F::ZERO, "Invalid lookup should have non-zero sum");
    }

    #[test]
    fn test_lookup_prove_verify() {
        let data = LookupData {
            table_entries: vec![
                (F::from_canonical_u64(0), F::from_canonical_u64(0)),
                (F::from_canonical_u64(1), F::from_canonical_u64(1)),
                (F::from_canonical_u64(2), F::from_canonical_u64(4)),
            ],
            multiplicities: vec![
                F::from_canonical_u64(2),
                F::from_canonical_u64(1),
                F::from_canonical_u64(1),
            ],
            lookups: vec![
                (F::from_canonical_u64(0), F::from_canonical_u64(0)),
                (F::from_canonical_u64(0), F::from_canonical_u64(0)),
                (F::from_canonical_u64(1), F::from_canonical_u64(1)),
                (F::from_canonical_u64(2), F::from_canonical_u64(4)),
            ],
        };

        let beta = F::from_canonical_u64(999);
        let delta = F::from_canonical_u64(777);
        let mut transcript = Transcript::new();
        transcript.domain_separate("test-lookup");

        let (proof, challenges, claimed_sum) =
            prove_lookup_check(&data, beta, delta, &mut transcript);

        assert_eq!(claimed_sum, F::ZERO, "Valid lookup claimed_sum should be 0");

        // Verify sumcheck structure
        use crate::sumcheck::verifier::verify_sumcheck;
        let mut v_transcript = Transcript::new();
        v_transcript.domain_separate("test-lookup");

        let result = verify_sumcheck(&proof, claimed_sum, challenges.len(), &mut v_transcript);
        assert!(result.is_ok(), "Lookup sumcheck verification failed");
    }
}
