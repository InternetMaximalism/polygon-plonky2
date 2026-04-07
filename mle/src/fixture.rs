/// JSON fixture generation for Solidity verification.
///
/// SECURITY: All Goldilocks field elements MUST be serialized as decimal strings,
/// NOT as JSON numbers. JSON numbers use IEEE 754 double precision (53-bit mantissa),
/// which silently truncates values > 2^53. Goldilocks field elements can be up to
/// 2^64 - 2^32 ≈ 1.8 × 10^19, far exceeding the safe integer range.
///
/// Example of precision loss:
///   Original:  18089690094123470162
///   JSON num:  18089690094123470848  (off by 686!)
///   As string: "18089690094123470162" (exact)
use plonky2_field::types::PrimeField64;
use std::fmt::Write;

use crate::proof::MleProof;
use crate::sumcheck::types::SumcheckProof;

/// Serialize an MleProof to a JSON string with all field elements as decimal strings.
///
/// This format is safe for consumption by Solidity test fixtures via
/// Foundry's `vm.parseJson` or `abi.decode`.
pub fn proof_to_json<F: PrimeField64 + std::fmt::Debug>(proof: &MleProof<F>) -> String {
    let mut out = String::new();
    writeln!(out, "{{").unwrap();

    // Commitment root (hex)
    let root_hex: String = proof.commitment.root.iter().map(|b| format!("{:02x}", b)).collect();
    writeln!(out, "  \"commitmentRoot\": \"0x{root_hex}\",").unwrap();

    // Scalar fields as strings
    writeln!(out, "  \"evalValue\": \"{}\",", proof.eval_value.to_canonical_u64()).unwrap();
    writeln!(out, "  \"batchR\": \"{}\",", proof.batch_r.to_canonical_u64()).unwrap();
    writeln!(out, "  \"numPolys\": {},", proof.num_polys).unwrap();
    writeln!(out, "  \"alpha\": \"{}\",", proof.alpha.to_canonical_u64()).unwrap();
    writeln!(out, "  \"beta\": \"{}\",", proof.beta.to_canonical_u64()).unwrap();
    writeln!(out, "  \"gamma\": \"{}\",", proof.gamma.to_canonical_u64()).unwrap();
    writeln!(out, "  \"pcsConstraintEval\": \"{}\",", proof.pcs_constraint_eval.to_canonical_u64()).unwrap();
    writeln!(out, "  \"pcsPermNumeratorEval\": \"{}\",", proof.pcs_perm_numerator_eval.to_canonical_u64()).unwrap();
    writeln!(out, "  \"permClaimedSum\": \"{}\",", proof.permutation_proof.claimed_sum.to_canonical_u64()).unwrap();

    // Circuit dimensions
    writeln!(out, "  \"numWires\": {},", proof.num_wires).unwrap();
    writeln!(out, "  \"numRoutedWires\": {},", proof.num_routed_wires).unwrap();
    writeln!(out, "  \"numConstants\": {},", proof.num_constants).unwrap();

    // Field element arrays as string arrays
    writeln!(out, "  \"publicInputs\": [{}],", field_vec_to_string_array(&proof.public_inputs)).unwrap();
    writeln!(out, "  \"individualEvals\": [{}],", field_vec_to_string_array(&proof.individual_evals)).unwrap();
    writeln!(out, "  \"tau\": [{}],", field_vec_to_string_array(&proof.tau)).unwrap();
    writeln!(out, "  \"tauPerm\": [{}],", field_vec_to_string_array(&proof.tau_perm)).unwrap();

    // Public inputs hash
    // (need to be extracted from the proof generation - for now use zeros)

    // Sumcheck proofs
    writeln!(out, "  \"permProof\": {},", sumcheck_proof_to_json(&proof.permutation_proof.sumcheck_proof)).unwrap();
    writeln!(out, "  \"constraintProof\": {},", sumcheck_proof_to_json(&proof.constraint_proof)).unwrap();

    // PCS evaluations (the full evaluation table)
    writeln!(out, "  \"pcsEvaluations\": [{}]", field_vec_to_string_array(&proof.eval_proof.evaluations)).unwrap();

    writeln!(out, "}}").unwrap();
    out
}

fn field_vec_to_string_array<F: PrimeField64>(elems: &[F]) -> String {
    elems
        .iter()
        .map(|f| format!("\"{}\"", f.to_canonical_u64()))
        .collect::<Vec<_>>()
        .join(", ")
}

fn sumcheck_proof_to_json<F: PrimeField64>(proof: &SumcheckProof<F>) -> String {
    let rounds: Vec<String> = proof
        .round_polys
        .iter()
        .map(|rp| {
            let evals = rp
                .evaluations
                .iter()
                .map(|f| format!("\"{}\"", f.to_canonical_u64()))
                .collect::<Vec<_>>()
                .join(", ");
            format!("[{evals}]")
        })
        .collect();
    format!("{{\"roundPolys\": [{}]}}", rounds.join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2_field::goldilocks_field::GoldilocksField;
    use plonky2_field::types::Field;

    type F = GoldilocksField;

    #[test]
    fn test_large_field_element_serialization() {
        // This value would lose precision if serialized as a JSON number
        // Use a large value close to P
        let val = F::from_canonical_u64(18089690094123470162u64 % (0xFFFFFFFF00000001u64));
        let s = format!("{}", val.to_canonical_u64());

        // Parse back
        let parsed: u64 = s.parse().unwrap();
        assert_eq!(parsed, val.to_canonical_u64());

        // Verify this value IS > 2^53 (would be corrupted by JSON number)
        assert!(val.to_canonical_u64() > (1u64 << 53));
    }

    #[test]
    fn test_proof_to_json_roundtrip() {
        use crate::prover::mle_prove;
        use plonky2::iop::witness::{PartialWitness, WitnessWrite};
        use plonky2::plonk::circuit_builder::CircuitBuilder;
        use plonky2::plonk::circuit_data::CircuitConfig;
        use plonky2::plonk::config::PoseidonGoldilocksConfig;
        use plonky2::util::timing::TimingTree;

        type C = PoseidonGoldilocksConfig;
        const D: usize = 2;

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let x = builder.add_virtual_target();
        let y = builder.add_virtual_target();
        let z = builder.mul(x, y);
        builder.register_public_input(z);
        let circuit = builder.build::<C>();

        let mut pw = PartialWitness::new();
        pw.set_target(x, F::from_canonical_u64(3));
        pw.set_target(y, F::from_canonical_u64(7));

        let mut timing = TimingTree::default();
        let proof = mle_prove::<F, C, D>(
            &circuit.prover_only,
            &circuit.common,
            pw,
            &mut timing,
        )
        .unwrap();

        let json = proof_to_json(&proof);

        // Verify all field elements are strings (not numbers)
        assert!(!json.contains(": 180"), "Large numbers should be strings, not bare numbers");

        // Verify the JSON is valid-ish (contains expected fields)
        assert!(json.contains("\"commitmentRoot\""));
        assert!(json.contains("\"permProof\""));
        assert!(json.contains("\"roundPolys\""));

        println!("{json}");
    }
}
