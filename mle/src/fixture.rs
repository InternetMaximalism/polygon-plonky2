/// JSON fixture generation and parsing for Solidity verification.
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
use serde::{Deserialize, Serialize};

use crate::proof::MleProof;
use crate::sumcheck::types::SumcheckProof;

// ═══════════════════════════════════════════════════════════════════════════
//  Serializable fixture types (all field elements as strings)
// ═══════════════════════════════════════════════════════════════════════════

/// A complete serializable proof fixture for Solidity consumption.
///
/// Every field element is a decimal string to prevent IEEE 754 precision loss.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ProofFixture {
    /// Merkle commitment root (hex with 0x prefix).
    pub commitment_root: String,
    /// Sumcheck proofs.
    pub perm_proof: SumcheckFixture,
    pub perm_claimed_sum: String,
    pub constraint_proof: SumcheckFixture,
    /// PCS evaluations (full table for Merkle verification).
    pub pcs_evaluations: Vec<String>,
    /// Batched evaluation at sumcheck point.
    pub eval_value: String,
    /// Public inputs.
    pub public_inputs: Vec<String>,
    /// Batch random scalar.
    pub batch_r: String,
    /// Number of batched polynomials.
    pub num_polys: usize,
    /// Individual MLE evaluations at sumcheck point.
    pub individual_evals: Vec<String>,
    /// Fiat-Shamir challenges.
    pub alpha: String,
    pub beta: String,
    pub gamma: String,
    pub tau: Vec<String>,
    pub tau_perm: Vec<String>,
    /// Oracle values (PCS-bound).
    pub pcs_constraint_eval: String,
    pub pcs_perm_numerator_eval: String,
    /// Circuit dimensions.
    pub num_wires: usize,
    pub num_routed_wires: usize,
    pub num_constants: usize,
    /// Circuit degree (log2).
    pub degree_bits: usize,
}

/// Serializable sumcheck proof.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SumcheckFixture {
    /// Round polynomials, each as a vector of evaluation strings.
    pub round_polys: Vec<Vec<String>>,
}

// ═══════════════════════════════════════════════════════════════════════════
//  Conversion from MleProof to ProofFixture
// ═══════════════════════════════════════════════════════════════════════════

fn field_to_string<F: PrimeField64>(f: F) -> String {
    f.to_canonical_u64().to_string()
}

fn field_vec_to_strings<F: PrimeField64>(v: &[F]) -> Vec<String> {
    v.iter().map(|f| field_to_string(*f)).collect()
}

fn sumcheck_to_fixture<F: PrimeField64>(proof: &SumcheckProof<F>) -> SumcheckFixture {
    SumcheckFixture {
        round_polys: proof
            .round_polys
            .iter()
            .map(|rp| field_vec_to_strings(&rp.evaluations))
            .collect(),
    }
}

/// Convert an MleProof to a ProofFixture for JSON serialization.
pub fn proof_to_fixture<F: PrimeField64>(
    proof: &MleProof<F>,
    degree_bits: usize,
) -> ProofFixture {
    let root_hex: String = proof
        .commitment
        .root
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();

    ProofFixture {
        commitment_root: format!("0x{root_hex}"),
        perm_proof: sumcheck_to_fixture(&proof.permutation_proof.sumcheck_proof),
        perm_claimed_sum: field_to_string(proof.permutation_proof.claimed_sum),
        constraint_proof: sumcheck_to_fixture(&proof.constraint_proof),
        pcs_evaluations: field_vec_to_strings(&proof.eval_proof.evaluations),
        eval_value: field_to_string(proof.eval_value),
        public_inputs: field_vec_to_strings(&proof.public_inputs),
        batch_r: field_to_string(proof.batch_r),
        num_polys: proof.num_polys,
        individual_evals: field_vec_to_strings(&proof.individual_evals),
        alpha: field_to_string(proof.alpha),
        beta: field_to_string(proof.beta),
        gamma: field_to_string(proof.gamma),
        tau: field_vec_to_strings(&proof.tau),
        tau_perm: field_vec_to_strings(&proof.tau_perm),
        pcs_constraint_eval: field_to_string(proof.pcs_constraint_eval),
        pcs_perm_numerator_eval: field_to_string(proof.pcs_perm_numerator_eval),
        num_wires: proof.num_wires,
        num_routed_wires: proof.num_routed_wires,
        num_constants: proof.num_constants,
        degree_bits,
    }
}

/// Serialize an MleProof to a JSON string (all field elements as strings).
pub fn proof_to_json<F: PrimeField64>(
    proof: &MleProof<F>,
    degree_bits: usize,
) -> String {
    let fixture = proof_to_fixture(proof, degree_bits);
    serde_json::to_string_pretty(&fixture).expect("Failed to serialize proof fixture")
}

// ═══════════════════════════════════════════════════════════════════════════
//  Parsing: ProofFixture back to values
// ═══════════════════════════════════════════════════════════════════════════

/// Parse a decimal string to a u64 (for Goldilocks field elements).
pub fn parse_field_string(s: &str) -> u64 {
    s.parse::<u64>().unwrap_or_else(|e| panic!("Invalid field element string '{}': {}", s, e))
}

/// Parse a vector of decimal strings to u64 values.
pub fn parse_field_strings(v: &[String]) -> Vec<u64> {
    v.iter().map(|s| parse_field_string(s)).collect()
}

/// Load a ProofFixture from a JSON string.
pub fn fixture_from_json(json: &str) -> ProofFixture {
    serde_json::from_str(json).expect("Failed to parse proof fixture JSON")
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2_field::goldilocks_field::GoldilocksField;
    use plonky2_field::types::Field;

    type F = GoldilocksField;

    #[test]
    fn test_large_field_element_roundtrip() {
        // This value > 2^53 — would be corrupted by JSON number
        let val = 18089690094123470162u64 % 0xFFFFFFFF00000001u64;
        let s = val.to_string();
        let parsed = parse_field_string(&s);
        assert_eq!(val, parsed, "String roundtrip should be exact");
        assert!(val > (1u64 << 53), "Test value should exceed IEEE 754 safe range");
    }

    #[test]
    fn test_proof_fixture_roundtrip() {
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

        // Serialize to JSON
        let json = proof_to_json(&proof, circuit.common.degree_bits());

        // Verify all field elements are strings (not bare numbers > 9 digits)
        // The JSON should never have a bare number that could be a field element
        assert!(json.contains("\"batchR\": \""), "batchR should be a string");
        assert!(json.contains("\"alpha\": \""), "alpha should be a string");
        assert!(json.contains("\"roundPolys\""), "should have roundPolys");

        // Parse back
        let fixture = fixture_from_json(&json);
        assert_eq!(fixture.num_polys, proof.num_polys);
        assert_eq!(fixture.degree_bits, circuit.common.degree_bits());

        // Verify field element roundtrip
        let batch_r_parsed = parse_field_string(&fixture.batch_r);
        assert_eq!(batch_r_parsed, proof.batch_r.to_canonical_u64());

        // Verify perm round polys roundtrip
        for (i, rp) in fixture.perm_proof.round_polys.iter().enumerate() {
            for (j, s) in rp.iter().enumerate() {
                let parsed = parse_field_string(s);
                let original = proof.permutation_proof.sumcheck_proof.round_polys[i]
                    .evaluations[j]
                    .to_canonical_u64();
                assert_eq!(parsed, original, "perm round[{i}][{j}] mismatch");
            }
        }
    }

    #[test]
    fn test_ieee754_precision_loss_detected() {
        // Demonstrate that using JSON numbers would lose precision
        let large_val = 18089690094123470162u64;
        let as_f64 = large_val as f64;
        let back_to_u64 = as_f64 as u64;
        assert_ne!(
            large_val, back_to_u64,
            "IEEE 754 double SHOULD lose precision for this value"
        );

        // Our string serialization preserves it
        let s = large_val.to_string();
        let parsed: u64 = s.parse().unwrap();
        assert_eq!(large_val, parsed, "String serialization MUST be exact");
    }
}
