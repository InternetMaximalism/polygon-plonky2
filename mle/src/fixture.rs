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
use ark_ff::{FftField, Field as ArkField, PrimeField as ArkPrimeField};
use plonky2_field::types::PrimeField64;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use whir::algebra::embedding::Basefield;
use whir::algebra::fields::{Field64_3, Field64 as ArkGoldilocks};
use whir::protocols::whir::Config as WhirConfig;

use crate::commitment::whir_pcs::{WhirPCS, WHIR_SESSION_NAME};
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
    /// Circuit digest (verifying key hash) — 4 Goldilocks field elements as decimal strings.
    /// SECURITY: Binds the proof to a specific Plonky2 circuit.
    pub circuit_digest: Vec<String>,
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
    /// WHIR transcript bytes (hex with 0x prefix).
    pub whir_transcript: String,
    /// WHIR hints bytes (hex with 0x prefix).
    pub whir_hints: String,
    /// WHIR protocol ID (hex with 0x prefix, 64 bytes).
    pub whir_protocol_id: String,
    /// WHIR session ID (hex with 0x prefix, 32 bytes).
    pub whir_session_id: String,
    /// WHIR evaluation value in Ext3 {c0, c1, c2}.
    pub whir_eval: Ext3Fixture,
    /// WHIR protocol parameters for on-chain verification.
    pub whir_params: WhirParamsFixture,
}

/// Ext3 field element fixture {c0, c1, c2} as decimal strings.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Ext3Fixture {
    pub c0: String,
    pub c1: String,
    pub c2: String,
}

/// WHIR protocol parameters for Solidity verifier.
/// Matches SpongefishWhirVerify.WhirParams struct exactly.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct WhirParamsFixture {
    pub num_variables: usize,
    pub folding_factor: usize,
    pub num_vectors: usize,
    pub out_domain_samples: usize,
    pub in_domain_samples: usize,
    pub initial_sumcheck_rounds: usize,
    pub num_rounds: usize,
    pub final_sumcheck_rounds: usize,
    pub final_size: usize,
    pub initial_codeword_length: usize,
    pub initial_merkle_depth: usize,
    pub initial_domain_generator: String,
    pub initial_interleaving_depth: usize,
    pub initial_num_variables: usize,
    pub initial_coset_size: usize,
    pub initial_num_cosets: usize,
    pub rounds: Vec<WhirRoundParamsFixture>,
}

/// Per-round WHIR parameters.
/// Matches SpongefishWhirVerify.RoundParams struct exactly.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct WhirRoundParamsFixture {
    pub codeword_length: usize,
    pub merkle_depth: usize,
    pub domain_generator: String,
    pub in_domain_samples: usize,
    pub out_domain_samples: usize,
    pub sumcheck_rounds: usize,
    pub interleaving_depth: usize,
    pub coset_size: usize,
    pub num_cosets: usize,
    pub num_variables: usize,
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

fn ext3_to_fixture(v: &Field64_3) -> Ext3Fixture {
    let elems: Vec<_> = ArkField::to_base_prime_field_elements(v).collect();
    Ext3Fixture {
        c0: elems[0].into_bigint().0[0].to_string(),
        c1: elems[1].into_bigint().0[0].to_string(),
        c2: elems[2].into_bigint().0[0].to_string(),
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    format!("0x{}", bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>())
}

fn log2_of(n: usize) -> usize {
    assert!(n.is_power_of_two());
    n.trailing_zeros() as usize
}

/// Compute the primitive root of unity for a domain of given size (Goldilocks field).
fn gl_root_of_unity(size: usize) -> u64 {
    use ark_ff::FftField;
    let gen = ArkGoldilocks::get_root_of_unity(size as u64).expect("No root of unity");
    gen.into_bigint().0[0]
}

/// Extract WHIR protocol parameters from config for Solidity verifier.
fn extract_whir_params(degree_bits: usize) -> (WhirParamsFixture, Vec<u8>, Vec<u8>) {
    let pcs = WhirPCS::for_num_vars(degree_bits);
    let size = 1 << degree_bits;
    let config = WhirConfig::<Basefield<Field64_3>>::new(size, &pcs.params);

    let num_variables = degree_bits;
    let folding_factor = pcs.params.folding_factor;
    let num_vectors = pcs.params.batch_size;
    let out_domain_samples = config.initial_committer.out_domain_samples;
    let in_domain_samples = config.initial_committer.in_domain_samples;
    let initial_sumcheck_rounds = config.initial_sumcheck.num_rounds;
    let num_rounds = config.round_configs.len();
    let final_sumcheck_rounds = config.final_sumcheck.num_rounds;

    // Final size: after all folding, what remains
    let mut remaining_vars = num_variables - pcs.params.initial_folding_factor;
    for _ in &config.round_configs {
        remaining_vars = remaining_vars.saturating_sub(folding_factor);
    }
    let final_size = 1 << remaining_vars;

    let initial_codeword_length = config.initial_committer.codeword_length;
    let initial_merkle_depth = log2_of(initial_codeword_length);
    let initial_domain_generator = gl_root_of_unity(initial_codeword_length);

    // Initial committer additional params
    let initial_interleaving_depth = config.initial_committer.interleaving_depth;
    let initial_num_variables = config.initial_num_variables();
    // masked_message_length = message_length + mask_length
    //                       = vector_size / interleaving_depth + mask_length
    let initial_mml = config.initial_committer.masked_message_length();
    let initial_coset_size = {
        let mut cs = initial_mml.next_power_of_two();
        while initial_codeword_length % cs != 0 { cs *= 2; }
        cs
    };
    let initial_num_cosets = initial_codeword_length / initial_coset_size;

    // Build per-round params using WHIR's own methods
    let rounds: Vec<WhirRoundParamsFixture> = config.round_configs.iter().map(|rc| {
        let cl = rc.irs_committer.codeword_length;
        let mml = rc.irs_committer.masked_message_length();
        let cs = {
            let mut c = mml.next_power_of_two();
            while cl % c != 0 { c *= 2; }
            c
        };
        // Use WHIR's own initial_num_variables() = log2(vector_size)
        let rv = rc.initial_num_variables();
        WhirRoundParamsFixture {
            codeword_length: cl,
            merkle_depth: log2_of(cl),
            domain_generator: gl_root_of_unity(cl).to_string(),
            in_domain_samples: rc.irs_committer.in_domain_samples,
            out_domain_samples: rc.irs_committer.out_domain_samples,
            sumcheck_rounds: rc.sumcheck.num_rounds,
            interleaving_depth: rc.irs_committer.interleaving_depth,
            coset_size: cs,
            num_cosets: cl / cs,
            num_variables: rv,
        }
    }).collect();

    let params_fixture = WhirParamsFixture {
        num_variables,
        folding_factor,
        num_vectors,
        out_domain_samples,
        in_domain_samples,
        initial_sumcheck_rounds,
        num_rounds,
        final_sumcheck_rounds,
        final_size,
        initial_codeword_length,
        initial_merkle_depth,
        initial_domain_generator: initial_domain_generator.to_string(),
        initial_interleaving_depth,
        initial_num_variables,
        initial_coset_size,
        initial_num_cosets,
        rounds,
    };

    // Compute protocol_id: keccak256(0x00 || cbor(config)) || keccak256(0x01 || cbor(config))
    let protocol_id = {
        let mut config_bytes = Vec::new();
        ciborium::into_writer(&config, &mut config_bytes).expect("CBOR serialization failed");
        let first: [u8; 32] = {
            let mut h = Keccak256::new();
            h.update([0x00]);
            h.update(&config_bytes);
            h.finalize().into()
        };
        let second: [u8; 32] = {
            let mut h = Keccak256::new();
            h.update([0x01]);
            h.update(&config_bytes);
            h.finalize().into()
        };
        let mut result = vec![0u8; 64];
        result[..32].copy_from_slice(&first);
        result[32..].copy_from_slice(&second);
        result
    };

    // Compute session_id: keccak256(cbor(session_name))
    let session_id = {
        let mut session_bytes = Vec::new();
        ciborium::into_writer(&WHIR_SESSION_NAME, &mut session_bytes)
            .expect("CBOR serialization failed");
        let mut h = Keccak256::new();
        h.update(&session_bytes);
        h.finalize().to_vec()
    };

    (params_fixture, protocol_id, session_id)
}

/// Convert an MleProof to a ProofFixture for JSON serialization.
pub fn proof_to_fixture<F: PrimeField64>(
    proof: &MleProof<F>,
    degree_bits: usize,
) -> ProofFixture {
    let root_hex: String = proof
        .commitment
        .proof_bytes
        .iter()
        .take(32)
        .map(|b| format!("{:02x}", b))
        .collect();

    let (whir_params, protocol_id, session_id) = extract_whir_params(degree_bits);

    ProofFixture {
        circuit_digest: field_vec_to_strings(&proof.circuit_digest),
        commitment_root: format!("0x{root_hex}"),
        perm_proof: sumcheck_to_fixture(&proof.permutation_proof.sumcheck_proof),
        perm_claimed_sum: field_to_string(proof.permutation_proof.claimed_sum),
        constraint_proof: sumcheck_to_fixture(&proof.constraint_proof),
        pcs_evaluations: vec![],
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
        whir_transcript: hex_encode(&proof.eval_proof.narg_string),
        whir_hints: hex_encode(&proof.eval_proof.hints),
        whir_protocol_id: hex_encode(&protocol_id),
        whir_session_id: hex_encode(&session_id),
        whir_eval: ext3_to_fixture(&proof.whir_eval_ext3),
        whir_params,
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
