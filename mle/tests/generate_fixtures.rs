/// Generate proof fixtures for Solidity E2E verification and gas benchmarking.
///
/// Creates proofs for circuits of varying sizes and writes JSON fixtures.
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use plonky2::util::timing::TimingTree;
use plonky2_field::goldilocks_field::GoldilocksField;
use plonky2_field::types::{Field, PrimeField64};
use plonky2_mle::fixture::{parse_field_string, proof_to_json};
use plonky2_mle::prover::{mle_prove, mle_setup};
use plonky2_mle::verifier::mle_verify;

type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;
const D: usize = 2;

fn build_mul_chain_circuit(
    chain_len: usize,
) -> (
    plonky2::plonk::circuit_data::CircuitData<F, C, D>,
    PartialWitness<F>,
) {
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let x = builder.add_virtual_target();
    let mut current = x;
    for _ in 0..chain_len {
        current = builder.mul(current, x);
    }
    builder.register_public_input(current);
    let circuit = builder.build::<C>();
    let mut pw = PartialWitness::new();
    pw.set_target(x, F::from_canonical_u64(2)).unwrap();
    (circuit, pw)
}

fn build_hash_circuit() -> (
    plonky2::plonk::circuit_data::CircuitData<F, C, D>,
    PartialWitness<F>,
) {
    use plonky2::hash::poseidon::PoseidonHash;
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let inputs: Vec<_> = (0..4).map(|_| builder.add_virtual_target()).collect();
    let hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(inputs.clone());
    for &h in hash.elements.iter() {
        builder.register_public_input(h);
    }
    let circuit = builder.build::<C>();
    let mut pw = PartialWitness::new();
    for (i, &input) in inputs.iter().enumerate() {
        pw.set_target(input, F::from_canonical_u64(i as u64 + 1))
            .unwrap();
    }
    (circuit, pw)
}

fn build_recursive_circuit() -> (
    plonky2::plonk::circuit_data::CircuitData<F, C, D>,
    PartialWitness<F>,
) {
    // Inner: x * y = z
    let inner_config = CircuitConfig::standard_recursion_config();
    let mut inner_builder = CircuitBuilder::<F, D>::new(inner_config);
    let x = inner_builder.add_virtual_target();
    let y = inner_builder.add_virtual_target();
    let z = inner_builder.mul(x, y);
    inner_builder.register_public_input(z);
    let inner_data = inner_builder.build::<C>();

    let mut inner_pw = PartialWitness::new();
    inner_pw.set_target(x, F::from_canonical_u64(3)).unwrap();
    inner_pw.set_target(y, F::from_canonical_u64(7)).unwrap();
    let inner_proof = inner_data.prove(inner_pw).unwrap();

    // Outer: verify inner proof
    let outer_config = CircuitConfig::standard_recursion_config();
    let mut outer_builder = CircuitBuilder::<F, D>::new(outer_config);
    let proof_t = outer_builder.add_virtual_proof_with_pis(&inner_data.common);
    let vd_t =
        outer_builder.add_virtual_verifier_data(inner_data.common.config.fri_config.cap_height);
    outer_builder.verify_proof::<C>(&proof_t, &vd_t, &inner_data.common);
    for &pi in &proof_t.public_inputs {
        outer_builder.register_public_input(pi);
    }
    let outer_data = outer_builder.build::<C>();

    let mut outer_pw = PartialWitness::new();
    outer_pw
        .set_proof_with_pis_target(&proof_t, &inner_proof)
        .unwrap();
    outer_pw
        .set_verifier_data_target(&vd_t, &inner_data.verifier_only)
        .unwrap();
    (outer_data, outer_pw)
}

/// Build a recursive circuit whose **inner** FRI is forced to fold at
/// least once, so the **outer** verifier circuit instantiates a
/// `CosetInterpolationGate` row at non-zero filter. This is the fixture
/// that exercises the Solidity `_evalCosetInterpolation` evaluator end
/// to end (see `tasks/coset_interpolation_port.md` §5 P2).
///
/// Why the dedicated builder: the default `build_recursive_circuit`
/// keeps the inner circuit so small (one multiplication, padded to
/// degree_bits ≈ 3) that the inner FRI does not need any folding
/// (`reduction_arity_bits = []` from
/// `FriReductionStrategy::ConstantArityBits(4,5)` since the trip-count
/// condition fails). We override the inner config in two ways:
///   1. **Many multiplications** to push the inner `degree_bits` past
///      the cap that `ConstantArityBits` needs to fold once.
///   2. **`Fixed(vec![4])` reduction strategy** as a belt-and-braces
///      guarantee that the inner FRI always emits exactly one
///      `arity_bits = 4` fold step (= subgroup_bits = 4 = supported
///      Solidity branch). Without (2), tweaks elsewhere (rate_bits,
///      cap_height, mul-chain length) could silently drop the fold and
///      the fixture would regress to "no CosetInterpolation".
fn build_recursive_circuit_with_coset_interp() -> (
    plonky2::plonk::circuit_data::CircuitData<F, C, D>,
    PartialWitness<F>,
) {
    use plonky2::fri::reduction_strategies::FriReductionStrategy;

    // Inner config: force exactly one FRI fold of arity 16
    // (= `subgroup_bits = 4` for the outer's `CosetInterpolationGate`).
    let mut inner_config = CircuitConfig::standard_recursion_config();
    inner_config.fri_config.reduction_strategy = FriReductionStrategy::Fixed(vec![4]);

    let mut inner_builder = CircuitBuilder::<F, D>::new(inner_config);
    let x = inner_builder.add_virtual_target();
    let mut current = x;
    // Long-enough mul-chain so the inner satisfies the FRI total-arity
    // check `total_arities ≤ degree_bits + rate_bits − cap_height`.
    // With `Fixed(vec![4])`, `rate_bits = 3`, `cap_height = 4`, we need
    // `inner_degree_bits ≥ 5`. plonky2's ArithmeticGate packs many mul
    // ops per row, so we err on the side of plenty: 2000 ops → about 100
    // rows → `degree_bits ≥ 7` with selector/padding overhead. This is
    // overkill but resilient to upstream gate-packing changes.
    for _ in 0..2000 {
        current = inner_builder.mul(current, x);
    }
    inner_builder.register_public_input(current);
    let inner_data = inner_builder.build::<C>();

    let mut inner_pw = PartialWitness::new();
    inner_pw.set_target(x, F::from_canonical_u64(2)).unwrap();
    let inner_proof = inner_data.prove(inner_pw).unwrap();

    // Outer: same standard config (unchanged).
    let outer_config = CircuitConfig::standard_recursion_config();
    let mut outer_builder = CircuitBuilder::<F, D>::new(outer_config);
    let proof_t = outer_builder.add_virtual_proof_with_pis(&inner_data.common);
    let vd_t =
        outer_builder.add_virtual_verifier_data(inner_data.common.config.fri_config.cap_height);
    outer_builder.verify_proof::<C>(&proof_t, &vd_t, &inner_data.common);
    for &pi in &proof_t.public_inputs {
        outer_builder.register_public_input(pi);
    }
    let outer_data = outer_builder.build::<C>();

    // SANITY: the outer's gate list MUST include `CosetInterpolationGate`.
    // If this fails, the fixture would silently regress to no-CosetInterp
    // and the on-chain E2E test would no longer exercise the new gate.
    let coset_in_outer = outer_data
        .common
        .gates
        .iter()
        .any(|g| g.0.id().starts_with("CosetInterpolationGate"));
    assert!(
        coset_in_outer,
        "build_recursive_circuit_with_coset_interp: outer gate list does not contain \
         CosetInterpolationGate. Inner FRI strategy did not produce a fold step; \
         this fixture would not exercise the Solidity `_evalCosetInterpolation` branch."
    );

    let mut outer_pw = PartialWitness::new();
    outer_pw
        .set_proof_with_pis_target(&proof_t, &inner_proof)
        .unwrap();
    outer_pw
        .set_verifier_data_target(&vd_t, &inner_data.verifier_only)
        .unwrap();
    (outer_data, outer_pw)
}

#[test]
fn generate_and_verify_all_fixtures() {
    let fixture_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("contracts")
        .join("test")
        .join("fixtures");
    std::fs::create_dir_all(&fixture_dir).unwrap();

    #[allow(clippy::type_complexity)]
    let circuits: Vec<(
        &str,
        Box<
            dyn Fn() -> (
                plonky2::plonk::circuit_data::CircuitData<F, C, D>,
                PartialWitness<F>,
            ),
        >,
    )> = vec![
        ("small_mul", Box::new(|| build_mul_chain_circuit(5))),
        ("medium_mul", Box::new(|| build_mul_chain_circuit(50))),
        ("large_mul", Box::new(|| build_mul_chain_circuit(200))),
        ("poseidon_hash", Box::new(build_hash_circuit)),
        ("recursive_verify", Box::new(build_recursive_circuit)),
        // E2E fixture that exercises `_evalCosetInterpolation` on-chain.
        // See `build_recursive_circuit_with_coset_interp` for why the
        // default `recursive_verify` does NOT trigger that branch.
        (
            "coset_recursive_verify",
            Box::new(build_recursive_circuit_with_coset_interp),
        ),
        ("huge_mul", Box::new(|| build_mul_chain_circuit(100000))),
    ];

    println!("\n============================================================");
    println!("  FIXTURE GENERATION + RUST VERIFICATION");
    println!("============================================================\n");

    for (name, build_fn) in &circuits {
        let (circuit, pw) = build_fn();
        let degree = circuit.common.degree();
        let degree_bits = circuit.common.degree_bits();
        let num_gates = circuit.common.gates.len();

        println!("Circuit: {name}");
        println!("  degree={degree}, degree_bits={degree_bits}, gate_types={num_gates}");

        let mut timing = TimingTree::default();
        let start = std::time::Instant::now();
        let proof =
            mle_prove::<F, C, D>(&circuit.prover_only, &circuit.common, pw, &mut timing).unwrap();
        let prove_time = start.elapsed();

        println!("  prove_time={:?}", prove_time);
        println!(
            "  public_inputs={:?}",
            proof
                .public_inputs
                .iter()
                .map(|f| f.to_canonical_u64())
                .collect::<Vec<_>>()
        );
        println!(
            "  num_polys={}",
            proof.witness_individual_evals.len() + proof.preprocessed_individual_evals.len()
        );
        println!(
            "  combined_sumcheck_rounds={}",
            proof.combined_proof.round_polys.len()
        );
        println!(
            "  whir_proof_bytes={}",
            proof.whir_eval_proof.narg_string.len() + proof.whir_eval_proof.hints.len()
        );

        // Verify in Rust
        let vk = mle_setup::<F, C, D>(&circuit.prover_only, &circuit.common);
        let start = std::time::Instant::now();
        let result = mle_verify::<F, D>(&circuit.common, &vk, &proof);
        let verify_time = start.elapsed();
        assert!(
            result.is_ok(),
            "{name}: Rust verify failed: {:?}",
            result.err()
        );
        println!("  rust_verify={:?} ✓", verify_time);

        // Generate JSON fixture
        let json = proof_to_json::<F, D>(&proof, &circuit.common, degree_bits);

        // Verify fixture roundtrip
        let fixture = plonky2_mle::fixture::fixture_from_json(&json);
        assert_eq!(
            parse_field_string(&fixture.witness_batch_r),
            proof.witness_batch_r.to_canonical_u64()
        );
        assert_eq!(fixture.degree_bits, degree_bits);

        // Check all field elements survived serialization
        for (i, rp) in fixture.combined_proof.round_polys.iter().enumerate() {
            for (j, s) in rp.iter().enumerate() {
                let parsed = parse_field_string(s);
                let original =
                    proof.combined_proof.round_polys[i].evaluations[j].to_canonical_u64();
                assert_eq!(
                    parsed, original,
                    "{name}: combined round[{i}][{j}] fixture mismatch: {parsed} != {original}"
                );
            }
        }

        // Write fixture
        let path = fixture_dir.join(format!("{name}.json"));
        std::fs::write(&path, &json).unwrap();
        println!(
            "  fixture_written={} ({} bytes)",
            path.display(),
            json.len()
        );

        println!();
    }
}
