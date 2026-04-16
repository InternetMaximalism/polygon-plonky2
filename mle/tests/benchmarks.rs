/// Comprehensive benchmarks: ZKP generation time + proof size for various circuits.
///
/// Run with: cargo test -p plonky2_mle --release --test benchmarks -- --nocapture
use std::time::Instant;

use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use plonky2::util::timing::TimingTree;
use plonky2_field::goldilocks_field::GoldilocksField;
use plonky2_field::types::Field;
use plonky2_mle::prover::{mle_prove, mle_setup};
use plonky2_mle::verifier::mle_verify;

type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;
const D: usize = 2;

struct BenchResult {
    name: String,
    degree: usize,
    degree_bits: usize,
    gate_types: usize,
    prove_ms: f64,
    verify_ms: f64,
    proof_bytes: usize,
    whir_proof_bytes: usize,
}

fn bench_circuit(
    name: &str,
    circuit: &plonky2::plonk::circuit_data::CircuitData<F, C, D>,
    pw: PartialWitness<F>,
) -> BenchResult {
    let degree = circuit.common.degree();
    let degree_bits = circuit.common.degree_bits();
    let gate_types = circuit.common.gates.len();

    // Prove
    let mut timing = TimingTree::default();
    let start = Instant::now();
    let proof =
        mle_prove::<F, C, D>(&circuit.prover_only, &circuit.common, pw, &mut timing).unwrap();
    let prove_ms = start.elapsed().as_secs_f64() * 1000.0;

    // Proof size
    let whir_proof_bytes =
        proof.whir_eval_proof.narg_string.len() + proof.whir_eval_proof.hints.len();
    let sumcheck_bytes: usize = proof
        .combined_proof
        .round_polys
        .iter()
        .map(|rp| rp.evaluations.len() * 8)
        .sum();
    let individual_evals_bytes =
        (proof.witness_individual_evals.len() + proof.preprocessed_individual_evals.len()) * 8;
    let proof_bytes = whir_proof_bytes + sumcheck_bytes + individual_evals_bytes;

    // Verify
    let vk = mle_setup::<F, C, D>(&circuit.prover_only, &circuit.common);
    let start = Instant::now();
    let result = mle_verify::<F, D>(&circuit.common, &vk, &proof);
    let verify_ms = start.elapsed().as_secs_f64() * 1000.0;
    assert!(result.is_ok(), "{name}: verify failed: {:?}", result.err());

    BenchResult {
        name: name.to_string(),
        degree,
        degree_bits,
        gate_types,
        prove_ms,
        verify_ms,
        proof_bytes,
        whir_proof_bytes,
    }
}

#[test]
fn benchmark_all_circuits() {
    let mut results = Vec::new();

    // ── 1. Small multiplication chain (degree_bits=2) ──
    {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let x = builder.add_virtual_target();
        let mut cur = x;
        for _ in 0..5 {
            cur = builder.mul(cur, x);
        }
        builder.register_public_input(cur);
        let circuit = builder.build::<C>();
        let mut pw = PartialWitness::new();
        pw.set_target(x, F::from_canonical_u64(2)).unwrap();
        results.push(bench_circuit("mul_chain_5", &circuit, pw));
    }

    // ── 2. Medium multiplication chain (degree_bits=3) ──
    {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let x = builder.add_virtual_target();
        let mut cur = x;
        for _ in 0..50 {
            cur = builder.mul(cur, x);
        }
        builder.register_public_input(cur);
        let circuit = builder.build::<C>();
        let mut pw = PartialWitness::new();
        pw.set_target(x, F::from_canonical_u64(2)).unwrap();
        results.push(bench_circuit("mul_chain_50", &circuit, pw));
    }

    // ── 3. Large multiplication chain (degree_bits=4) ──
    {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let x = builder.add_virtual_target();
        let mut cur = x;
        for _ in 0..200 {
            cur = builder.mul(cur, x);
        }
        builder.register_public_input(cur);
        let circuit = builder.build::<C>();
        let mut pw = PartialWitness::new();
        pw.set_target(x, F::from_canonical_u64(2)).unwrap();
        results.push(bench_circuit("mul_chain_200", &circuit, pw));
    }

    // ── 4. Poseidon hash (degree_bits=2) ──
    {
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
        for (i, &inp) in inputs.iter().enumerate() {
            pw.set_target(inp, F::from_canonical_u64(i as u64 + 1))
                .unwrap();
        }
        results.push(bench_circuit("poseidon_hash", &circuit, pw));
    }

    // ── 5. Fibonacci 20 terms ──
    {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let mut targets = Vec::new();
        targets.push(builder.add_virtual_target());
        targets.push(builder.add_virtual_target());
        for i in 2..20 {
            targets.push(builder.add(targets[i - 1], targets[i - 2]));
        }
        builder.register_public_input(*targets.last().unwrap());
        let circuit = builder.build::<C>();
        let mut pw = PartialWitness::new();
        pw.set_target(targets[0], F::ONE).unwrap();
        pw.set_target(targets[1], F::ONE).unwrap();
        results.push(bench_circuit("fibonacci_20", &circuit, pw));
    }

    // Print non-recursive results first
    print_results(&results);

    // ── 6. Recursive verification — with per-step timing ──
    {
        println!("\n--- Recursive verify timing breakdown ---");

        let t0 = Instant::now();
        let inner_config = CircuitConfig::standard_recursion_config();
        let mut inner_builder = CircuitBuilder::<F, D>::new(inner_config);
        let x = inner_builder.add_virtual_target();
        let y = inner_builder.add_virtual_target();
        let z = inner_builder.mul(x, y);
        inner_builder.register_public_input(z);
        let inner_data = inner_builder.build::<C>();
        println!("  [1] inner circuit build:  {:?}", t0.elapsed());

        let t1 = Instant::now();
        let mut inner_pw = PartialWitness::new();
        inner_pw.set_target(x, F::from_canonical_u64(3)).unwrap();
        inner_pw.set_target(y, F::from_canonical_u64(7)).unwrap();
        let inner_proof = inner_data.prove(inner_pw).unwrap();
        println!("  [2] inner plonky2 prove: {:?}", t1.elapsed());

        let t2 = Instant::now();
        let outer_config = CircuitConfig::standard_recursion_config();
        let mut outer_builder = CircuitBuilder::<F, D>::new(outer_config);
        let proof_t = outer_builder.add_virtual_proof_with_pis(&inner_data.common);
        let vd_t =
            outer_builder.add_virtual_verifier_data(inner_data.common.config.fri_config.cap_height);
        outer_builder.verify_proof::<C>(&proof_t, &vd_t, &inner_data.common);
        for &pi in &proof_t.public_inputs {
            outer_builder.register_public_input(pi);
        }
        println!("  [3] outer circuit setup:  {:?}", t2.elapsed());

        let t3 = Instant::now();
        let outer_data = outer_builder.build::<C>();
        let degree = outer_data.common.degree();
        let degree_bits = outer_data.common.degree_bits();
        println!(
            "  [4] outer circuit build:  {:?} (degree={degree}, bits={degree_bits})",
            t3.elapsed()
        );

        let t4 = Instant::now();
        let mut outer_pw = PartialWitness::new();
        outer_pw
            .set_proof_with_pis_target(&proof_t, &inner_proof)
            .unwrap();
        outer_pw
            .set_verifier_data_target(&vd_t, &inner_data.verifier_only)
            .unwrap();
        results.push(bench_circuit("recursive_verify", &outer_data, outer_pw));
        println!("  [5] mle_prove+verify:     {:?}", t4.elapsed());
        println!("  [TOTAL] recursive:        {:?}", t0.elapsed());
        println!("---\n");
    }

    // Print final (including recursive)
    print_results(&results);
}

#[test]
fn benchmark_recursive_only() {
    println!("\n--- Recursive verify timing breakdown ---");

    let t0 = Instant::now();
    let inner_config = CircuitConfig::standard_recursion_config();
    let mut inner_builder = CircuitBuilder::<F, D>::new(inner_config);
    let x = inner_builder.add_virtual_target();
    let y = inner_builder.add_virtual_target();
    let z = inner_builder.mul(x, y);
    inner_builder.register_public_input(z);
    let inner_data = inner_builder.build::<C>();
    println!("  [1] inner circuit build:  {:?}", t0.elapsed());

    let t1 = Instant::now();
    let mut inner_pw = PartialWitness::new();
    inner_pw.set_target(x, F::from_canonical_u64(3)).unwrap();
    inner_pw.set_target(y, F::from_canonical_u64(7)).unwrap();
    let inner_proof = inner_data.prove(inner_pw).unwrap();
    println!("  [2] inner plonky2 prove: {:?}", t1.elapsed());

    let t2 = Instant::now();
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
    let degree = outer_data.common.degree();
    let degree_bits = outer_data.common.degree_bits();
    println!(
        "  [3] outer circuit build:  {:?} (degree={degree}, bits={degree_bits})",
        t2.elapsed()
    );

    let t3 = Instant::now();
    let mut outer_pw = PartialWitness::new();
    outer_pw
        .set_proof_with_pis_target(&proof_t, &inner_proof)
        .unwrap();
    outer_pw
        .set_verifier_data_target(&vd_t, &inner_data.verifier_only)
        .unwrap();

    let mut timing = TimingTree::default();
    let proof = mle_prove::<F, C, D>(
        &outer_data.prover_only,
        &outer_data.common,
        outer_pw,
        &mut timing,
    )
    .unwrap();
    println!("  [4] mle_prove:            {:?}", t3.elapsed());

    let vk = mle_setup::<F, C, D>(&outer_data.prover_only, &outer_data.common);
    let t4 = Instant::now();
    let result = mle_verify::<F, D>(&outer_data.common, &vk, &proof);
    println!("  [5] mle_verify:           {:?}", t4.elapsed());
    assert!(result.is_ok(), "verify failed: {:?}", result.err());

    println!("  [TOTAL]:                  {:?}", t0.elapsed());
}

fn print_results(results: &[BenchResult]) {
    println!("\n{}", "=".repeat(110));
    println!("  BENCHMARK RESULTS (WHIR PCS, Goldilocks field, release mode)");
    println!("{}\n", "=".repeat(110));

    println!(
        "{:<22} {:>6} {:>5} {:>6} {:>12} {:>12} {:>12} {:>12}",
        "Circuit", "Degree", "Bits", "Gates", "Prove(ms)", "Verify(ms)", "Proof(B)", "WHIR(B)"
    );
    println!("{}", "-".repeat(110));

    for r in results {
        println!(
            "{:<22} {:>6} {:>5} {:>6} {:>12.1} {:>12.1} {:>12} {:>12}",
            r.name,
            r.degree,
            r.degree_bits,
            r.gate_types,
            r.prove_ms,
            r.verify_ms,
            r.proof_bytes,
            r.whir_proof_bytes
        );
    }

    println!("{}\n", "=".repeat(110));
}
