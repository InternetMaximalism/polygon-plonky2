/// Dump Plonky2's Goldilocks Poseidon constants as Solidity array literals.
///
/// Run with:
///   cargo test --release --test dump_poseidon_constants --no-default-features -- --nocapture
///
/// Output can be pasted into Plonky2GateEvaluator.sol.
use plonky2::hash::poseidon::{Poseidon, ALL_ROUND_CONSTANTS, N_PARTIAL_ROUNDS};
use plonky2_field::goldilocks_field::GoldilocksField;

fn row(vs: &[u64]) -> String {
    vs.iter()
        .map(|v| format!("0x{v:016x}"))
        .collect::<Vec<_>>()
        .join(", ")
}

#[test]
fn dump_constants() {
    println!(
        "// === ALL_ROUND_CONSTANTS: {} entries ===",
        ALL_ROUND_CONSTANTS.len()
    );
    for (i, chunk) in ALL_ROUND_CONSTANTS.chunks(12).enumerate() {
        println!("    // round {i}");
        for c in chunk {
            println!("    0x{c:016x},");
        }
    }

    println!("\n// === MDS_MATRIX_CIRC ===");
    println!("[{}]", row(&<GoldilocksField as Poseidon>::MDS_MATRIX_CIRC));

    println!("\n// === MDS_MATRIX_DIAG ===");
    println!("[{}]", row(&<GoldilocksField as Poseidon>::MDS_MATRIX_DIAG));

    println!("\n// === FAST_PARTIAL_FIRST_ROUND_CONSTANT ===");
    println!(
        "[{}]",
        row(&<GoldilocksField as Poseidon>::FAST_PARTIAL_FIRST_ROUND_CONSTANT)
    );

    println!(
        "\n// === FAST_PARTIAL_ROUND_CONSTANTS ({}) ===",
        N_PARTIAL_ROUNDS
    );
    for c in <GoldilocksField as Poseidon>::FAST_PARTIAL_ROUND_CONSTANTS {
        println!("    0x{c:016x},");
    }

    println!(
        "\n// === FAST_PARTIAL_ROUND_VS ({} x 11) ===",
        N_PARTIAL_ROUNDS
    );
    for (r, v) in <GoldilocksField as Poseidon>::FAST_PARTIAL_ROUND_VS
        .iter()
        .enumerate()
    {
        println!("    // r={r}");
        for c in v {
            println!("    0x{c:016x},");
        }
    }

    println!(
        "\n// === FAST_PARTIAL_ROUND_W_HATS ({} x 11) ===",
        N_PARTIAL_ROUNDS
    );
    for (r, v) in <GoldilocksField as Poseidon>::FAST_PARTIAL_ROUND_W_HATS
        .iter()
        .enumerate()
    {
        println!("    // r={r}");
        for c in v {
            println!("    0x{c:016x},");
        }
    }

    println!("\n// === FAST_PARTIAL_ROUND_INITIAL_MATRIX (11 x 11, row-major) ===");
    for (r, v) in <GoldilocksField as Poseidon>::FAST_PARTIAL_ROUND_INITIAL_MATRIX
        .iter()
        .enumerate()
    {
        println!("    // r={r}");
        for c in v {
            println!("    0x{c:016x},");
        }
    }
}
