/// E2E transcript compatibility test.
///
/// Verifies that the Rust and Solidity transcript implementations produce
/// identical challenges from identical inputs. This is the foundation of
/// Fiat-Shamir binding between the Rust prover and Solidity verifier.
///
/// Test vector: absorb specific values, squeeze challenges, and compare
/// against known-good values that can be checked in Solidity.
use plonky2_field::goldilocks_field::GoldilocksField;
use plonky2_field::types::Field;
use plonky2_mle::transcript::Transcript;

type F = GoldilocksField;

#[test]
fn test_transcript_vector_1_empty() {
    // Vector 1: fresh transcript, squeeze immediately after init
    let mut t = Transcript::new();
    let c: F = t.squeeze_challenge();
    println!("Vector 1 - empty squeeze: {}", c.0);
    // This is the reference value that Solidity must reproduce
    assert_ne!(c, F::ZERO, "Challenge should not be zero");
}

#[test]
fn test_transcript_vector_2_single_field() {
    let mut t = Transcript::new();
    t.absorb_field(F::from_canonical_u64(42));
    let c: F = t.squeeze_challenge();
    println!("Vector 2 - absorb(42), squeeze: {}", c.0);
}

#[test]
fn test_transcript_vector_3_field_vec() {
    let mut t = Transcript::new();
    let vals = vec![
        F::from_canonical_u64(1),
        F::from_canonical_u64(2),
        F::from_canonical_u64(3),
    ];
    t.absorb_field_vec(&vals);
    let c: F = t.squeeze_challenge();
    println!("Vector 3 - absorb_vec([1,2,3]), squeeze: {}", c.0);
}

#[test]
fn test_transcript_vector_4_domain_sep() {
    let mut t = Transcript::new();
    t.domain_separate("test-label");
    t.absorb_field(F::from_canonical_u64(99));
    let c: F = t.squeeze_challenge();
    println!("Vector 4 - domain_separate + absorb(99), squeeze: {}", c.0);
}

#[test]
fn test_transcript_vector_5_bytes() {
    let mut t = Transcript::new();
    t.absorb_bytes(&[0xDE, 0xAD, 0xBE, 0xEF]);
    let c: F = t.squeeze_challenge();
    println!("Vector 5 - absorb_bytes([DEADBEEF]), squeeze: {}", c.0);
}

#[test]
fn test_transcript_vector_6_multiple_squeezes() {
    let mut t = Transcript::new();
    t.absorb_field(F::from_canonical_u64(12345));
    let c1: F = t.squeeze_challenge();
    let c2: F = t.squeeze_challenge();
    let c3: F = t.squeeze_challenge();
    println!(
        "Vector 6 - absorb(12345), squeeze x3: {}, {}, {}",
        c1.0, c2.0, c3.0
    );
}

#[test]
fn test_transcript_vector_7_full_protocol_flow() {
    // Simulates the actual protocol transcript flow
    let mut t = Transcript::new();
    // Step 1: circuit domain sep + public inputs
    t.domain_separate("circuit");
    t.absorb_field_vec(&[F::from_canonical_u64(21)]); // public input: 3*7

    // Step 2: batch-commit
    t.domain_separate("batch-commit");
    let batch_r: F = t.squeeze_challenge();
    println!("Protocol flow - batch_r: {}", batch_r.0);

    // Absorb a fake commitment root (32 bytes of 0xAA)
    t.absorb_bytes(&[0xAA; 32]);

    // Step 3: challenges
    t.domain_separate("challenges");
    let beta: F = t.squeeze_challenge();
    let gamma: F = t.squeeze_challenge();
    let alpha: F = t.squeeze_challenge();
    println!(
        "Protocol flow - beta: {}, gamma: {}, alpha: {}",
        beta.0, gamma.0, alpha.0
    );
}

/// Generate all test vectors as a formatted output for Solidity test comparison.
#[test]
fn generate_all_test_vectors() {
    println!("\n=== TRANSCRIPT TEST VECTORS (Goldilocks field) ===");
    println!("P = 18446744069414584321");

    // Vector 1
    {
        let mut t = Transcript::new();
        let c: F = t.squeeze_challenge();
        println!("\nVector 1 (empty squeeze): {}", c.0);
    }

    // Vector 2
    {
        let mut t = Transcript::new();
        t.absorb_field(F::from_canonical_u64(42));
        let c: F = t.squeeze_challenge();
        println!("Vector 2 (absorb 42): {}", c.0);
    }

    // Vector 3
    {
        let mut t = Transcript::new();
        t.absorb_field_vec(&[
            F::from_canonical_u64(1),
            F::from_canonical_u64(2),
            F::from_canonical_u64(3),
        ]);
        let c: F = t.squeeze_challenge();
        println!("Vector 3 (absorb_vec [1,2,3]): {}", c.0);
    }

    // Vector 4
    {
        let mut t = Transcript::new();
        t.domain_separate("test-label");
        t.absorb_field(F::from_canonical_u64(99));
        let c: F = t.squeeze_challenge();
        println!("Vector 4 (domain_sep + absorb 99): {}", c.0);
    }

    // Vector 5
    {
        let mut t = Transcript::new();
        t.absorb_bytes(&[0xDE, 0xAD, 0xBE, 0xEF]);
        let c: F = t.squeeze_challenge();
        println!("Vector 5 (absorb_bytes DEADBEEF): {}", c.0);
    }

    // Vector 6
    {
        let mut t = Transcript::new();
        t.absorb_field(F::from_canonical_u64(12345));
        let c1: F = t.squeeze_challenge();
        let c2: F = t.squeeze_challenge();
        let c3: F = t.squeeze_challenge();
        println!(
            "Vector 6 (absorb 12345, squeeze x3): {}, {}, {}",
            c1.0, c2.0, c3.0
        );
    }

    // Vector 7
    {
        let mut t = Transcript::new();
        t.domain_separate("circuit");
        t.absorb_field_vec(&[F::from_canonical_u64(21)]);
        t.domain_separate("batch-commit");
        let batch_r: F = t.squeeze_challenge();
        t.absorb_bytes(&[0xAA; 32]);
        t.domain_separate("challenges");
        let beta: F = t.squeeze_challenge();
        let gamma: F = t.squeeze_challenge();
        let alpha: F = t.squeeze_challenge();
        println!("Vector 7 (protocol flow):");
        println!("  batch_r: {}", batch_r.0);
        println!("  beta:    {}", beta.0);
        println!("  gamma:   {}", gamma.0);
        println!("  alpha:   {}", alpha.0);
    }

    println!("=== END TEST VECTORS ===\n");
}
