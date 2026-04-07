# plonky2_mle — Multilinear-Native Proof System for Plonky2 Circuits

A sumcheck + multilinear PCS proof system that reuses Plonky2's circuit format
(gate definitions, wiring, witness generation) while replacing the FRI-based
proof engine with a multilinear-native pipeline:

- **MLE construction** on `{0,1}^n` from raw evaluation tables
- **Zero-check sumcheck** for gate constraint verification
- **Log-derivative permutation argument** (replaces univariate grand product)
- **Log-derivative lookup argument** (replaces Sum/RE/LDC)
- **Merkle-based PCS** (fallback; WHIR integration via `MultilinearPCS` trait)
- **Keccak256 Fiat-Shamir** (single transcript, no dual-system ambiguity)
- **Solidity on-chain verifier** with Yul-optimized field arithmetic

## Prerequisites

- **Rust** toolchain (stable, 1.70+)
- **Foundry** (`forge`, `cast`) for Solidity compilation and testing

```
curl -L https://foundry.paradigm.xyz | bash
foundryup
```

## Repository Layout

```
mle/
├── Cargo.toml                    # Rust crate definition
├── src/
│   ├── lib.rs                    # Module root
│   ├── config.rs                 # WHIR rate=1/64 configuration
│   ├── dense_mle.rs              # DenseMultilinearExtension<F>
│   ├── eq_poly.rs                # eq(τ,b) tensor-product evaluation
│   ├── transcript.rs             # Keccak256 Fiat-Shamir transcript
│   ├── constraint_eval.rs        # Plonky2 gate → MLE evaluation bridge
│   ├── prover.rs                 # Integrated MLE prover
│   ├── verifier.rs               # Integrated MLE verifier
│   ├── proof.rs                  # MleProof<F> structure
│   ├── sumcheck/
│   │   ├── prover.rs             # Sumcheck prover (product & plain)
│   │   ├── verifier.rs           # Sumcheck verifier
│   │   └── types.rs              # RoundPolynomial, Lagrange interpolation
│   ├── permutation/
│   │   ├── logup.rs              # Log-derivative permutation argument
│   │   └── lookup.rs             # Log-derivative lookup argument
│   └── commitment/
│       ├── traits.rs             # MultilinearPCS trait
│       └── merkle_pcs.rs         # Merkle-tree-based PCS (fallback)
├── tests/
│   ├── integration_tests.rs      # 15 integration + soundness tests
│   └── transcript_compat.rs      # Rust↔Solidity transcript compatibility
└── contracts/
    ├── foundry.toml              # Foundry configuration
    ├── src/
    │   ├── GoldilocksField.sol   # Field arithmetic (Yul)
    │   ├── TranscriptLib.sol     # Keccak transcript (Rust-compatible)
    │   ├── SumcheckVerifier.sol  # Sumcheck verification + Lagrange (Yul)
    │   ├── EqPolyLib.sol         # eq(τ,r) evaluation (Yul)
    │   ├── ConstraintEvaluator.sol # Gate constraint re-evaluation
    │   └── MleVerifier.sol       # Integrated on-chain verifier
    └── test/
        ├── MleVerifierTest.sol   # Field/sumcheck/gas benchmark tests
        ├── GasBenchmark.t.sol    # Foundry gas measurement harness
        └── TranscriptCompat.t.sol # Cross-language transcript vectors
```

## Building

### Rust

From the workspace root (`polygon-plonky2/`):

```bash
cargo build -p plonky2_mle
```

### Solidity

```bash
cd mle/contracts
forge build
```

## Running Tests

### Rust — Unit Tests (38 tests)

```bash
cargo test -p plonky2_mle --lib
```

Covers: MLE evaluation, eq polynomial, transcript, sumcheck prover/verifier,
Lagrange interpolation, permutation logUp, lookup logUp, Merkle PCS, config,
integrated prover, integrated verifier.

### Rust — Integration Tests (15 tests)

```bash
cargo test -p plonky2_mle --test integration_tests
```

Covers:
- **Permutation soundness**: `Σ h(b) = 0` on real Plonky2 circuits
- **Poseidon gate**: degree-7 constraint zero-check + E2E prove/verify
- **Large circuit**: 200-multiplication chain
- **Fibonacci**: 20-term sequence (fib(19) = 6765)
- **Randomized**: 120 random arithmetic circuits (add/mul/mixed)
- **Soundness (negative)**: tampered public inputs, eval value, commitment,
  constraint round poly, permutation round poly — all rejected
- **Lookup**: standalone logUp prove/verify with multiplicity tracking

### Rust — Transcript Compatibility Vectors (8 tests)

```bash
cargo test -p plonky2_mle --test transcript_compat -- --nocapture
```

Generates reference challenge values that must be reproduced by the Solidity
transcript. Run with `--nocapture` to see the numeric values.

### Solidity — All Tests (26 tests)

```bash
cd mle/contracts
forge test -vvv
```

### Solidity — Transcript Compatibility Only

```bash
forge test --match-contract TranscriptCompatTest -vvv
```

Verifies 7 test vectors against Rust-generated reference values:

| Vector | Description |
|--------|-------------|
| V1 | Fresh transcript, immediate squeeze |
| V2 | `absorb_field(42)` |
| V3 | `absorb_field_vec([1, 2, 3])` |
| V4 | `domain_separate("test-label") + absorb_field(99)` |
| V5 | `absorb_bytes([0xDE, 0xAD, 0xBE, 0xEF])` |
| V6 | Three consecutive squeezes after `absorb_field(12345)` |
| V7 | Full protocol flow: circuit domain sep, public inputs, batch commit, challenges |

### Solidity — Gas Benchmarks

```bash
forge test --match-test "test_bench" -vvvv
```

### Plonky2 Regression

```bash
cargo test -p plonky2
```

All 94 existing Plonky2 tests must continue to pass.

## Generating Transcript Fixture Data

To regenerate the Rust reference values used by the Solidity compatibility tests:

```bash
cargo test -p plonky2_mle --test transcript_compat generate_all_test_vectors -- --nocapture
```

Sample output:

```
=== TRANSCRIPT TEST VECTORS (Goldilocks field) ===
P = 18446744069414584321
Vector 1 (empty squeeze): 5564066233726241458
Vector 2 (absorb 42): 5382117256048105213
...
=== END TEST VECTORS ===
```

Copy the numeric values into `contracts/test/TranscriptCompat.t.sol` constants
(`V1_EMPTY_SQUEEZE`, etc.) and re-run `forge test` to confirm Solidity matches.

## WHIR Configuration

The system targets WHIR with the following parameters (defined in `src/config.rs`):

| Parameter | Value | Meaning |
|-----------|-------|---------|
| `rate_bits` | 4 | Code rate = 1/2^4 = 1/16 |
| `inv_rate` | 16 | Codeword is 16x the message length |
| `num_queries` | 28 | Query rounds for 90-bit security |
| `security_bits` | 90 | Target security level |
| `pow_bits` | 0 | Proof-of-work disabled |
| `folding_factor` | 4 | Fold 2^4 = 16 per WHIR round |

The current PCS is a Merkle-tree fallback (`merkle_pcs.rs`) with O(2^n) proof
size. Replacing it with WHIR via the `MultilinearPCS` trait reduces proof size
to polylog(2^n) without changing any prover/verifier logic.

## Gas Estimates (Solidity Verifier)

Measured on Foundry with `--via-ir` and optimizer (200 runs):

| Operation | Gas |
|-----------|-----|
| Goldilocks add (x100) | 6,436 |
| Goldilocks mul (x100) | 6,438 |
| Goldilocks inv (x1) | 7,959 |
| eq(τ,r) 8 vars | 1,913 |
| eq(τ,r) 16 vars | 3,705 |
| Sumcheck verify 8 rounds | 234,567 |
| Sumcheck verify 12 rounds | 353,209 |
| Sumcheck verify 16 rounds | 478,558 |

Estimated total verification gas (current Merkle PCS):

| Circuit Size | Estimated Gas |
|---|---|
| n=8 (256 gates) | ~107K |
| n=12 (4K gates) | ~339K |
| n=16 (64K gates) | ~3.6M |

With WHIR PCS the Merkle/MLE terms become polylogarithmic, bringing n=16
verification to an estimated ~500K gas.

## Security Audit Status

An adversarial subagent audit identified 20 findings (3 CRITICAL, 5 HIGH,
5 MEDIUM, 2 LOW). All have been addressed:

- **Transcript hash reduction** — exact Rust-matching `reduce96` in Yul
- **Final evaluation checks** — `ConstraintEvaluator.sol` recomputes `C(r)`
  and `h(r)` from PCS-bound values
- **Input validation** — `require(< P)` on all calldata field elements
- **Field arithmetic safety** — `inv(0)` reverts, `sub`/`neg` reduce inputs
- **Merkle tree** — power-of-two length enforced, scratch space for hashing
- **Bit ordering** — LSB convention documented and verified against Rust

See the commit history for the full audit report and corresponding fixes.
