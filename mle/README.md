# plonky2_mle — Multilinear-Native Proof System for Plonky2 Circuits

A sumcheck + multilinear PCS proof system that reuses Plonky2's circuit format
(gate definitions, wiring, witness generation) while replacing the FRI-based
proof engine with a multilinear-native pipeline:

- **MLE construction** on `{0,1}^n` from raw evaluation tables
- **Zero-check sumcheck** for gate constraint verification
- **Log-derivative permutation argument** (replaces univariate grand product)
- **Log-derivative lookup argument** (replaces Sum/RE/LDC)
- **Unified split-commit WHIR PCS**: single proof covering both preprocessed (constants+sigmas) and witness (wires) with per-vector Merkle roots for VK binding
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
│   ├── prover.rs                 # Integrated MLE prover + mle_setup()
│   ├── verifier.rs               # Integrated MLE verifier (VK-aware)
│   ├── proof.rs                  # MleProof<F> + MleVerificationKey<F>
│   ├── sumcheck/
│   │   ├── prover.rs             # Sumcheck prover (product & plain)
│   │   ├── verifier.rs           # Sumcheck verifier
│   │   └── types.rs              # RoundPolynomial, Lagrange interpolation
│   ├── permutation/
│   │   ├── logup.rs              # Log-derivative permutation argument
│   │   └── lookup.rs             # Log-derivative lookup argument
│   ├── fixture.rs                # JSON fixture generation for Solidity tests
│   └── commitment/
│       ├── traits.rs             # MultilinearPCS trait
│       ├── whir_pcs.rs           # WHIR PCS wrapper (split-commit/prove/verify)
│       └── merkle_pcs.rs         # Merkle-tree-based PCS (fallback)
├── tests/
│   ├── integration_tests.rs      # 16 integration + soundness tests
│   ├── generate_fixtures.rs      # JSON fixture generation for all circuits
│   ├── benchmarks.rs             # Prover/verifier benchmarks
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
        ├── MleE2ETest.t.sol      # End-to-end verification tests (6 circuits)
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

### Rust — Unit Tests (53 tests)

```bash
cargo test -p plonky2_mle --lib
```

Covers: MLE evaluation, eq polynomial, transcript, sumcheck prover/verifier,
Lagrange interpolation, permutation logUp, lookup logUp, WHIR PCS (legacy +
split-commit), config, integrated prover, integrated verifier, VK setup
determinism, security tests (tampered preprocessed root, cross-circuit rejection,
split commit root consistency).

### Rust — Integration Tests (16 tests)

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
- **Recursive circuit**: inner proof verified in outer circuit (2048+ gates)

### Rust — Transcript Compatibility Vectors (8 tests)

```bash
cargo test -p plonky2_mle --test transcript_compat -- --nocapture
```

Generates reference challenge values that must be reproduced by the Solidity
transcript. Run with `--nocapture` to see the numeric values.

### Solidity — All Tests (66 tests)

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

## Unified Split-Commit WHIR PCS Architecture

The proof system uses a **single WHIR proof** covering both preprocessed and
witness polynomials via the split-commit API. Each vector is committed
individually (yielding per-vector Merkle roots), but the proof is unified:

1. **Preprocessed vector** (constants + sigmas): committed during setup,
   Merkle root stored in the Verification Key (VK). The Solidity verifier
   receives this as a deploy-time constant (`preprocessedCommitmentRoot`).

2. **Witness vector** (wires): committed per-proof. Merkle root absorbed
   into the Fiat-Shamir transcript to bind all subsequent challenges.

3. **Cross-term binding**: the unified WHIR proof includes cross-OOD
   evaluations (each vector evaluated at the other's OOD points), providing
   cryptographic binding between preprocessed and witness polynomials.

This design prevents an attacker from substituting fabricated gate selectors
or permutation routing that trivially satisfy constraints. The VK binding ensures
the prover used the correct preprocessed polynomials for the target circuit.

A single WHIR session name is used for domain separation:
- Split-commit: `"plonky2-mle-whir-split"`

### API

```rust
// Setup (once per circuit)
let vk = mle_setup::<F, C, D>(&prover_data, &common_data);

// Prove (per witness)
let proof = mle_prove::<F, C, D>(&prover_data, &common_data, witness, &mut timing)?;

// Verify
mle_verify::<F, D>(&common_data, &vk, &proof)?;
```

### Proof Structure

```rust
pub struct MleProof<F: Field> {
    pub circuit_digest: Vec<F>,              // 4 Goldilocks elements (circuit identity)

    // ── Unified WHIR PCS ────────────────────────────────────────────────
    pub whir_eval_proof: WhirEvalProof,      // Single proof (transcript + hints)
    pub preprocessed_root: Vec<u8>,          // 32 bytes (VK binding)
    pub witness_root: Vec<u8>,               // 32 bytes

    // ── Preprocessed batch evaluation ───────────────────────────────────
    pub preprocessed_eval_value: F,          // Batched eval
    pub preprocessed_batch_r: F,             // Deterministic from circuit_digest
    pub preprocessed_individual_evals: Vec<F>, // [const_0..C, sigma_0..R]
    pub preprocessed_whir_eval_ext3: Field64_3,

    // ── Witness batch evaluation ────────────────────────────────────────
    pub witness_eval_value: F,               // Batched eval
    pub witness_batch_r: F,                  // Fiat-Shamir derived
    pub witness_individual_evals: Vec<F>,    // [wire_0..W]
    pub witness_whir_eval_ext3: Field64_3,

    // ── Sub-protocol proofs ─────────────────────────────────────────────
    pub constraint_proof: SumcheckProof<F>,
    pub permutation_proof: PermutationProof<F>,
    pub lookup_proofs: Vec<LookupProof<F>>,

    // ── Public data + challenges ────────────────────────────────────────
    pub public_inputs: Vec<F>,
    pub alpha: F, pub beta: F, pub gamma: F,
    pub tau: Vec<F>, pub tau_perm: Vec<F>,
    pub pcs_constraint_eval: F,
    pub pcs_perm_numerator_eval: F,
    pub num_wires: usize, pub num_routed_wires: usize, pub num_constants: usize,
}
```

### Verification Key (VK)

The `MleVerificationKey<F>` is a per-circuit artifact computed once during setup.
It binds the verifier to the circuit's preprocessed data (gate selectors, constant
values, permutation routing). Without it, an attacker can substitute fabricated
constants/sigmas that trivially satisfy all constraints.

#### Structure

```rust
pub struct MleVerificationKey<F: Field> {
    pub circuit_digest: Vec<F>,                // 4 Goldilocks field elements (Plonky2 VK hash)
    pub preprocessed_commitment_root: Vec<u8>, // 32 bytes (WHIR Merkle root)
    pub num_constants: usize,                  // Number of constant polynomial columns
    pub num_routed_wires: usize,               // Number of sigma permutation columns
}
```

| Field | Size | Description |
|-------|------|-------------|
| `circuit_digest` | 32 bytes (4 x u64) | Plonky2 verifying key hash. Identifies the circuit topology (gates, wiring, public input positions). |
| `preprocessed_commitment_root` | 32 bytes | WHIR Merkle root over the batched preprocessed polynomial. This is the critical binding: changing any constant or sigma value changes this root. |
| `num_constants` | 8 bytes | Number of constant columns (selectors + gate constants). Used by the verifier for individual_evals decomposition. |
| `num_routed_wires` | 8 bytes | Number of routed wire columns (sigma permutations). Used by the verifier for individual_evals decomposition. |

#### Generation (`mle_setup`)

```rust
let vk = mle_setup::<F, C, D>(&circuit.prover_only, &circuit.common);
```

Steps:

1. **Extract `circuit_digest`** from `prover_data.circuit_digest` (Plonky2's VK hash,
   4 Goldilocks field elements).

2. **Build preprocessed MLEs** from the circuit's constant and sigma tables:
   - `const_mles`: one MLE per constant column (from `prover_data.constant_evals`,
     row-major `[row][col]`). Includes gate selectors, lookup selectors, and
     per-gate constants.
   - `sigma_mles`: one MLE per routed wire (from `prover_data.sigmas`,
     row-major `[row][col]`). Encodes copy-constraint routing as
     `k_is[target_col] * subgroup[target_row]`.

3. **Derive deterministic batch scalar** `batch_r_pre` from `circuit_digest`:
   ```
   t = Transcript::new()         // includes "plonky2-mle-v0" separator
   t.domain_separate("preprocessed-batch-r")
   t.absorb_field_vec(circuit_digest)
   batch_r_pre = t.squeeze_challenge()
   ```
   This value is public and deterministic — security comes from the WHIR
   commitment binding, not from batch_r secrecy.

4. **Batch preprocessed polynomials** into a single MLE:
   ```
   P_pre(x) = Σ_i batch_r_pre^i · poly_i(x)
   ```
   where `poly_i` are ordered as `[const_0, ..., const_C, sigma_0, ..., sigma_R]`.

5. **Compute WHIR commitment root**: call `WhirPCS::commit_root(&P_pre)` which
   runs a single-vector WHIR commit with session name `"plonky2-mle-whir-split"`
   and returns the first 32 bytes (Merkle root).

#### Determinism Guarantee

`mle_setup()` is a **pure function** of the circuit: same circuit code always
produces the same VK. This is guaranteed because:
- `circuit_digest` is deterministic (Plonky2 circuit build is deterministic)
- `batch_r_pre` is a deterministic Keccak256 derivation from `circuit_digest`
- Constant and sigma tables are fixed at circuit build time
- WHIR commitment uses deterministic Fiat-Shamir (no external randomness)

You can call `mle_setup()` multiple times or in different processes and always
get identical results.

#### On-Chain Usage (Solidity)

The Solidity verifier receives the VK as a `bytes32` parameter:

```solidity
function verify(
    MleProof calldata proof,
    uint256 degreeBits,
    bytes32 preprocessedCommitmentRoot,  // ← VK (deploy-time constant)
    SpongefishWhirVerify.WhirParams memory whirParams,
    bytes memory protocolId,
    bytes memory splitSessionId,         // ← single session ID
    GoldilocksExt3.Ext3[] memory whirEvals  // ← [preprocessed, witness] evaluations
) external pure returns (bool)
```

The `MleProof` struct contains a single unified WHIR proof:

```solidity
struct MleProof {
    uint256[] circuitDigest;
    // ── Unified WHIR PCS ──────────────────────────
    bytes whirTranscript;       // Single WHIR proof transcript
    bytes whirHints;            // Single WHIR hints
    bytes32 preprocessedRoot;   // From split-commit (VK binding)
    bytes32 witnessRoot;        // From split-commit
    // ── Batch evaluations ─────────────────────────
    uint256 preprocessedEvalValue;
    uint256 preprocessedBatchR;
    uint256[] preprocessedIndividualEvals;
    uint256 witnessEvalValue;
    uint256 witnessBatchR;
    uint256[] witnessIndividualEvals;
    // ── Sumcheck + public data ────────────────────
    SumcheckVerifier.SumcheckProof permProof;
    uint256 permClaimedSum;
    SumcheckVerifier.SumcheckProof constraintProof;
    uint256[] publicInputs;
    uint256 alpha; uint256 beta; uint256 gamma;
    uint256[] tau; uint256[] tauPerm;
    uint256 numWires; uint256 numRoutedWires; uint256 numConstants;
    uint256 pcsConstraintEval;
    uint256 pcsPermNumeratorEval;
}
```

The verifier performs:
1. **`_derivePreprocessedBatchR(proof.circuitDigest)`** — recomputes the
   deterministic batch scalar from the proof's circuit_digest and verifies
   it matches `proof.preprocessedBatchR`.
2. **VK binding** — checks `proof.preprocessedRoot == preprocessedCommitmentRoot`.
3. **Single WHIR verification** — one call to `SpongefishWhirVerify.verifyWhirProof()`
   with combined evaluations `[preprocessedEval, witnessEval]`.

In production, `preprocessedCommitmentRoot` would be set as an immutable
contract parameter at deployment time (one VK per circuit).

### Fiat-Shamir Transcript Order

```
[domain] "circuit"
[absorb] circuit_digest (4 field elements)
[absorb] public_inputs
[absorb] preprocessed_commitment_root (32 bytes)    ← VK binding
[domain] "batch-commit-witness"
[squeeze] witness_batch_r
[absorb] witness_commitment_root (32 bytes)
[domain] "challenges"
[squeeze] beta, gamma, alpha, tau, tau_perm
[domain] "permutation"
         ... permutation sumcheck ...
[domain] "extension-combine"
[squeeze] ext_challenge
[domain] "zero-check"
         ... constraint sumcheck ...
[domain] "pcs-eval"
```

Note: `preprocessed_batch_r` is derived from a separate deterministic
mini-transcript seeded with `circuit_digest` only.

### WHIR Internal Transcript (Split-Commit)

Within the unified WHIR proof, the split-commit transcript has the following
structure for 2 commitments (preprocessed + witness), each with `numVectors=1`:

```
[prover_hash]  preprocessed Merkle root
[verifier]     K OOD challenge points (Ext3)
[prover]       K OOD answers for preprocessed vector
[prover_hash]  witness Merkle root
[verifier]     K OOD challenge points (Ext3)
[prover]       K OOD answers for witness vector
[prover]       K cross-term evaluations (witness at preprocessed OOD points)
[prover]       K cross-term evaluations (preprocessed at witness OOD points)
[verifier]     2 vector RLC coefficients
[verifier]     (1 + 2K) constraint RLC coefficients
               ... initial sumcheck ...
               ... intermediate rounds (if any) ...
               ... final vector + Merkle ...
               ... final sumcheck ...
```

### WhirParams (Solidity)

The `WhirParams` struct passed to the Solidity verifier includes:

```solidity
struct WhirParams {
    uint256 numVariables;
    uint256 foldingFactor;
    uint256 numVectors;        // Per-commitment vector count (typically 1)
    uint256 numCommitments;    // Number of split-commit calls (2 for preprocessed + witness)
    uint256 outDomainSamples;
    uint256 inDomainSamples;
    uint256 initialSumcheckRounds;
    uint256 numRounds;
    uint256 finalSumcheckRounds;
    uint256 finalSize;
    // ... additional fields for Merkle/domain/FinalClaim parameters
    RoundParams[] rounds;
}
```

## WHIR Configuration

| Parameter | Value | Meaning |
|-----------|-------|---------|
| `rate_bits` | 4 | Code rate = 1/2^4 = 1/16 |
| `inv_rate` | 16 | Codeword is 16x the message length |
| `security_bits` | 90 | Target security level |
| `pow_bits` | 0 | Proof-of-work disabled |
| `folding_factor` | 4 | Fold 2^4 = 16 per WHIR round |

Both preprocessed and witness vectors share the same WHIR parameters (same
`degree_bits` determines polynomial size). A single protocol ID and session ID
are used for the unified proof.

## Gas Estimates (Solidity Verifier)

### Primitive Operations

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

### End-to-End Verification Gas (Unified Split-Commit WHIR PCS)

Measured from Solidity E2E tests (`MleE2ETest.t.sol`):

| Circuit | degree_bits | Gates | verify() Gas |
|---------|-------------|-------|-------------|
| small_mul (5 chain muls) | 2 | 4 | **1,158,773** |
| medium_mul (50 chain muls) | 3 | 8 | **1,444,884** |
| large_mul (200 chain muls) | 4 | 16 | **1,698,640** |
| poseidon_hash (4 inputs) | 2 | 4 | **1,157,939** |
| recursive_verify (inner proof) | 11 | 2048 | **4,449,082** |
| huge_mul (100K chain muls) | 13 | 8192 | **6,306,932** |

The unified split-commit WHIR PCS reduces gas by 13-33% compared to the
previous two-separate-proof architecture, with larger circuits benefiting most.

## Security Audit Status

### Unified Split-Commit Architecture (latest)

The split-commit migration consolidates two separate WHIR proofs into one,
providing the following security properties:

- **VK binding**: Preprocessed Merkle root from split-commit is deterministic
  and checked against the VK. Changing any constant or sigma value changes
  the root, failing verification.
- **Cross-term binding**: The unified WHIR proof includes cross-OOD evaluations
  (each vector evaluated at the other's OOD points), cryptographically binding
  preprocessed and witness polynomials within a single Fiat-Shamir chain.
- **Domain separation**: Session name `"plonky2-mle-whir-split"` prevents
  cross-protocol confusion with any legacy proof format.

### Previous Audit Findings (all addressed)

An adversarial subagent audit of the two-commitment migration identified
10 findings (3 HIGH, 3 MEDIUM, 2 LOW, 2 INFO). Addressed items:

- **[HIGH] Shared WHIR session name** — Fixed: split-commit uses a single
  session `"plonky2-mle-whir-split"` with unified proof
- **[HIGH] WHIR canonical evaluation point** — Documented as known limitation.
  Soundness relies on WHIR proximity testing (commitment binding for all evals).
  Phase 2: move WHIR evaluation to sumcheck output point for stronger binding.
- **[HIGH] Verifier does not recompute C(r)** — By design (oracle approach).
  Soundness argument: committed polynomials are binding, Schwartz-Zippel over
  batch_r ensures individual evals are correct, sumcheck proves constraint = 0.
- **[MEDIUM] Public preprocessed batch_r** — Safe: VK binding makes polynomial
  forgery impossible regardless of batch_r knowledge.
- **[MEDIUM] Preprocessed WHIR proof is static** — By design: VK binding makes
  replayability safe.

### Original Solidity Verifier Audit

An adversarial subagent audit identified 20 findings (3 CRITICAL, 5 HIGH,
5 MEDIUM, 2 LOW). All have been addressed:

- **Transcript hash reduction** — exact Rust-matching `reduce96` in Yul
- **Final evaluation checks** — `ConstraintEvaluator.sol` recomputes `C(r)`
  and `h(r)` from PCS-bound values
- **Input validation** — `require(< P)` on all calldata field elements
- **Field arithmetic safety** — `inv(0)` reverts, `sub`/`neg` reduce inputs
- **Bit ordering** — LSB convention documented and verified against Rust

See the commit history for the full audit reports and corresponding fixes.
