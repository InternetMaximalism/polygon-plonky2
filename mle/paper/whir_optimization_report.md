# WHIR/MLE Configuration Optimality Analysis Report

## Overview

This report analyzes the multilinear native proof system described in `plonky2_mle_paper.pdf` from the perspective of WHIR query costs and proposes improvements.

The current design requires **two WHIR proofs**:
1. **Main WHIR**: split-commit of the preprocessed and witness polynomials, committed before challenge derivation.
2. **Auxiliary WHIR**: batched commitment for C̃ and h̃, committed after challenge derivation.

The conclusion is that **the auxiliary WHIR proof can be removed entirely**, yielding roughly a 50% reduction in verification cost and a significant reduction in proof size.

---

## 1. WHIR Query Characteristics

WHIR is a multilinear PCS with the following properties:

| Property | Details |
|------|------|
| Commit | Merkle commitment over evaluations on the hypercube, producing a root hash |
| Open | Proves the evaluation value `f(r)` at a specified point `r` |
| Folding | Folds `folding_factor` variables at once per round |
| Query count | `q ≈ λ / log(1/ρ)`, where `ρ = rate` (currently `1/16`, so `q ≈ λ/4`) |
| Verification cost | `O(q · n/ff · 2^ff)` hash evaluations, where `ff = folding_factor` |
| Proof size | `O(q · n/ff)` Merkle paths plus folding data |
| Batch support | Native support for batch opening multiple polynomials at the same point |

**Key observation**: WHIR verification has a high fixed cost per proof. Two WHIR proofs roughly double that cost. Compared with the size increase of sumcheck round polynomials, which is on the order of a few hundred bytes, the cost of a single WHIR proof, typically several KB to tens of KB, is orders of magnitude larger.

---

## 2. Analysis of the Current Design

### 2.1 Why the Auxiliary Commitment Exists

In the current design, C̃ (constraint MLE) and h̃ (permutation MLE) are **materialized in advance** over the hypercube:

```
C̃(b) = Σ_j α^j · c_j(wires(b), consts(b))   ∀b ∈ {0,1}^n
h̃(b) = Σ_j [1/(β + w_j(b) + γ·id_j(b)) - 1/(β + w_j(b) + γ·σ_j(b))]
```

Because C̃ and h̃ depend on the challenges `(α, β, γ)`, they cannot be computed at the time of the main commitment. That is why an auxiliary WHIR commitment is currently required.

The benefit of pre-materialization is that the sumcheck degree stays fixed at **2 per variable**, since it only needs to handle a product of two multilinear polynomials. That means only 3 evaluation points are needed per round.

### 2.2 Cost Structure

```
Current verification cost:
  Sumcheck verification:  n rounds × 3 evaluation points = 3n field operations
  Main WHIR:              ~q₁ · (n/ff) Merkle path verifications
  Auxiliary WHIR:         ~q₂ · (n/ff) Merkle path verifications
  Final check:            a few field operations

  → WHIR dominates (roughly 80-90% of the total)
```

**Approximate Solidity gas cost (n=16, ff=4, λ=90)**:
- Sumcheck: about 48 field multiplications ≈ about 5,000 gas
- One WHIR proof: about 23 queries × 4 rounds × Merkle verification ≈ about 200,000-400,000 gas
- **Two WHIR proofs total: about 400,000-800,000 gas**

---

## 3. Proposed Improvements

### 3.1 Primary Proposal: Eliminate the C̃ Commitment via On-the-Fly Constraint Evaluation

**Core insight**: instead of pre-materializing C̃, evaluate the gate constraints directly during sumcheck.

```
Current:
  Sumcheck polynomial: g(x) = eq(τ,x) · C̃(x) + μ · h̃(x)
  Since C̃ is multilinear, g has degree 2 per variable

Proposal:
  Sumcheck polynomial: g(x) = eq(τ,x) · Σ_j α^j c_j(wire(x), const(x)) + μ · h̃(x)
  If each constraint c_j has maximum degree d_gate, then g has degree (1 + d_gate) per variable
```

**Difference in the final check**:

- **Current**: the verifier obtains `C̃(r)` from the auxiliary WHIR proof.
- **Proposed**: the verifier computes `C_raw(r) = Σ_j α^j c_j(wire_j(r), const_j(r))` directly from the point evaluations opened by the main WHIR proof.

This is possible because Plonky2 gate constraints `c_j` are known polynomial functions, for example `ArithmeticGate: a·b - c` and `PoseidonGate: x^7 - y`. If `wire(r)` and `const(r)` are bound by WHIR, the verifier can reconstruct `C_raw(r)` soundly.

**Important note**: `C̃(r)`, meaning the MLE evaluation of the constraint table over the hypercube, and `C_raw(r)`, meaning the direct evaluation of the constraint function on the MLE inputs, are generally **not the same value**. However, if the sumcheck target polynomial is changed accordingly, then the final check also changes, and `C_raw(r)` is sufficient.

#### Degree impact

| Gate type | Constraint degree `d_gate` | Sumcheck degree per variable | Evaluation points per round |
|-------------|----------------|-------------------|----------------|
| Arithmetic  | 2              | 3                 | 4              |
| Poseidon    | 7              | 8                 | 9              |
| BaseSumGate | 3              | 4                 | 5              |

For circuits containing Poseidon, this increases to 9 evaluation points per round, up from 3. Even so:
- Extra cost: `n` rounds × 6 additional field elements = `6n × 8 bytes`
- For `n=16`, that is 768 extra bytes of proof data
- **Savings from removing one WHIR proof: several KB to tens of KB**

#### Prover-side changes

The current prover (`prover.rs:242-253`) precomputes C̃:

```rust
let combined_ext = compute_combined_constraints(...);
let padded_constraints = flatten_extension_constraints(...);
```

Under the proposal, each sumcheck round evaluates constraints directly. Plonky2's `eval_unfiltered(vars: EvaluationVars)` interface already works at arbitrary field points, as noted in paper section 7.2, so the necessary infrastructure already exists.

The prover's asymptotic work remains the same, `O(2^n · #constraints)`, but memory usage drops from `O(2^n)` to `O(2^{n-round})` because the pre-materialized tables are no longer needed.

### 3.2 Primary Proposal: Eliminate the h̃ Commitment via a GKR-Based Permutation Check

Removing h̃ is more difficult, but it becomes possible with the **GKR (Goldwasser-Kalai-Rothblum) protocol**.

#### Current LogUp permutation check

```
Σ_b h(b) = 0
h(b) = Σ_j [1/(β + w_j(b) + γ·id_j(b)) - 1/(β + w_j(b) + γ·σ_j(b))]
```

h̃ is the MLE of a rational-function table, so `h̃(r)` cannot be reconstructed from `wire(r)` and `sigma(r)` alone.

#### GKR-based alternative

Prove multiset equality in GKR form:

`{w_j(b) + γ·id_j(b)} = {w_j(b) + γ·σ_j(b)}`

More concretely, use the logarithmic form of the grand product:

```
Π_{b,j} (β + w_j(b) + γ·id_j(b)) / (β + w_j(b) + γ·σ_j(b)) = 1
```

Then decompose this into a sumcheck-over-hyperplane argument:

1. **Layer 0**: for each `(b,j)`, define `f(b,j) = (β + w_j(b) + γ·id_j(b))` and `g(b,j) = (β + w_j(b) + γ·σ_j(b))`.
2. **GKR induction**: reduce equality of products through a chain of sumchecks down to evaluations of `wire(r)`, `sigma(r)`, and `id(r)`.
3. **Final check**: verify using the `wire(r)` and `sigma(r)` values already bound by the main WHIR proof.

This completely removes the need for an h̃ commitment.

#### Additional GKR cost

- Additional sumcheck rounds: `O(log(W_R))`, where `W_R` is the number of routed wires
- Each round remains degree 2 per variable
- For a typical `W_R = 80`, this is about 7 additional rounds × `n` variables = `7n` field operations

**Compared with a single WHIR proof at about 200,000-400,000 gas, the added GKR cost is only around 10,000 gas**.

### 3.3 Integrated Proposal: A Single-WHIR-Proof Architecture

Combining proposals 3.1 and 3.2 yields:

```
Improved architecture:
  1. Main WHIR: commit preprocessed + witness polynomials (the only WHIR proof)
  2. Derive challenges: α, β, γ, τ
  3. On-the-fly constraint sumcheck: degree (1 + d_gate) per variable
  4. GKR-based permutation check: additional sumcheck rounds
  5. Main WHIR: open at point r
  6. Final check: the verifier reconstructs everything from the main WHIR evaluations

  WHIR proofs: 1 instead of the current 2
```

#### Cost comparison

| Item | Current | Proposed | Difference |
|------|------|------|------|
| Number of WHIR proofs | 2 | 1 | **-50%** |
| Sumcheck degree per variable | 2 | 8 (Poseidon) | +6 |
| Sumcheck evaluation points per round | 3 | 9 | +6 |
| Additional sumcheck rounds | 0 | about `7n` (GKR) | +`7n` |
| Proof size (`n=16`) | about 2 WHIR + 48 elements | about 1 WHIR + about 200 elements | **-30% to -40%** |
| Solidity verification gas estimate | about 500K-900K | about 300K-500K | **-35% to -45%** |
| Prover memory | `O(2^n)` for C̃ and h̃ | `O(2^n)` for wire MLEs | **-40%** |

---

## 4. Optimizing WHIR Parameters

Current parameters (`WhirPCS::for_num_vars`):
```
folding_factor = min(num_vars, 4)
starting_log_inv_rate = 4  (rate = 1/16)
security_level = min(90, num_vars * 5 + 10)
pow_bits = 0
```

### 4.1 Tuning the rate for on-chain verification

Ethereum hash costs:
- Keccak256: about 30 gas base + 6 gas per 32-byte word
- SHA256 precompile: 60 gas base + 12 gas per 32-byte word

Since `q = λ / log₂(1/ρ)`:
- rate `1/16` (`k=4`): `q = 90/4 ≈ 23` queries
- rate `1/64` (`k=6`): `q = 90/6 = 15` queries  ← **35% reduction**
- rate `1/256` (`k=8`): `q = 90/8 ≈ 12` queries ← **48% reduction**

Tradeoff: lowering the rate increases the initial commitment size, meaning more leaves in the Merkle tree, but calldata cost at 16 gas per byte is cheaper than hash verification cost.

**Recommendation**: for on-chain verification, `starting_log_inv_rate = 6` (rate `1/64`) is the best balance.

### 4.2 Tuning the folding factor

The current value is `ff = 4`. Each WHIR round reads a coset of `2^ff = 16` elements.

- `ff = 3`: 5-6 rounds, 8-element cosets; more rounds but cheaper per round
- `ff = 4`: 4 rounds, 16-element cosets; current balance
- `ff = 5`: 3 rounds, 32-element cosets; fewer rounds but costlier per round

In Solidity, Merkle-path verification has significant loop overhead, so **reducing the number of rounds, for example with `ff = 5`,** can be beneficial. This should be tuned by measurement.

---

## 5. Additional Improvement Ideas

### 5.1 Sumcheck-WHIR fusion

WHIR itself is also sumcheck-based internally, since folding is a form of sumcheck. That suggests a possible **fusion** between the outer sumcheck, used for the zero-check, and WHIR's inner sumcheck, used for the proximity test.

Concretely, the evaluation point `r` from the final sumcheck round could be used as the starting point for WHIR folding, and part of WHIR's opening phase could be executed as an extension of sumcheck. That may eliminate several rounds of folding.

This is still at the research stage, but if it works, it could reduce verification cost by another 15-20%.

### 5.2 Move preprocessed batches into the verification key

Currently, preprocessed polynomials are included in the main WHIR split-commit. Since preprocessed data is circuit-fixed and belongs in the verifier key, it may be possible to remove it from the WHIR proof and store only the Merkle root in the VK, leaving the main WHIR proof witness-only. That would reduce WHIR proof size even further.

However, the current `verify_split` API proves two vectors simultaneously, so this would require changes to WHIR internals.

### 5.3 Optimize extension-field embedding

Currently, Goldilocks (64-bit) is embedded into `Basefield<Field64_3>`, a 192-bit cubic extension. WHIR security depends on the challenge-space size, but the 64-bit Goldilocks field is already sufficient for sumcheck security, with soundness error about `n·d/2^64`.

It is worth checking whether the extension field is truly needed for WHIR folding accuracy, or whether the base field would suffice. If the base field is enough, field arithmetic cost could drop by about 3x.

---

## 6. Suggested Implementation Priorities

| Priority | Improvement | Expected effect | Implementation difficulty |
|--------|--------|----------|----------|
| **P0** | On-the-fly constraint evaluation (§3.1) | WHIR 2→1.5 by removing C̃ | Medium |
| **P0** | Rate parameter tuning (§4.1) | About 35% lower verification gas | Low |
| **P1** | GKR-based permutation check (§3.2) | WHIR 2→1 by removing h̃ | High |
| **P1** | Folding factor tuning (§4.2) | About 10-15% lower verification gas | Low |
| **P2** | Sumcheck-WHIR fusion (§5.1) | Additional 15-20% reduction | Very high |
| **P2** | Preprocessed separation (§5.2) | Smaller proof size | Medium |
| **P3** | Extension-field review (§5.3) | About 3x cheaper field arithmetic | Medium |

**Even implementing only P0 is likely to reduce on-chain verification cost by 30-40%.**

---

## 7. Security Notes

### 7.1 Soundness of on-the-fly constraint evaluation

In the on-the-fly design, the target sumcheck polynomial changes:

```
Current:   g(x) = eq(τ,x) · C̃_MLE(x)        (C̃_MLE is multilinear)
Proposed:  g(x) = eq(τ,x) · C_raw(x)         (C_raw has degree d_gate)
```

`C̃_MLE(x)` and `C_raw(x)` agree on `{0,1}^n`, since both represent `C(b) = Σ α^j c_j(wires(b),...)`, but they differ off the Boolean hypercube. Sumcheck soundness relies on Schwartz-Zippel, giving soundness error at most `n·d/|F|` for a degree-`d` polynomial. Even if the degree increases, `|F| = 2^64` is still sufficient.

### 7.2 Soundness of the GKR-based permutation check

The GKR protocol is standard, but the following points matter:
- The sumcheck challenges for each GKR layer must be derived correctly via Fiat-Shamir.
- The numerator and denominator of the grand product must be domain-separated correctly.
- The `β` and `γ` challenges must be derived only after all wire commitments are fixed.

---

## 8. Conclusion

The current design follows the philosophy of "pre-materialize C̃ and h̃, commit them in an auxiliary WHIR proof, and keep sumcheck low-degree." That is optimal if the only goal is minimizing sumcheck degree, but it is **not optimal when WHIR query cost is the dominant factor**.

Because one WHIR proof costs far more than the degree increase in sumcheck round polynomials, the globally optimal tradeoff is to **sacrifice sumcheck degree in exchange for fewer WHIR proofs**.

The most effective improvements are:
1. Remove C̃ via on-the-fly constraint evaluation, reducing WHIR proof size and prover memory.
2. Remove h̃ via a GKR-based permutation check, eliminating the auxiliary WHIR proof entirely.
3. Tune WHIR rate parameters specifically for on-chain verification.

Together, these changes are expected to reduce verification cost to roughly **35-50%** of the current design.
