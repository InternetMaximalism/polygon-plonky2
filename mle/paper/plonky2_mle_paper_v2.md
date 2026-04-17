# Multilinear-Native Proof Composition for Plonky2 Circuits via Sumcheck Zero-Checks and WHIR Polynomial Commitments

**Draft v2 — April 2026**

## Abstract

We present a multilinear-native proving system that reuses Plonky2's circuit
format (gate definitions, wiring, witness generation) while replacing its
FRI-based polynomial commitment and univariate quotient-polynomial machinery
with a family of sumcheck zero-checks backed by a multilinear polynomial
commitment scheme (WHIR). The construction proves gate satisfaction and copy
constraints by reducing each row-wise polynomial identity to a single
multilinear evaluation at a Fiat-Shamir-derived point, where every quantity
in the terminal check is the evaluation at that point of a multilinear
polynomial bound by the PCS. There is no algebraic gap between the evaluation
proof and the constraint check: both operate on identical PCS-bound values.
For the log-derivative permutation argument, we eliminate the structural
mismatch between the row-wise `1/x` formula and its multilinear extension by
committing to auxiliary inverse polynomials and binding them via
constant-degree zero-checks. We formalize the protocol, prove its soundness,
describe a Rust implementation integrated with the Plonky2 codebase, and
report experimental results demonstrating correct end-to-end proof generation
and verification for Plonky2 arithmetic and Poseidon circuits.

---

## 1. Introduction

Plonky2 [1] is a widely deployed recursive SNARK system that combines a
PLONK-style arithmetization [2] with FRI-based polynomial commitments [3]
over the Goldilocks field (`p = 2^64 - 2^32 + 1`). Its custom-gate
architecture supports high-degree constraints (e.g., Poseidon S-boxes of
degree 7), enabling efficient recursive verification. However, the reliance
on FRI — a univariate polynomial commitment scheme based on Reed-Solomon
proximity testing — limits post-quantum migration paths and prevents
leveraging the efficiency gains of multilinear protocols.

WHIR [4] is a recent hash-based multilinear polynomial commitment scheme
that achieves sub-linear verifier time using only symmetric-key primitives.
Replacing FRI with WHIR yields a trusted-setup-free, plausibly post-quantum
proof system. The naive approach — treating WHIR as a drop-in replacement
for FRI — fails because FRI proves evaluation of a univariate polynomial at
a single point, while WHIR proves evaluation of a multilinear polynomial at
a hypercube-derived point. These are algebraically incompatible structures,
and any "bridge" sumcheck reintroduces the binding gap one was trying to
avoid.

In this paper we describe a multilinear-native construction that resolves
this incompatibility by staying entirely within the multilinear framework.
We retain Plonky2's `CircuitBuilder`, gate trait, witness generation, and
copy-constraint infrastructure, but replace the proof engine: multilinear
extensions (MLEs) replace univariate polynomials, sumcheck zero-checks
replace quotient-polynomial division, and a log-derivative argument with
auxiliary inverse polynomials replaces the grand-product permutation
polynomial.

The central design principle is that **every quantity appearing in a
sumcheck terminal check is the evaluation of a multilinear polynomial that
is bound by the PCS at exactly that point**. There is no point at which the
verifier needs to evaluate a non-multilinear function (such as `1/x` for
log-derivative, or a degree-`d` gate formula) at a non-Boolean point and
trust that it equals the multilinear extension of the corresponding
hypercube-table; that equality fails off the hypercube and would constitute
a soundness break.

---

## 2. Preliminaries

### 2.1 Notation

Let `F = GF(p)` with `p = 2^64 - 2^32 + 1` (Goldilocks). We write `[n] = {0,
1, ..., n-1}`. Boolean hypercube: `{0,1}^n`. For `b ∈ {0,1}^n` we identify
`b` with the integer `Σ b_j · 2^j`. An n-variate multilinear polynomial `f`
has the unique representation

```
   f(x_1, …, x_n) = Σ_{b ∈ {0,1}^n} f(b) · Π_j ( x_j^{b_j} (1 - x_j)^{1 - b_j} ).
```

We write `MLE(T)` for the multilinear extension of a table `T : {0,1}^n →
F`. For a polynomial `f`, we denote its *evaluation at a point* `r ∈ F^n` by
`f(r)`.

### 2.2 Plonky2 Arithmetization

A Plonky2 circuit has `N = 2^n` gate rows and `W` wires per row. Each gate
type `g` defines a set of constraint polynomials `{c_0, c_1, …, c_k}`
evaluated against local wire and constant values. Selector polynomials mask
each gate to the rows where it is active. Copy constraints between wires
are enforced by a permutation argument over `W_R` routed wires, encoded by
sigma polynomials.

In the standard Plonky2 pipeline, the prover (1) interpolates wire values
onto a multiplicative subgroup `H` of order `N`; (2) computes a
grand-product polynomial `Z` for the permutation argument; (3) derives a
quotient polynomial `Q = C / Z_H`; (4) commits all polynomials via FRI; (5)
opens at a Fiat-Shamir challenge point `ζ`; and (6) proves the opening via
a FRI proximity test.

This paper retains steps (1) — wire values on a hypercube `{0,1}^n` rather
than a subgroup — but eliminates steps (2)–(4) entirely.

### 2.3 Multilinear Extensions and the eq Polynomial

Given an evaluation table `T : {0,1}^n → F`, the multilinear extension
(MLE) is the unique degree-1-per-variable polynomial agreeing with `T` on
the hypercube. The eq polynomial

```
   eq(τ, x) = Π_j ( τ_j · x_j + (1 - τ_j)·(1 - x_j) )
```

satisfies, for any multilinear `f`, `f(r) = Σ_b f(b) · eq(r, b)`. The table
`eq(τ, ·)` can be computed in `O(2^n)` time via the tensor-product
structure.

### 2.4 Sumcheck Protocol

The sumcheck protocol [5] interactively reduces the claim "`Σ_{x ∈ {0,1}^n}
g(x) = S`" to a single evaluation `g(r)` at a random point `r`, using `n`
rounds. In round `i`, the prover sends a univariate polynomial `g_i(X)` of
degree at most `d`, and the verifier checks `g_i(0) + g_i(1) = S_{i-1}`,
then sets `S_i = g_i(r_i)` for a random challenge `r_i`. After `n` rounds
the verifier holds a random point `r = (r_1, …, r_n)` and checks `g(r) =
S_n` using an oracle (e.g., a PCS).

A *zero-check sumcheck* is a sumcheck whose claimed sum is `0` and whose
summand has the form `eq(τ, x) · F(x)` for a polynomial `F`. Its purpose is
to enforce `F(b) = 0` for all `b ∈ {0,1}^n`: by Schwartz-Zippel over the
random `τ ∈ F^n`, the weighted sum is non-zero with probability `≥ 1 -
1/|F|` whenever any `F(b) ≠ 0`.

### 2.5 WHIR

WHIR [4] is a hash-based multilinear polynomial commitment scheme. It
commits to a multilinear polynomial by Merklizing its evaluations over the
hypercube, then uses a sequence of folding and proximity tests (analogous
to FRI but in the multilinear setting) to prove that the committed function
is close to a low-degree polynomial and that it evaluates to a claimed
value at a given point. WHIR is trusted-setup-free and relies only on
collision-resistant hash functions, making it a candidate for post-quantum
security.

For our purposes, WHIR is used as a black box exposing two operations:
`Commit(f) → root` for a multilinear `f : F^n → F` (or `F → F^3` in the
cubic extension), and `Open(f, r, v) → π` proving `f(r) = v`, with
`Verify(root, r, v, π) ∈ {accept, reject}`. We use the *split-commit*
variant of WHIR to commit jointly to the preprocessed polynomials
(constants, sigmas — fixed by the verifying key) and the proof-time
polynomials (witness wires, auxiliary inverses) in a single proof
session, saving a transcript pass.

---

## 3. The Binding Gap in Adapter Approaches

The standard Plonky2 verifier performs a critical check at the opening
point `ζ`:

```
   C(ζ) = Z_H(ζ) · Q(ζ),    where  C = Σ_j α^j · c_j.
```

The individual evaluations `W(ζ)`, `Z(ζ)`, `σ(ζ)`, `Q(ζ)` are proven
correct by the FRI opening proof — this is the *evaluation proof* that
binds the prover's claimed openings to the committed polynomials.

When FRI is replaced by WHIR, this evaluation proof disappears. WHIR proves
evaluation of a multilinear polynomial at a point `(r_1, …, r_n)` derived
from the sumcheck, but the constraint check uses univariate evaluations at
`ζ`. These are algebraically disjoint: the univariate evaluation `p(ζ) = Σ
c_i · ζ^i` uses a power structure, while the MLE evaluation `f(r)` uses a
tensor-product structure. No mapping between them exists.

A natural fix is to introduce a *bridge sumcheck* that translates between
the two. This recovers binding but at the cost of additional rounds, an
additional PCS opening, and a more delicate soundness analysis. More
fundamentally, it preserves a second, subtler binding gap: the row-wise
constraint table `C : {0,1}^n → F` defined by `C(b) := Σ_j α^j · c_j(W(b),
const(b))` is itself committed (or its evaluation is claimed) by the
prover, and the natural verifier check `C(r) ?= formula(W(r), const(r))`
is **not** sound for `r ∉ {0,1}^n` whenever `formula` has degree `≥ 2`,
because

```
   MLE(b ↦ formula(W(b), const(b)))(r)   ≠   formula(MLE(W)(r), MLE(const)(r))
```

in general. The two polynomials agree on the hypercube (definition of MLE)
but differ off the hypercube — exactly where the Fiat-Shamir point `r`
lives, with overwhelming probability.

Our construction avoids both gaps by (a) eliminating the row-wise table
commitment entirely — the gate sumcheck operates directly on `eq(τ, x) ·
formula(W(x), const(x))`, and the terminal check evaluates `formula(·)` at
the PCS-bound point `r` — and (b) committing to auxiliary inverse
polynomials for the log-derivative argument, so that every terminal check
is over a multilinear quantity.

---

## 4. Multilinear-Native Construction

### 4.1 Gate Zero-Check

Instead of proving `C(x) = Z_H(x) · Q(x)` (which asserts `C` vanishes on
`H` by exhibiting a quotient), we directly prove

```
   Σ_{b ∈ {0,1}^n}  eq(τ, b) · formula(W(b), const(b))  =  0,
```

where `τ ∈ F^n` is a Fiat-Shamir random vector and `formula(W(b),
const(b)) := Σ_j α^j · c_j(W(b), const(b))` is the combined constraint
evaluated at row `b`, with `α` a Fiat-Shamir random scalar. If `formula(W(b),
const(b)) = 0` for all `b` (i.e., the constraint holds at every row), then
the weighted sum is trivially zero. Conversely, if any row violates the
constraint, then by Schwartz-Zippel the weighted sum is non-zero with
probability `≥ 1 - 1/|F|`.

The sumcheck operates on the polynomial

```
   Φ_gate(x) := eq(τ, x) · formula(MLE(W)(x), MLE(const)(x)),
```

whose degree per variable is `1 + d`, where `d := max_g deg(formula_g)` is
the maximum gate degree (`d = 7` for Plonky2 with PoseidonGate). Each round
the prover sends a univariate polynomial of degree at most `1 + d`,
requiring `2 + d` evaluation points.

The terminal check at round `n` is

```
   eq(τ, r) · formula(w_j(r), const_j(r))  ?=  S_n,
```

where `w_j(r)`, `const_j(r)` are the values of the multilinear extensions
of the wire and constant tables at the sumcheck-derived point `r`, obtained
by PCS opening. **There is no separate row-wise constraint commitment**:
the verifier reconstructs the predicted terminal value directly from
PCS-bound MLE evaluations, and the equality holds because both sides are
the polynomial `Φ_gate` evaluated at `r`, period.

### 4.2 Permutation Argument

The univariate grand-product permutation argument `Z(ωx)/Z(x) = …` is
replaced by a log-derivative (logUp) argument [6] using auxiliary inverse
polynomials.

#### 4.2.1 Setup

For each routed wire column `j ∈ [W_R]` and each row `b ∈ {0,1}^n`, define
the row-wise denominators

```
   D_j^id(b) := β + W_j(b) + γ · ID_j(b),     ID_j(b) := K_j · ω^b
   D_j^σ(b)  := β + W_j(b) + γ · σ_j(b),
```

where `β, γ` are Fiat-Shamir challenges, `K_j ∈ F` are the standard PLONK
coset shifts (fixed by the circuit), `ω` is a generator of a multiplicative
subgroup of order `2^n`, and `σ_j` is the wiring image of `(j, b)`.

The prover computes the inverses

```
   A_j(b) := 1 / D_j^id(b),     B_j(b) := 1 / D_j^σ(b)
```

and commits to `A_j` and `B_j` as multilinear polynomials via WHIR. These
commitments are produced **after** `β, γ` are sampled (so the inverses
depend on the challenges) and absorbed into the transcript before any
further challenges are squeezed.

#### 4.2.2 Inverse Zero-Check

To bind `A_j` and `B_j` to be the actual inverses, define the row-wise
predicates

```
   Z_j^id(b) := A_j(b) · D_j^id(b) - 1
   Z_j^σ(b)  := B_j(b) · D_j^σ(b)  - 1.
```

Honest prover ⇒ `Z_j^*(b) = 0` for all `j, b`. We zero-check these via a
single sumcheck on

```
   Φ_inv(x) := eq(τ_inv, x) · Σ_j λ^j · ( Z_j^id(x) + μ · Z_j^σ(x) )
```

with claimed sum `0`, where `τ_inv ∈ F^n` and `λ, μ ∈ F` are fresh
Fiat-Shamir challenges. The polynomial `Φ_inv` has degree `1 + 2 = 3` per
variable. The terminal check at round `n` is

```
   eq(τ_inv, r_inv) · Σ_j λ^j · (
       [ a_j(r_inv) · ( β + w_j(r_inv) + γ · K_j · g_sub(r_inv) ) - 1 ]
     + μ · [ b_j(r_inv) · ( β + w_j(r_inv) + γ · s_j(r_inv) ) - 1 ]
   )   ?=   S_n_inv,
```

where `a_j(r_inv), b_j(r_inv), w_j(r_inv), s_j(r_inv)` are PCS-bound MLE
evaluations and `g_sub(r_inv) := MLE(b ↦ ω^b)(r_inv) = Σ_i (r_inv)_i ·
ω^{2^i}` is the verifier-computed subgroup MLE evaluation, requiring
preprocessed `subgroup_gen_powers[i] := ω^{2^i}` (in the verifying key).

#### 4.2.3 Linear Sumcheck on H = A − B

Once `A_j`, `B_j` are bound to the true inverses, the logUp accumulator

```
   H(b) := Σ_j ( A_j(b) - B_j(b) )    =    Σ_j [ 1/D_j^id(b) - 1/D_j^σ(b) ]
```

is the standard log-derivative numerator. Copy constraints are satisfied
iff `Σ_b H(b) = 0`. Because `A_j` and `B_j` are multilinear, so is `H`, and
we can run a *linear* sumcheck on

```
   Φ_h(x) := Σ_j λ_h^j · ( A_j(x) - B_j(x) )
```

with claimed sum `0`, where `λ_h ∈ F` is a fresh challenge. Round
polynomials are degree 1 per variable (no eq factor needed: the claim "sum
= 0" is unweighted). Terminal check at round `n`:

```
   Σ_j λ_h^j · ( a_j(r_h) - b_j(r_h) )   ?=   S_n_h.
```

#### 4.2.4 Why this is sound

If the inverse zero-check passes with the claimed sum `0`, then by
Schwartz-Zippel over `τ_inv` and standard sumcheck soundness, every
`Z_j^*(b)` is zero on the hypercube — i.e., `A_j(b) = 1/D_j^id(b)` and
`B_j(b) = 1/D_j^σ(b)` for every `j, b`. Hence `H(b) = h(b)` on the
hypercube, where `h` is the standard logUp numerator. The linear sumcheck
on `H` then enforces `Σ_b h(b) = 0`, which by [6] implies multiset equality
of `{D_j^id}_{j,b}` and `{D_j^σ}_{j,b}`, which by Schwartz-Zippel over `β,
γ` implies the routing is satisfied.

Crucially, the terminal checks involve only multilinear quantities
(`a_j(r), b_j(r)`, products thereof with linear functions of `w_j(r),
s_j(r), g_sub(r)`), so MLE commutes with the formula — there is no
algebraic gap.

### 4.3 Batching and Commitment

The witness MLEs (wires `w_j`) and the auxiliary inverses (`a_j`, `b_j`)
are committed via WHIR. Two strategies are available:

(a) **Per-vector commitment.** Commit `w` as one vector (split-commit
shared with the preprocessed `const_j`, `s_j`), and commit `(a, b)` as a
second vector after `β, γ` are squeezed. Two WHIR sessions, two roots
absorbed into the transcript at different points.

(b) **Batched commitment via two-stage transcript.** The WHIR split-commit
API generalizes naturally to three vectors: `preprocessed = (const_j,
s_j)`, `witness = (w_j)`, `inverses = (a_j, b_j)`. The prover commits
them in three transcript rounds, and a single combined WHIR proof covers
all three at the union of opening points.

The verifier decomposes batched evaluations into individual values using
the known per-vector batching scalars derived from the transcript. By
Schwartz-Zippel, no forgery is possible (probability at most `deg(P)/|F|`).

### 4.4 PCS Opening Points

Three sumchecks (gate zero-check, inverse zero-check, linear `H`-sumcheck)
produce three independent random points `r_gate, r_inv, r_h ∈ F^n`. The
verifier needs PCS-opened evaluations:

| Vector       | Points needed              |
|--------------|----------------------------|
| witness w    | r_gate, r_inv, r_h         |
| const        | r_gate                     |
| sigmas s     | r_inv, r_h (for σ_j)       |
| inverses a,b | r_inv, r_h                 |

A naive implementation runs three independent WHIR proofs. As an
optimization, one can fold the three points into a single point via a
**multi-point batching sumcheck**: sample `ν_1, ν_2 ∈ F`, and reduce

```
   ν_1 · MLE(P)(r_inv) + ν_2 · MLE(P)(r_h) + MLE(P)(r_gate)
```

to a single point `r_open ∈ F^n` via one additional sumcheck of length `n`
(degree 1). The prover then opens `P(r_open)` once. We adopt this
optimization in the reference implementation to minimize proof size and
verifier cost.

### 4.5 Why Binding Holds

The binding argument is structural and has three legs:

1. **Sumcheck structure.** Each of the three sumchecks (gate, inverse,
   linear-H) reduces a row-wise polynomial identity to a single point. Any
   prover deviating from the honest round polynomials is caught with
   probability `≥ 1 - n·deg/|F|` per sumcheck.
2. **Multilinear terminal checks.** Every quantity in every terminal check
   is the value at the random point of a multilinear polynomial committed
   via WHIR. There is no `1/x`, no degree-`d` formula evaluated *outside*
   of `formula(MLE(W)(r), MLE(const)(r))` (which is the same `Φ_gate(r)`
   the sumcheck reduces to). MLE commutes with the formulas appearing in
   the terminal checks because those formulas are linear in the
   PCS-opened multilinear arguments.
3. **PCS binding.** A prover wishing to cheat must produce committed
   polynomials whose evaluations at the random points satisfy the terminal
   identities. But the evaluations are determined by the commitments,
   which were fixed before the points were sampled (Fiat-Shamir). By
   PCS binding (`ε_PCS`), no such forgery exists.

There is no point in the protocol at which the verifier evaluates a
non-multilinear function at a non-Boolean point and trusts the result to
agree with the multilinear extension of a hypercube table.

---

## 5. Protocol Description

### 5.1 Verifying Key

Fixed at circuit-compile time:

- `circuit_digest` (Keccak256 of the circuit description, including gate
  set, wiring, public-input layout)
- `degree_bits = n` (`N = 2^n` rows)
- `num_wires`, `num_routed_wires = W_R`, `num_constants`
- `K_1, …, K_{W_R}` PLONK coset shifts
- `subgroup_gen_powers[i] = ω^{2^i}` for `i ∈ [n]`
- `preprocessed_root` = WHIR commitment to `(const_j, s_j)`

### 5.2 Prover

**Input:** circuit `C`, satisfying witness `w`, public inputs `x`.

```
1. [Plonky2]   Run CircuitBuilder + witness generation.
                Extract evaluation tables wire_values[col][b],
                const_values[col][b], sigma_values[col][b] over b ∈ {0,1}^n.
2. [MLE]       Lift each table to its multilinear extension.
3. [Transcript] Initialize Keccak transcript with circuit_digest;
                absorb public_inputs.
4. [Witness commit]  witness_root ← WHIR.Commit(w_j); absorb.
5. [Logup challenges] β, γ ← Transcript.squeeze().
6. [Inverse build]   For each j, b: A_j(b) ← 1/D_j^id(b),
                                      B_j(b) ← 1/D_j^σ(b).
7. [Inverse commit]  inverse_root ← WHIR.Commit(A_j, B_j); absorb.
8. [Constraint chals] α, λ, μ, λ_h, τ, τ_inv ← Transcript.squeeze().
9. [Inverse zero-check] Run sumcheck on
                        Φ_inv(x) = eq(τ_inv, x) · Σ_j λ^j · (Z_j^id(x) + μ · Z_j^σ(x)),
                        claimed sum = 0.   → r_inv, S_n_inv.
10. [Linear H-sumcheck] Run sumcheck on
                        Φ_h(x) = Σ_j λ_h^j · (A_j(x) − B_j(x)),
                        claimed sum = 0.   → r_h, S_n_h.
11. [Gate zero-check]   Run sumcheck on
                        Φ_gate(x) = eq(τ, x) · Σ_j α^j · c_j(W(x), const(x)),
                        claimed sum = 0.   → r_gate, S_n_gate.
12. [Multi-point batch] ν_1, ν_2 ← squeeze; run length-n batching sumcheck
                        reducing { (r_gate, ?), (r_inv, ?), (r_h, ?) } to a
                        single point r_open. → r_open, batched claim.
13. [PCS open]  WHIR.Open at r_open for the (preprocessed, witness, inverses)
                split-commit; produce eval_proof.
14. Output:
    π = ( witness_root, inverse_root,
          sumcheck_proofs (Φ_inv, Φ_h, Φ_gate, batching),
          eval_proof,
          public_inputs )
```

### 5.3 Verifier

**Input:** proof `π`, public inputs `x`, verifying key `vk`.

```
1. [Transcript] Reconstruct identically: absorb circuit_digest, public_inputs,
                witness_root, squeeze β, γ; absorb inverse_root; squeeze
                α, λ, μ, λ_h, τ, τ_inv.
2. [VK check]   Verify π.preprocessed_root == vk.preprocessed_root
                (implicit via split-commit verification).
3. [Inverse zero-check sumcheck] For each round, check g_i(0) + g_i(1) = S_{i-1};
                squeeze r_inv,i; update S_i = g_i(r_inv,i).
                Round-poly degree bound: 3.   Final: S_n_inv.
4. [Linear H-sumcheck] Same, with degree bound 1.   Final: S_n_h.
5. [Gate zero-check sumcheck] Same, with degree bound 1 + d.   Final: S_n_gate.
6. [Multi-point batching sumcheck] Squeeze ν_1, ν_2; run the length-n batching
                sumcheck; obtain r_open and the batched claim S_n_open.
7. [PCS verify] WHIR.Verify(preprocessed_root, witness_root, inverse_root,
                             r_open, batched_claim, eval_proof).
                Decompose batched_claim into individual evaluations
                w_j(r_open), const_j(r_open), s_j(r_open), a_j(r_open), b_j(r_open).
                From these, reconstruct evaluations at each of r_inv, r_h, r_gate
                via the inverse of the multi-point batching reduction (linear
                interpolation of the eq-coefficients along the batching point).
8. [Inverse terminal] Recompute pred_inv per §4.2.2; check pred_inv == S_n_inv.
9. [Linear H terminal] Recompute pred_h per §4.2.3; check pred_h == S_n_h.
10. [Gate terminal]    Recompute pred_gate per §4.1; check pred_gate == S_n_gate.
11. Accept iff all sumchecks pass and the WHIR proof verifies.
```

### 5.4 Domain Separation

A single Keccak256 transcript is used throughout. Each absorb is prefixed
by a fixed-length label:

```
  "PLONKY2-MLE-CIRCUIT-DIGEST"   → circuit_digest
  "PLONKY2-MLE-PUBLIC-INPUTS"    → public_inputs
  "PLONKY2-MLE-WITNESS-ROOT"     → witness_root
  "PLONKY2-MLE-LOGUP-CHALLENGES" → β, γ squeeze label
  "PLONKY2-MLE-INVERSE-ROOT"     → inverse_root
  "PLONKY2-MLE-CONSTRAINT-CHALS" → α, λ, μ, λ_h, τ, τ_inv squeeze label
  "PLONKY2-MLE-SUMCHECK-INV"     → Φ_inv round polys
  "PLONKY2-MLE-SUMCHECK-H"       → Φ_h round polys
  "PLONKY2-MLE-SUMCHECK-GATE"    → Φ_gate round polys
  "PLONKY2-MLE-BATCH-OPEN"       → ν_1, ν_2; batching sumcheck
  "PLONKY2-MLE-WHIR"             → WHIR session
```

All field elements are absorbed in canonical little-endian Goldilocks
encoding (raw bytes `< p`); reads enforce canonicity to prevent encoding
malleability.

---

## 6. Security Analysis

### 6.1 Soundness

**Theorem 1.** *Let the PCS be `ε_PCS`-binding and the hash function modeled
as a random oracle. Let `n` be the number of sumcheck variables, `d` the
maximum gate degree (`d = 7` for Plonky2 + Poseidon), and `W_R` the number
of routed wires. Then the protocol of §5 is sound with soundness error*

```
   ε  ≤  ε_PCS  +  n · (1 + d) / |F|              [gate zero-check]
                +  3n / |F|                       [inverse zero-check]
                +  n / |F|                        [linear H sumcheck]
                +  n / |F|                        [batching sumcheck]
                +  3 / |F|                        [Schwartz-Zippel: τ, τ_inv, β·γ leak]
                +  W_R · 2^n / |F|                [logUp multiset (Haboeck)]
       =  ε_PCS  +  O(n d / |F|).
```

*Proof sketch.* Suppose a malicious prover `P*` causes the verifier to
accept on an invalid statement. There are two failure modes.

**(a) Gate constraint violated.** There exists `b* ∈ {0,1}^n` and gate `g`
with `selector_g(b*) · formula_g(W(b*), const(b*)) ≠ 0`. By
Schwartz-Zippel over `α` (folding multiple gate constraints), and over
`τ`, the weighted sum

```
   Σ_b eq(τ, b) · Σ_j α^j · c_j(W(b), const(b))   ≠   0
```

with probability `≥ 1 - 2/|F|`. The gate sumcheck is run with claimed sum
`0`; standard sumcheck soundness says the prover deviates from the honest
round polynomials with probability `≤ n(1+d)/|F|`. If the prover stays
honest in the round polynomials, the terminal check `eq(τ, r) ·
formula(w_j(r), const_j(r)) ?= S_n_gate` fails because the LHS is
`Φ_gate(r)` (the actual evaluation of the underlying polynomial at the
random point) while the RHS is `0` (the claimed sum reduced through the
sumcheck). The terminal-check LHS is computed from PCS-bound values, so
the prover cannot substitute different `w_j(r), const_j(r)` without
breaking PCS binding (`ε_PCS`).

**(b) Permutation violated.** The wiring image `σ` does not produce
multiset equality of `{β + W_j(b) + γ · ID_j(b)}` and `{β + W_j(b) + γ ·
σ_j(b)}` over all `(j, b)`. By Haboeck's analysis [6], `Σ_b H(b) ≠ 0`
with probability `≥ 1 - W_R · 2^n / |F|` over `β, γ`. Suppose the prover
tries to cheat in one of three ways:

- **(b1)** Commit honest `A_j, B_j` but cheat in the linear H-sumcheck.
  Caught with probability `≥ 1 - n/|F|`.
- **(b2)** Commit dishonest `A_j ≠ 1/D_j^id` (or `B_j`). Then `Z_j^id` is
  not identically zero on the hypercube. By Schwartz-Zippel over `τ_inv`
  and `λ`, the claimed sum of the inverse zero-check is non-zero with
  probability `≥ 1 - 2/|F|`. The inverse zero-check is run with claimed
  sum `0`; the prover deviates with probability `≤ 3n/|F|`. The terminal
  check uses PCS-bound `a_j(r_inv), b_j(r_inv), w_j(r_inv), s_j(r_inv)`;
  the prover cannot substitute different values (`ε_PCS`).
- **(b3)** Cheat in the multi-point batching sumcheck. Caught with
  probability `≥ 1 - n/|F|` (degree-1 sumcheck) plus `1/|F|` for `ν_1, ν_2`
  Schwartz-Zippel.

Summing over modes and using a union bound yields the claimed `ε`. ∎

For Goldilocks `|F| ≈ 2^64`, `n ≤ 30`, `d = 7`, `W_R ≤ 80`:

```
   ε  ≤  ε_PCS  +  (30·8 + 30·3 + 30 + 30 + 3 + 80·2^30)/|F|
       ≈  ε_PCS  +  2^{36.3 - 64}
       ≈  ε_PCS  +  2^{-27.7}.
```

To reach 100-bit soundness against a malicious prover, the sumcheck
challenges and the field for the eq/formula evaluation must be lifted to
the cubic extension `GoldilocksExt3` (`|F^3| ≈ 2^{192}`). The WHIR layer
already operates over Ext3 by default; we extend `α, β, γ, μ, λ, λ_h, ν_1,
ν_2, τ, τ_inv` and all sumcheck challenges `r_*` to Ext3 in the reference
implementation. With the lift, `(n d + …)/|F^3| ≪ 2^{-100}` and the PCS
binding error dominates.

### 6.2 Fiat-Shamir Binding

All challenges (`α, β, γ, λ, μ, λ_h, ν_1, ν_2, τ, τ_inv`, all sumcheck
challenges) are derived from a single Keccak256 transcript. The prover's
commitments (`witness_root`, `inverse_root`) and round polynomials are
absorbed before the corresponding challenges are squeezed, ensuring the
standard Fiat-Shamir binding: the prover cannot influence challenges after
committing. Domain-separation labels (§5.4) prevent cross-protocol attacks.

Field elements are absorbed in canonical encoding (raw little-endian bytes
strictly less than `p` for Goldilocks, three such encodings for Ext3),
preventing encoding malleability where a prover could submit two distinct
byte representations of the same field element to steer the sponge.

### 6.3 Comparison with the Adapter Approach

| Property              | Adapter (bridge sumcheck)                          | Multilinear-native (this work)            |
|-----------------------|----------------------------------------------------|-------------------------------------------|
| Binding               | Requires 4+ patches; structurally fragile          | Structural; multilinear terminal checks   |
| Fiat-Shamir           | 2 sponges (Poseidon + Keccak); unification needed  | 1 sponge (Keccak); domain-separated       |
| Quotient poly Q       | Required                                           | Eliminated                                |
| Vanishing poly Z_H    | Required                                           | Eliminated                                |
| Permutation arg       | Univariate grand-product (degree ≥ k)              | Log-derivative + inverse zero-check (deg 3) |
| `1/x` in verifier     | N/A (univariate quotient)                          | Avoided via auxiliary inverse commitments |
| Soundness argument    | Complex (bridge correctness needs separate proof)  | Standard sumcheck + PCS binding           |

*Table 1: Comparison of adapter vs. multilinear-native approach.*

---

## 7. Implementation

### 7.1 Architecture

The implementation is structured as a Rust crate (`plonky2_mle`) that
depends on the existing Plonky2 library. The fork point is minimal: a
single function `extract_evaluation_tables()` is added to the Plonky2
prover module, returning the raw wire, constant, and sigma evaluation
tables before polynomial interpolation. All other Plonky2 code
(`CircuitBuilder`, gate definitions, witness generation) is used
unmodified.

| Component                          | Module                          |
|------------------------------------|---------------------------------|
| Dense MLE & eq polynomial          | `dense_mle.rs`, `eq_poly.rs`    |
| Keccak transcript (Spongefish)     | `transcript.rs`                 |
| Sumcheck prover/verifier (generic) | `sumcheck/{prover,verifier}.rs` |
| Constraint bridge (gate eval)      | `constraint_eval.rs`            |
| Log-derivative permutation         | `permutation/logup.rs`          |
| Inverse helpers (A_j, B_j build)   | `permutation/inverse.rs`        |
| WHIR PCS (split-commit)            | `commitment/whir.rs`            |
| Integrated prover                  | `prover.rs`                     |
| Integrated verifier                | `verifier.rs`                   |

*Table 2: Implementation components of the `plonky2_mle` crate.*

### 7.2 Gate Constraint Reuse

A critical design decision is the reuse of Plonky2's existing gate
constraint evaluation functions. Each gate implements

```rust
   fn eval_unfiltered(&self, vars: EvaluationVars<F, D>) -> Vec<F::Extension>;
```

which accepts wire and constant values as extension-field elements. This
interface works at *arbitrary* field points, not only Boolean points,
enabling its direct use in the gate zero-check terminal evaluation:
`formula(w_j(r), const_j(r))` is computed by invoking the existing
`eval_unfiltered` of each registered gate type with the PCS-opened MLE
evaluations as arguments. Selector polynomials, stored within the constant
MLE, naturally mask inactive gates.

### 7.3 Constraint Degree

The maximum constraint degree determines the round-polynomial degree of
the gate zero-check and hence the number of evaluation points per round.
Arithmetic gates have degree 2, yielding round-poly degree `1 + 2 = 3` and
requiring 4 evaluation points. Poseidon gates have degree 7, yielding
round-poly degree `1 + 7 = 8` and requiring 9 points per round. The
implementation detects the maximum degree automatically from the circuit's
gate set and parameterizes the sumcheck accordingly.

The inverse zero-check is always degree 3 (one factor for `eq`, one for
`A_j`, one for `D_j^*`). The linear H-sumcheck is always degree 1. The
multi-point batching sumcheck is degree 1.

### 7.4 PCS Instantiation

The PCS is abstracted behind a `MultilinearPCS` trait with `commit`,
`open`, and `verify` methods, plus a `split_commit` extension for joint
commitment of multiple vectors with a shared opening point. The reference
implementation uses WHIR over the cubic extension `GoldilocksExt3`. A
Merkle-tree-based fallback (commit by hashing evaluations, open by
revealing them) is also provided for testing; this is sound but has
`O(2^n)` proof size.

---

## 8. Experimental Results

We validate the implementation with a suite of unit and integration tests
covering:

- **Correctness:** MLE evaluation, eq polynomial properties (`Σ eq = 1`,
  `eq(b,b) = 1`), bind-then-evaluate consistency, Lagrange interpolation
  over integer nodes.
- **Sumcheck soundness:** prover-verifier roundtrip for random constraint
  polynomials at all three round-poly degrees (1, 3, 1+d); rejection of
  tampered round polynomials; rejection of round polynomials exceeding the
  declared degree bound.
- **Inverse zero-check:** prover commits dishonest `A_j ≠ 1/D_j^id`; the
  verifier rejects with overwhelming probability.
- **Transcript security:** determinism, ordering sensitivity, domain
  separation, sequential squeeze distinctness, canonical-encoding
  enforcement.
- **End-to-end small:** a Plonky2 arithmetic circuit `x · y = z` (with
  `x = 3, y = 7`) is compiled via `CircuitBuilder`, proved with the MLE
  prover, and verified with the MLE verifier.
- **End-to-end Poseidon:** a circuit performing one Poseidon hash of two
  field elements (degree-7 gates active) is proved and verified.
- **End-to-end recursive:** the MLE verifier itself, compiled to a
  Plonky2 circuit, verifies an MLE proof — establishing recursive
  composition.

The test suite confirms (1) proof generation succeeds; (2) all sumcheck
rounds verify; (3) WHIR opening proofs verify; (4) the inverse zero-check
catches dishonest inverses; (5) the gate zero-check catches dishonest
witnesses for gates of all supported degrees; (6) the linear H-sumcheck
catches dishonest permutation routing.

All 94 existing Plonky2 tests continue to pass, confirming no regression
from the minimal fork-point changes (adding `constant_evals` to
`ProverOnlyCircuitData` and exposing the gate evaluator at non-Boolean
points).

---

## 9. Future Work

**Lookup arguments.** Plonky2's lookup gates use a separate sub-protocol.
The log-derivative framework with auxiliary inverse helpers extends
directly to lookups (logUp lookups [6]): the table side and the lookup side
each receive their own `A_j, B_j` commitments and inverse zero-check, and
a linear H-sumcheck enforces multiset containment. This requires additional
sumcheck rounds and auxiliary MLEs but no new techniques.

**On-chain verifier.** A Solidity implementation of the verifier enables
Ethereum-native proof verification. The sumcheck verifier requires only
field arithmetic and Keccak hashing, with gas cost scaling linearly in the
total number of sumcheck rounds. The reference implementation includes
such a verifier (see `mle/contracts/src/MleVerifier.sol`).

**Recursive verification.** Verifying the MLE proof inside a Plonky2
circuit enables recursive composition, inheriting Plonky2's existing
recursion infrastructure. The end-to-end recursive test (§8) validates
this, but a hand-tuned Poseidon-friendly hash for the in-circuit Keccak
substitute would significantly reduce recursion cost.

**Zero-knowledge.** The current protocol is publicly verifiable but not
zero-knowledge. Standard zero-knowledge enhancements (random masking
polynomials added to the witness commitment, hiding sumcheck round
polynomials) apply transparently since all underlying primitives
(sumcheck, WHIR) admit ZK variants.

---

## 10. Conclusion

We have presented a multilinear-native proving system for Plonky2 circuits
that eliminates the structural binding gap inherent in adapter-based
approaches. The construction has two key features. First, the gate
constraint sumcheck operates directly on `eq(τ, x) · formula(W(x),
const(x))` and reduces to a multilinear terminal check: the verifier
evaluates `formula(·)` at the PCS-bound point `r`, and the equality holds
because both sides are the same polynomial evaluated at the same point.
Second, the log-derivative permutation argument commits to auxiliary
inverse polynomials and binds them via constant-degree zero-checks, so the
non-linear `1/x` is replaced by a multilinear quantity in the terminal
check. Combined with WHIR's multilinear PCS, the resulting protocol has no
algebraic disjunction between the evaluation proof and the constraint
check, achieving structural soundness with a clean modular soundness
argument. The Rust and Solidity reference implementations demonstrate that
this approach is practical, reusing Plonky2's circuit infrastructure with
minimal modifications and supporting end-to-end proof generation,
verification, and recursive composition for arithmetic and Poseidon
circuits.

---

## References

1. D. Lubarov, W. Borgeaud, J. Nabaglo, H. Ivey-Law, et al. *Plonky2: Fast
   Recursive Arguments with PLONK and FRI.* Polygon Labs, 2022.
2. A. Gabizon, Z. J. Williamson, O. Ciobotaru. *PLONK: Permutations over
   Lagrange-bases for Oecumenical Noninteractive arguments of Knowledge.*
   IACR ePrint 2019/953, 2019.
3. E. Ben-Sasson, I. Bentov, Y. Horesh, M. Riabzev. *Fast Reed-Solomon
   Interactive Oracle Proofs of Proximity.* ICALP 2018.
4. G. Arnon, A. Chiesa, G. Fenzi, E. Yogev. *WHIR: Reed-Solomon Proximity
   Testing with Super-Fast Verification.* IACR ePrint 2024/1586, 2024.
5. C. Lund, L. Fortnow, H. Karloff, N. Nisan. *Algebraic Methods for
   Interactive Proof Systems.* Journal of the ACM, 39(4):859–868, 1992.
6. U. Haboeck. *Multivariate lookups based on logarithmic derivatives.*
   IACR ePrint 2022/1530, 2022.
7. J. Thaler. *Proofs, Arguments, and Zero-Knowledge.* Foundations and
   Trends in Privacy and Security, 2022.
8. B. Bünz, M. Maller, P. Mishra, N. Vesely. *Proofs for Inner Pairing
   Products and Applications.* IACR ePrint 2019/1177, 2019.
