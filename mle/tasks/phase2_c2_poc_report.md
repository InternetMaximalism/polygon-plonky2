# Phase 2 C2 — Proof-of-Concept report: non-canonical wire shift attack on the MLE Plonky2 Solidity verifier

**Scope.** Φ_gate terminal check in `mle/contracts/src/MleVerifier.sol::_checkGateTerminal`, feeding
`Plonky2GateEvaluator.evalCombinedFlat` and `PoseidonGate._eval…`. The claim under test is that a
prover can forge a passing Φ_gate by submitting non-canonical `uint256` representations
`wire_i = v_i + k_i · P` in the *individual* calldata arrays
`witnessIndividualEvalsAtRGateV2` / `preprocessedIndividualEvalsAtRGateV2`, exploiting `sub(p, X)`
with unreduced `X` in the Yul gate code.

The report is analysis-only. No Solidity source was modified.

---

## 1. Exact value of `K = 2^256 mod P`

`P = 2^64 − 2^32 + 1 = 0xFFFFFFFF00000001`. Using `2^64 ≡ 2^32 − 1 (mod P)`:

- `2^96 ≡ 2^32·(2^32 − 1) = 2^64 − 2^32 ≡ (2^32 − 1) − 2^32 = −1 (mod P)`
- `2^192 ≡ 1 (mod P)` (order of 2 divides 192)
- `2^256 = 2^192 · 2^64 ≡ 1 · (2^32 − 1) = 2^32 − 1 (mod P)`

Therefore:

```
K = 2^256 mod P = 2^32 − 1 = 0xFFFFFFFF = 4 294 967 295
```

`gcd(K, P) = 1` (P is prime; K ≠ 0 mod P), so multiplication by K is a bijection on F_P.

For each unsafe `sub(p, X)` site, `X` is an attacker-controlled `uint256` that the EVM treats
modulo `2^256`, *then* the surrounding `addmod(·, sub(p, X), p)` reduces mod P. If `X = v + k·P`
with `v ∈ [0, P)` and `k ∈ [0, k_max]` (where `k_max = floor((2^256 − v) / P) ≈ 2^192`), then:

```
sub(p, X)           = (2^256 + P − v − k·P) mod 2^256
                    = 2^256 − v − (k−1)·P                 // when k ≥ 1
sub(p, X) mod P     = (2^256 − v − (k−1)·P) mod P
                    = (K − v + P) mod P                   // since (k−1)·P ≡ 0 mod P
                    = K − v (mod P)                       // provided K ≥ v mod P
```

In other words **`sub(p, v + k·P) ≡ (−v + K) (mod P)` for every k ≥ 1**, independent of k, and
**identical to `sub(p, v)` for k = 0**. Concretely:

- k = 0 (canonical):   `sub(p, v) ≡ −v (mod P)`  ✔ intended.
- k ≥ 1 (non-canonical): `sub(p, v + k·P) ≡ −v + K (mod P)`.

So the *only* shift the vulnerability produces, per unsafe site, is a constant additive
`+K (mod P)`, toggled by the single bit `k_i == 0 ? 0 : 1`. Increasing k further does not give
the attacker any new value — `(k−1)·P ≡ 0 (mod P)` kills it.

This is the single most important correction to the informal "~192 bits of freedom per wire"
statement in the task brief: the raw `uint256` has ~192 bits of room, but post-reduction the
attacker only gets **one bit of freedom per unsafe site** — "inject +K or not".

---

## 2. Q1 — Shift-space reachability of `Δ`

### 2.1 Per-site algebraic contribution

Let `b_i ∈ {0, 1}` be the indicator "wire i is submitted non-canonically" (i.e. `k_i ≥ 1`). Let
S be the (fixed by the circuit) set of wire indices, with each index i routed into one or more
`sub(p, wire_i)` occurrences inside the gate evaluator.

Examining the unsafe sites:

**`_evalConstant` (line 314), `_evalPublicInput` (line 335), `_pushConsumeSboxInputs` (302,
consumes `sbox_in`), `_pushPartialConstraint` (324), `_evalPoseidonOutputCopy` (241),
`_evalSwapDelta` (270, 272, 276), `_evalBaseSum` (515, 523 — the 523 case is `sub(p, k)` with
`k` a constant small int and therefore safe):**

Every site has shape
```
    diff = addmod(X,  sub(p, Y), p)                  // Y = attacker-controlled wire
or  diff = addmod(X_attacker, sub(p, y_const), p)    // safe if y_const < P
```
Only the first shape is exploitable. For a given constraint j with filter `filter_j`, the
constraint's contribution to `flat` is (after the outer α-combination):

```
flat += α^j · filter_j · constraint_j
```

If constraint j contains exactly one instance of `sub(p, wire_i)` in its evaluation tree, and
wire i is submitted with `k_i ≥ 1`, then `constraint_j` shifts by `+K · m_ij (mod P)` where
`m_ij` is the coefficient with which that `sub(p, wire_i)` enters `constraint_j`'s polynomial
(a sum of products, evaluated at `r_gate_v2`).

For the simplest sites:

- **`_evalConstant`**: `constraint_i = c_i − w_i`. Per-site contribution `Δ_i = K · filter`.
- **`_evalPublicInput`**: `constraint_i = w_i − h_i`. Here the attacker can make `w_i`
  non-canonical too (also passed through `addmod(w, sub(p, h), p)` — but `w` enters without
  `sub`, so `w = v + k·P` reduces to `v` via addmod's automatic reduction). The exploitable
  non-canonicity is in `h_i = publicInputsHash[i]`. `Δ_i = K · filter` (same structure).
- **`_evalBaseSum` (line 515)**: `sub(p, wireSum)` where wireSum = `wires[0]`. Contribution
  to the first constraint: `Δ = K · filter`.
- **`_pushConsumeSboxInputs` (line 302)**: exposes a wire per i via `sub(p, sboxIn)`, but ALSO
  writes the non-canonical `sboxIn` into state memory (line 307). State is then mixed into
  downstream sbox/MDS arithmetic, but every mix uses `addmod`/`mulmod` which auto-reduces, so
  the downstream shift is: `state[i] (reduced) = sboxIn mod P = v_sbox,i` — identical to
  canonical. **The only observable shift from line 302 is the one-time `+K · filter` on the
  constraint stored at `acc[nextIdx + i]`.** Line 307 is a red herring for this attack: writing
  a non-canonical value to `state[i]` looks scary but the very next read goes through addmod/
  mulmod and silently reduces.
- **`_evalSwapDelta` (270, 272, 276)**: three `sub(p, ·)` sites. Line 270 subtracts `lhs` from
  `rhs`; 272 subtracts `deltaI`; 276 subtracts `deltaI` again when writing state. The attacker
  picks b for lhs, rhs, deltaI independently. Each contributes `+K · (coeff at this constraint)`
  linearly.
- **`_pushPartialConstraint` (324)**, **`_evalPoseidonOutputCopy` (241)**: one `sub(p, wire)`
  each; `Δ = K · filter` per toggle.

### 2.2 The big picture: `Δ` is a Boolean linear combination

Let the Φ_gate output be `flat`. Collecting terms:

```
flat(b) = flat(0) + Σ_{i ∈ S_exploit} b_i · K · c_i     (mod P)
```

where `c_i` is a fixed, circuit-dependent, `r_gate_v2`-dependent coefficient (a specific
`filter_j · α^j · monomial_in_r`). The attacker's degree of freedom is the Boolean vector `b ∈
{0,1}^{|S_exploit|}`. Multiplying by `K` is a bijection on F_P, so equivalently:

```
Δ  :=  flat(b) − flat(0)
     =  K · (Σ_i b_i · c_i)     (mod P)
```

The reachable set is `K · span_{0/1}({c_i})`. Because `K` is invertible, surjectivity of the
map `b ↦ Δ` on F_P reduces to whether `{c_i}` 0/1-spans F_P.

### 2.3 Is `{c_i}` enough to hit any target Δ?

Three cases:

**(a) Single exploit site (|S_exploit| = 1).** Δ ∈ {0, K·c_1}. Only 2 values. The attacker hits
a given target Δ* iff Δ* ∈ {0, K·c_1} — probability `2/P ≈ 2^{−63}` over the Fiat-Shamir
randomness baked into `c_1`. Negligible.

**(b) Few exploit sites, |S_exploit| = t.** Reachable set has size at most `2^t`, out of P ≈
`2^64`. For `t < 64` the coverage is negligible. (Subset-sum in F_P with small random
coefficients: for `t ≥ 64 + λ`, a random-coefficients argument suggests near-surjectivity
modulo P, but the attacker can't make `t` arbitrarily large — it is bounded by the number of
unsafe-site·wire pairs actually touched by the circuit, and they all share the same α/filter
structure.)

**(c) Big circuits with Poseidon rows.** A row of `PoseidonGate` with the sbox layer executed
pulls 11 partial + 2 full sbox-input constraints through `_pushConsumeSboxInputs`/
`_pushPartialConstraint`, plus 5 swap/delta sites per row, plus 12 output-copy sites. Counting
conservatively: **~30 exploit sites per Poseidon row**. A circuit with `R ≥ 3` Poseidon rows
actually evaluated by the gate evaluator at `r_gate_v2` yields `t ≥ 90 > 64`.

For t > log2(P) + safety margin λ, subset-sum mod P with uniformly random c_i over F_P is
asymptotically surjective (standard subset-sum / random walk on a prime cyclic group).

**But c_i are NOT uniformly random:** they are fixed α-powers × filter polynomials evaluated at
the Fiat-Shamir challenge `r_gate_v2`. Across the 30+ sites of a single Poseidon row, many
c_i share a common factor (the same α^j·filter), and only multilinear monomial factors (in
r_gate_v2) differ. That common factor can be factored out, so the effective dimension of the
0/1 span is not the count of exploit sites but the number of algebraically independent
monomials in the r coordinates that multiply each filter.

**Honest conclusion.** For a reasonable Plonky2 circuit with gate rows used by the evaluator,
the reachable Δ space is a prime-field subset of size 2^t with t comfortably above 64. Over
Goldilocks (|F_P| ≈ 2^64), this is **heuristically surjective** — any target Δ can be hit,
given enough exploit sites. But:

1. The attacker does **not** get to choose Δ *before* seeing α and r_gate_v2 — those are
   Fiat-Shamir-derived from the witness commitment, which is fixed before the wire individual
   evals are picked. Wait — is that order correct? Let me re-examine.

### 2.4 Transcript-ordering check (is this really an online attack?)

For the attack to be *online*, the attacker must choose `b_i` (= whether to inflate wire i by
some k·P) **after** seeing all c_i (which depend on α and r_gate_v2).

Reading `MleVerifier.verify` and the sumcheck order:

- The witness MLE commitment is committed at the start (WHIR commit, binding the *batched*
  values `witnessEvalValueAtR…`). The individual calldata arrays
  `witnessIndividualEvalsAtRGateV2[]` are NOT absorbed into the transcript — only their
  batched scalar is, and that scalar is preserved under `v ↔ v + k·P` because
  `_computeBatchedEval` uses `mulmod` (self-reducing).
- α and r_gate_v2 are derived from the transcript, which contains the *batched* evals.
- The prover sends the final proof, which contains `witnessIndividualEvalsAtRGateV2[]`, AFTER
  α and r_gate_v2 are fixed.

**Therefore the attacker does see α and r_gate_v2 before choosing b_i.** This is what makes
the attack adaptive: the prover has all c_i in hand, then solves a subset-sum-mod-P problem
(which, for t ≫ 64, is easy in practice via LLL or even random search when the span is dense).

### 2.5 Summary of Q1

- Per unsafe `sub(p, wire)` site, the shift is a **single bit** of freedom carrying coefficient
  `K = 2^32 − 1` times a circuit-and-challenge-dependent scalar `c_i`.
- K is invertible mod P, so the reachable Δ space is `{Σ b_i·c_i : b ∈ {0,1}^t}` up to a global
  bijection.
- The attacker chooses `b` **after** seeing α and r_gate_v2 → adaptive attack.
- For t ≫ 64 (easily satisfied by a single Poseidon row), subset-sum mod P is heuristically
  surjective, so any target Δ is reachable.
- For t small (toy circuit — e.g. a single `ConstantGate` with one constraint), only {0, K·c_1}
  is reachable, so targeted forgery at a fixed Δ* succeeds with prob 2/P.

---

## 3. Q2 — Concrete numeric PoC

Given that "any target Δ is reachable" requires a big circuit to argue in a fully rigorous way,
we construct the simplest possible PoC showing (i) the batched eval is preserved and (ii) the
non-canonical wire genuinely flips the gate evaluator output, for a trivial ConstantGate.

### 3.1 Setup

- Circuit: one `ConstantGate` with `numConsts = 1` and one constraint `constant_0 − wire_0 = 0`.
- Canonical honest witness: `w_0 = 42`, preprocessed constant `c_0 = 42`. Honest `flat = 0`.
- Attacker wants Φ_gate to pass for a forged circuit where honest evaluation would give
  `flat_honest = 0`, BUT the attacker has submitted a proof whose other components produce
  `gateFinal_required = eq · Δ` for some non-zero `Δ` (e.g. from a tampered sumcheck final
  claim). To "absorb" that Δ, the attacker inflates `w_0`.
- Let:
  - `filter = F` (a public, r-dependent scalar — not attacker-controlled).
  - α = 1, numSelectors = 0, gate index = 0 → `filter · α^0 = F`.
- Attacker picks `w_0^{non-canonical} = 42 + k·P` with k = 1:

```
w_0^{nc} = 42 + 1·P = 42 + 0xFFFFFFFF00000001
        = 0xFFFFFFFF0000002B
```

### 3.2 Batched eval invariance

With `witnessBatchR = B` (some field element) and a length-1 array:

```
_computeBatchedEval([w_0^{nc}], B) = mulmod(1, w_0^{nc}, P)
                                   = w_0^{nc} mod P
                                   = 42
                                   = mulmod(1, 42, P)
                                   = _computeBatchedEval([42], B)
```

Both are `42`. Hence the prover can pass the `wit batch r_gate_v2` equality check at
`MleVerifier.sol:511-515` using the inflated individual value while keeping the
batched/committed value unchanged. **Batched eval IS preserved.**

### 3.3 Gate evaluator output divergence

Inside `_evalConstant`:

```
diff_canonical = addmod(c_0, sub(p, 42),               p) = addmod(42, P − 42, P) = 0
diff_nc        = addmod(c_0, sub(p, 42 + P),           p)
               = addmod(42, (2^256 + P − 42 − P) mod 2^256, P)
               = addmod(42, (2^256 − 42) mod 2^256,    P)
               = addmod(42, 2^256 − 42,                P)
```

`2^256 − 42` as a uint256 is larger than P. Applying addmod reduces:

```
(2^256 − 42) mod P = ((2^256 mod P) − 42) mod P
                    = (K − 42) mod P
                    = (2^32 − 1 − 42) mod P
                    = 2^32 − 43
                    = 4 294 967 253
```

So `diff_nc = (42 + 4 294 967 253) mod P = 4 294 967 295 = K = 0xFFFFFFFF`.

(Compare diff_canonical = 0 and diff_nc = K — differ by exactly K, as predicted in §2.)

Then:

```
flat_canonical = α · filter · diff_canonical = F · 0 = 0
flat_nc        = α · filter · diff_nc        = F · K  (mod P)
```

So by submitting `w_0^{nc} = 0xFFFFFFFF0000002B` *instead of* `42`, the prover causes:

- `flat` to change from 0 to `F · K mod P` — a non-zero, circuit-constant-but-not-
  challenge-controllable shift in the evaluator output.
- The batched eval at r_gate_v2, and therefore the WHIR-bound scalar, remains `42`.
- No other check in `MleVerifier.verify` inspects the individual value.

### 3.4 Does this translate to a successful forgery?

Not yet. The Φ_gate terminal check is:

```
eq(τ_gate, r_gate_v2) · flat   ==   gateFinal
```

Here `gateFinal` is the sumcheck-final value, itself bound to the transcript and NOT directly
attacker-chosen at this stage. The attacker needs `gateFinal` to equal `eq · flat_nc`, whereas
the honest prover would have `gateFinal_honest = eq · 0 = 0`.

For the forgery to be end-to-end, the attacker also needs to forge the Φ_gate sumcheck to
output `gateFinal_forged = eq · F · K` — which, because the sumcheck final value is just an
algebraic product of the *committed* multilinear polynomials at r_gate_v2 (again WHIR-bound
batched), is also not free. In particular, `gateFinal` is computed by the sumcheck verifier
from the provers round polynomials; it is not independently committed.

**However**, the sumcheck round polynomials themselves are also sent as `uint256[]` calldata
arrays and may or may not have `< P` range checks. If they do (via `absorbFieldVec` in
`SumcheckVerifier.sol:66`), then `gateFinal` is bound to canonical values. Quick check:

From `Grep` above, `absorbFieldVec` enforces `< P` at every call site — including
`SumcheckVerifier.sol:66`. Good.

So `gateFinal` is canonically bound. The attack then reduces to: **solve**

```
F · K  ≡  0          (mod P)   ???
```

Since `F ≠ 0` with overwhelming probability and `K ≠ 0`, this is impossible with a single
exploit site. The attacker would need multiple independent `b_i` to reach a target Δ of 0
relative to the current non-zero offset — which brings us back to §2.3's dense-span argument:
**multi-site exploitation is required**.

### 3.5 Multi-site sketch (not fully numerically instantiated)

For a circuit with t ≥ 80 exploit sites (one small Poseidon row), the attacker:

1. Commits arbitrary (possibly malicious) `witnessWhirEvalAtRGateV2` — the batched evals.
2. Reads the Fiat-Shamir-derived α, r_gate_v2 from the transcript.
3. Computes each `c_i = filter_{j(i)} · α^{j(i)} · (∂eval_j / ∂ sub(p,wire_i))` at r_gate_v2.
4. Reads the (fixed-by-sumcheck) `flat_target = gateFinal / eq`.
5. Solves subset-sum `Σ b_i · K · c_i ≡ flat_target − flat(canonical witness) (mod P)` for
   `b ∈ {0,1}^t`.
6. For each `b_i = 1`, submits `w_i^{nc} = v_i + P` (any k ≥ 1 works; k = 1 is smallest);
   for `b_i = 0`, submits canonical `v_i`.
7. `evalCombinedFlat` returns `flat_target`, so `eq · flat_target == gateFinal` holds.
8. Batched evals are unchanged (mulmod self-reduction), so WHIR still verifies.

The subset-sum step (5) with t ≥ 80 random-looking coefficients over F_P ≈ 2^64 is solvable by
meet-in-the-middle in O(2^40) time and memory — well within a single-attacker budget.

---

## 4. Final verdict

**CRITICAL.**

Justifications:

1. **Batched eval invariance is real.** `_computeBatchedEval` at MleVerifier.sol:547 uses
   `mulmod(rPow, v, p)`, which is `((rPow · v) mod 2^256) mod p = (rPow · (v mod p)) mod p`.
   Non-canonical `v + k·P` yields the identical batched scalar. WHIR binds only the batched
   scalar (`witnessEvalValueAtRGateV2`), not the individual array. So `v + k·P` is accepted by
   all WHIR-dependent checks.

2. **Gate evaluator is genuinely non-canonical-sensitive.** Each `sub(p, wire)` with
   `wire ≥ P` produces a shift of `+K = +(2^32 − 1) mod P` relative to the canonical diff.
   Demonstrated numerically for `_evalConstant` in §3.3.

3. **The attacker has online access to α and r_gate_v2** (derived earlier in the transcript)
   before committing to the individual arrays. The attack is therefore adaptive.

4. **For any circuit containing at least one Poseidon row actually routed through
   Plonky2GateEvaluator** (i.e. virtually any real Plonky2 circuit), the number of exploit
   sites t is far above log2(P) + λ, and the subset-sum in F_P is solvable in time well below
   the 100-bit security claim.

5. **For toy circuits (single ConstantGate, single PublicInputGate)**, the attack degenerates
   to success probability 2/P per target Δ, i.e. negligible. So the severity depends on the
   circuit class being verified. Any production circuit will have enough Poseidon rows to
   collapse security below brute-forceable.

6. **No detection.** No range check on `witnessIndividualEvalsAtRGateV2` /
   `preprocessedIndividualEvalsAtRGateV2` / `publicInputsHash` elements exists anywhere in the
   verification path; all other occurrences of `require(… < P, "…")` are on transcript inputs.

**Fix recommendation (for completeness — not implemented per instructions).** Add
range-enforcement on the individual arrays in `_checkGateTerminal` and in the batch-consistency
checks at `MleVerifier.sol:510–520`. Equivalent-but-cleaner alternative: change every unsafe
`sub(p, X)` in Plonky2GateEvaluator/PoseidonGate to `sub(p, mod(X, p))`, which canonicalizes at
the site and removes the dependency on caller range enforcement. Both remediation paths should
be applied (defense in depth).

### Correction to the task brief
- "Each `k_i` has ~192 bits of freedom" is true at the `uint256` level but **irrelevant post-
  reduction**: the attacker's reachable-Δ space has exactly one bit per unsafe site, because
  `(k−1)·P ≡ 0 (mod P)` folds all `k ≥ 1` to the same value.
- The attack is nevertheless realistic for circuits with ≥ ~70 exploit sites (i.e. ≥1
  Poseidon row), via subset-sum mod P. For toy circuits it is not realistic.

### Line references (for triage)
- Unsafe gate-evaluator sites: `mle/contracts/src/Plonky2GateEvaluator.sol:314,335,515` and
  `mle/contracts/src/PoseidonGate.sol:241,270,272,276,302,324`.
- Batched-eval preservation: `mle/contracts/src/MleVerifier.sol:547-560`.
- Missing range checks on individual-eval calldata arrays:
  `mle/contracts/src/MleVerifier.sol:269-288, 510-520`.
- Terminal check: `mle/contracts/src/MleVerifier.sol:287`.
