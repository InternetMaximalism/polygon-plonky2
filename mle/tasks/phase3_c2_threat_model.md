# C2 Threat Model — Non-canonical input sanitization

## 1. Asset under protection

Correctness of every `sub(p, X)` in the gate evaluators, where `X` is
prover-supplied and may be represented non-canonically (≥ P = 0xFFFFFFFF00000001).

## 2. Mechanism of the bug

EVM `SUB(a, b) = (a - b) mod 2^256`.

When `b < P ≤ a`, `sub(P, b)` = `P - b` (correct field negation when `a = P`).
When `b ≥ P > a = P`, `sub(P, b) = 2^256 + P - b` (256-bit underflow wraps).

`addmod(c, sub(P, b), P)` then computes `(c + 2^256 + P - b) mod P`
= `(c - b + K) mod P` where **K = 2^256 mod P**.

For Goldilocks P = 2^64 − 2^32 + 1 ≈ 1.8e19, K is a specific 64-bit value
(computed exactly in Phase-2 PoC subagent report). It is non-zero.

Net effect: a non-canonical wire value `w = v + j·P` (where `v = w mod P < P`,
`j ≥ 1`) causes the gate evaluator to compute `(c - v + K) mod P` instead of
the correct `(c - v) mod P` at every affected `sub(P, wire)` site.

## 3. Unsafe sites (exhaustive inventory)

### 3.1 Plonky2GateEvaluator.sol

| Line | Function | Unsafe term | Source of X |
|---|---|---|---|
| 314 | `_evalConstant` | `sub(p, w)` | `wires[i]` (prover) |
| 335 | `_evalPublicInput` | `sub(p, h)` | `publicInputsHash[i]` (proof) |
| 515 | `_evalBaseSum` | `sub(p, wireSum)` | `wires[0]` (prover) |

Sites using `F.sub` (which does `mod(b, P)` first — SAFE):
- 254, 258 (`_computeFilter`) — safe
- 391-396, 441-446, 485-490 (Ext gate helpers) — safe
- 606-611, 668-673 (Reducing gates) — safe
- 713, 744, 758, 775, 782 (`_evalRandomAccess`) — safe

`_evalArithmetic` line 290: `sub(p, computed)` — `computed` is always a
`mulmod` result, hence canonical. **Safe.**

### 3.2 PoseidonGate.sol

| Line | Function | Unsafe term | Source of X |
|---|---|---|---|
| 241 | `_outputConstraints` | `sub(p, outI)` | `w[i+12]` (prover) |
| 270 | `_evalSwapDelta` | `sub(p, lhs)` | `w[i]` (prover) |
| 272 | `_evalSwapDelta` | `sub(p, deltaI)` | `w[i+25]` (prover) |
| 276 | `_evalSwapDelta` | `sub(p, deltaI)` | `w[i+25]` (prover) |
| 302 | `_pushConsumeSboxInputs` | `sub(p, sboxIn)` | `w[startSbox+i]` (prover) |
| 324 | `_pushPartialConstraint` | `sub(p, sboxIn)` | `w[START_PARTIAL+r]` (prover) |

**Compounding issue at line 307**: `mstore(stSlot, sboxIn)` writes the raw
(non-canonical) wire back into the Poseidon state. Subsequent `_sboxLayer` uses
`mulmod` (self-reducing) so downstream arithmetic silently treats the state as
`sboxIn mod P`. This means the *constraint* evaluates against the non-canonical
representation (with K-offset) while the *state* carries the canonical value —
the K-offset becomes observable at the constraint but invisible downstream, a
classic "commitment/evaluation mismatch" vector.

### 3.3 PoseidonGate.sol — safe sites

`sub(p, k)` at line 523 in `_evalBaseSum` is safe (`k < B ≤ 2^16`, canonical).

## 4. Caller context (why this reaches the prover)

`MleVerifier.verify` passes `proof.witnessIndividualEvalsAtRGateV2`,
`proof.preprocessedIndividualEvalsAtRGateV2`, `proof.publicInputsHash` directly
to `Plonky2GateEvaluator.evalCombinedFlat` without canonical-form checks.

The `uint256[]` calldata type admits any 256-bit value. The WHIR binding path
(`_computeBatchedEval` at line 547-560) uses `mulmod` which self-reduces, so
non-canonical representations of individual evals produce the SAME batched eval
as their canonical counterparts. The WHIR proof verifies the batched eval, not
the per-entry representation.

Therefore: the adversary has a free parameter `j_i ∈ [0, ⌊(2^256 − v_i) / P⌋]`
for each individual eval `i`, bounded only by the `uint256` type.

## 5. Exploitability (awaiting Phase-2 PoC report)

See `phase2_c2_poc_report.md` (in progress) for the formal analysis. Expected
findings:

- **If** `{Σ_i c_i · K : c_i ∈ F_P}` covers enough of F_P with `c_i` = `filter·α^j`
  constrained by the gate layout, THEN the adversary can realize any target
  offset Δ and the attack is **Critical — realistic forgery**.
- **If** the shift space is constrained to a sparse set that generically misses
  `Δ`, THEN the attack requires specific circuit shapes and downgrades to
  **High — conditionally exploitable**.

Regardless of the PoC verdict, the code path is unsafe and should be hardened.

## 6. Proposed fix — two independent defenses (use BOTH)

### 6.1 Caller-side: canonicalization at `MleVerifier.verify` entry

Add to the start of `verify`:

```solidity
_requireCanonicalArray(proof.witnessIndividualEvalsAtRGateV2);
_requireCanonicalArray(proof.preprocessedIndividualEvalsAtRGateV2);
_requireCanonicalArray(proof.witnessIndividualEvalsAtRInv);
_requireCanonicalArray(proof.preprocessedIndividualEvalsAtRInv);
_requireCanonicalArray(proof.inverseHelpersEvalsAtRInv);
_requireCanonicalArray(proof.inverseHelpersEvalsAtRH);
for (uint256 i = 0; i < 4; i++) require(proof.publicInputsHash[i] < P, "pih");
```

Where `_requireCanonicalArray` is a one-liner that loops and calls
`F.requireCanonical`. The gas cost is O(proof-size) single `lt(v, P)` check per
element, negligible.

### 6.2 Library-side: defensive self-reduction

In each Yul block with `sub(p, X)` where X is untrusted, replace:

```yul
let diff := addmod(c, sub(p, w), p)
```
with:
```yul
let diff := addmod(c, sub(p, mod(w, p)), p)
```

This makes the library robust against misuse. Gas impact: one extra `mod` op
per occurrence (~5 gas).

`_pushConsumeSboxInputs` additionally needs `mstore(stSlot, mod(sboxIn, p))` at
line 307 to ensure the Poseidon state always carries canonical values (prevents
the "constraint vs downstream arithmetic" mismatch at §3.2 compound issue).

### 6.3 Why BOTH defenses

- Caller-side is the canonical fix: enforces the documented invariant at the
  trust boundary, single enforcement point, audit-friendly.
- Library-side is defense-in-depth: if `Plonky2GateEvaluator` or `PoseidonGate`
  is ever reused by a different caller (e.g., a future on-chain proof aggregator)
  that forgets the canonicalization, the library still produces correct results.
- The CLAUDE.md "Security over speed" and "No silent workarounds" norms favor
  belt-and-suspenders for cryptographic primitives.

## 7. Rejected alternatives

### 7.1 Rely on WHIR binding alone

Claim: "Individual evals are WHIR-bound so canonicalization is enforced by WHIR."
False. WHIR binds the BATCHED eval (via `_computeBatchedEval` with self-reducing
`mulmod`), not the per-entry representation. Prover has degrees of freedom in
individual eval representation.

### 7.2 Reduce once inside gate evaluator entry

A single reduction of `wires[i] := wires[i] mod P` at the start of
`evalCombinedFlat` would fix all Plonky2GateEvaluator sites in one place, but:
- Requires writable memory (`wires` is already copied to memory, so feasible).
- Does NOT fix PoseidonGate, which receives `w` from its own caller.
- Is less transparent than caller-side enforcement.

Option 7.2 is an acceptable backup if gas is tight, but 6.1 + 6.2 is preferred.

## 8. Test plan

1. **Unit / canonicalization**: wire `= v + P` for various `v, j`. Verify that
   `MleVerifier.verify` reverts with `"canonical"` before reaching gate logic.
2. **Unit / library self-reduction**: call `Plonky2GateEvaluator.evalCombinedFlat`
   directly with non-canonical wires, observe same output as canonical.
3. **Unit / Poseidon state**: call `PoseidonGate.evalConstraints` with a
   non-canonical `w[SBox_input]`. Verify output unchanged vs canonical form
   (i.e., after fix, non-canonical input does not alter the constraint value).
4. **End-to-end regression**: real Rust-generated proof still verifies (honest
   provers always emit canonical values, so no behavior change expected).
5. **Adversarial**: using the PoC from Phase 2 (if realistic), verify that the
   attack now reverts before ever reaching the gate evaluator.
6. **Differential fuzz**: generate random canonical wire vectors and their
   non-canonical translations `{v_i + j_i·P}`; assert `evalCombinedFlat` result
   is invariant after the library-side fix.

## 9. Acceptance criteria

- All six Yul sites listed in §3.1–§3.2 use safe subtraction.
- Line 307 writes `mod(sboxIn, p)` to state.
- `MleVerifier.verify` requires canonical form on every `uint256[]` / `uint256[4]`
  field derived from `proof` that reaches any gate evaluator.
- The test plan in §8 passes on the fix branch.
- Fix is reviewed by a security-review subagent distinct from the implementer.

## 10. Out of scope

- α, β, γ, μ, extChallenge, etc., are already canonical by transcript-squeeze
  construction (assuming `TranscriptLib.squeezeChallenge` returns `< P`; verify
  this assumption in a follow-up subagent, NOT part of C2).
- C1 (gate metadata VK binding) is orthogonal, see `phase3_c1_threat_model.md`.
- `_computeBatchedEval` itself is correct — it's the gate evaluator and
  PoseidonGate internal `sub(p, X)` that are vulnerable, not the batching.
