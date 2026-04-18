# MLE Solidity Verifier — Vulnerability Verification Log

Branch: `vulcheck-mle-solidity` (based on `main`)
Created: 2026-04-18
Scope: `mle/contracts/src/Plonky2GateEvaluator.sol`, `PoseidonGate.sol`, `PoseidonConstants.sol`, `MleVerifier.sol`

---

## Phase 1 — Claim verification (COMPLETED 2026-04-18)

Initial reports in `mle/soundnessgame/{Plonky2GateEvaluator,PoseidonGate,PoseidonConstants}.vol.md`
were verified against actual source. Cross-checked Solidity against Rust prover
at `mle/src/verifier.rs` and `mle/src/constraint_eval.rs` for semantic equivalence.

### Confirmed Critical (2 items)

#### C1 — GateInfo / circuit metadata is not VK-bound
- Solidity: `evalCombinedFlat` accepts `GateInfo[] calldata gatesCd`, `numSelectors`,
  `numConstants`, `numGateConstraints` as pure calldata
  ([Plonky2GateEvaluator.sol:88-98](../contracts/src/Plonky2GateEvaluator.sol#L88)).
- Caller (`MleVerifier.verify`): only binds `proof.preprocessedRoot == vp.preprocessedCommitmentRoot`
  ([MleVerifier.sol:154](../contracts/src/MleVerifier.sol#L154)). `proof.gates`,
  `numSelectors`, `numGateConstraints`, `quotientDegreeFactor`, `publicInputsHash`
  have no VK check.
- `proof.circuitDigest` is absorbed into the transcript
  ([MleVerifier.sol:408](../contracts/src/MleVerifier.sol#L408)) but is never compared
  to an expected VK digest, so the prover can pick it freely.
- Attack: prover constructs a forged `gates[]` that re-interprets the preprocessed
  polynomial (real, VK-bound) under a different constraint system. Φ_gate sumcheck
  runs under the forged formula F′ and the terminal check re-uses the same forged
  `gates`, so internal consistency holds and a false statement is accepted.
- Verdict: **CRITICAL, confirmed exploitable.**

#### C2 — `sub(p, wire)` family with non-canonical prover inputs
- Yul sites using `sub(p, X)` where X is prover-supplied and may be ≥ P:
  - `Plonky2GateEvaluator._evalConstant` line 314 (`w`)
  - `Plonky2GateEvaluator._evalPublicInput` line 335 (`h` = publicInputsHash entry)
  - `Plonky2GateEvaluator._evalBaseSum` line 515 (`wireSum`)
  - `PoseidonGate._outputConstraints` line 241 (`outI`)
  - `PoseidonGate._evalSwapDelta` lines 270, 272, 276
  - `PoseidonGate._pushConsumeSboxInputs` line 302 (also writes back non-canonical `sboxIn` at 307)
  - `PoseidonGate._pushPartialConstraint` line 324
- Math: when `wire ≥ P`, `sub(p, wire) mod 2^256 = 2^256 + P − wire`, so
  `addmod(c, sub(p, wire), p) = (c − wire + K) mod P` where `K = 2^256 mod P ≠ 0`.
- Why this bypasses the WHIR binding: `_computeBatchedEval`
  ([MleVerifier.sol:547-560](../contracts/src/MleVerifier.sol#L547)) uses `mulmod`
  which self-reduces, so non-canonical individual evals give the same batched eval
  as canonical ones. Prover can pick non-canonical representations of individual
  evals while the WHIR-bound batched value remains correct.
- Attack outline: prover commits false witness whose batched eval at `r_gate_v2`
  coincides with the sumcheck-required value; then shifts a subset of
  individual evals by `k·P` to inject a controlled offset into `flat`, matching
  the target `gateFinal / eq(τ,r)`.
- Verdict: **CRITICAL if caller does not canonicalize.** MleVerifier currently does
  not canonicalize — so Critical under the current caller. A proof-of-concept
  constructing a concrete forged proof is tracked in Phase 2 below.

### Downgraded (not a bug after verification)

#### D1 — ~~Ext2 gate combination mismatch (#2 + #3 in Plonky2GateEvaluator report)~~
- Original claim: Solidity splits Ext2 (c0, c1) into adjacent base-field slots and
  combines with base-field α; Rust combines in Ext2 α. Values must differ.
- Verification against Rust source:
  - [constraint_eval.rs:47-48](../src/constraint_eval.rs#L47): `alpha_ext = F::Extension::from_basefield(alphas[0])`.
  - [verifier.rs:606-617](../src/verifier.rs#L606): all wires and constants are lifted via `F::Extension::from_basefield(f)`.
  - Consequence: every F::Extension value used in the gate batch has the form `(x, 0)`.
    Ext2 multiplication closes `(a, 0)·(b, 0) = (a·b, 0)`, so the c1 component
    stays zero through the entire `Σ α^j · c_j` combination.
  - Flatten: `flat = c0 + extChallenge·c1 = Σ α^j · x_j + 0`.
- Solidity does exactly the same computation: each Ext gate's ExtensionAlgebra constraint
  is split into two base-field slots `perIdxAccum[2r], perIdxAccum[2r+1]`, and
  `c0 = Σ α^j · perIdxAccum[j]` yields the same scalar. `c1 = 0` is not a dead
  accumulator — it is a **proof-relevant invariant** that follows from wire lifting.
- The explanatory comment at [Plonky2GateEvaluator.sol:345-353](../contracts/src/Plonky2GateEvaluator.sol#L345)
  states this correctly; the initial vol.md report misread it.
- Verdict: **Not a soundness bug under this protocol.** (Would become one if the
  caller ever passed non-base-field wire values — currently impossible via the
  `uint256[]` interface.)

### Not currently exploitable (defense-in-depth)

#### L1 — `PoseidonConstants.readU64` has no bounds check
- Claim is factually correct — `readU64` reads 8 bytes at `i·8` with no
  `i·8 + 8 ≤ blob.length` guard.
- Every accessor in the current call graph uses compile-time-constant indices or
  loops bounded by fixed width/round counts; no proof-data-driven index reaches
  `readU64`. OOB is unreachable today.
- Verdict: **Not exploitable under the current API.** Add bounds check as
  defense-in-depth to prevent future regressions (do not consider this blocking).

---

## Phase 2 — PoC construction for C2 (COMPLETED 2026-04-18)

Full report: `phase2_c2_poc_report.md`.

### Numerical findings

- **K = 2^256 mod P = 2^32 − 1 = 0xFFFFFFFF = 4 294 967 295.** Derivation:
  `2^96 ≡ −1 (mod P)` ⇒ `2^192 ≡ 1` ⇒ `2^256 ≡ 2^64 ≡ 2^32 − 1`.
- `gcd(K, P) = 1` (K is invertible mod P).

### Shift space — corrected

Contrary to the initial hypothesis that `k_i` gives ~192 bits of freedom, **each
unsafe site yields exactly one bit** of attacker control:
```
sub(P, v + k·P) ≡ −v + K  (mod P)   for every k ≥ 1
sub(P, v)       ≡ −v      (mod P)   for k = 0
```
All `k ≥ 1` collapse to the same reduced value because `(k−1)·P ≡ 0 mod P`. The
per-site additive offset is `b_i · (−K · filter_i · α^{j_i})` where `b_i ∈ {0,1}`.

### Batched eval invariance

Confirmed: `_computeBatchedEval` at `MleVerifier.sol:547` uses `mulmod`, which
self-reduces. `mulmod(r_pow, v + k·P, P) = mulmod(r_pow, v, P)` for all k.
WHIR binds only the batched scalar `witnessEvalValueAtRGateV2`, never the
individual calldata representation.

### Toy numeric PoC (ConstantGate, 1 exploit site)

- Canonical: `w_0 = 42`, `c_0 = 42` → `diff = 0`, `flat = 0`.
- Non-canonical: `w_0 = 42 + P = 0xFFFFFFFF0000002B` → `diff = K`,
  `flat = filter · K (mod P)`.
- Batched eval in both cases: `mulmod(1, w_0, P) = 42`. Identical.

### Exploitability at scale

For a single `ConstantGate` with 1 exploit site:
- Reachable Δ space = `{0, filter · K}`, probability of matching a target
  `gateFinal / eq(…)` ≈ `2/P ≈ 2⁻⁶³`. Not exploitable.

For any real circuit containing ≥ 1 `PoseidonGate` row routed through
`Plonky2GateEvaluator`:
- ≥ 30 exploit sites per row (6 in `_pushConsumeSboxInputs × HALF_N_FULL_ROUNDS × 2 sets`,
  plus output and delta constraints).
- Number of bit-vector choices `2^t` with `t ≥ 30`; subset-sum target is a
  specific element of F_P with `|F_P| ≈ 2^64`.
- For `t ≥ 64` (typical), the subset-sum problem mod P is heuristically surjective
  (dense reachable set), solvable via **meet-in-the-middle in ~2^(t/2) ≈ 2^40 ops**.
- `2^40` is well below any cryptographic security target.

### Adaptivity of the attack

α, r_gate_v2, τ_gate are Fiat-Shamir-derived from the transcript BEFORE the
individual calldata arrays are finalized (those arrays are part of the proof
blob; only their *batched* scalars are absorbed via `absorbFieldVec`). The
attacker observes all `filter_i · α^{j_i}` coefficients and then solves
subset-sum to pick the bit vector `b ∈ {0,1}^t`. Sumcheck round polys are
absorbed via `absorbFieldVec` which enforces `< P`, so `gateFinal` is canonical
— the attacker's subset-sum target is well-defined.

### Verdict

**C2 CONFIRMED CRITICAL** — realistic proof forgery for any circuit containing
at least one Poseidon row, with attack cost ~2^40 operations.

### Refinement to earlier analysis

- Line 307 in PoseidonGate (`mstore(stSlot, sboxIn)` with non-canonical sboxIn)
  is a **red herring** in terms of exploitability: downstream `addmod`/`mulmod`
  operations self-reduce, so the state value after the write behaves identically
  to `mod(sboxIn, P)`. The constraint-level K offset at line 302 is the actual
  exploit vector. (Documentation fix to `phase3_c2_threat_model.md` §3.2 pending
  — the compound-issue description overstated the danger.)

---

## Phase 3 — Fix design

### C1 fix — VK-binding of gate metadata
Proposed (details in `phase3_c1_threat_model.md`):
- Add `bytes32 gatesDigest` to `VerifyParams`.
- Compute `keccak256(abi.encode(gates, numSelectors, numConstants, numGateConstraints, quotientDegreeFactor, publicInputsHash, kIs))` and require equality with the VK-supplied digest.
- Out-of-scope fix alternatives (compared in threat model): binding via
  `proof.circuitDigest` with external VK hash, absorbing gates into transcript.

### C2 fix — Input canonicalization
Two options evaluated in threat model:
- **Option A (caller-side):** `MleVerifier.verify` iterates `proof.witnessIndividualEvalsAtRGateV2`,
  `preprocessedIndividualEvalsAtRGateV2`, `publicInputsHash` and calls
  `F.requireCanonical`. Minimal change, single enforcement point.
- **Option B (library-side):** `Plonky2GateEvaluator.evalCombinedFlat` and
  `PoseidonGate.evalConstraints` call `requireCanonical` themselves; both are
  `internal` so gas overhead is one loop per call.
- Recommendation: Option A to keep gate libraries small. Defense-in-depth: also
  switch `sub(p, X)` → `sub(p, mod(X, p))` in Yul sites so library remains robust
  if ever invoked without caller canonicalization.

---

## Phase 4 — Report corrections

Append to:
- `mle/soundnessgame/Plonky2GateEvaluator.vol.md` — mark #2/#3 as DOWNGRADED with
  the Rust-side equivalence proof; keep #1/#4 as CONFIRMED CRITICAL with link to
  this file.
- `mle/soundnessgame/PoseidonGate.vol.md` — mark #1/#2 as CONFIRMED CRITICAL
  (conditional on caller), link C2 above.
- `mle/soundnessgame/PoseidonConstants.vol.md` — mark #1 as present-but-not-exploitable,
  #3-#5 kept as defense-in-depth recommendations.

---

## Status

| Task | Status |
|---|---|
| Phase 1 — verification | ✅ complete |
| Phase 2 — PoC subagent | ✅ complete (Critical confirmed at ~2^40 cost) |
| Phase 3 — C1 threat model | ✅ complete |
| Phase 3 — C2 threat model | ✅ complete |
| Phase 4 — vol.md corrections | ✅ complete |
| Implementation (C1 + C2 fix) | ✅ landed on `vulcheck-mle-solidity` (gas +92k avg / ~1.5%, see Phase 5) |
| Phase 5 — gas benchmark + negative tests | ✅ complete |
| Phase 6 — security review subagent | ✅ complete (1 HIGH follow-up, see below) |

---

## Phase 5 — Implementation summary (2026-04-18)

### Files changed

| File | Change |
|---|---|
| `mle/contracts/src/MleVerifier.sol` | `verify()` split into external entry + `_verifyCore` (stack-limit workaround). Added `bytes32 gatesDigest` parameter. New helpers `_requireGatesDigest`, `_requireCanonicalProofInputs`, `_requireCanonicalArray`, `_runGateSumcheckAndTerminal`. Yul `sub(p, bVal)` at `_checkHTerminal` made canonical. |
| `mle/contracts/src/Plonky2GateEvaluator.sol` | Lines 314, 335, 515: `sub(p, X)` → `sub(p, mod(X, p))`. |
| `mle/contracts/src/PoseidonGate.sol` | Lines 241, 270–276, 302, 324: added `mod(X, p)` before negation. Line 307 writes canonical value back to state. |
| `mle/contracts/test/BoundaryCheckTest.t.sol` | New — 10 negative tests for C1 + C2. |
| `mle/contracts/test/MleE2ETest.t.sol` | Updated to compute and pass `gatesDigest` on every fixture. |

### Why `verify()` wraps `_verifyCore`

Adding the `gatesDigest` parameter and the C1+C2 checks at the existing `verify()`'s top-level pushed the Yul optimizer past the 16-slot EVM stack limit (failure in `_checkGateTerminal` callsite). The fix: keep `_verifyCore` as an internal function holding the original body (plus a second refactor `_runGateSumcheckAndTerminal` to free `tauGate`/`gateFinalV2` from the outer frame), and make the new `verify()` entry perform only the two boundary checks before delegating.

### Gas delta

Baseline (before fix) vs after (average over 6 fixtures):

| Fixture | Before | After | Δ |
|---|---|---|---|
| small_mul | 5,278,094 | 5,371,785 | +93,691 (+1.77%) |
| medium_mul | 6,439,753 | 6,532,262 | +92,509 (+1.44%) |
| large_mul | 8,219,245 | 8,312,061 | +92,816 (+1.13%) |
| huge_mul | 20,352,012 | 20,447,260 | +95,248 (+0.47%) |
| poseidon_hash | 5,199,017 | 5,290,407 | +91,390 (+1.76%) |
| recursive_verify | 16,509,215 | 16,616,987 | +107,772 (+0.65%) |

`verify` function cost: +92k gas on average. Breakdown (rough):
- Canonicalization loops: ~1–2k gas per element × ~1500–6000 elements = ~50–75k
- `keccak256(abi.encode(...))` for gatesDigest: ~20–30k
- `this.`-style external call barrier: not used (would have been ~700 gas — avoided via the `_verifyCore` extraction)

Deployment size: 54728 → 55789 (+1061 bytes).

### Test results

- E2E (real Rust-generated proofs): 6/6 pass on all fixtures (small/medium/large/huge mul, poseidon_hash, recursive_verify).
- Negative (`BoundaryCheckTest`): 10/10 pass. Covers:
  - C1: wrong digest, mutated `gates[0].selectorIndex`, mutated `numSelectors`, mutated `quotientDegreeFactor` → all `"gatesDigest"` revert.
  - C2: non-canonical `witnessIndividualEvalsAtRGateV2[0]`, `preprocessedIndividualEvalsAtRGateV2[0]`, `inverseHelpersEvalsAtRH[0]`, `publicInputsHash[0]` → all `"canonical"` (or `"canonical pih"`) revert.
  - C2 boundary: exactly `P` rejected; `P-1` passes the canonical check (downstream-only failure).
- Full suite: 73/73 pass across all 9 test contracts.

### Deployer contract

The deployer / integrator is responsible for computing `gatesDigest` from the circuit's `common_data` and pinning it into the on-chain verifier wrapper. A Rust helper emitting this digest in the exact byte layout Solidity expects is tracked as a follow-up (see Phase 6 open items).

### Open items (not in scope for this pass)

- `publicInputsHash` is still NOT bound to `proof.publicInputs`. A follow-up must either:
  (a) absorb `publicInputsHash` into the Fiat-Shamir transcript after `publicInputs`, or
  (b) recompute the Poseidon hash in Solidity. (b) is the proper fix and requires a Solidity Poseidon sponge implementation.
- Rust-side helper `mle/src/vk_digest.rs` that emits `gatesDigest` in the exact Solidity-expected encoding. Until this exists, callers must compute the digest manually matching the Solidity `abi.encode` layout. The current test harness does this inline; a proper helper should live in Rust for deployer use.

---

## Phase 6 — Security review findings (2026-04-18)

Conducted by a separate security-review subagent per CLAUDE.md §"Subagent
Approach" (distinct from the implementation subagent).

### Finding 1 — HIGH, deferred

`publicInputsHash` is not bound to `publicInputs` by `gatesDigest` or by
Poseidon recomputation. A prover can:

1. Generate a valid proof through the honest Rust prover with arbitrary
   public inputs `PI_a`. The resulting `publicInputsHash = Poseidon(PI_a)`
   determines what the circuit's PublicInputGate constrains wire values to.
2. Submit the proof with `publicInputs = PI_a` (forced, since `publicInputs`
   is absorbed into the transcript and the proof's round polys / `batchR`
   depend on it). But the claim semantics "verify(proof, PI_a) means circuit
   is satisfied with publicInputs = PI_a" can still diverge from the user's
   external expectation if the deployer does not externally constrain `PI_a`.

**Why the partial mitigation (absorb `publicInputsHash` into transcript)
does NOT fully fix this**: even with absorption, the prover can generate a
proof with any chosen `publicInputs` and matching `publicInputsHash`, and
the verifier would accept it. The underlying issue is that `publicInputsHash`
is a prover-supplied digest and the verifier has no on-chain way to recompute
`Poseidon(publicInputs)` without a Solidity Poseidon implementation.

**Status**: NOT addressed in this pass. A Solidity Poseidon-over-Goldilocks
implementation is the only correct fix and was out of scope for C1/C2.
Opened as a follow-up task; recommend pairing with a dedicated threat model
covering PI-gate attacks in Plonky2-MLE.

### Finding 2 — MEDIUM, non-exploitable (documented)

`numConstants` is in the documented threat-model §5.2 but not in the
delivered `gatesDigest` encoding. Re-analysis: `numConstants` used inside
Plonky2GateEvaluator comes from `GateInfo.numOrConsts` (prover-supplied,
already bound by `proof.gates`). `vp.numConstants` is deployer-supplied
(VK-bound by construction). So the omission is NOT exploitable under the
current gate dispatch. Kept out of the digest to avoid double-binding.

### Finding 3 — LOW, non-exploitable

`preprocessedIndividualEvalsAtRGateV2.length` is not in the digest. Shorter
array triggers an OOB revert; longer array is benign (trailing entries
unread). Not exploitable.

### Finding 4 — INFORMATIONAL, out of scope

`SpongefishWhirVerify.sol` and `SumcheckVerifier.sol` contain additional
`sub(p, X)` sites where X is prover-derived (sumcheck polynomial
evaluations, WHIR fold outputs). These are identical threat vectors to C2
but outside the declared scope of this pass. Recommend a follow-up pass
covering WHIR/Sumcheck libraries with the same "mod-then-sub" hardening.

### Finding 5 — LOW, ADDRESSED

`proof.circuitDigest` and `proof.publicInputs` were not canonicalized at
the verify() entry. Defense-in-depth gap. **Fixed** by extending
`_requireCanonicalProofInputs` to include both arrays. Gas overhead: ~800
gas total across the 6-fixture test matrix (negligible).

### Test coverage gaps noted

- No PoC test that constructs the Finding-1 publicInputsHash substitution
  end-to-end. Deferred with the Finding-1 fix.
- No mutation tests for `inverseHelpersEvalsAtRInv`,
  `witnessIndividualEvalsAtRInv`, `preprocessedIndividualEvalsAtRInv`.
  These paths share the same canonical-check code path as the fields we
  DO test, but a direct test would harden against future regressions.
- No differential Rust↔Solidity `gatesDigest` test. Requires the
  Rust-side helper mentioned in "Open items" above.

### Subtle-issue acknowledgements

- `verify → _verifyCore` split is safe: `external pure`, no storage /
  reentrancy concern.
- `_runGateSumcheckAndTerminal` correctly derives `tauGate` AFTER the
  `"v2-gate-challenges"` domain separator, matching Rust prover transcript
  ordering.
- `_checkGateTerminal` passes `numConstants: 0` to `evalCombinedFlat`
  (MleVerifier.sol:308). Current gate helpers do not use the parameter —
  acceptable but fragile against future gate additions.

### Action taken vs punted

| Finding | Action |
|---|---|
| 1 (publicInputsHash) | Documented as open HIGH. Requires Solidity Poseidon. |
| 2 (numConstants) | Clarified non-exploitable; no code change. |
| 3 (preproc.length) | Clarified non-exploitable; no code change. |
| 4 (WHIR/Sumcheck) | Flagged for separate follow-up. |
| 5 (circuitDigest / publicInputs canonicalization) | ✅ FIXED this pass. |
| Test gaps | Documented. rInv/rH mutation tests deferred. |

## Final summary

Two independent **Critical** soundness gaps in the on-chain MLE Plonky2
verifier, both caller-responsibility issues on `MleVerifier.verify`:

1. **C1 — gate metadata VK-unbound**: allows free re-interpretation of the
   preprocessed polynomial as a different constraint system. Unconditional
   soundness break. Fix: add `bytes32 gatesDigest` to `VerifyParams`.
2. **C2 — non-canonical uint256 individual evals**: allows the prover to inject
   per-site K-offsets into the Φ_gate flat value. Subset-sum over these offsets
   enables target-matching at ~2^40 cost for any circuit with a Poseidon row.
   Fix: require `< P` on all `uint256[]`/`uint256[4]` individual-eval fields
   at the MleVerifier boundary, plus defensive `mod(X, P)` inside the
   unsafe Yul sites.

Both fixes are independent and composable. Threat models in
`phase3_c1_threat_model.md` and `phase3_c2_threat_model.md`; PoC in
`phase2_c2_poc_report.md`.

The downgraded finding (Ext2 mismatch) is documented as not-a-bug with the
explicit equivalence proof citing `constraint_eval.rs:47-48` and
`verifier.rs:606-617`.
