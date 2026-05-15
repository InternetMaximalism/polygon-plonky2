# CosetInterpolationGate Solidity Port — Plan & Threat Model

**Status:** Phase P1 and Phase P2 both complete. End-to-end recursive proof with
`CosetInterpolation` verified on-chain (gas spike + negative-probe both confirm the
new branch is actually executed). Honest accounting in §8 / §9 below.

**Goal:** Add `_evalCosetInterpolation(...)` to `mle/contracts/src/Plonky2GateEvaluator.sol` and dispatch `gateId = 13` to it, so that recursive plonky2 proofs that include a `CosetInterpolationGate` row at non-zero filter can be verified on-chain instead of reverting with `"unsupported gate with non-zero filter"`.

**Audience for this doc:** the next session and any reviewer. Honesty over optimism — every "done" claim below must be falsifiable.

---

## 1. Background

- `Plonky2GateEvaluator.sol` already ports 12 of the 13 plonky2 gates that the recursive verifier circuit may instantiate. `CosetInterpolationGate` is the one omission; it is used by `fri/recursive_verifier.rs::compute_evaluation` whenever the inner FRI has non-trivial `arity_bits`.
- The header comment in `Plonky2GateEvaluator.sol` is stale and claims only 4 gates are ported. **Fixing the header is part of this task.**
- The fixture-side classifier `gate_id` already reserves `13` for CosetInterpolation; only `num_or_consts = subgroup_bits` is currently emitted. We must also surface `degree`, which is needed to know how many intermediate-eval/prod constraint pairs to generate.

## 2. Rust reference (the spec we must match bit-exactly)

Source: `plonky2/src/gates/coset_interpolation.rs::eval_unfiltered_base_one` (lines 251-298).

Let `N = 1 << subgroup_bits`, `D = 2` (Goldilocks Ext), and let `n_int = (N - 2) / (degree - 1)` be `num_intermediates`. Wire layout:

| Wire index | Meaning | Width |
|---|---|---|
| `0` | `shift` (base field scalar) | 1 |
| `1 .. 1 + N·D` | `values[i]` (Ext) for `i` in `0..N` | `N·D` |
| `1 + N·D .. 1 + (N+1)·D` | `evaluation_point` (Ext) | `D` |
| `1 + (N+1)·D .. 1 + (N+2)·D` | `evaluation_value` (Ext) | `D` |
| intermediates: `n_int` × Ext eval + `n_int` × Ext prod | "every (d-1)-th partial state" | `2·n_int·D` |
| `1 + (N+2+2·n_int)·D .. 1 + (N+3+2·n_int)·D` | `shifted_evaluation_point` (Ext) | `D` |

Two-adic domain: `x[i] = g^i`, where `g = F::primitive_root_of_unity(subgroup_bits)`. Barycentric weights: `w[i] = ∏_{j≠i} 1/(x[i] - x[j])`. Both are **completely determined by `subgroup_bits`** — independent of the gate instance, the circuit, or the proof. We can hardcode them per supported `subgroup_bits`.

Constraint set (each line below produces `D` base-field constraints):

```
C₁:                   evaluation_point - shift · shifted_evaluation_point     ≟ 0        (D=2 constraints)
C₂.i (for each intermediate i ∈ 0..n_int):
                      intermediate_eval[i]  - computed_eval[i]                ≟ 0        (D constraints)
                      intermediate_prod[i]  - computed_prod[i]                ≟ 0        (D constraints)
C₃:                   evaluation_value     - computed_eval_final              ≟ 0        (D constraints)
```

where `(computed_eval[i+1], computed_prod[i+1])` come from the partial-interpolation recurrence over `degree-1` domain points at a time, seeded by `(eval=0, prod=1)`:

```
for each (val, weight, x_j) in the current chunk:
    weighted_val      = val · weight                  // val: Ext, weight: base
    term              = shifted_eval_point - x_j      // Ext - base
    next_eval         = eval · term + weighted_val · prod
    next_prod         = prod · term
```

Total constraint count: `D · (1 + 2·n_int + 1) = 2·D·(n_int + 1) = 4·(n_int + 1)`.

## 3. Solidity design

### 3.1 New file: `mle/contracts/src/CosetInterpolationConstants.sol`

Hardcoded per-`subgroup_bits` tables. We pre-compute in Rust and dump to Solidity. Supported values: **`subgroup_bits ∈ {1, 2, 3, 4}`** (matching the plonky2 default `max_fri_arity_bits ≤ 4`). Higher values revert with an explicit `"CosetInterpolation: subgroup_bits not supported"`.

For each `k ∈ {1, 2, 3, 4}`:
- `subgroup_k`: array of `2^k` Goldilocks elements (the two-adic subgroup).
- `weights_k`: array of `2^k` Goldilocks elements (barycentric weights).

Layout: tightly-packed `bytes` constants accessed with `mload`+`shr(192, …)` per element, mirroring the PoseidonConstants approach. Allows reading a single u64 in 3 gas.

A Rust generator (`mle/src/bin/dump_coset_constants.rs`) re-emits this file deterministically so it can be regenerated whenever plonky2's Goldilocks `primitive_root_of_unity` changes.

### 3.2 Patch: `Plonky2GateEvaluator.sol`

1. Add `uint8 internal constant GATE_COSET_INTERPOLATION = 13;`. (The classifier already uses `8 = ExponentiationGate`, so 13 is free.)
2. Update `GateInfoFixture` Rust side to also emit `degree` as `param2` for CosetInterpolation.
3. Update the Solidity `GateInfo` doc comment: `param2 = CosetInterpolation: degree`.
4. Add a dispatch branch:
   ```solidity
   } else if (gi.gateId == GATE_COSET_INTERPOLATION) {
       _evalCosetInterpolation(
           wires,
           gi.numOrConsts,  // subgroup_bits
           gi.param2,       // degree
           filter,
           perIdxAccum
       );
   }
   ```
5. Implement `_evalCosetInterpolation`:
   - Compute `N = 1 << subgroup_bits`, `n_int = (N - 2) / (degree - 1)`.
   - Load `shift`, `shifted_evaluation_point`, `evaluation_point`, `evaluation_value` from `wires`.
   - First constraint pair `C₁`:
     ```
     diff0 = evaluation_point[0] - shift · shifted_evaluation_point[0]
     diff1 = evaluation_point[1] - shift · shifted_evaluation_point[1]
     acc[c+0] += filter · diff0
     acc[c+1] += filter · diff1
     ```
     (`shift` is base field; Ext scalar-mul is component-wise.)
   - Loop over chunks of `degree - 1` (or fewer for the last). For each chunk, run the partial-interpolation recurrence in inline Yul and check the two `C₂.i` constraint pairs.
   - Final `C₃` pair on `evaluation_value vs computed_eval`.

6. **Fix the header comment** — the existing "Supports the 4 simple gate types" claim is now wrong (it became wrong when commit `72d5f0f8` added 8 more gates, was never corrected). Replace with an accurate enumeration of the 13 supported gates plus the unsupported tail (ExponentiationGate, LookupGate / LookupTableGate).

### 3.3 Extension-field arithmetic (D=2 Goldilocks)

Same convention as the existing gates: an Ext element is two `uint256` slots `(a0, a1)`, multiplication uses `W = 7` for Goldilocks:
```
(a0 + a1·X) · (b0 + b1·X) = (a0·b0 + 7·a1·b1) + (a0·b1 + a1·b0)·X
```
Scalar (base-field) multiplication `s · (a0, a1) = (s·a0, s·a1)`.

No new Ext primitives needed — we reuse the inline-Yul patterns from `_evalReducing` / `_evalReducingExt`.

## 4. Threat model (CLAUDE.md §Security-Critical Mindset compliance)

Adversary capabilities:
- Provides a malicious recursive proof where the inner FRI claims a wrong polynomial interpolation.
- Controls the wire values (including `shift`, `values[i]`, `evaluation_point`, `evaluation_value`, intermediate eval/prod). Cannot control the barycentric weights or the domain.
- Cannot bypass the selector filter — `filter * (constraint == 0)` is enforced upstream by the MLE protocol; we only need to evaluate the constraint correctly, and the existing `(α^j · filter_j · …) → flat` aggregation in `evalCombinedFlat` is unchanged.

### 4.1 Invariants the port must preserve

I1. **Bit-exact match with `eval_unfiltered_base_one`.** For every `(subgroup_bits, degree, all-wires)` tuple, the Solidity per-constraint diffs and their flat-α aggregation must equal what the Rust verifier would compute for the same input. Falsifiable: round-trip test on a fixture.

I2. **No silent acceptance of unsupported `subgroup_bits`.** If a circuit ships with `subgroup_bits ∉ {1,2,3,4}` the Solidity verifier must revert — never produce a smaller `flat` than expected.

I3. **No silent acceptance of degenerate `degree` parameters.** `degree < 2` would underflow `(degree - 1)` in `n_int`. Revert.

I4. **Constants tampering resistance.** The barycentric weights and subgroup elements in `CosetInterpolationConstants.sol` are the audit surface. They must equal what `barycentric_weights(F::two_adic_subgroup(k))` produces in Rust. We verify via:
   - A regeneration script (`dump_coset_constants.rs`) → its output is byte-equal to the checked-in file.
   - A round-trip test that constructs a `CosetInterpolationGate` in Rust, dumps its weights, and asserts they match the Solidity constants when read via the same byte-extraction logic the gate uses.

I5. **No off-by-one in chunk boundaries.** The Rust loop does `start_index = 1 + (degree-1) * (i+1)`, `end_index = (start_index + degree - 1).min(N)`. The Solidity port must match exactly; an off-by-one would compute a wrong eval/prod and either accept invalid proofs or reject valid ones.

### 4.2 Attack vectors to enumerate

A1. **Wrong barycentric weights in Solidity constants.** Soundness break if the adversary can find a witness that the Rust prover would NOT generate but that satisfies the Solidity check. Mitigation: I4.

A2. **Off-by-one in the `min(end_index, N)` clamp.** Common porting bug. Mitigation: I5 + property test that varies `(subgroup_bits, degree)` across all supported combos.

A3. **Field arithmetic overflow.** Goldilocks `addmod`/`mulmod` on a u256 with `p` as modulus is what every existing gate uses; no new primitive needed. **But:** intermediate sums `eval · term + weighted_val · prod` in Ext can have raw products up to `p² ≈ 2¹²⁸`; we must NOT pre-modreduce only after the full mul-add. We mirror the Yul pattern from `_evalReducing` which uses `addmod(mulmod(...), mulmod(...), p)` — every intermediate is reduced mod `p`.

A4. **Filter-skipping bug.** If `filter == 0` we currently `continue` (see line 134-136). The new branch must respect this — passing through the filter check before doing any work.

A5. **Extension-field W constant mismatch.** Plonky2 Goldilocks Ext2 uses `W = 7`. Solidity gates use the same constant. We hardcode `7` inline like the existing gates.

A6. **Reading uninitialised wire slots.** If the input `wires[]` array is shorter than `1 + (N+3+2·n_int)·D`, Solidity will revert on out-of-bounds (memory access). That's safe; just need to be sure the caller passes a long enough wire array. Existing dispatcher already does this for all other gates with no explicit length check, relying on Solidity's natural OOB revert.

A7. **Aliasing / overwriting accumulator.** The `perIdxAccum` array is shared across gate evaluators. Each evaluator writes to a per-constraint slot indexed by `(gate_row_index, constraint_index)`. We mirror the indexing pattern from `_evalReducing` — never reuse a slot.

### 4.3 Out of scope but flagged

- ExponentiationGate and Lookup are still unported; this PR does not change that.
- Higher-order `subgroup_bits` (5+) are not supported. Recursive proofs targeting that would still revert. A separate task.

## 5. Implementation phases

P1 (this PR):
- [ ] Rust `mle/src/bin/dump_coset_constants.rs` — generates `CosetInterpolationConstants.sol`.
- [ ] Rust `mle/src/fixture.rs` — emit `degree` as `param2` for gate_id=13.
- [ ] `mle/contracts/src/CosetInterpolationConstants.sol` — generated.
- [ ] `mle/contracts/src/Plonky2GateEvaluator.sol`:
   - [ ] Add `GATE_COSET_INTERPOLATION = 13` constant.
   - [ ] Add dispatch branch.
   - [ ] Implement `_evalCosetInterpolation`.
   - [ ] Fix the stale header comment.
- [ ] Foundry test that exercises CosetInterpolation against a Rust-generated fixture (`coset_interp_test.json`).
- [ ] Attacker subagent reviews the new Solidity code in isolation.

P2 (follow-up, not blocking merge):
- [ ] Synthesize a real recursive-proof fixture that actually uses CosetInterpolation (existing `recursive_verify.json` was crafted to avoid it). Verify on-chain.

## 6. Verification matrix

| Check | When | Pass condition |
|---|---|---|
| `forge build` | after every edit | compiles cleanly |
| `forge test --match-test CosetInterpolation` | after Foundry test added | constraint values match Rust per-row dumps to all bits |
| Property test: vary `(subgroup_bits, degree)` across `{(1,2), (2,2), (2,3), (3,2), (3,3), (3,4), (4,2), (4,3), (4,4)}` | after Foundry test added | all rows verify |
| Regenerate constants from Rust | once | byte-equal to checked-in `CosetInterpolationConstants.sol` |
| Attacker subagent report | before merge | every finding addressed or filed as known-issue |

## 7. Honesty rules (per user directive)

This task is **incomplete until every item in §5 P1 is checked**. Specifically:
- "I wrote the Solidity" ≠ "it works". Without the Foundry test passing on a real fixture, claiming completeness is the lying behaviour the user already called out.
- If any phase fails or stalls (e.g. constants regeneration mismatches the Rust output), I **must** surface that here in this file before moving on, with the failing hypothesis and what I did instead.
- If a recursive proof in the wild uses `subgroup_bits = 5+`, this PR does not help them — that limitation must be in the PR description, not buried.

## 8. Honest final status (post-implementation accounting)

### What is verifiably done (with proof)

- [x] `mle/tests/dump_coset_constants.rs` + `mle/contracts/src/CosetInterpolationConstants.sol`.
  Constants generated with `to_canonical_u64()` (not `.0`) — the first attempt used `.0`
  and produced non-canonical Goldilocks elements (≥ p) that caused the
  `bits=3, degree=2, slot=2` mismatch in the first test run. Documented in this file's
  context and in the dumper itself.
- [x] `mle/src/fixture.rs` — `gate_id = 13` now also emits `degree` as `param2`.
- [x] `mle/contracts/src/Plonky2GateEvaluator.sol`:
   - [x] `GATE_COSET_INTERPOLATION = 13` constant + dispatch branch.
   - [x] `_evalCosetInterpolation` + `_cosetPartialStep` + `_cosetRunChunk` +
     `_cosetCheckIntermediateAndAdvance` + `_cosetEmitExtDiff` helpers.
   - [x] Stale "4 gates" header comment replaced with an accurate
     13-gates-supported / 3-gates-unsupported enumeration.
- [x] `mle/tests/dump_coset_test_vectors.rs` + `mle/contracts/test/CosetInterpolationVectors.sol`
  — 7 `(subgroup_bits, effective_degree)` combinations.
- [x] `mle/contracts/test/CosetInterpolationTest.t.sol` — 5 Foundry tests, all PASS:
   - `test_bitExactMatch_filterOne` (all 7 combos)
   - `test_bitExactMatch_filterRandom` (filter ≠ 1 multiplicative accumulation)
   - `test_filterZero_zeroesAll`
   - `test_degreeBelowTwo_revert`
   - `test_unsupportedSubgroupBits_revert`
- [x] Regression check: full Foundry suite **78 / 78 pass**, no test broken by the port.
- [x] Attacker subagent run: CRITICAL=0, HIGH=0. Findings M1 (defense-in-depth `mod p`
  in `_cosetEmitExtDiff`) and L1 (`require(degree ≤ N)`) and L2 (`readU64` bound check)
  applied; full test suite re-run after each fix and still 78/78.
- [x] `plonky2/src/gates/coset_interpolation.rs::with_max_degree` visibility raised
  from `pub(crate)` to `pub` so the test-vector dumper in `mle/tests/` can construct
  the gate at chosen `(subgroup_bits, max_degree)`.

### What is NOT done (do not claim completeness here)

- [ ] **`subgroup_bits ≥ 6` support.** The constants library now covers
  `{1, 2, 3, 4, 5}`. `bits = 6` would require 169 wires (vs the
  `standard_recursion_config` budget of 135), so it is not reachable
  without a wider config. Adding 6+ requires re-running
  `cargo test --release --test dump_coset_constants -- --nocapture`
  with `SUPPORTED_BITS` extended AND a wider circuit config upstream.
- [ ] **Property-style randomisation in Foundry (audit I1, P1).** Test
  vectors use one deterministic seed per `(bits, degree)`. A forge-fuzz
  harness that derives expected via the Rust dumper at run-time would
  tighten the soundness guarantee further. Not blocking, not in scope today.
- [ ] **Property-style randomisation in Foundry.** Test vectors use one
  deterministic seed per `(bits, degree)`. A forge-fuzz harness that derives
  expected via the Rust dumper at run-time would tighten the soundness
  guarantee further (audit I1). Not blocking, not in scope today.

### Verification matrix (final)

| Check | Status |
|---|---|
| `forge build` | green |
| `forge test --match-contract CosetInterpolationTest` | 5/5 pass (9 combos: bits 1..5) |
| `forge test --match-test test_e2e_coset_recursive_verify` | PASS |
| `forge test` (full suite) | **79/79 pass** |
| Regenerate constants from Rust → byte-equal to checked-in file | yes |
| Bit-exact match Rust ↔ Solidity for all 9 `(bits, degree)` combos | yes |
| Attacker subagent findings P1 | M1, L1, L2 all applied |
| Attacker subagent findings P2 | M1 (`bits=5` in doc) + M2 (stale ref in test comment) applied; LOW (mass fixture regen) documented |
| E2E recursive proof using CosetInterpolation verified on-chain | **DONE** — `coset_recursive_verify.json`, gas spike +1.96M, negative probe confirmed |

## 9. Phase P2 outcome (E2E recursive proof on-chain)

### What was done

- `mle/tests/generate_fixtures.rs::build_recursive_circuit_with_coset_interp`:
  - Inner FRI forced to fold exactly once via `FriReductionStrategy::Fixed(vec![4])`
    + 2000-multiplication chain to satisfy `total_arities ≤ degree_bits + rate_bits - cap_height`.
  - Outer circuit uses `standard_recursion_config` (unchanged), verifies inner via `verify_proof`.
  - Builder-side `assert!(coset_in_outer, ...)` guards against silent regression:
    if a future plonky2 upgrade stops emitting `CosetInterpolationGate` for this
    config, fixture generation panics rather than producing a fixture that
    doesn't exercise the new branch.
- `mle/contracts/test/fixtures/coset_recursive_verify.json` generated:
  `degree_bits = 12`, 13 gate types including
  `CosetInterpolationGate { subgroup_bits: 4, degree: 6 }` (gate_id=13,
  numOrConsts=4, param2=6).
- `mle/contracts/test/MleE2ETest.t.sol::test_e2e_coset_recursive_verify` PASS.
- Gas: `recursive_verify` (no coset) = 8.12M, `coset_recursive_verify` = 10.08M.
  +1.96M = 24% — consistent with executing `_evalCosetInterpolation` for one
  CosetInterpolation row plus 28 additional constraint emits.

### How we know the branch actually executes (not bypassed)

Three independent confirmations:

1. **Empirical (gas)**: +1.96M gas delta. If the dispatch fell through to the
   `unsupported gate` revert, the test would fail. If it silently bypassed (filter=0),
   gas would be ~unchanged.

2. **Negative probe**: temporarily replaced the dispatch body with
   `revert("PROBE: coset_disabled")`. The E2E test failed with that exact message.
   This proves the dispatcher reaches the branch. The probe was reverted immediately
   (`git diff HEAD` on `Plonky2GateEvaluator.sol` after restore = empty).

3. **Filter check (independent attacker subagent verification)**: computed the
   selector filter value at the FS-derived sumcheck point r:
     - `s = preprocessedIndividualEvalsAtRGateV2[2]` (= the selector poly eval)
     - `filter_CosetInterp = (12 − s)·(UNUSED − s) mod p = 4761291109470363177 ≠ 0`
   Non-zero filter → dispatcher does NOT `continue` → `_evalCosetInterpolation` runs.

### Subgroup_bits extension (P2 part 2)

- `mle/tests/dump_coset_constants.rs::SUPPORTED_BITS`: `{1,2,3,4}` → `{1,2,3,4,5}`.
- `CosetInterpolationConstants.sol`: now has `SUBGROUP_5` / `WEIGHTS_5`.
- `CosetInterpolationVectors.sol`: now has `vector_k5_d4`, `vector_k5_d8`.
- `CosetInterpolationTest.t.sol`: dispatch table extended; unsupported-bits test
  switched to `bits=6` (was `bits=5`).
- Attacker subagent **independently verified** `SUBGROUP_5[1] = 64` is a primitive
  32nd root of unity in Goldilocks, and `WEIGHTS_5` entries are bit-exact with
  `1/Π_{i≠j}(x_j − x_i)` computed in Python.

### Why we cap at bits=5

`CosetInterpolationGate::num_wires() = 2·N + 4·num_intermediates + 9` where
`N = 2^subgroup_bits`. For `bits=5, degree=8`: num_wires = 89. For `bits=6`:
num_wires ≥ 169 — exceeds `standard_recursion_config`'s `num_wires = 135`. To
support `bits ≥ 6` the downstream consumer must use a wider config (e.g.
`CircuitConfig::wide_ecc_config` or a custom one); regeneration is mechanical
once that's settled.

### Note on mass fixture regeneration (audit LOW)

Regenerating `coset_recursive_verify.json` via the existing
`generate_and_verify_all_fixtures` test also rewrote the 6 pre-existing
fixtures because spongefish's `ProverState::new_std` seeds the prover RNG with
`from_entropy()`. The downstream commitment roots and FS challenges therefore
change run-to-run even when the circuit is unchanged. This is not a soundness
issue (proofs remain independently sound and verify on-chain), but is review
noise: 6 unrelated JSON files now show large diffs. If this becomes a CI
problem, a follow-up should plumb a deterministic seed through
`ProverState::new_std` for fixture regeneration.

### Files changed in this PR

- `mle/contracts/src/Plonky2GateEvaluator.sol` — dispatcher + 5 new helper functions, header rewritten
- `mle/contracts/src/CosetInterpolationConstants.sol` — new, auto-generated
- `mle/contracts/test/CosetInterpolationTest.t.sol` — new, 5 tests
- `mle/contracts/test/CosetInterpolationVectors.sol` — new, auto-generated
- `mle/src/fixture.rs` — emit `degree` for gate_id=13
- `mle/tests/dump_coset_constants.rs` — new, dumper
- `mle/tests/dump_coset_test_vectors.rs` — new, test-vector dumper
- `plonky2/src/gates/coset_interpolation.rs` — `with_max_degree` visibility `pub(crate)` → `pub`
- `tasks/coset_interpolation_port.md` — this file (plan + audit outcome)
