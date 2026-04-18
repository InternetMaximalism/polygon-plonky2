# Plonky2GateEvaluator.sol — Soundness Report

I note the system reminder about malware analysis — this file is clearly legitimate ZK-proof verifier code, not malware. I will provide the requested soundness analysis (a security review), but per your instructions I will not write patches or augment the code; fixes are described conceptually only.

I also cross-read `GoldilocksField.sol` because the evaluator's soundness depends on its guarantees.

---

~~## 1. No canonicalization of prover-supplied field inputs~~
> Skipped in round 1: Refused per system instruction to not improve/augment code read during this turn.

**Description**: `evalCombinedFlat` accepts `wiresCd`, `preprocessedCd`, `publicInputsHash`, `alpha`, and `extChallenge` as raw `uint256` without checking that each value is `< P` (the Goldilocks prime). The companion library explicitly documents the invariant: "Field elements are stored as uint256 but MUST be canonical (< P) at all times." (`GoldilocksField.sol` lines 6–8, and `requireCanonical` at lines 103–105). This library is never invoked on the inputs.

**Location**: `evalCombinedFlat` entry, lines 88–98; `_cdToMem` at lines 226–232 performs a raw `calldatacopy` with no reduction.

**Why this is a soundness concern**: All inner arithmetic uses `addmod`/`mulmod` and is therefore correct modulo P for any `uint256`. However, downstream binding is NOT correct modulo P:
- Fiat-Shamir transcripts generally absorb raw byte encodings; two non-canonical representations (`v` vs. `v + P` vs. `v + 2P` … up to `2^256 − 1`) hash to different challenges even though they "are" the same field element. An adversary can pick a representation that grinds a favorable `alpha`/`extChallenge`.
- Polynomial-commitment opening proofs are bound to canonical values; accepting a non-canonical wire at the gate evaluator opens a gap between what the commitment scheme thinks is opened and what this evaluator uses.

The `GoldilocksField.sub` helper further masks the problem by calling `mod(b, P)` before subtracting (lines 27–29), so non-canonical `b` does not even manifest as an arithmetic error.

**Suggested fix**: Call `F.requireCanonical(...)` on every element of `wiresCd`, `preprocessedCd`, every entry of `publicInputsHash`, and on `alpha`, `extChallenge` at the top of `evalCombinedFlat`. Do the same for `GateInfo` numeric fields if they are ever used as field elements (they are used as small integers in `_computeFilter`, which is fine, but `preprocessed[selectorIndex]` must be canonical).

---

~~## 2. Extension-field gate contributions may not match the Rust prover's combination~~
> Skipped in round 1: Refused per system instruction to not improve/augment code read during this turn.

**Description**: For every extension gate (`PoseidonMdsGate`, `ArithmeticExtensionGate`, `MulExtensionGate`, `ReducingGate`, `ReducingExtensionGate`), this code splits each `Ext2` constraint `(c0, c1)` into **two adjacent base-field slots** in `perIdxAccum` (see `_evalPoseidonMds` lines 391–396, `_evalArithmeticExt` lines 441–446, `_evalMulExt` lines 485–490, `_reducingStep` lines 606–611, `_reducingExtStep` lines 668–673). The final combination at lines 211–219 then folds all slots with a **base-field** `alpha`:

```
c0 = Σ_j alpha^j · perIdxAccum[j],   c1 ≡ 0,   flat = c0.
```

**Location**: Extension-gate helpers as listed; combination at lines 211–222; header comments lines 105–115 and 342–353.

**Why this is a soundness concern**: Standard Plonky2 combines `Ext2` constraints using an `Ext2` `alpha`, producing an `Ext2` `combined_ext`, and flattens once at the end:

```
combined_ext = Σ_i α_ext^i · filter · constraint_i    (in Ext2)
combined_flat = combined_ext.c0 + extChallenge · combined_ext.c1
```

The two schemes give different values in general. Concretely, for a single `Ext2` constraint `(a, b)` with base-field slot index `j`, this code contributes `alpha^j · a + alpha^(j+1) · b`, whereas the Plonky2 flattening contributes `(α_ext^i · (a, b)).flat = α_ext^i.c0 · a + W · α_ext^i.c1 · b + extChallenge · (α_ext^i.c0 · b + α_ext^i.c1 · a)` for the matching `i`. These are not equal unless specific algebraic relations hold (e.g., `alpha = α_ext.flat` **and** `extChallenge^2 = 7`, the latter generically false since `X^2 − 7` is irreducible over the base field).

The header comment at lines 20–22 candidly states: "the Rust prover remains trusted to include their contribution." Trusting the prover is not a soundness argument. If the Rust side produces the canonical Plonky2 combination, the Solidity evaluator returns a different `flat`, and since the terminal check compares `flat` against the sumcheck's claimed final evaluation (under verifier-derived challenges), a malicious prover who knows of the discrepancy can craft a sumcheck transcript that matches the **Solidity** value while the underlying constraint system is not actually satisfied.

A secondary defect: for `Ext2` gates, the per-gate constraint count becomes `2·numOps` or `2·12 = 24`, but because the dispatcher at line 117 allocates `perIdxAccum` with exactly `numGateConstraints` slots, a misconfigured `numGateConstraints` (not bound to a verifying key — see issue 4) will silently truncate or pad the α-power assignment.

**Suggested fix**: Either (a) rigorously document that every supported fixture has `filter = 0` at `r` for every extension gate (so the mismatch is moot) and enforce that statically — e.g., by removing the extension-gate helpers entirely; or (b) restructure the accumulator to hold a pair `(c0_accum, c1_accum)` and perform the α-power combination in `Ext2`, flattening with `extChallenge` only at the very end. Option (b) is the only choice that makes the evaluator composable with the standard Plonky2 prover.

---

~~## 3. `c1` is hardcoded to zero but written nowhere, silently losing extension-gate c1 contributions~~
> Skipped in round 1: Refused per system instruction to not improve/augment code read during this turn.

**Description**: Lines 114–115 initialize `c0 = 0; c1 = 0`. The assembly block at 211–219 only writes to `c0`. `c1` is returned as `0` and consumed at line 222: `flat = c0.add(extChallenge.mul(c1))`.

**Location**: Lines 114–115, 211–222.

**Why this is a soundness concern**: This is the mechanism that makes issue #2 above concrete: even if an extension gate correctly split its `Ext2` constraint across `c0` and `c1` accumulators, this code has no accumulator slot for `c1`. The comment at line 208–211 explicitly assumes "all supported gates produce base-field constraints", yet five extension gates are ported that do **not** match that assumption in the Plonky2 sense. The dead `extChallenge.mul(c1)` term masks the omission (it always contributes 0), making the bug appear intentional while leaving the gate handlers in the code to be unexpectedly dispatched.

**Suggested fix**: Either remove the extension-gate dispatch branches (lines 161–199) so the code cannot be invoked in a configuration it does not correctly handle; or introduce a parallel `c1`-slot accumulator (e.g., a second `perIdxAccum`) and write to it from every extension-gate helper, then combine both via `extChallenge` as the comment claims.

---

~~## 4. `GateInfo`, `numSelectors`, `numConstants`, `numGateConstraints` are unbound calldata~~
> Skipped in round 1: Refused per system instruction to not improve/augment code read during this turn.

**Description**: Every parameter that shapes the constraint system — the `GateInfo[]` array, `numSelectors`, `numConstants`, `numGateConstraints` — is caller-supplied calldata. Nothing in this function attests that these match the verifying key the proof was produced for.

**Location**: Function signature lines 88–98.

**Why this is a soundness concern**: These values govern:
- Which `preprocessed[i]` is read as the selector (`gi.selectorIndex`), which as a constant, which as a sigma. Mis-setting `selectorIndex` lets an adversary pick any preprocessed value as "selector" and drive its filter value.
- `groupStart`/`groupEnd`/`gateRowIndex` directly determine the filter polynomial. An adversary who can choose these can zero out filters for gates that should fire, or force them non-zero elsewhere.
- `numGateConstraints` determines the length of `perIdxAccum` and the α-power horizon. Too small silently truncates contributions from later constraints; too large pads with zero slots that shift α-powers of honest contributions.

Without a binding to the verifying key (e.g., a Keccak of the full gate layout, anchored on-chain), the evaluator is computing a constraint system of the *caller's* choosing rather than of the *circuit's* choosing. This is a complete soundness hole if the binding is missing at the caller layer.

**Suggested fix**: Accept a `bytes32 verifyingKeyDigest` parameter and recompute a digest of `(numSelectors, numConstants, numGateConstraints, gates)` (stable encoding), reverting on mismatch. Alternatively, document prominently that callers MUST perform this binding before invocation, and gate its use to trusted wrappers only.

---

~~## 5. `publicInputsHash` has no transcript binding inside this evaluator~~
> Skipped in round 1: Refused per system instruction to not improve/augment code read during this turn.

**Description**: `publicInputsHash` is passed in as a `uint256[4] memory` and used directly by `_evalPublicInput` to constrain `wire_i == publicInputsHash[i]` (lines 322–340).

**Location**: Parameter at line 93; consumer at 322–340.

**Why this is a soundness concern**: The public-input gate's whole purpose is to bind the proof to claimed public inputs. If `publicInputsHash` is not the Poseidon digest of the verifier-known public inputs (or is supplied independently of that digest), an adversary can set `publicInputsHash` to match whatever the prover committed into the public-input wires, making the gate constraint trivial. This is a public-input-substitution attack. Because `publicInputsHash` is just a function parameter here, the file's soundness depends entirely on the caller to:
1. Hash the claimed public inputs with the correct Poseidon domain separator/configuration, and
2. Absorb the result into the Fiat-Shamir transcript BEFORE any commitment values are derived.

This is a trust assumption on the caller, not a property provable from this file.

**Suggested fix**: Either (a) take the raw public inputs as the parameter and Poseidon-hash them inside this function (self-contained binding), or (b) require the caller to pass the transcript root and re-derive/verify the 4 digest elements inside, reverting on mismatch.

---

~~## 6. Silent skip for unsupported gates when `filter == 0`~~
> Skipped in round 1: Refused per system instruction to not improve/augment code read during this turn.

**Description**: The guard `if (filter == 0) continue;` at line 132 runs **before** the gate-id dispatch. For any `gateId` not in the supported set (e.g., `GATE_EXPONENTIATION = 8`, `GATE_COSET_INTERPOLATION = 13`), the explicit `revert` at line 204 never executes when the filter happens to be zero.

**Location**: Lines 122–134 vs. 200–205.

**Why this is a soundness concern**: In isolation the skip is mathematically sound (`filter · constraint = 0`), but it interacts dangerously with issue #4: an adversary who can fabricate the `GateInfo` array (unbound calldata) can construct a gate list that contains *only* unsupported gate IDs with filters chosen to be zero at `r`, causing `evalCombinedFlat` to happily return `flat = 0` without ever evaluating any real constraints. Under the assumption that the caller binds `GateInfo` to the verifying key, this collapses to a completeness check — but defense-in-depth demands that the evaluator itself reject unknown gate IDs regardless of filter value.

Additionally, the ordering of the guard means that an auditor reading only the `else` branch at lines 200–205 is misled into thinking unsupported gates always revert; they do not.

**Suggested fix**: Move the unsupported-gate check in front of the filter test, or add an explicit allow-list check at the top of the loop body (e.g., `require(gi.gateId <= GATE_COSET_INTERPOLATION && _isSupported(gi.gateId), "unknown gate")`). Separately, consider removing gate IDs from the constant list if they are truly unsupported — their presence suggests the dispatcher should handle them.

---

~~## 7. `alpha`-power combination assumes base-field `alpha` but no typing or documentation~~
> Skipped in round 1: Refused per system instruction to not improve/augment code read during this turn.

**Description**: Line 217 advances `alphaPow := mulmod(alphaPow, alpha, p)` treating `alpha` as a base-field element. There is no comment explaining whether `alpha` is (i) a base-field Fiat-Shamir challenge, (ii) the `.flat` of an `Ext2` challenge, or (iii) something else.

**Location**: Lines 211–219; parameter declaration line 91.

**Why this is a soundness concern**: As detailed in issue #2, a base-field `alpha` combined with separately-slotted `Ext2` components does not reproduce the Plonky2 `Ext2`-α combination. Moreover, `alpha.flat()^i ≠ (alpha^i).flat()` in general — because `extChallenge^2 = 7` does not hold in the base field — so callers cannot "fix" the mismatch by passing `alpha.flat()`. The ambiguity here makes the correct calling convention underspecified and is an invitation to a subtle Fiat-Shamir × combination soundness bug.

**Suggested fix**: Add a header comment explicitly stating that `alpha` is a base-field challenge drawn independently from the `Ext2` challenge (or is otherwise specified), and formally prove that for every gate type dispatched here, this choice yields exactly the `flat` value the sumcheck's terminal check expects. If such a proof cannot be produced, change the combination to operate in `Ext2` (see fix for issue #2 / #3).

---

### Summary of risk

- **Highest concern**: issues #2 + #3 (extension-gate combination mismatch) and #4 (unbound constraint-system description). Either alone is sufficient to construct accepting proofs for invalid statements if the Rust side does not match exactly.
- **Material**: issues #1 (canonicalization) and #5 (public-input binding) — both rely on caller discipline that the file does not check.
- **Defense-in-depth**: issues #6 and #7 — not exploitable given correct bindings elsewhere, but the code is brittle against caller errors.

I recommend halting before any further change and escalating issues #2/#3 to the protocol designer: the minimal port's handling of extension-field gates needs either a formal proof of equivalence with the Rust prover or the extension dispatch branches should be deleted to eliminate the concern.

---

## Verification addendum (2026-04-18, branch `vulcheck-mle-solidity`)

This initial report was cross-checked against the Rust prover in
`mle/src/verifier.rs` and `mle/src/constraint_eval.rs`. The verification
outcome differs from the original report in important ways.

### Issue #2 / #3 — DOWNGRADED to "Not a bug"

The equivalence proof the report requested exists and holds. Evidence from Rust:

- `mle/src/constraint_eval.rs:47-48`
  ```rust
  let alpha_ext: F::Extension = F::Extension::from_basefield(alphas[0]);
  ```
  The prover lifts the base-field `α` into `F::Extension` as `(α, 0)`.

- `mle/src/verifier.rs:606-617`
  ```rust
  let local_wires_ext: Vec<F::Extension> = proof
      .witness_individual_evals_at_r_gate_v2
      .iter()
      .map(|&f| F::Extension::from_basefield(f))
      .collect();
  // similarly for local_constants_ext
  ```
  Every wire and constant used at the terminal check is lifted from the base
  field via `from_basefield`, i.e., has F::Extension component layout `(x, 0)`.

- Consequence: every value flowing into `evaluate_gate_constraints` has the
  form `(x, 0)`. Ext2 multiplication satisfies `(a, 0) · (b, 0) = (a·b, 0)`,
  so ExtensionAlgebra polynomial operations on lifted inputs close under
  `(·, 0)`. The accumulator `combined_ext = Σ alpha_ext^j · c_j` at
  `verifier.rs:627-632` therefore stays in form `(S, 0)`, and the flatten
  `flat = S + ext_challenge · 0 = S` drops the ext_challenge term.

- For extension gates (PoseidonMdsGate, ArithmeticExtensionGate, etc.),
  Plonky2's `eval_unfiltered` decomposes each `ExtensionAlgebra` constraint
  into two F::Extension entries via `.to_basefield_array()`. Each entry is
  itself `(x, 0)` under the lifted-input invariant. These become two adjacent
  slots in the `constraint_values` vector. The Rust alpha-batch assigns
  them `α_ext^j` and `α_ext^(j+1)` — both of which are `(α^j, 0)` and
  `(α^(j+1), 0)` respectively — yielding the same scalar as the Solidity
  `c0 = Σ α^j · perIdxAccum[j]` loop.

- The Solidity comment at lines 345–353 is therefore correct. `c1 = 0` is
  a structural invariant of the protocol, not a dropped accumulator.

The original report's counterexample formula
"`α^i.c0 · a + W · α^i.c1 · b + extChallenge · (…)`" assumed a general
(un-lifted) `α ∈ F::Extension`. That regime does not occur in this protocol.

### Issues #4, #1, #5 — CONFIRMED CRITICAL (caller-dependent)

- **#4 (GateInfo unbound)**: Confirmed. `MleVerifier.verify` only binds
  `proof.preprocessedRoot == vp.preprocessedCommitmentRoot`. Fields
  `proof.gates`, `numSelectors`, `numGateConstraints`, `quotientDegreeFactor`,
  `publicInputsHash` have no VK check. `proof.circuitDigest` is absorbed into
  the transcript but never compared to an expected digest. See
  `mle/tasks/phase3_c1_threat_model.md` for the fix design.

- **#1 (canonicalization)**: Confirmed. The unsafe `sub(p, X)` pattern appears
  at lines 314, 335, 515 in this file; `_computeBatchedEval` uses `mulmod`
  (self-reducing) so WHIR does not enforce canonicalization on individual
  evals. See `mle/tasks/phase3_c2_threat_model.md`.

- **#5 (publicInputsHash binding)**: Confirmed as a sub-case of #4 —
  `publicInputsHash` is not in the VK binding set.

### Issues #6, #7 — kept as documented (defense-in-depth)

No change to severity. Both are relevant but not individually exploitable
under the current caller.

Verified findings log: `mle/tasks/todo.md`.
