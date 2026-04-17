# MleVerifier.sol — Soundness Report

## Round 2 (vulcheck417): Deeper soundness audit and fixes

The findings from the second round of audit are merged here. Status legend:
- ✅ FIXED — implemented in `vulcheck417` branch
- ⚠️ PROTOCOL-LEVEL — gap acknowledged but not solvable at the Solidity layer
  alone; documented in code with a SECURITY NOTE

### ✅ Issue R2-#3 + R2-#7 [HIGH]: `whirEvals` ↔ proof eval values not bound
Previously `whirEvals` was an **external parameter** to `verify(...)`. WHIR
verifies the committed polynomial evaluates to `whirEvals[i]` at the sumcheck
point r, while the rest of the protocol uses `proof.*EvalValue`. With the two
desynced, an adversarial caller could pass `whirEvals` that pass WHIR but
disagree with the proof's other fields — breaking the entire binding chain.

**Fix**: moved `preprocessedWhirEval`, `witnessWhirEval`, `auxWhirEval` (Ext3)
into `MleProof`. They are now part of the same atomic object.

### ✅ Issue R2-#4 [HIGH]: `proverMessageField64x3` non-canonical encoding
`_leModReduce64` reduced raw bytes mod GL_P **before** the `< GL_P` check made
the check vacuous. The sponge absorbed the **raw** 24 bytes, allowing a prover
to use dual encodings of the same field element to steer Fiat-Shamir challenges.

**Fix**: read raw u64 LE values directly via inline assembly and check
`< GL_P` **before** any reduction (matching `proverMessageField64`).

### ✅ Issue R2-#5 [HIGH]: dead `proof.tau` field
`MleProof.tau` was a prover-supplied array that was never read, while the
verifier re-derived `tau` from the transcript. A footgun if anyone added a
check against it later.

**Fix**: removed `proof.tau` from `MleProof`. `tau` is exclusively
transcript-derived inside `verify()`.

### ✅ Issue R2-#8 [MEDIUM]: sumcheck round-poly degree upper bound missing
`SumcheckVerifier.verify()` rejected `evals.length < 2` but had no upper
bound, allowing higher-degree round polynomials with extra coefficient
freedom and weaker Schwartz-Zippel soundness (d/|F|).

**Fix**: added `maxDegree` parameter and `evals.length <= maxDegree + 1`
check. `MleVerifier` passes 2 (combined sumcheck of `eq · multilinear C̃` is
degree 2).

### ✅ Issue R2-#2 [CRITICAL] **FIXED in `vulcheck417`** — h̃(r) ↔ logUp formula

logUp permutation argument now uses auxiliary inverse-helper polynomials
`A_j(b) = 1/D_j^id(b)`, `B_j(b) = 1/D_j^σ(b)` committed via WHIR
(`commit_additional`, after β,γ are squeezed) and bound by two sumchecks:

- **Φ_inv** zero-check (round-poly degree 3):
  `Σ_b eq(τ_inv,b) · Σ_j λ^j · ( A_j·D_j^id − 1 + μ_inv · (B_j·D_j^σ − 1) ) = 0`
- **Φ_h** linear sumcheck (round-poly degree 1):
  `Σ_b H(b) = 0,  H(b) = Σ_j (A_j(b) − B_j(b))`

Terminal checks operate on PCS-bound multilinear values
(`a_j(r), b_j(r), w_j(r), σ_j(r), g_sub(r)`) — no `1/x` is ever
evaluated by the verifier, so MLE commutes with the formula and the
binding gap is closed.

WHIR PCS extended to support 3 evaluation points (`r_gate, r_inv, r_h`)
via `additionalEvaluationPoints[]` in `WhirParams`.

Rust + Solidity end-to-end: 54/54 Rust tests + 63/63 Solidity tests pass.

---

### 🔧 Issue R2-#1 [CRITICAL]: C̃(r) is PCS-bound but **not** bound to the
gate-constraint formula applied to wires.

A malicious prover can commit to `C̃ ≡ 0`. The combined sumcheck (claimed
sum = 0) trivially passes for the gate term and the final check
`eq(τ,r)·0 == 0` is satisfied — bypassing all gate constraints regardless
of the witness.

**Why this is NOT fixed by a single-point Solidity check**: for gates of
degree ≥ 2, `C̃_MLE(r) = Σ_b eq(b,r)·formula(w[b])` cannot be expressed
as `formula(w_MLE(r))` (e.g. ArithmeticGate `c0·w0·w1 + c1·w2 - w3`,
PoseidonGate degree 7). MLE does not commute with non-linear formulas.

**Required fix** (paper v2, §4.1): drop the standalone `C̃` commitment.
Run a zero-check sumcheck on `Φ_gate(x) = eq(τ,x)·Σ_j α^j·c_j(W(x),
const(x))` of round-poly degree `1 + d`. Terminal check uses PCS-bound
`w_j(r)`, `const_j(r)` directly via the existing Plonky2 gate evaluator
(`eval_unfiltered`). This requires extending the sumcheck prover to
evaluate the gate formula at multiple non-Boolean partial bindings per
round — a substantial change to the sumcheck infrastructure.

**Status**: deferred to next iteration (per user scoping decision). The
Rust v2 logUp fix above (Issue R2-#2) demonstrates the same architectural
pattern (commit auxiliary polynomials + zero-check sumcheck +
multilinear terminal check) and validates the v2 protocol approach
end-to-end.

The current Schwartz-Zippel-over-(β,γ) argument still bounds **honest-prover**
forgery to ≤ degree·num_routed_wires/|F| ≈ 2^{-60}, but does **not** prevent a
prover from committing to fake all-zero C̃ — hence the v2 redesign.

---

## Round 1 (mleintroduction)

## Architecture: Unified Split-Commit WHIR PCS

The verifier uses a single unified WHIR proof covering both preprocessed and witness
polynomials via the split-commit API:
- **Preprocessed** (constants + sigmas): commitment root fixed in VK (`preprocessedCommitmentRoot` parameter)
- **Witness** (wires): commitment root per-proof, absorbed into Fiat-Shamir transcript
- **Cross-term binding**: the unified proof includes cross-OOD evaluations binding both vectors

The VK binding check (`proof.preprocessedRoot == preprocessedCommitmentRoot`) prevents an attacker from
substituting fabricated constants/sigmas. A single WHIR session name
(`plonky2-mle-whir-split`) is used for domain separation. The split-commit API
produces per-vector Merkle roots while generating one combined proof.

`_derivePreprocessedBatchR()` uses a separate mini-transcript to deterministically derive the
preprocessed batching scalar from `circuitDigest`. This matches Rust's `derive_preprocessed_batch_r()`.

---

~~## 1. [HIGH] Permutation final evaluation (permFinalEval) is not verified against recomputed h(r)~~
> Fixed in round 1: Added `require(permFinalEval == proof.pcsPermNumeratorEval)` check. h(r_perm) is now a PCS-bound oracle value.
> **Severity: HIGH — Formal soundness gap; sumcheck's Schwartz-Zippel already bounds forgery probability to ≤ nd/|F| ≈ 2^{-60}, but oracle check is required for proof completeness.**

**Description**: At lines 123-124, `permChallenges` and `permFinalEval` are unused. The comment at lines 106-122 explains that the permutation sumcheck operates on a different random point than the constraint sumcheck, requiring a separate PCS opening. However, no separate PCS opening is performed. The permutation argument's soundness relies solely on the sumcheck structure + claimed_sum=0, without verifying the final evaluation against an oracle.

**Affected code**: Lines 103-124

**Why this is a soundness concern**: Without verifying `permFinalEval == h(r_perm)` via PCS-opened values, a malicious prover can submit round polynomials that satisfy g(0)+g(1)=0 at each round but whose final evaluation is arbitrary. The sumcheck structure alone does catch most attacks (by Schwartz-Zippel, the probability of forging consistent round polynomials is negligible), but the standard protocol requires the oracle check for formal soundness.

**Suggested fix**: Add a second PCS opening at r_perm for the wire/sigma MLEs, recompute h(r_perm) via `ConstraintEvaluator.evaluatePermutationNumerator()`, and verify `permFinalEval == h(r_perm)`.

~~## 2. [HIGH] pcsEvaluations are validated < P but not range-checked for count consistency~~
> Fixed in round 1: Added `require(proof.individualEvals.length == numWires + numConstants + numRoutedWires)`.
> **Severity: HIGH — Missing evaluations default to zero, enabling incorrect constraint evaluation C(r).**

**Description**: At lines 231-236, `individualEvals` elements are validated < P, and at line 340, `pcsEvaluations.length == 1 << n` is checked. However, there is no check that `individualEvals.length == numWires + numConstants + numRoutedWires`. A prover could submit fewer individual evals, causing array out-of-bounds (which Solidity handles as zero) or more evals (which are ignored but waste gas).

**Affected code**: Lines 146-156

**Why this is a soundness concern**: If `individualEvals.length < numWires`, the missing wire evaluations default to 0 (from the `new uint256[]` initialization). This could cause the constraint evaluation to produce an incorrect C(r) value, potentially allowing the prover to exploit the zero-padding.

**Suggested fix**: Add `require(proof.individualEvals.length == proof.numWires + proof.numConstants + proof.numRoutedWires)`.

~~## 3. [HIGH] Extension field constraint combination is not fully verified on-chain~~
> Fixed in round 1: Oracle approach — Rust prover computes flattened C(r) in extension field, commits via PCS. Solidity receives PCS-bound value. No extension field arithmetic needed on-chain.
> **Severity: HIGH — Soundness gap for circuits with extension field gates (CosetInterpolation, ArithmeticExtension); base-field-only evaluation misses c1 component.**

**Description**: At line 128, the extension-combine challenge is squeezed to advance the transcript, but the actual extension field combination (flattening D=2 components into a single base field value) is done by the Rust prover. The Solidity verifier's `ConstraintEvaluator.evaluateConstraints()` operates in the base field only and does not handle extension field constraint components.

**Affected code**: Lines 126-128, and ConstraintEvaluator.evaluateConstraints() which returns uint256 (base field)

**Why this is a soundness concern**: For circuits with extension field gates (CosetInterpolationGate, ArithmeticExtensionGate, etc.), the Rust prover flattens D=2 extension components via `c_0 + ext_challenge * c_1`. The Solidity evaluator computes only the base field component c_0 (since it doesn't implement extension field arithmetic). This is the same class of bug that was fixed in the Rust constraint_eval.rs — the Solidity side has not been updated to match.

**Suggested fix**: Either implement extension field arithmetic in the Solidity constraint evaluator, or require the prover to supply the D=2 constraint components separately and verify the combination with the ext_challenge on-chain.

~~## 4. [HIGH] Merkle tree odd-node duplication must match Rust implementation~~
> Skipped in round 1: Power-of-two length is enforced, so odd-node case only arises during internal tree construction. Duplication strategy matches Rust. No attack vector.
> **Severity: HIGH — No current attack vector; duplication matches Rust. Cross-language compatibility concern.**

**Description**: At line 317, when the number of nodes is odd, the last node is duplicated: `right = layer[2*i]` (same as left). The Rust `merkle_pcs.rs` uses the same strategy (`hash_pair(&chunk[0], &chunk[0])`), so they match. However, this is not explicitly tested in the compatibility tests.

**Affected code**: Line 317

**Why this is a soundness concern**: LOW. The duplication strategy matches Rust, and inputs are required to be power-of-two length, so odd cases only arise during internal tree construction (which always halves a power of two, giving even counts except for the final level). No real attack vector.

**Suggested fix**: Add a cross-language Merkle root compatibility test (Rust computes root, Solidity verifies same root).
