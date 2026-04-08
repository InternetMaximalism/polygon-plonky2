# MleVerifier.sol — Soundness Report

## Architecture: Two-Commitment WHIR PCS

The verifier uses two separate WHIR polynomial commitments:
- **Preprocessed** (constants + sigmas): commitment root fixed in VK (`preprocessedCommitmentRoot` parameter)
- **Witness** (wires): commitment root per-proof, absorbed into Fiat-Shamir transcript

The VK binding check (`proofPreRoot == preprocessedCommitmentRoot`) prevents an attacker from
substituting fabricated constants/sigmas. Two distinct WHIR session names
(`plonky2-mle-whir-preprocessed` / `plonky2-mle-whir-witness`) prevent cross-protocol proof swapping.

`_derivePreprocessedBatchR()` uses a separate mini-transcript to deterministically derive the
preprocessed batching scalar from `circuitDigest`. This matches Rust's `derive_preprocessed_batch_r()`.

---

~~## 1. Permutation final evaluation (permFinalEval) is not verified against recomputed h(r)~~
> Fixed in round 1: Added `require(permFinalEval == proof.pcsPermNumeratorEval)` check. h(r_perm) is now a PCS-bound oracle value.

**Description**: At lines 123-124, `permChallenges` and `permFinalEval` are unused. The comment at lines 106-122 explains that the permutation sumcheck operates on a different random point than the constraint sumcheck, requiring a separate PCS opening. However, no separate PCS opening is performed. The permutation argument's soundness relies solely on the sumcheck structure + claimed_sum=0, without verifying the final evaluation against an oracle.

**Affected code**: Lines 103-124

**Why this is a soundness concern**: Without verifying `permFinalEval == h(r_perm)` via PCS-opened values, a malicious prover can submit round polynomials that satisfy g(0)+g(1)=0 at each round but whose final evaluation is arbitrary. The sumcheck structure alone does catch most attacks (by Schwartz-Zippel, the probability of forging consistent round polynomials is negligible), but the standard protocol requires the oracle check for formal soundness.

**Suggested fix**: Add a second PCS opening at r_perm for the wire/sigma MLEs, recompute h(r_perm) via `ConstraintEvaluator.evaluatePermutationNumerator()`, and verify `permFinalEval == h(r_perm)`.

~~## 2. pcsEvaluations are validated < P but not range-checked for count consistency~~
> Fixed in round 1: Added `require(proof.individualEvals.length == numWires + numConstants + numRoutedWires)`.

**Description**: At lines 231-236, `individualEvals` elements are validated < P, and at line 340, `pcsEvaluations.length == 1 << n` is checked. However, there is no check that `individualEvals.length == numWires + numConstants + numRoutedWires`. A prover could submit fewer individual evals, causing array out-of-bounds (which Solidity handles as zero) or more evals (which are ignored but waste gas).

**Affected code**: Lines 146-156

**Why this is a soundness concern**: If `individualEvals.length < numWires`, the missing wire evaluations default to 0 (from the `new uint256[]` initialization). This could cause the constraint evaluation to produce an incorrect C(r) value, potentially allowing the prover to exploit the zero-padding.

**Suggested fix**: Add `require(proof.individualEvals.length == proof.numWires + proof.numConstants + proof.numRoutedWires)`.

~~## 3. Extension field constraint combination is not fully verified on-chain~~
> Fixed in round 1: Oracle approach — Rust prover computes flattened C(r) in extension field, commits via PCS. Solidity receives PCS-bound value. No extension field arithmetic needed on-chain.

**Description**: At line 128, the extension-combine challenge is squeezed to advance the transcript, but the actual extension field combination (flattening D=2 components into a single base field value) is done by the Rust prover. The Solidity verifier's `ConstraintEvaluator.evaluateConstraints()` operates in the base field only and does not handle extension field constraint components.

**Affected code**: Lines 126-128, and ConstraintEvaluator.evaluateConstraints() which returns uint256 (base field)

**Why this is a soundness concern**: For circuits with extension field gates (CosetInterpolationGate, ArithmeticExtensionGate, etc.), the Rust prover flattens D=2 extension components via `c_0 + ext_challenge * c_1`. The Solidity evaluator computes only the base field component c_0 (since it doesn't implement extension field arithmetic). This is the same class of bug that was fixed in the Rust constraint_eval.rs — the Solidity side has not been updated to match.

**Suggested fix**: Either implement extension field arithmetic in the Solidity constraint evaluator, or require the prover to supply the D=2 constraint components separately and verify the combination with the ext_challenge on-chain.

~~## 4. Merkle tree odd-node duplication must match Rust implementation~~
> Skipped in round 1: Power-of-two length is enforced, so odd-node case only arises during internal tree construction. Duplication strategy matches Rust. No attack vector.

**Description**: At line 317, when the number of nodes is odd, the last node is duplicated: `right = layer[2*i]` (same as left). The Rust `merkle_pcs.rs` uses the same strategy (`hash_pair(&chunk[0], &chunk[0])`), so they match. However, this is not explicitly tested in the compatibility tests.

**Affected code**: Line 317

**Why this is a soundness concern**: LOW. The duplication strategy matches Rust, and inputs are required to be power-of-two length, so odd cases only arise during internal tree construction (which always halves a power of two, giving even counts except for the final level). No real attack vector.

**Suggested fix**: Add a cross-language Merkle root compatibility test (Rust computes root, Solidity verifies same root).
