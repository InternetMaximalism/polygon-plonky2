# SpongefishWhirVerify.sol — Soundness Report

Now I have the full picture. Here is the analysis.

---

~~## 1. Unverified Merkle Leaf Data When Challenge Indices Collide~~
> Fixed in round 1

**Description.** `_sortAndDedupWithHashes` removes duplicate entries by index, keeping only the first occurrence's hash. Merkle verification then covers only those deduplicated hashes. However, `rowOffsets` is populated sequentially from `hints` *before* deduplication and is never deduplicated. When two challenge indices collide, both row offsets are used in the in-domain evaluation sum, but only the first occurrence's hash is Merkle-verified. The data read at the second row offset is completely unconstrained.

**Affected locations.**
- `_sortAndDedupWithHashes`: lines 556–572 (dedup logic)
- Standard path in `_openAndVerifyCommitment`: lines 794–818 (`rowOffsets` built sequentially; `rawLeafHashes` deduplicated but `rowOffsets` is not)
- Split-commit path in `_openSplitCommitments`: lines 839–860 (`perCommitRowOffsets[c]` retains all raw positions; only deduplicated hashes verified per commitment)
- Final-vector path in `_phaseFinalVectorAndMerkle`: lines 384–415

**Why this is a soundness concern.** A malicious prover can insert arbitrary bytes in `hints` at positions corresponding to second (and subsequent) occurrences of a colliding index. Those bytes feed directly into `_dotEqWithRow` → `_addOodAndInDomainToSum` → `vs.theSum`. By choosing the extra payload so that `theSum` satisfies the final claim equation for an invalid proof, the prover can make `_phaseFinalClaim` accept.

The prover cannot directly choose the challenge indices (they are squeezed from a Keccak-based sponge after the prover's commitments are fixed). However, the birthday-paradox collision probability for `k` queries over a domain of `N` leaves is `O(k²/N)`. For small domain sizes or larger query counts, this is non-negligible. More seriously, this removes an entire row of data from Merkle binding entirely: it is a structural break in the security argument regardless of probability.

**Suggested fix.** After sorting+dedup, build a lookup from deduplicated index → leaf hash. Then check that every `rowOffsets[i]` hashes to the leaf hash already verified for `rawIndices[i]` (post-sort):

```solidity
// After sort+dedup, build mapping: sortedIndex -> verifiedHash
// Then for each raw sample i, assert:
//   _keccak256At(hints, rowOffsets[i], o.rowBytes) == verifiedHashFor(rawIndices[i])
```

Alternatively, deduplicate `rowOffsets` alongside `rawLeafHashes` (combining the dot-product contributions of duplicates before hashing) so only verified data enters the sum.

---

~~## 2. `finalSize` Not Validated to Equal `2^finalSumcheckRounds`~~
> Fixed in round 1

**Description.** `_phaseFinalVectorAndMerkle` reads exactly `params.finalSize` elements into `finalVector` from the transcript (lines 352–356). `_foldEval` then folds that vector using `params.finalSumcheckRounds` rounds of halving (line 1040: `let half := shr(1, size)`). If `finalSize` is not exactly `2^finalSumcheckRounds`, the fold is incorrect: if `finalSize` is larger, trailing elements are silently discarded; if it is odd at any fold step, the last element is dropped without contributing to the output; if `finalSize < 2^finalSumcheckRounds`, the fold reads past the allocated array into adjacent memory.

**Affected locations.** Lines 352–356 (reading `finalVector`), lines 429–430 (calling `_foldEval`), line 1040 (`shr(1, size)`). There is no `require(params.finalSize == (1 << params.finalSumcheckRounds))` anywhere in the file.

**Why this is a soundness concern.** A prover submitting a malformed `finalSize` (or a verifier with misconfigured `params`) can cause `_foldEval` to evaluate a subset of `finalVector`. Trailing elements are committed to via the last-round Merkle tree (they influence leaf hashes) but do not contribute to `polyEval`. A prover can therefore embed arbitrary extra elements that shift the Merkle root without affecting the final claim check, potentially enabling a proof with a subtly different committed polynomial than the one being claimed.

**Suggested fix.**

```solidity
require(params.finalSize == (1 << params.finalSumcheckRounds),
    "finalSize must equal 2^finalSumcheckRounds");
```

---

~~## 3. Modular Bias in Challenge Index Sampling for Non-Power-of-2 Leaf Counts~~
> Fixed in round 1

**Description.** `_challengeIndicesUnsorted` (lines 527–554) computes `sizeBytes = ceil(log2(numLeaves) / 8)` and squeezes `count * sizeBytes` bytes, then maps each chunk to an index via `val % numLeaves`. When `numLeaves` is not a power of 2, the value space `[0, 256^sizeBytes)` does not divide evenly by `numLeaves`, so the resulting distribution is non-uniform. Lower-indexed leaves are more likely to be queried.

**Affected locations.** Lines 538 (`_ceilDiv(_log2(numLeaves), 8)`), line 552 (`val % numLeaves`).

**Why this is a soundness concern.** WHIR's soundness proof assumes the verifier samples query indices uniformly at random. Non-uniform sampling reduces the effective security parameter: a prover can concentrate their malicious deviation in under-sampled leaf positions. The bias magnitude depends on `numLeaves mod 256^sizeBytes` relative to `256^sizeBytes`. For `numLeaves = 2^k + 1`, the bias is `1 / (2^k + 1)` per favored index, which is small but nonzero, and breaks the proof's statistical security argument.

Note that intermediate round commitments have codeword lengths derived from folding, which may or may not be powers of 2 depending on the folding factor and initial parameters. There is no validation that `codewordLength` is always a power of 2.

**Suggested fix.** Use rejection sampling: draw candidate indices and discard any that fall in the biased tail region `[numLeaves * floor(2^bits / numLeaves), 2^bits)`:

```solidity
// Only accept val if val < (maxVal / numLeaves) * numLeaves
```

Alternatively, enforce `require(numLeaves & (numLeaves - 1) == 0, "numLeaves must be a power of 2")` and use a bitmask instead of modulo.

---

~~## 4. Missing Range Check on Prover-Supplied Field Elements Allows Non-Canonical Inputs~~
> Fixed in round 1

**Description.** The Goldilocks prime is `GL_P = 2^64 − 2^32 + 1 = 0xFFFFFFFF00000001`. Valid field elements must be in `[0, GL_P)`. `proverMessageField64x3` reads three `uint64` values (lines 210–212, 245–248, 329–331, 354–355). A uint64 can hold values in `[GL_P, 2^64 − 1]`, which are non-canonical representations of elements already in `[0, GL_P − 1]`. None of the prover-message reading paths check that received values are `< GL_P`.

**Affected locations.** All calls to `SpongefishWhir.proverMessageField64x3` and `SpongefishWhir.proverMessageField64x3`: throughout `_phaseSumcheck` (lines 245–246), `_receiveCommitmentsAndOod` (lines 210–212), `_doIntermediateRound` (lines 329–330), and `_phaseFinalVectorAndMerkle` (lines 354–355).

**Why this is a soundness concern.** The `_keccak256At` function (line 700) hashes raw bytes including non-canonical representations. A non-canonical value `v ≥ GL_P` has the same field element identity as `v − GL_P`, but its byte representation is different. Consequently:

1. The Merkle leaf hash is computed over the non-canonical bytes. The prover can provide a leaf containing `v ≥ GL_P` and it passes Merkle verification.
2. All arithmetic via `mulmod/addmod` correctly reduces `v mod GL_P`.
3. However, the Fiat-Shamir sponge absorbs the non-canonical byte encoding. Depending on whether the Rust prover also uses non-canonical encodings (it typically does not), the transcript diverges, producing a cross-implementation gap where a Solidity verifier accepts a proof the Rust verifier would reject, and vice versa.

More critically, if two distinct byte strings `v` and `v − GL_P` both hash to Merkle-valid leaves and represent the same field value, the binding of the commitment to a specific polynomial evaluation is weakened.

**Suggested fix.** After reading each `uint64` component, assert it is less than `GL_P`:

```solidity
require(c0 < GL_P && c1 < GL_P && c2 < GL_P, "non-canonical field element");
```
