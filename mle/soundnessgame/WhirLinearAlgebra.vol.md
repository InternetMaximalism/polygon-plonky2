# WhirLinearAlgebra.sol — Soundness Report

Now I have enough context. The `Ext3` struct stores components as `uint64`, meaning valid values are `[0, 2^64-1]`. Since `p = 0xFFFFFFFF00000001 = 2^64 - 2^32 + 1`, values in `[p, 2^64-1]` are valid `uint64`s but **unreduced** field elements — a range of `2^32 - 1 ≈ 4 billion` exploitable values.

---

~~## 1. `sub(p, r)` Underflows for Unreduced `uint64` Field Components, Corrupting All Arithmetic~~
> Fixed in round 1

**Description**

Throughout the library, the negation of an Ext3 component is computed as `sub(p, ri)` in inline assembly. This is only correct when `ri ∈ [0, p-1]`. Because the struct stores components as `uint64`, values in `[p, 2^64-1]` are representable (there are `2^32 - 1 ≈ 4.3 billion` such values). A malicious prover can craft proof-supplied `Ext3` elements with any component `r ≥ p`.

When `ri = p + k` for `k ≥ 1`, the EVM `sub` instruction wraps in 256-bit arithmetic:
```
sub(p, p+k) = 2^256 - k   (not in [0, p-1])
```
This 256-bit value is then consumed by `addmod` or `mulmod`. For example:
```
addmod(1, sub(p, r0), p)
```
evaluates to `(1 + 2^256 - k) mod p = (1 - k + 2^256 mod p) mod p`, which is **not** `(1 - r0) mod p = (1 - k) mod p`. The corruption silently propagates through every subsequent multiplication.

**Affected locations**

| Function | Lines |
|---|---|
| `mleEvaluateUnivariateFrom` | 54–55 |
| `mleEvaluateEqCanonical` | 137–138 |
| `mleEvaluateEq` | 204–205, 207–208 |
| `eqWeightsFrom` | 267–268 |
| `eqWeights` | 321–322 |

**Why this is a soundness concern**

Any function that receives proof-supplied `Ext3` values (e.g., committed polynomial evaluations passed to `dotProduct` or `mleEvaluateEq`) is vulnerable. A prover can set a single component to `p + 1` to shift the computed negation by an arbitrary non-zero field value `(2^256 mod p) - 1`, enabling a soundness break without triggering any revert.

**Suggested fix**

Reduce all loaded components before negating:
```solidity
// Instead of:
let omr1 := sub(p, r1)
let omr2 := sub(p, r2)

// Use:
r1 := mod(r1, p)       // or addmod(r1, 0, p) to force 256-bit mod
r2 := mod(r2, p)
let omr1 := sub(p, r1)
let omr2 := sub(p, r2)
```
Or add an explicit range check at the Solidity level before calling any assembly function, rejecting any `Ext3` whose components are `≥ p`.

---

~~## 2. Silent Length Truncation in `dotProduct`, `mleEvaluateEq`, and Related Functions Allows Partial-Check Bypass~~
> Fixed in round 1

**Description**

`dotProduct` (lines 356–357), `mleEvaluateEq` (lines 179–180), and `mleEvaluateUnivariateFrom` (lines 43–44) all silently iterate over `min(len_a, len_b)` elements when the two input arrays differ in length:

```solidity
let n := aLen
if lt(bLen, aLen) { n := bLen }  // silent truncation, no revert
```

No error is raised. The function returns a result computed over fewer variables than the protocol requires.

**Affected locations**

- `dotProduct`: lines 354–357
- `mleEvaluateEq`: lines 177–180
- `mleEvaluateUnivariateFrom`: lines 43–44 (via `start`/`point.length`)
- `mleEvaluateEqCanonical`: line 116

**Why this is a soundness concern**

In WHIR verification, `dotProduct(eqWeights, evaluations)` computes the inner product that checks the committed polynomial. If a malicious prover supplies an `evaluations` array shorter than `eqWeights`, the verifier sums only the first `m < n` terms. The omitted terms are treated as zero, which means the verifier accepts a polynomial that is incorrect on the remaining `n - m` evaluation points. An adversary can use this to fabricate a proof for a polynomial that satisfies the constraint only on a proper subset of the required domain.

**Suggested fix**

Assert equal lengths before proceeding. In the assembly blocks, add a revert on mismatch:

```solidity
// At the start of dotProduct assembly:
if iszero(eq(aLen, bLen)) { revert(0, 0) }
let n := aLen
```

The same guard must be added to `mleEvaluateEq`, `mleEvaluateUnivariateFrom`, and `mleEvaluateEqCanonical` (where `numVariables` must equal `evalPoint.length`).

---

~~## 3. `eqWeightsFrom` Reads Out-of-Bounds Memory When `start + count > arr.length`~~
> Fixed in round 1

**Description**

`eqWeightsFrom` (lines 240–293) uses `start` and `count` to slice `arr`, but performs no bounds check. The assembly loop at line 261 reads:

```assembly
let riPtr := mload(add(aData, mul(add(start, idx), 0x20)))
```

for `idx` in `[0, count)`. If `start + count > arr.length`, this reads beyond the end of the `arr` pointer table into adjacent EVM memory, which contains either zero-padding or other in-flight allocations from the same call frame.

**Affected location**

`eqWeightsFrom`, lines 260–264 (the outer loop body accessing `arr[start + idx]`).

**Why this is a soundness concern**

The `eqWeights` vector is a foundational input to the polynomial commitment check: `dotProduct(eqWeights, evaluations)` must equal the claimed MLE value. If the eq-weights are computed from garbage memory pointers instead of the intended challenge values, the inner product check is performed against an attacker-controlled or undefined polynomial, breaking both soundness and completeness. A caller that computes `start + count` from proof-supplied data without validating against `arr.length` will silently accept corrupted weights.

**Suggested fix**

Add an explicit bounds check before entering the assembly block:

```solidity
function eqWeightsFrom(
    GoldilocksExt3.Ext3[] memory arr,
    uint256 start,
    uint256 count
) internal pure returns (GoldilocksExt3.Ext3[] memory weights) {
    require(start + count <= arr.length, "eqWeightsFrom: out of bounds");
    // ... existing code
}
```

---

~~## 4. `mleEvaluateUnivariateFrom` Iterates Points in Reverse — Potential Prover/Verifier Mismatch~~
> Fixed in round 1

**Description**

The loop in `mleEvaluateUnivariateFrom` (lines 45–85) runs from `i = len` down to `i = start + 1`, pairing:

- `point[len-1]` with `x^(2^0) = x`
- `point[len-2]` with `x^(2^1) = x^2`
- `point[start]` with `x^(2^{len-start-1})`

This implements: `Π_{j=0}^{len-start-1} ((1 - point[start+j]) + point[start+j] · x^{2^{len-start-1-j}})`, which is the **reversed** pairing relative to the natural convention where `point[start]` pairs with `x^{2^0}`.

**Affected location**

`mleEvaluateUnivariateFrom`, lines 45–85.

**Why this is a soundness concern**

If the prover computes the univariate MLE using the natural (forward) pairing — `point[start]` with `x^1`, `point[start+1]` with `x^2`, etc. — while the verifier uses the reversed pairing, the two computations evaluate *different* polynomials. The verifier may accept a proof that is valid for the reversed polynomial but not for the intended one. This is a prover/verifier semantic mismatch that will not be caught by unit tests that use matching conventions on both sides.

**Suggested fix**

Verify that the point ordering here exactly matches the corresponding computation in the prover. If the intent is the reversed order, add an explicit comment such as:
```solidity
// SECURITY: Points are paired in reverse order (point[n-1] → x^1, ..., point[0] → x^{2^{n-1}}).
// This must match the prover's bit-reversal convention exactly.
```
If the ordering is incorrect, change the loop to iterate `i` from `start` upward, squaring `x` before each multiplication:
```assembly
for { let i := start } lt(i, len) { i := add(i, 1) } {
    // use point[i] with current x2i, then square x2i
}
```
