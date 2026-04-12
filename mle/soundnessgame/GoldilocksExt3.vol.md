# GoldilocksExt3.sol — Soundness Report

Now I have enough context. Let me write the analysis.

---

~~## 1. [CRITICAL] `inv` Silently Returns Zero for a Zero Element — No Revert~~
> Fixed in round 1
> **Severity: CRITICAL — Part of confirmed exploit chain: non-canonical zero (c0=P) bypasses isZero guard → inv(0)=0 → linearFormRlc=0 → WHIR final check trivially passes. Combined with issues #2, #3, #5 and SpongefishWhirVerify #4.**

**Description.** The `inv` function computes the inverse via Fermat's little theorem applied to the norm. If the input is the zero element, `norm = 0`, and the loop computes `0^(P-2) mod P = 0`, so `normInv = 0`. The function returns `(0, 0, 0)` — the zero element — instead of reverting.

**Affected code.** `GoldilocksExt3.sol:148–183`

```solidity
let base := mod(norm, p)   // base = 0 when α = 0
let e := sub(p, 2)
let result := 1
for {} gt(e, 0) {} {
    if and(e, 1) { result := mulmod(result, base, p) }  // immediately makes result=0
    ...
}
// result = 0 silently returned
```

**Why this is a soundness concern.** The caller in `SpongefishWhirVerify.sol:431–434` guards with `require(!isZero(polyEval))` before calling `inv`. This guard fails to catch a *non-canonical* zero: if `polyEval.c0 == P` (and `c1 == c2 == 0`), then `isZero` returns `false` (bitwise comparison, `P != 0`), the `require` passes, but `inv` still computes `norm = 0` and silently returns `(0,0,0)`. This sets `linearFormRlc = theSum * zero = zero`, making the final equality check at line 520 trivially satisfiable with `expectedRlc = 0`. Division by zero should be an unconditional revert inside `inv`.

**Suggested fix.** Add an explicit zero-check and revert at the top of `inv`:

```solidity
// Compute norm first, then revert if it is zero (zero element has no inverse)
require(!isZero(a), "GoldilocksExt3: inverse of zero");
```

Or, inside the assembly block, revert if `norm == 0` after computing it.

---

~~## 2. [CRITICAL] `isZero` and `eq` Use Bitwise Comparison, Not Field Equality~~
> Fixed in round 1
> **Severity: CRITICAL — Part of confirmed exploit chain: enables non-canonical zero (c0=P) to bypass isZero guard before inv(). See #1.**

**Description.** Both functions compare the raw `uint64` slot values:

```solidity
function isZero(Ext3 memory a) internal pure returns (bool) {
    return a.c0 == 0 && a.c1 == 0 && a.c2 == 0;
}
function eq(Ext3 memory a, Ext3 memory b) internal pure returns (bool) {
    return a.c0 == b.c0 && a.c1 == b.c1 && a.c2 == b.c2;
}
```

**Affected code.** `GoldilocksExt3.sol:34–36`, `38–40`

**Why this is a soundness concern.** The Goldilocks prime `P = 0xFFFFFFFF00000001` fits strictly inside a `uint64` (maximum `0xFFFFFFFFFFFFFFFF`). Any element with `c0 = P`, `c1 = 0`, `c2 = 0` represents the zero element in the field but passes `isZero` as non-zero. This is the exact condition that breaks the guard in front of `inv` (Issue 1). If any codepath — even `fromBase` — introduces values in `[P, 2^64-1]`, the guard is defeated. Similarly, `eq` can return `false` for two field-equal elements with different representatives.

**Suggested fix.** Normalize before comparing, or compare after subtracting:

```solidity
function isZero(Ext3 memory a) internal pure returns (bool) {
    uint256 P = 0xFFFFFFFF00000001;
    return (a.c0 % P) == 0 && (a.c1 % P) == 0 && (a.c2 % P) == 0;
}
```

Better: enforce that all `Ext3` values produced or accepted are already in canonical form `[0, P-1]` and add an invariant check in construction functions.

---

~~## 3. [CRITICAL] `fromBase` Accepts Out-of-Range `uint64` Values Without Canonicalization~~
> Fixed in round 1
> **Severity: CRITICAL — Part of confirmed exploit chain: entry point for non-canonical values [P, 2^64-1] into Ext3 arithmetic. See #1.**

**Description.** `fromBase` stores the raw `uint64` argument directly without checking `x < P`:

```solidity
function fromBase(uint64 x) internal pure returns (Ext3 memory r) {
    r.c0 = x;
}
```

**Affected code.** `GoldilocksExt3.sol:30–32`; called at `SpongefishWhirVerify.sol:966`.

**Why this is a soundness concern.** `uint64` can represent values up to `0xFFFFFFFFFFFFFFFF`, while `P = 0xFFFFFFFF00000001`. Values in `[P, 2^64-1]` — there are `2^32 - 2` such values — are representable as `uint64` but are non-canonical field elements. Specifically, if `x = P`, the resulting `Ext3` has `c0 = P`, which equals zero in the field but:
- `isZero` returns `false` (Issue 2)
- `inv` computes `norm = 0`, silently returns zero (Issue 1)

If `_glPow` (called at line 966) can return a value ≥ P — for instance if it performs non-reduced arithmetic — the resulting point will corrupt all downstream verification.

**Suggested fix.** Add a range check:

```solidity
function fromBase(uint64 x) internal pure returns (Ext3 memory r) {
    require(x < uint64(P), "GoldilocksExt3: value not in field");
    r.c0 = x;
}
```

---

~~## 4. [HIGH] `evalL0` Silently Returns Zero When `degreeBits >= 64` (Unsafe `uint64` Truncation)~~
> Fixed in round 1
> **Severity: HIGH — Currently dead code; exploitable only if a future caller passes degreeBits >= 64.**

**Description.** The denominator scalar `n` is computed as a `uint256`, then truncated to `uint64`:

```solidity
uint256 n = 1 << degreeBits;
Ext3 memory denominator = mulScalar(sub(x, one()), uint64(n));
```

**Affected code.** `GoldilocksExt3.sol:200, 203`

**Why this is a soundness concern.** If `degreeBits >= 64`, `1 << degreeBits` overflows `uint64` to 0 (Solidity does not check shift-induced overflow for unsigned types). `mulScalar(_, 0)` returns the zero element, `inv(zero)` returns zero (Issue 1), and `mul(numerator, zero)` returns zero — so `evalL0` silently returns `0` regardless of `x`. Any verification that relies on `evalL0(x, d) == 1` for `x = ω^0` (the first root of unity) would trivially fail to enforce the constraint if `degreeBits` is attacker-influenced or unexpectedly large. This function is currently dead code in the codebase, but represents a latent vulnerability for any future caller.

**Suggested fix.**

```solidity
require(degreeBits < 64, "GoldilocksExt3: degreeBits out of range");
uint64 nScalar = uint64(1) << uint64(degreeBits);
require(nScalar < uint64(P), "GoldilocksExt3: n exceeds field modulus");
Ext3 memory denominator = mulScalar(sub(x, one()), nScalar);
```

Also add an explicit `inv` zero-check (Issue 1) so a zero denominator (when `x == 1`, i.e., the coset root itself) reverts rather than silently returning a wrong answer.

---

~~## 5. [CRITICAL] `sub` Underflows in 256-bit Space for Non-Canonical Second Operands~~
> Fixed in round 1
> **Severity: CRITICAL — Part of confirmed exploit chain: non-canonical inputs produce (a - b + 2^32 - 1) mod P instead of (a - b) mod P, corrupting all downstream WHIR verification arithmetic. See #1.**

**Description.** The subtraction is implemented as:

```solidity
mstore(r, addmod(mload(a), sub(p, mload(b)), p))
```

**Affected code.** `GoldilocksExt3.sol:54–56`; same pattern in `neg` at lines 66–68.

**Why this is a soundness concern.** EVM `SUB` is 256-bit wrapping subtraction. If `mload(b) > p` — which can occur if `b.c0` is in `[P, 2^64-1]` (a non-canonical field element, see Issue 3) — then `sub(p, b.c0)` wraps to `2^256 + P - b.c0`, a huge 256-bit value. The subsequent `addmod` reduces this mod `P`:

```
(a + 2^256 + P - b) mod P = (a + (2^32 - 1) + P - b) mod P  [since 2^256 ≡ 2^32-1 mod P]
                          = (a - b + 2^32 - 1) mod P
```

This is **not equal to** `(a - b) mod P` in general, producing a wrong result. The correct answer requires `2^256 ≡ 0 mod P`, but `2^256 mod P = 2^32 - 1 ≠ 0`. So `sub` silently computes an incorrect field subtraction for any non-canonical second argument.

**Suggested fix.** Either enforce canonical inputs via `fromBase`/`fromBaseU256` (Issue 3) or add explicit normalization inside `sub`:

```solidity
// Normalize b components before negating
let b0n := mod(mload(b), p)
mstore(r, addmod(mload(a), sub(p, b0n), p))
```

Note: `sub(p, 0)` is handled correctly by `addmod` since `addmod(a, p, p) = a`. The normalization only needs to handle values in `(0, 2^64) \ [0, P)`.
