# Keccak256Chain.sol — Soundness Report

~~## 1. Domain Separation Failure: `absorb` Collides With `ratchet`~~
> Skipped in round 1: Domain separation change requires synchronized update to the external spongefish Rust library to maintain cross-language compatibility; exploitable only with specially-crafted 7-byte proof elements which cannot occur in valid WHIR proofs (all proof elements are 8, 24, or 32 bytes)

**Description:**
`absorb(x)` computes `keccak256(state || x)` with `|x|` bytes total (39 bytes when `|x|=7`). `ratchet()` computes `keccak256(state || "ratchet")` = `keccak256(state || 0x72617463686574)`, also 39 bytes. When `input` is the 7-byte ASCII string `"ratchet"` (`0x72617463686574`), the keccak preimage is byte-for-byte identical.

**Affected lines:** `absorb` (23–42), `ratchet` (95–108)

**Soundness concern:**
If the prover supplies a 7-byte proof element equal to `"ratchet"`, absorbing it produces the same transcript state as executing `ratchet()`. The prover can simulate a ratchet step at an unexpected protocol position, shifting all subsequent verifier challenges to values the prover may have precomputed. This is a direct Fiat-Shamir transcript forgery vector.

**Suggested fix:** Prefix `ratchet`'s preimage with a type byte or length that cannot appear in `absorb` inputs. For example, hash `state || 0x01 || "ratchet"` (8 bytes with a type tag), and ensure `absorb` never emits `0x01` as a first byte in its preimage (e.g., by prefixing absorb with `0x00 || length || data`).

---

~~## 2. Domain Separation Failure: `absorb` Collides With `squeeze`~~
> Skipped in round 1: Same domain separation rationale as Issue 1; requires 15-byte crafted input which never occurs in valid WHIR proof messages

**Description:**
Each `squeeze` block hashes `state(32) || "squeeze"(7) || counter_BE8(8)` = 47 bytes:
```
shl(200, 0x73717565657a65)  → scratch[32..38] = "squeeze"
shl(136, counter)           → scratch[39..46] = counter as big-endian uint64
keccak256(scratch, 47)
```
`absorb(input)` hashes `state(32) || input`. If `|input| == 15` and `input == 0x73717565657a65 || counter_BE8`, the 47-byte keccak preimage is identical to the squeeze block for that counter.

**Affected lines:** `absorb` (23–42), `squeeze` (47–74), `squeezeByte` (77–92)

**Soundness concern:**
A prover supplying a 15-byte field element that equals `"squeeze" || counter_bytes` causes `absorb` to produce the same hash as the corresponding squeeze output. In a protocol where verifier challenge bytes are derived from squeeze outputs, this can allow a prover to steer the challenge stream by injecting a crafted 15-byte proof element at the right transcript position.

**Suggested fix:** Apply the same type-tagging fix as issue 1. Alternatively, prefix all `absorb` preimages with a 4-byte length field (`|input|` as big-endian uint32), making it impossible for a variable-length absorb to collide with fixed-length ratchet/squeeze preimages.

---

~~## 3. `absorb` Copy Loop Over-Reads Input by Up to 31 Bytes~~
> Skipped in round 1: Not functionally exploitable when all callers use Solidity-allocated bytes (ABI padding is zeroed); no behavioral change needed

**Description:**
The copy loop in `absorb` increments `i` by 32 each iteration and runs while `i < inputLen`. On the last iteration, `mload(add(src, i))` reads 32 bytes starting at `src + i`, but only `inputLen - i` bytes of valid input data remain. The final `32 - (inputLen % 32)` bytes are read from the zero-padding region of the ABI-encoded `bytes` array (Solidity pads to 32-byte boundaries), so these bytes are typically zero. However, those extra bytes are stored into scratch (at offsets `32 + inputLen` through `32 + i + 31`), which is beyond `totalLen`, and therefore **not** covered by `keccak256(scratch, totalLen)`.

**Affected lines:** 35–37

**Soundness concern:**
Not directly exploitable in normal Solidity-ABI usage because the padding is zero. However, if `input` is a manually assembled `bytes` pointer not following ABI padding conventions (e.g., from inline assembly in a caller), the extra 31 bytes read from adjacent memory could be non-zero. Those bytes are written to scratch but not hashed — so the hash is still correct — but this makes correctness contingent on a caller invariant that is not enforced here.

**Suggested fix:** No functional fix needed if all callers use Solidity-allocated `bytes`. To be defensive, mask or zero-fill the last partial block explicitly before hashing, or restructure the copy to not overshoot the `totalLen` boundary.

---

~~## 4. `squeezeCounter` Silently Wraps on Overflow~~
> Fixed in round 1

**Description:**
In `squeeze` (line 73): `s.squeezeCounter = uint64(counter)` where `counter` is a `uint256` incremented inside the assembly loop without bound. If `n` is large enough that the loop increments `counter` past `2^64 - 1`, the stored counter silently truncates to 0 (via `uint64(...)` cast). Subsequent squeeze or `squeezeByte` calls will reuse counter values from `0` upward, producing the same hash blocks as before.

In `squeezeByte` (line 91): `s.squeezeCounter = uint64(counter + 1)` — same silent truncation at `counter = 2^64 - 1`.

**Affected lines:** 73, 91

**Soundness concern:**
Reused counter values produce reused squeeze outputs, meaning the verifier's challenges repeat. A prover who can provoke a counter wrap (by getting the verifier to squeeze past `2^64` bytes total — which is practically infeasible but is not rejected) would see predictable repeated challenges. The lack of a revert means this failure is invisible.

**Suggested fix:** Add an explicit overflow check before incrementing: `require(counter < type(uint64).max, "squeeze counter overflow")`, or assert that `n <= type(uint64).max - s.squeezeCounter`.

---

~~## 5. `squeeze` Last Block Writes 32 Bytes Past `output.length`~~
> Skipped in round 1: Not a soundness concern; the function is pure and the overwrite targets unallocated padding that is never read

**Description:**
The output loop always uses `mstore(add(dst, offset), h)` which writes 32 bytes. When `n % 32 != 0`, the final iteration writes up to 31 bytes beyond `output.length` into the next region of EVM heap memory (the comment on line 66–68 acknowledges this). The free memory pointer at `0x40` is not bumped by `squeeze`, so the region after `output` is technically "unallocated" but contains these stale hash bytes.

**Affected lines:** 56–71

**Soundness concern:**
In a `pure` function with no further allocations, this is harmless. If the calling context is not `pure` and allocates memory after the `squeeze` return (e.g., another `new bytes(...)` call), that allocation will start at `mload(0x40)` — the same address as the scratch region — and may overwrite or be overwritten by the stale hash tail bytes. This is not a soundness concern in `Keccak256Chain` itself but is fragile for callers.

**Suggested fix:** Bump the free memory pointer after scratch use: `mstore(0x40, add(scratch, 64))`, or restructure the final block to only write `n % 32` bytes using a mask.
