# SpongefishWhir.sol — Soundness Report

Now I have enough context. Here is my analysis of `SpongefishWhir.sol`:

---

~~## 1. `verifySumcheck` Operates Over the Base Field Instead of the Extension Field~~
> Skipped in round 1: verifySumcheck is dead code not called anywhere; full Ext3 refactor would be a significant protocol change; risk of introducing new bugs outweighs fixing unused code

**Description:** The function signature (line 263) accepts `uint64 sum` and returns `uint64 newSum`, meaning sumcheck is performed entirely in the 64-bit base field GF(p). However, WHIR operates over the cubic extension GF(p³). The sumcheck polynomial, its coefficients, and the running sum are all extension field elements. The actual verification in `SpongefishWhirVerify._phaseSumcheck` confirms this: it reads `c0`, `c2` as `Ext3` triples (lines 245–246), and propagates `theSum` as an `Ext3` value.

**Affected code:** Lines 258–286 (`verifySumcheck` function signature and loop body).

**Soundness concern:** If a caller uses `verifySumcheck` rather than the correct extension-field implementation, it verifies the wrong equation. The base-field `c1 = sum - 2*c0 - c2` is a projection of the true Ext3 constraint, not the actual constraint. A prover could produce values where the base field coordinate satisfies this while the extension field coordinates do not.

**Suggested fix:** Replace `uint64 sum` with `(uint64 s0, uint64 s1, uint64 s2)` and replicate the Ext3 sumcheck arithmetic from `SpongefishWhirVerify._phaseSumcheck`. Until that is done, `verifySumcheck` should revert unconditionally to prevent incorrect use.

---

~~## 2. Proof-of-Work Verification Is Silently Omitted~~
> Skipped in round 1: PoW verification requires protocol-level coordination with the Rust WHIR prover to determine the pow_bits configuration; cannot be implemented without knowing the exact PoW scheme used

**Description:** Lines 275–276 explicitly skip the PoW check with a `// TODO` comment. In WHIR and related FRI-based protocols, PoW provides additional soundness bits — typically 20–30 bits of grinding security. Without it, an adversary can attempt transcript manipulations that would otherwise be computationally infeasible.

**Affected code:** Lines 275–276 inside `verifySumcheck`.

**Soundness concern:** Any soundness bound claimed for the protocol assumes PoW is enforced. Removing it reduces the soundness error by a factor of up to `2^pow_bits`. Since this is a verifier function, a prover that skips the PoW entirely will still pass this check, giving an adversary that many extra "free" tries when searching for a cheating transcript.

**Suggested fix:** Implement PoW verification: squeeze a nonce from the transcript (as a `prover_hint`), then verify that `keccak256(sponge_state || nonce)` has the required number of leading zero bits. This must be done after the prover's round message but before squeezing the folding randomness.

---

~~## 3. Challenge Index Byte Assembly Is Big-Endian; Rust Uses Little-Endian~~
> Skipped in round 1: Cannot safely change byte-assembly order from BE to LE without cross-validating against the Rust prover convention; most existing test fixtures use sizeBytes=1 where the issue is invisible; risk of breaking valid test vectors

**Description:** In `challengeIndices` (lines 188–194), the squeezed bytes are assembled into an index value using left-shift accumulation:

```solidity
val = (val << 8) | uint256(uint8(entropy[i * sizeBytes + j]));
```

With `j` starting at 0, the first squeezed byte is placed in the most significant position — big-endian order. The spongefish/WHIR Rust implementation squeezes individual bytes via `verifier_message::<u8>()` and assembles them as a little-endian integer (first byte = LSB). For `sizeBytes = 2` and squeezed bytes `[0xAB, 0xCD]`: Rust produces `0xCDAB`, Solidity produces `0xABCD`.

**Affected code:** Lines 188–194 in `challengeIndices`.

**Soundness concern:** The verifier checks Merkle openings at indices it derives from the transcript. If those indices differ from the ones the prover prepared Merkle proofs for, all valid proofs fail (completeness break). More critically, a malicious prover who knows the Solidity verifier's incorrect index-derivation can craft a proof where the "wrong" indices happen to open to valid-looking leaves while the Merkle structure is actually broken at the correct indices. This is an exploit surface for selective Merkle forgery against the Solidity verifier specifically.

**Suggested fix:** Reverse byte order when assembling the index:

```solidity
for (uint256 j = 0; j < sizeBytes; j++) {
    val |= uint256(uint8(entropy[i * sizeBytes + j])) << (j * 8);
}
```

---

~~## 4. Non-Canonical Field Element Encodings Are Silently Reduced~~
> Fixed in round 1

**Description:** `proverMessageField64` (lines 81–94) and `proverMessageField64x3` (lines 117–125) decode prover-supplied field elements and apply `mod GL_P` without first checking whether the raw decoded value is in canonical range `[0, GL_P)`. In the 8-byte LE encoding, GL_P = `0xFFFFFFFF00000001` fits exactly in 64 bits. A prover can encode the value `0` as the 8 bytes `[0x01, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF]` (= GL_P in LE), which reduces to 0 but causes a different byte pattern to be absorbed into the Fiat-Shamir sponge.

**Affected code:** Line 92 (`mod(raw, 0xFFFFFFFF00000001)` in assembly) and lines 122–124 (`_leModReduce64(data, *, 8)` calls).

**Soundness concern:** The sponge absorbs the raw transcript bytes, not the reduced values. A malicious prover who sends non-canonical encodings causes the same field values to be used in the proof, but the derived challenges are computed from different absorbed bytes. This gives the prover a degree of freedom to steer challenge derivation — choosing between canonical and non-canonical representations to bias the transcript hash toward favorable challenges. This is a Fiat-Shamir malleability attack surface.

**Suggested fix:** After decoding, assert that the raw value is strictly less than GL_P:

```solidity
require(val < GL_P, "non-canonical field element");
```

For the assembly path in `proverMessageField64`, add a bounds check after the byte-swap and before the final `mod`.

---

~~## 5. Dead Code with Incorrect `2^256 mod P` Placeholder Reveals Dangerous Developer Confusion~~
> Fixed in round 1

**Description:** Inside `_leModReduce64` (line 312), a local variable is declared but never used:

```solidity
uint256 pow256modP = uint256(2) ** 64; // Simplified — need exact value
```

`2^64` is not `2^256 mod GL_P`. The correct value is `2^32 - 1 = 4294967295`, which is what `_pow256ModP()` returns and what is actually used on line 318. The comment explicitly acknowledges the placeholder is wrong.

**Affected code:** Line 312.

**Soundness concern:** The dead variable has no effect on execution today. However, its presence shows the developer was uncertain about the modular reduction constant when writing this function. The comment `// Simplified — need exact value` signals the function may have been deployed with the wrong constant at some point, or the uncertainty may affect related code paths. Any future refactor that accidentally wires up `pow256modP` instead of `_pow256ModP()` would silently produce wrong field element reductions for all 40-byte challenge squeezes, breaking every verifier challenge.

**Suggested fix:** Remove the dead variable entirely. Add a verifiable derivation comment near `_pow256ModP()` (already present at lines 328–335) and add a `require` or `assert` constant test.

---

~~## 6. `_sortAndDedup` Writes Into Free Memory Without Updating the Free Memory Pointer~~
> Fixed in round 1

**Description:** The inline assembly quicksort (lines 384–456) allocates a scratch stack by reading the current free memory pointer (`mload(0x40)`) and using that address as the stack base. It grows the stack upward by pushing lo/hi pairs (64 bytes each) but never updates the EVM free memory pointer at `0x40` before or after use.

**Affected code:** Lines 384–394, 431–440 (stack push operations).

**Soundness concern:** If any Solidity-managed allocation (a `new` expression, a function returning a dynamic type, or a `keccak256` with a dynamic-length input) occurs after the `mload(0x40)` call but before `_sortAndDedup` returns, Solidity will read the stale free memory pointer and allocate its memory at the same address the sort stack is using, silently corrupting the sort stack mid-operation. In the current call graph this does not happen because `_sortAndDedup` is called last in `challengeIndices` with only inline assembly thereafter. However, this is a latent memory corruption bug: any future code change that adds an allocation after the sort stack is claimed will corrupt the array being sorted, producing silently wrong challenge indices. Incorrect challenge indices allow a prover to selectively open Merkle paths for indices the verifier does not actually query.

**Suggested fix:** Before entering the sort, save the stack end address and update the EVM free memory pointer to point past the scratch area:

```solidity
let stackEnd := add(stackBase, mul(64, 128)) // e.g., 128 levels × 64 bytes
mstore(0x40, stackEnd)
```

Restore or leave the pointer updated after the sort completes.
