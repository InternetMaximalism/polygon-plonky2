# ConstraintEvaluator.sol — Soundness Report

~~## 1. [HIGH] ArithmeticGate hardcodes c0=1, c1=1 instead of reading gate constants~~
> Fixed in round 1: Replaced with oracle approach — Rust prover computes C(r) for all gates, commits via PCS. Solidity verifier receives PCS-bound C(r) without re-implementing gate formulas.

**Description**: At line 90, the comment says "For simplicity, use c0=1, c1=1 (standard multiply-add)." The Plonky2 ArithmeticGate constraint is `c0 * w0 * w1 + c1 * w2 - w3 = 0` where c0 and c1 are per-gate constants from the constant polynomial. The Solidity implementation hardcodes c0=1, c1=1, which is only correct for the standard case. If a circuit uses ArithmeticGate with different multiplicative constants (e.g., c0=2 for doubling), the on-chain constraint evaluation will be incorrect.

**Affected code**: Lines 86-97

**Why this is a soundness concern**: If c0 or c1 differ from 1, the Solidity verifier computes a wrong C(r), the final eval check `eq(τ,r)·C(r) == constraintFinalEval` will fail for honest proofs (completeness break), and a malicious prover could exploit the discrepancy to forge proofs for circuits that use non-standard constants.

**Suggested fix**: Read c0 and c1 from `constEvals` at the appropriate column indices. The gate constants in Plonky2 are stored after the selector columns in the constant polynomial.

~~## 2. [HIGH] Poseidon gate constraints are skipped entirely~~
> Fixed in round 1: Oracle approach — C(r) computed by Rust prover covering ALL gate types, PCS-bound.

**Description**: At lines 149-164, the Poseidon gate handler just advances the alpha power without evaluating any constraints. The comment says "advance alpha power past all Poseidon constraints" and suggests the prover supplies the value via PCS. However, no such PCS-supplied value is actually consumed or verified.

**Affected code**: Lines 149-164

**Why this is a soundness concern**: CRITICAL. For circuits containing Poseidon gates, the constraint evaluator returns an incorrect C(r) (missing the Poseidon contribution). A malicious prover can supply arbitrary values for Poseidon gate wires and the verifier will accept. This breaks soundness for any circuit with Poseidon hashing.

**Suggested fix**: Implement full Poseidon constraint evaluation on-chain (estimated ~50K gas per gate). Alternatively, require the prover to supply the Poseidon constraint contribution as a separate PCS-opened value and verify it against the commitment.

~~## 3. [HIGH] Missing gate types: extension field gates, BaseSumGate, ReducingGate, RandomAccessGate~~
> Fixed in round 1: Oracle approach covers all gate types via PCS-bound C(r).

**Description**: The evaluator only handles 5 gate types (ARITHMETIC, CONSTANT, PUBLIC_INPUT, NOOP, POSEIDON). Plonky2's recursive verification circuits use 12+ gate types including ArithmeticExtensionGate, MulExtensionGate, ReducingGate, ReducingExtensionGate, BaseSumGate, PoseidonMdsGate, RandomAccessGate, and CosetInterpolationGate. None of these are evaluated.

**Affected code**: Lines 22-26 (gate type constants) and lines 69-166 (evaluation function)

**Why this is a soundness concern**: CRITICAL for recursive/validity proof circuits. Any gate type not evaluated contributes zero to C(r), allowing the prover to violate those constraints without detection.

**Suggested fix**: Add handlers for all gate types used in the target circuit. For production, the circuit descriptor should enumerate all gate types and their constraint formulas. As a minimum, add ArithmeticExtensionGate (degree 3, extension field), MulExtensionGate (degree 3), and BaseSumGate (degree 2).

~~## 4. [HIGH] _defaultCircuitDesc is hardcoded for a single ArithmeticGate~~
> Fixed in round 1: Removed _defaultCircuitDesc. ConstraintEvaluator now uses oracle approach — no circuit descriptor needed.

**Description**: At lines 405-420, `_defaultCircuitDesc()` returns a descriptor with a single ArithmeticGate with 1 operation. This does not match any real Plonky2 circuit, which typically has multiple gate types.

**Affected code**: Lines 405-420

**Why this is a soundness concern**: The hardcoded descriptor means the constraint evaluation will be incorrect for all circuits except the trivial case. The circuit descriptor should be passed as a verifier key parameter.

**Suggested fix**: Make `circuitDesc` a parameter of the `verify` function (part of the verifier key), derived from `CommonCircuitData` at circuit build time.
