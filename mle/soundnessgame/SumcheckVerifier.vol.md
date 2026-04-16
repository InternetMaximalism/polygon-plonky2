# SumcheckVerifier.sol — Soundness Report

~~## 1. [HIGH] Free memory pointer not restored on fullProduct==0 path AND fullProduct>0 path simultaneously~~
> Fixed in round 1
> **Severity: HIGH — Defensive dead code; not reachable after point < d check. Code simplification fix.**

**Description**: In `_evaluateRoundPoly` (lines 96-163), the free memory pointer (`mload(0x40)`) is read at line 96 and scratch space is used starting at `scratchStart`. The pointer is updated at line 120 (fullProduct==0 branch) and line 163 (fullProduct>0 branch). Both branches update `mstore(0x40, ...)`. This is correct because only one branch executes. However, if `fullProduct == 0` (which should be unreachable given the `point < d` early return), the zero-diff loop at lines 113-117 does not break — it iterates all `d` nodes and the last matching node's eval wins. This is functionally correct (there can be at most one zero diff for distinct integer nodes) but wasteful.

**Affected code**: Lines 110-121

**Why this is a soundness concern**: Not a direct soundness issue since the `point < d` check at line 86 catches all integer-node cases before the assembly block. The `fullProduct == 0` branch is defensive dead code.

**Suggested fix**: Remove the `iszero(fullProduct)` branch entirely since it cannot be reached after the `point < d` check. This simplifies the code and eliminates the dead path.

~~## 2. [HIGH] Lagrange interpolation gas cost scales quadratically with degree~~
> Skipped in round 1: Gas optimization only, not a soundness issue; the report itself states "Not a soundness issue"

**Description**: The Lagrange interpolation at lines 126-160 computes one Fermat inverse per evaluation node (O(d) inversions, each ~8K gas). For degree-2 round polynomials (d=3), this is ~24K gas per round. For higher-degree round polynomials (e.g., degree 8 for Poseidon), this would be ~72K gas per round.

**Affected code**: Lines 126-160

**Why this is a soundness concern**: Not a soundness issue, but a gas efficiency concern. The current implementation works correctly for all degrees.

**Suggested fix**: Use batch inversion (Montgomery's trick) to compute all inverses with a single Fermat exponentiation, reducing the cost to ~8K + O(d) mulmod per round.
