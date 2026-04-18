# C1 Threat Model — GateInfo VK-binding fix

## 1. Asset under protection

Soundness of the Φ_gate terminal check:
```
gateFinal_claim ?= eq(τ_gate, r_gate_v2) · flat(gates, numSelectors, numConstants,
                                                numGateConstraints, wires(r_gate_v2),
                                                preprocessed(r_gate_v2),
                                                publicInputsHash, α, extChallenge)
```

The terminal check is the final witness-to-circuit binding in the MLE protocol.
If the formula `flat(·)` can be replaced with a formula of the prover's choosing
while preserving everything else, then a malicious prover can exhibit a witness
that satisfies a circuit DIFFERENT from the one the deployer intended, and the
verifier will accept.

## 2. Current bindings (what is already trusted)

From `MleVerifier.verify` (source `mle/contracts/src/MleVerifier.sol`):

| Value | Source | Binding |
|---|---|---|
| `proof.preprocessedRoot` | proof | `== vp.preprocessedCommitmentRoot` (L154) — VK-bound via deployer-supplied `VerifyParams` |
| `proof.circuitDigest` | proof | absorbed into transcript (L408); **no external VK check** |
| `proof.publicInputs` | proof | absorbed into transcript (L409) |
| `proof.witnessRoot` | proof | absorbed into transcript (L414); bound by WHIR to `witnessEvalValue*` |
| `proof.alpha, beta, gamma, mu, extChallenge, auxBatchR, …` | proof | verified equal to transcript squeeze (L417, 428, 439, …) |
| `vp.kIs, vp.subgroupGenPowers` | VerifyParams | deployer-supplied, used for g_sub consistency (L215) |
| `proof.gates` | proof | **UNBOUND** |
| `proof.numSelectors, numGateConstraints, quotientDegreeFactor` | proof | **UNBOUND** |
| `proof.publicInputsHash` | proof | **UNBOUND to the `publicInputs` field that IS absorbed** |
| `proof.numWires` (implicit via array lengths) | proof | **UNBOUND** |

The preprocessed polynomial (selectors/constants/sigmas) is VK-bound, but the
*interpretation* of that polynomial via the `gates[]` metadata is entirely in
the prover's hands.

## 3. Adversary model

- Computationally bounded, polynomial-time.
- Can choose any proof object satisfying the Solidity struct layout.
- Cannot break WHIR, Poseidon, sumcheck, or the Fiat-Shamir hash.
- Knows the deployer's `VerifyParams` (public on-chain).
- Has oracle access to run the Rust prover on any circuit / witness of their choosing.

## 4. Attack: Gate re-interpretation

### 4.1 Setup

Deployer has committed a VK for circuit `C_legit` whose preprocessed polynomial
commitment is `R = vp.preprocessedCommitmentRoot`. `C_legit` contains, say:
- row 0: `ConstantGate(numConsts=3)` with selector index 0
- row 1: `ArithmeticGate(num_ops=4)` with selector index 0
- row 2: `PoseidonGate` with selector index 1

### 4.2 Adversary's alternative interpretation

Adversary wants to prove statement `S` which is FALSE under `C_legit` but TRUE
under a different circuit `C_fake` that shares the preprocessed polynomial
values at every boolean input. The simplest example:

Take `C_fake` with the same selectors/constants/sigmas polynomial, but where
`gates[]` is permuted so that rows that were "Poseidon" under `C_legit` are
interpreted as `NoopGate` (no constraints). All gate positions whose filter can
be fabricated as 0 at the sumcheck output point `r_gate_v2` essentially remove
those constraints from the verification.

More potent attack: adversary chooses `gates[i].gateId` freely. Because the
`_computeFilter` result depends only on `gateRowIndex`, `groupStart`, `groupEnd`,
and the selector value `preprocessed[selectorIndex]`, the adversary can:

1. Pick any `gateId` from the supported set (GATE_NOOP gives zero constraints
   deterministically — but then the whole gate contributes nothing, weakening soundness).
2. Pick `selectorIndex` to point to a preprocessed slot whose value gives the
   desired `filter`.
3. Pick `groupStart`, `groupEnd`, `gateRowIndex` to control the filter polynomial's
   roots.

### 4.3 Why internal consistency still holds

The Φ_gate sumcheck's round polynomials are computed (by the prover) using
whichever formula `F' = Σ_j α^j · filter'_j · gate'_j.eval(…)` the adversary
chose. The verifier absorbs these round polynomials into the transcript and
derives `r_gate_v2` — all consistent with `F'`.

At the terminal check, the verifier re-invokes `Plonky2GateEvaluator.evalCombinedFlat`
with the SAME `proof.gates` that the prover used, so the re-computed `flat'`
matches the sumcheck claim `gateFinal`. The check `eq(τ,r)·flat' == gateFinal`
passes.

Meanwhile, the real circuit's `flat` at the prover's witness at `r_gate_v2`
would be non-zero, but the verifier never computes that — it only computes `flat'`.

### 4.4 Falsifiability criterion

The attack described above is **exploitable** iff:
(a) `proof.gates` is not verified against any VK-derived digest.
(b) The adversary's alternative `gates[]` can represent a valid constraint system
    for which the adversary has a satisfying witness.

(a) is true today — verified in Phase 1. (b) is trivially true: the adversary
can construct any circuit they want in Rust and run the real prover against it.

## 5. Proposed fix — option-A: `VerifyParams.gatesDigest`

### 5.1 Schema change

```solidity
struct VerifyParams {
    // ... existing fields ...
    bytes32 gatesDigest;   // keccak256 of canonical encoding of gate metadata
}
```

### 5.2 Canonical encoding

```
digest = keccak256(abi.encode(
    uint8 VERSION,                          // bump on layout change
    uint256 numWires,                       // derived from proof but bound here
    uint256 numSelectors,
    uint256 numConstants,
    uint256 numGateConstraints,
    uint256 quotientDegreeFactor,
    GateInfo[] gates                        // order-sensitive, must match prover
))
```

`numWires` is included because `witnessIndividualEvalsAtRGateV2.length`
determines how `wires` is sliced inside the gate helpers.

### 5.3 Verification step

Inside `MleVerifier.verify`, after existing VK binding at line 154, add:

```solidity
// Bind gate metadata to VK. Prevents gate-reinterpretation forgery.
bytes32 computed = keccak256(abi.encode(
    uint8(1),  // VERSION
    proof.witnessIndividualEvalsAtRGateV2.length,
    proof.numSelectors,
    proof.numConstants,
    proof.numGateConstraints,
    proof.quotientDegreeFactor,
    proof.gates
));
require(computed == vp.gatesDigest, "gates VK binding");
```

### 5.4 Deployer responsibility

The deployer computes `gatesDigest` off-chain from the Rust-side circuit data
and pins it into the on-chain verifier wrapper. A Rust helper should be added
at `mle/src/vk_digest.rs` that emits the digest in the exact byte layout the
Solidity side expects — with a Solidity-side unit test asserting the encoding
matches for a reference circuit.

### 5.5 Gas cost

`abi.encode` of a ~10–50 element `GateInfo[]` (each 6–9 bytes logical, padded
to slots) is dominated by calldata copy + keccak. Rough estimate: <10k gas for
typical circuits. Negligible vs the rest of verification.

## 6. Alternative — option-B: bind `proof.circuitDigest`

### 6.1 Schema change

```solidity
struct VerifyParams {
    ...
    uint256[4] expectedCircuitDigest;  // matches proof.circuitDigest[0..4]
}
```

### 6.2 Verification step

```solidity
for (uint256 i = 0; i < 4; i++) {
    require(proof.circuitDigest[i] == vp.expectedCircuitDigest[i], "circuit digest");
}
```

### 6.3 Implicit binding

Plonky2's `circuit_digest` is a Poseidon hash over the full gate layout
(`common_data.circuit_digest`). If binding `circuit_digest` transitively binds
`gates[]`, this is the cleaner fix: the Rust side already produces the digest.

### 6.4 Risk

The transitivity assumption — "Plonky2's circuit_digest fully determines the
GateInfo layout this evaluator uses" — must be verified. Specifically:
- Does Plonky2's circuit_digest cover `quotientDegreeFactor`, `numSelectors`,
  the exact `selectors_info` layout, and the gate ordering this Solidity port
  assumes (ascending by gate.degree())?
- Does it cover `publicInputsHash` semantics?

If YES, option-B is simpler. If NO, option-B is incomplete and we still need
option-A for the uncovered fields.

### 6.5 Open question — to resolve before implementing option-B

Read `plonky2/src/plonk/circuit_data.rs` for the `circuit_digest` construction
and confirm which fields are absorbed. Defer to a separate subagent analysis
if the answer is non-obvious from the source.

## 7. Recommended path

1. **Immediate**: implement **option-A** (explicit `gatesDigest`). It is the most
   conservative fix and does not depend on external Plonky2 invariants.
2. **Parallel**: analyze option-B's transitivity claim; if confirmed, the
   `gatesDigest` can be replaced with a circuit-digest check in a future version.

## 8. Non-goals for this fix

- Does NOT address C2 (input canonicalization). That is an orthogonal concern,
  addressed in `phase3_c2_threat_model.md`.
- Does NOT change the Φ_gate protocol math. Pure input-binding tightening.
- Does NOT break proof compatibility with honest provers that emit matching
  `gates[]` — their `gatesDigest` will equal the VK's by construction.

## 9. Residual risks

- Deployer off-chain error: if `gatesDigest` is mis-computed at deployment, no
  valid proof will verify (availability failure, not soundness failure). Mitigate
  with a deployment-time integration test that produces and verifies a real proof.
- Cross-version drift: if the Solidity `GateInfo` struct layout changes, every
  deployed `gatesDigest` becomes invalid. Mitigate with the `VERSION` byte in the
  encoding (already proposed) and a clear upgrade procedure.
- ABI-encoding ambiguity: `abi.encode` of a struct array is well-defined in Solidity
  but requires alignment with the Rust side's byte layout. Concrete test required.

## 10. Test plan (must be written before merging the fix)

1. Happy path: real circuit's `gates[]` + correct `gatesDigest` → verify passes.
2. Single-bit flip: modify one byte in `gates[0].selectorIndex` → `require(computed == vp.gatesDigest)` reverts.
3. Length mismatch: add/remove a `GateInfo` entry → reverts.
4. Cross-version: old `gatesDigest` against new `GateInfo` layout with bumped `VERSION` → reverts with clear error.
5. **Adversarial**: construct a witness satisfying circuit `C_fake ≠ C_legit` and submit with `C_fake`'s `gates[]` + `C_legit`'s `gatesDigest` → reverts.
6. Differential: same `gates[]` hashed in Rust and Solidity → identical digest.
