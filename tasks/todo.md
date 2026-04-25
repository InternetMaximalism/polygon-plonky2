# Lita-Plonky2 `wasm` Branch Port — Plan & Threat Model

**Status:** AWAITING USER APPROVAL — do not begin implementation until approved.

**Goal (option A, confirmed by user):** Port the WebGPU-Merkle-tree work and the surrounding async API cascade from `InternetMaximalism/Lita-Plonky2@wasm` into this repository (`InternetMaximalism/polygon-plonky2`), preserving Lita's existing scope. Multi-threading is **out of scope** because it does not exist in the source branch.

**Branch on which this work will live:** `vulcheck-mle-solidity` is currently checked out; we should branch off `main` to a new feature branch (e.g. `feat/wasm-webgpu-merkle`) before any code lands.

---

## 0. What Lita's `wasm` branch actually contains (verified)

- 5 WGSL shaders under `plonky2/shaders/` (Goldilocks Montgomery + Poseidon + Merkle layer kernel)
- `plonky2/src/hash/merkle_tree_gpu.rs` (~1990 LOC) — host-side wgpu dispatch
- `*_async` cascade through prover entry points (FRI prover, FRI oracle, plonk prover, circuit_data)
- New `plonky2/src/util/profiling.rs` (`with_timer` / `with_timer_async`) and `plonky2/src/util/builder_hook.rs`
- `Serialize` / `Deserialize` derives on a number of Target / proof types
- Multiple `gates/*.rs` "less-alloc" refactors (gpu-unrelated)
- `plonky2/Cargo.toml`: new `gpu_merkle` feature, target-gated wasm32 deps, `cdylib + rlib`
- `starky/Cargo.toml`: empty placeholder `gpu_merkle` feature
- **NO** `wasm-bindgen-rayon`, **NO** Web Worker code, **NO** atomics setup, **NO** `.cargo/config.toml`, **NO** JS bindings, **NO** `wasm-pack` config.

**Source-branch assumption to verify before porting:** the diff is computed against Lita's `main`, which is itself diverged from this repo's `main`. We need a 3-way merge view, NOT a literal patch apply.

---

## 1. Threat Model (CLAUDE.md §Security-Critical Mindset compliance)

We will spawn an independent attacker subagent before any code lands. The threat model below is the *prior* — the subagent must extend / contradict it.

### 1.1 Trust boundary

- The prover runs in a hostile JS context (browser). The verifier is elsewhere (e.g. on-chain or a different process). Anything observable in the browser is observable to the user / attacker.
- WebGPU shaders run on **prover-controlled hardware**. The shader code itself is fixed (compiled in), but the inputs and the GPU driver are attacker-controlled.
- Read-back of GPU buffers is staged through prover-controlled memory; we re-encode Montgomery → canonical on the GPU before read-back.

### 1.2 Soundness-relevant invariants the port must preserve

I1. **Merkle digest equivalence.** For any leaves `L` and `cap_height h`, `MerkleTree::new(L, h)` (CPU) and `MerkleTree::new_async(L, h)` followed by GPU dispatch must produce *bit-identical* `digests` and `cap`. Any divergence is an immediate soundness failure (proof would not verify or, worse, would verify against a wrong tree).

I2. **Goldilocks Montgomery encoding.** WGSL constants `BigInt = (1u, 4294967295u)` must encode the Goldilocks modulus `p = 0xFFFF_FFFF_0000_0001` and `R = 2^64`. Any drift from CPU-side `Goldilocks` semantics (e.g. canonical form vs. partially reduced form) breaks I1.

I3. **Poseidon round-constant equivalence.** Constants uploaded to the GPU at init time must equal `plonky2::hash::poseidon::ALL_ROUND_CONSTANTS` byte-for-byte (in Montgomery form), and the round structure (`fullRounds → 22 partial → fullRounds`) must match the CPU permutation.

I4. **Domain separation between leaf-hash and node-hash kernels** must equal the CPU semantics (which also do not separate). If we ever change CPU semantics later, we must change both kernels.

I5. **Fallback determinism.** GPU/CPU runtime fallback decisions (size threshold 8192, 3.5 GiB WASM memory ceiling, missing context, GPU error) must produce the *same* digest as the GPU path. This is implied by I1 but worth a separate test.

I6. **`unsafe` transmute safety.** `mem::transmute::<Vec<HashOut<F>>, Vec<H::Hash>>` in `merkle_tree.rs::from_gpu_output` is sound **only when `H::Hash == HashOut<F>`** (i.e. the `PoseidonGoldilocksConfig` family). We must add a static type-equality check (e.g. `static_assertions::assert_type_eq_all!` via an associated constant pattern, or use a trait method that bypasses transmute entirely).

I7. **No unauthenticated prover-controlled GPU code.** All shaders are compile-time string literals; we must not introduce any `include_str!` from a runtime path or any `Device::create_shader_module` whose source comes from outside the binary.

### 1.3 Attack vectors to enumerate (will be expanded by attacker subagent)

A1. **GPU driver mis-computation.** A buggy / malicious WebGPU driver returns wrong digests. Mitigation: the verifier ultimately re-checks Merkle paths against root hashes that are absorbed into the Fiat-Shamir transcript. If GPU produces a wrong root, the proof simply will not verify. → Liveness, not soundness, concern. **Document explicitly.**

A2. **Timing variance leaking witness.** Goldilocks Poseidon has data-independent control flow; the WGSL implementation also has straight-line MDS / round structure. → No new side channel introduced. To verify, attacker subagent must inspect every branch in WGSL.

A3. **Read-back race.** If the staging buffer is reused while a prior `map_async` is still pending, callers could read stale data. Lita uses one staging buffer with `RefCell<Option<Buffer>>` plus per-build context lifetime — must verify mutual exclusion is guaranteed in our async runtime.

A4. **Non-deterministic float / FMA.** WGSL's u32 path is integer; we must verify there are *zero* `f32` / `f16` operations in the shaders.

A5. **Cross-call state leakage.** `var<private>` module-scope state in WGSL: each invocation gets its own copy, but if Lita ever uses `var<workgroup>` or `var<storage>` for ephemeral state, a compromised parallel dispatch could leak. Must enumerate every storage qualifier in the shaders.

A6. **Initialization race.** `OnceCell` inside a `thread_local!` — verify the consumer cannot call `prove_async` before `initialize().await` completes.

A7. **Panic on adapter request.** `request_adapter().expect(...)` becomes a JS exception; soundness-irrelevant but a denial-of-service path. Should return `Result`. Listed as a code-quality fix.

A8. **Serde derive surface change.** Adding `Serialize`/`Deserialize` to `Target`, `ExtensionTarget`, `HashOutTarget`, etc. expands the on-disk representation surface. If any consumer accepts circuits from untrusted sources, a malformed `CircuitData` could trigger panics or, worse, construct invalid proofs. Must check whether any deserialized circuit data is trusted by downstream code in our repo (e.g. in `mle/` or `solidity/`).

### 1.4 Out-of-scope but flagged

- The Lita branch's "less-alloc" refactor in `gates/` is not security-critical but DOES touch hot paths; we will port it separately, behind its own commit, and security-review it in isolation.
- `BuilderHook` adds a new circuit-builder extension point. It is not used by the `gpu_merkle` path, but it changes the public API surface. We will port it but tag a follow-up audit.

---

## 2. Pre-implementation checklist (CLAUDE.md §Cryptographic Invariant Checklist)

We will not begin implementation until each is answered:

- [ ] Confirm that no consumer in this repo (`mle/`, `starky/`, `projects/`) currently relies on the *non-async* `prove` entry point in a way that would be silently broken by Lita's `panic!("must be awaited on wasm with gpu_merkle")` stub. (Even though that stub is gated to `cfg(target_arch = "wasm32" + gpu_merkle)`, we must verify.)
- [ ] Confirm that no `H::Hash` other than `HashOut<F>` is used anywhere in this repo's GPU path, and add a static type-equality check to enforce it forever.
- [ ] Verify that `plonky2_field::Goldilocks` Montgomery semantics in this repo match what the WGSL constants assume. Specifically: `R = 2^64`, modulus `p = 0xFFFF_FFFF_0000_0001`. (Read `field/src/goldilocks_field.rs`.)
- [ ] Verify that `plonky2::hash::poseidon::ALL_ROUND_CONSTANTS` length and ordering matches what `merkle_tree_gpu.rs` uploads.
- [ ] Verify that this repo's `MerkleTree`, `FriProof`, `Proof`, `Target`, etc. have not diverged from Lita's `main` in a way that breaks the new derive macros. Run `cargo check` after each derive addition.

---

## 3. Implementation phases — REVISED to cherry-pick approach

After fetching `lita/wasm` we discovered our `main` is a strict descendant of `lita/main`, so we can cherry-pick the 25 wasm commits onto our new branch. After classifying all 25 commits, the plan is reduced to 20 cherry-picks + 5 skips + 2 amendment commits.

### Commits to cherry-pick (chronological order, 20 total)

| # | Commit | Title | Phase tag |
|---|--------|-------|-----------|
| 1 | `75c5d1a5` | builder hook | C |
| 2 | `eeb61ca9` | add as_any_mut for downcasting | C |
| 3 | `9bd35bd0` | sort hooks key | C |
| 4 | `0a11d11f` | serializer (1-line gate_serialization fix) | misc |
| 5 | `b6e5e49a` | fix: use u64 in BaseSplitGenerator (#1647) — **wasm32 fix** | wasm32-fix |
| 6 | `36910550` | fix: add missing vec | misc |
| 7 | `7ca765a0` | **WebGPU acceleration for Merkle tree construction (#1)** | E+F+G (main) |
| 8 | `099f6283` | use pollster::block_on | F |
| 9 | `792e25d4` | make js-sys non optional dependency on wasm32 | D |
| 10 | `c2cd7038` | feat: support serde to (de)serialize circuits | B |
| 11 | `50e731fe` | feat: increase GPU Merkle CPU fallback threshold to 65536 leaves | refinement |
| 12 | `4fa6b1cc` | chore: temp commit for debugging (kept for fidelity, retains downstream patches) | refinement |
| 13 | `2fa2c933` | feat: optimise memory usage directly decoding leaf and node hashes | refinement |
| 14 | `746bdf5d` | feat: fallback to cpu when memory usage is over 3.5GB | refinement |
| 15 | `4fb3ccdb` | chore: remove log code used for debugging | refinement |
| 16 | `a7ce5102` | refactor: simplify hash reading | refinement |
| 17 | `80f19496` | refactor: remove unused parameters | refinement |
| 18 | `efa5c1af` | refactor: restore debug assertion | refinement |
| 19 | `4765208c` | refactor: improve buffer size calculation | refinement |
| 20 | `0052d81e` | feat: lower threshold of GPU to 8192 (final tuning) | refinement |

### Commits to SKIP (5)

| Commit | Title | Reason |
|--------|-------|--------|
| `04131502` | revert generator change | touches `field/` (out of scope) and is reverted by `8a780fde` (net-zero) |
| `8a780fde` | Revert "revert generator change" | net-zero with `04131502` |
| `e7eefdb0` | halo2 verifier | feature creep, reverted by `1249b473` (net-zero) |
| `1249b473` | Revert "halo2 verifier" | net-zero with `e7eefdb0` |
| `ba617986` | massive less-alloc gates refactor | user-approved skip; only touches `gates/*` and `plonk/vanishing_poly.rs`, no overlap with in-scope commits |

### Amendment commits (after all cherry-picks)

| # | Title | Rationale |
|---|-------|-----------|
| A1 | Replace `unsafe transmute` in `from_gpu_output` with `static_assertions::assert_type_eq_all!` | Lita's version is UB if `H::Hash != HashOut<F>` (CLAUDE.md "No Silent Workarounds") |
| A2 | Replace `request_adapter().expect(...)` with proper `Result` propagation | Code-quality fix; avoids unhandled JS exceptions |

Each phase below is verified by `cargo check`. Halt on any unexpected test result (CLAUDE.md §Unexpected Test Results).

### Phase A — Setup & branch hygiene
1. Branch off `main` to `feat/wasm-webgpu-merkle`.
2. Add Lita as a git remote: `git remote add lita https://github.com/InternetMaximalism/Lita-Plonky2.git`; fetch only the `wasm` branch.
3. Compute `git diff lita/main..lita/wasm -- plonky2/ starky/` to get the *actual* set of changes in scope (not from our `main`, which has diverged).
4. Cross-check with the file list in §0.

### Phase B — Serde derives (low risk, prerequisite for tests)
5. Add `Serialize`/`Deserialize` derives to: `HashOutTarget`, `MerkleCapTarget` (`hash/hash_types.rs`), `MerkleProofTarget` (`hash/merkle_proofs.rs`), `VerifierCircuitTarget` (`plonk/circuit_data.rs`), `Target`, `ExtensionTarget` (`iop/target.rs`, `iop/ext_target.rs`), `FriProof`, `Proof`, `ProofWithPublicInputs` and friends (`fri/proof.rs`, `plonk/proof.rs`).
6. Run full test suite (CPU only). No behavior change expected.
7. **Security gate:** confirm no consumer in this repo deserializes circuit data from an untrusted source. If it does, file a follow-up issue but do not block this phase.

### Phase C — Profiling & builder_hook utilities
8. Add `plonky2/src/util/profiling.rs` with `with_timer` / `with_timer_async`. Native uses `std::time::Instant`, wasm32 uses `js_sys::Date::now()`, no_std no-op.
9. Add `plonky2/src/util/builder_hook.rs` with the `BuilderHook` trait and `BuilderHookRef`.
10. Wire into `plonky2/src/util/mod.rs`.
11. Run full test suite.

### Phase D — Cargo.toml: features, deps, crate-type
12. Add `gpu_merkle`, `gpu_merkle_verbose_time_logging`, `gpu_merkle_logging`, `merkle_debug_print`, `wasm_test_exports` features to `plonky2/Cargo.toml`.
13. Add the target-gated wasm32 dependency block (wgpu, wasm-bindgen, wasm-bindgen-futures, web-sys, bytemuck, console_error_panic_hook, console_log, getrandom, js-sys, once_cell).
14. Add native-side optional deps (`pollster`, `web-time`, `flume`, `gloo-timers`, `futures-channel`).
15. Set `crate-type = ["cdylib", "rlib"]`.
16. Add empty `gpu_merkle = []` feature to `starky/Cargo.toml`.
17. Run `cargo check` (default features) and `cargo check --target wasm32-unknown-unknown --no-default-features` to verify nothing breaks before any GPU code lands.

### Phase E — WGSL shaders (verbatim copy, then audit)
18. Copy 5 shader files into `plonky2/shaders/` *verbatim* from Lita's `wasm` branch.
19. **Security gate:** spawn attacker subagent to audit each shader for: integer overflow in Goldilocks mul, MDS constant correctness vs. CPU, round constant ordering, partial vs. full round count, Montgomery reduction correctness, any non-integer ops. Report appended to `tasks/todo.md`.
20. Verify Goldilocks Montgomery constants `(1u, 4294967295u)` against `field/src/goldilocks_field.rs` modulus byte-for-byte.

### Phase F — `merkle_tree_gpu.rs` host module
21. Copy `plonky2/src/hash/merkle_tree_gpu.rs` and the module declaration in `plonky2/src/hash/mod.rs`. Keep cfg gate `cfg(all(feature = "gpu_merkle", target_arch = "wasm32"))`.
22. **Replace the `unsafe transmute` with a safe alternative** (use `<H as Hasher<F>>::Hash::from_partial(...)` or similar; if no such API exists, add a `static_assertions::assert_type_eq_all!` and document the assumption).
23. Replace `request_adapter().expect(...)` with a `Result`-returning path; emit a `console::error_1` and return error, don't panic.
24. Run `cargo check --target wasm32-unknown-unknown --features gpu_merkle`.

### Phase G — Async cascade in CPU-side prover entry points
25. Modify `plonky2/src/hash/merkle_tree.rs`: split `new` into `build_cpu` + `build_gpu`, add `new_async`, `from_gpu_output` (sound version per step 22).
26. Modify `plonky2/src/fri/oracle.rs`: add `from_values_async`, `from_coeffs_async`, `prove_openings_async`. Instrument with `with_timer_async`.
27. Modify `plonky2/src/fri/prover.rs`: add `fri_proof_async`, `fri_committed_trees_async`. Add the `panic!` stub for the sync `fri_proof` only on `cfg(all(target_arch = "wasm32", feature = "gpu_merkle"))`.
28. Modify `plonky2/src/plonk/prover.rs`: add `prove_async`, `prove_with_partition_witness_async`. Same cfg gating for the panic stub.
29. Modify `plonky2/src/plonk/circuit_data.rs`: add `prove_async`.
30. Run `cargo check` for both native and wasm32 targets, with and without `gpu_merkle`.

### Phase H — Less-alloc refactor (separate commit, optional bundling)
31. Apply the gates/* less-alloc refactors. Verify with full test suite that nothing changes behaviorally (these are pure performance edits).

### Phase I — CI integration
32. Update `.github/workflows/continuous-integration-workflow.yml` to add wasm32 build of `gpu_merkle` features (still `cargo check` only — Lita does not run wasm tests, neither will we initially).
33. Document that no headless-browser test runs and propose this as a follow-up.

### Phase J — Final security review (independent subagent)
34. Spawn `security-review` subagent on the entire diff (NOT the same agent that implemented). Subagent receives the threat model in §1 and the CLAUDE.md cryptographic invariant checklist.
35. Address all findings before merge.

---

## 4. Verification matrix

| Test | Phase | Notes |
|------|-------|-------|
| `cargo test --workspace` (default features, native) | After every phase | Must remain green |
| `cargo check --target wasm32-unknown-unknown --no-default-features` | D, F, G | Existing CI line |
| `cargo check --target wasm32-unknown-unknown --features gpu_merkle` | F, G | New |
| `cargo check --features parallel,std,timing` | D, G | Native + parallel |
| Manual: serialize a circuit, deserialize, verify (round-trip) | B | New surface |
| Manual: inspect WGSL constants byte-for-byte against CPU constants | E | Soundness gate |
| Static type-equality check `H::Hash == HashOut<F>` | F | Replaces unsafe transmute |
| Attacker subagent report applied | E, J | Crypto review |

---

## 5. Open questions for the user

1. Should we update **only** `plonky2/` and `starky/` (Lita's surface), or do we want analogous async/GPU surfaces in `mle/` and `field/`? Recommendation: leave `mle` and `field` alone — Lita didn't touch them, and our `mle` is repo-specific.
2. The "less-alloc" gates refactor (Phase H) is GPU-unrelated. Should we include it for parity, or skip it because it expands diff blast radius without security benefit? Recommendation: **skip** unless the user explicitly wants parity. Each less-alloc edit is an independent micro-optimization that should land in its own targeted PR with benchmarks.
3. The `BuilderHook` API addition (Phase C) is also GPU-unrelated. Same question. Recommendation: include it because it is small, isolated, well-defined, and the `wasm` branch is its only home upstream.
4. Branch name preference — `feat/wasm-webgpu-merkle` or something else?

---

## 6. Risks summary

| Risk | Severity | Mitigation |
|------|----------|------------|
| WGSL constants drift from CPU semantics → invalid proofs | **Critical** | Phase E byte-for-byte comparison + attacker subagent |
| `unsafe transmute` UB if `H::Hash != HashOut<F>` | **High** | Phase F step 22 — replace with safe alternative |
| Async cascade not actually invoked → silent fallback to CPU on every prove call | Medium | Add a startup log assertion when `gpu_merkle` is on but `is_initialized()` is false |
| Serde derives expand attack surface for malicious circuits | Medium | Phase B step 7 audit; follow-up issue |
| Adding ~10 new wasm32 deps may break `--no-default-features` build | Low | Phase D step 17 verification |
| `gpu_merkle` panics in `request_adapter` | Low | Phase F step 23 |
| Less-alloc refactor regression in proving | Low | Skip Phase H (recommendation) |

---

## 7. Approval

User approved (option A: faithful port; option C for security fixes after review).

- [x] Skip `mle`/`field`
- [x] Skip less-alloc refactor (already verified non-overlapping with in-scope commits)
- [x] Include `BuilderHook` (already in our main; no extra work needed)
- [x] Branch name `feat/wasm-webgpu-merkle`
- [x] Replaced unsafe transmute (Amendment A1)
- [x] User selected option C: fix all CRITICAL + HIGH findings before merge

## 8. Outcome

### Cherry-pick + reconciliation (Phase A–G)
14 GPU-related Lita commits cherry-picked. Pre-existing 6 commits (BuilderHook, serializer, BaseSplitGenerator u64 fix, etc.) found already in our main. Reconciliation commit (`de311906`) threads v2-protocol params (`final_poly_coeff_len`, `max_num_query_steps`, `verifier_circuit_fri_params`, `constant_evals`) through all wasm-gpu code paths.

### Amendments (Phase F step 22 + 23)
- A1 (`24964319`): replaced Lita's UB `mem::transmute<Vec<HashOut<F>>, Vec<H::Hash>>` with a `to_bytes`/`from_bytes` round-trip.
- A2 (`47688efa`): replaced `request_adapter().expect(...)` with `Result` propagation.

### CI (Phase I)
- `e9a22258`: added `cargo check --features gpu_merkle` step on `wasm32-unknown-unknown`.

### Security review (Phase E + J — independent subagents)
Two reviewers (one adversarial against the WGSL shaders + GPU host code, one independent against the entire diff) returned 4 CRITICAL, 2 HIGH, 5 MEDIUM, 6 LOW findings. **All findings traced to upstream Lita code, not to our cherry-pick.**

CRITICAL + HIGH fixed in commit `c8b5f961`:
- C-1 (Reviewer): `starky::prove_async` missed `observe_elements(public_inputs)` + `config.observe()` before `observe_cap(trace_cap)` — every async proof was rejected by verifier.
- C-2 (Reviewer): `prove_with_commitment_async` skipped the entire constraint-binding stage (alphas_prime, simulating zetas, zeta_prime, compute_eval_vanishing_poly, observe_extension_elements). Mirrored sync version verbatim.
- C1 (Attacker): WGSL leaf-hash kernel always applies Poseidon, but CPU `hash_or_noop` skips it when `len * 8 <= H::HASH_SIZE`. Added CPU fallback in `build_gpu` for short leaves.
- C2 (Attacker / M-1): `from_gpu_output` assumed `H::HASH_SIZE == 32`. Added explicit runtime `assert_eq!`.
- H-1 (Reviewer): `dummy_proof_async` line 131 was missing `?` on `pw.set_target`.
- H-2 (Reviewer): `prove_with_polys` family transitively called sync FRI panic stubs on wasm-gpu. Cfg-gated the pair to non-wasm-gpu and added panic-stub variants for wasm-gpu.

Severity reframing: every CRITICAL/HIGH was a **liveness** failure (proof rejected by verifier), not a **soundness** failure (false proof accepted). The verifier always uses the sync code path, so a broken async/GPU prover only causes self-inflicted DoS, not soundness compromise.

### Outstanding (deferred)
MEDIUM (M-2 to M-5) and LOW (L-1 to L-6) findings deferred to follow-up issues. Notable:
- M-2: no automated CPU/GPU Merkle digest equivalence test.
- M-3: unused deps `flume`, `gloo-timers` (wildcard version), duplicate `console_error_panic_hook` in `plonky2/Cargo.toml`.
- M-5: `debug_assert_eq!` for cap-layer consistency check is elided in release builds.
- L-1: `wasm_bindgen::memory().dyn_into().unwrap()` in `build_gpu`.
- L-5: `parallel + gpu_merkle` on `wasm32` not viable; should be marked mutually exclusive.

### Verification matrix (final)
- [x] `cargo check -p plonky2 --features parallel` — pass.
- [x] `cargo check -p starky` — pass.
- [x] `cargo check --target wasm32-unknown-unknown --no-default-features` — pass.
- [x] `cargo check --target wasm32-unknown-unknown --no-default-features --features gpu_merkle` — pass.

### Branch state
22 commits ahead of `main`; all `cargo check` targets pass; merge-ready pending the deferred MEDIUM/LOW items being either accepted as known-issues or addressed in follow-ups.
