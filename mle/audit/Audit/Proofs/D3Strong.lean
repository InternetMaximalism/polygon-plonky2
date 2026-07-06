/-
  Audit/Proofs/D3Strong.lean — 段階3: 所見 D3 の**強い版**

  検証者を完全に (RustVerifyAccepts 全フィールド) 満たす 2 つの proof で、
  inverse helper 評価値のみが異なり、片方は正直な逆元 (a₀,b₀)=(1,1)、片方は
  不正な逆元 (a₀,b₀)=(0,2) を主張する — にもかかわらず両方が受理される。
  これは「検証者が不正な逆元を受理する = 置換引数の健全性破れ」の形式的確定。

  設計上の空隙 (D3): inverse helpers a_j,b_j には witness/preprocessed のような
  batch consistency 検査が無く、Φ_inv 終端の唯一の線形関係 a₀+b₀=2 しか
  課されない。よって (1,1) と (0,2) の 2 解が両方通る。

  構成: degreeBits=0 (全 sumcheck 空、終端 finalEval は 0 に強制)、
  numRoutedWires=1, β=γ=0, μ_inv=1, w₀=1 ⇒ Φ_inv 内側和 = (a₀−1)+(b₀−1)。
-/
import Audit.Impl.RustVerifier
import Audit.Proofs.SumcheckCore
import Audit.Algebra

namespace Audit.Proofs

open Audit
open Audit.RustImpl

variable {F : Type} [Field F]

/-- preprocessed batch_r の再導出値 (keccak 由来、preBatchROk を rfl にするため
    proof フィールドに一致させる)。 -/
def pbrVal (enc : U64Encoding) (fe : FieldEncoding F) (ko : KeccakSqueeze F) : F :=
  (squeezeChallenge enc ko
    (absorbFieldVec enc fe
      (domainSeparate enc { state := [], squeezeCounter := 0 } [0x70])
      ([] : List F))).1

/-- inverse helper 評価値 `ih` をパラメータとする proof。
    ih 以外はすべて固定 (degreeBits=0 の縮退した proof)。 -/
def mkP (enc : U64Encoding) (fe : FieldEncoding F) (ko : KeccakSqueeze F)
    (ih : List F) : RustMleProof F where
  circuitDigest := []
  publicInputs := []
  publicInputsHash := []
  preprocessedRoot := []
  witnessRoot := []
  inverseHelpersRoot := []
  auxCommitmentRoot := []
  preprocessedBatchR := pbrVal enc fe ko
  witnessBatchR := 0
  inverseHelpersBatchR := 0
  auxBatchR := 0
  beta := 0
  gamma := 0
  alpha := 0
  tau := []
  tauPerm := []
  lambdaInv := 0
  muInv := 1
  lambdaH := 0
  tauInv := []
  extChallenge := 0
  mu := 0
  tauGate := []
  combinedProof := []
  invSumcheckProof := []
  hSumcheckProof := []
  gateSumcheckProof := []
  sumcheckChallenges := []
  invSumcheckChallenges := []
  hSumcheckChallenges := []
  gateSumcheckChallenges := []
  auxConstraintEval := 0
  auxPermEval := 0
  auxEvalValue := 0
  preprocessedIndividualEvals := []
  preprocessedEvalValue := 0
  witnessIndividualEvals := []
  witnessEvalValue := 0
  witnessIndividualEvalsAtRInv := [1]
  witnessEvalValueAtRInv := batchedEval ([1] : List F) 0
  preprocessedIndividualEvalsAtRInv := [0]
  preprocessedEvalValueAtRInv := batchedEval ([0] : List F) (pbrVal enc fe ko)
  inverseHelpersEvalsAtRInv := ih
  inverseHelpersEvalsAtRH := [0, 0]
  witnessIndividualEvalsAtRGateV2 := [0]
  witnessEvalValueAtRGateV2 := batchedEval ([0] : List F) 0
  preprocessedIndividualEvalsAtRGateV2 := [0]
  preprocessedEvalValueAtRGateV2 := batchedEval ([0] : List F) (pbrVal enc fe ko)
  numConstants := 0
  numRoutedWires := 1
  numWires := 1
  kIs := [0]
  subgroupGenPowers := []
  gSubEvalAtRInv := gSubRecompute ([] : List F) []
  whirEvalProof := []

/-- 空 sumcheck は必ず (challenges=[], finalEval=0) で受理される。 -/
theorem emptyChecked (enc : U64Encoding) (fe : FieldEncoding F) (ko : KeccakSqueeze F)
    (t : RTranscript) :
    rustVerifySumcheckChecked enc fe ko (0 : F) 0 [] t = some ([], 0, t) := rfl

/-- 空 sumcheck の受理から finalEval = 0。 -/
theorem emptyFinal (enc : U64Encoding) (fe : FieldEncoding F) (ko : KeccakSqueeze F)
    {t t' : RTranscript} {fe0 : F}
    (h : rustVerifySumcheckChecked enc fe ko (0 : F) 0 [] t = some ([], fe0, t')) :
    fe0 = 0 := by
  rw [emptyChecked] at h
  injection h with h1
  injection h1 with _ h2
  injection h2 with hfe _
  exact hfe.symm

/-- Φ_inv 内側和は (a₀−1) + (b₀−1) に等しい (固定値の下で)。 -/
theorem invInner_val (enc : U64Encoding) (fe : FieldEncoding F) (ko : KeccakSqueeze F)
    (ih : List F) :
    invTerminalInner (mkP enc fe ko ih)
      = (ih.getD 0 0 - 1) + (ih.getD 1 0 - 1) := by
  simp only [invTerminalInner, mkP, fsum, fpow, Fin.val_zero, Nat.add_zero,
    List.getD_cons_zero, zero_mul, mul_zero, zero_add', add_zero, mul_one, one_mul]

/-- Φ_h 終端は 0 (inverse helper at r_h は両 proof 共通 [0,0])。 -/
theorem hPred_zero (enc : U64Encoding) (fe : FieldEncoding F) (ko : KeccakSqueeze F)
    (ih : List F) : hTerminalPred (mkP enc fe ko ih) = 0 := by
  simp only [hTerminalPred, mkP, fsum, Fin.val_zero, Nat.add_zero,
    List.getD_cons_zero, List.getD_cons_succ, sub_self, add_zero]

/-- 正直な逆元 (a₀,b₀)=(1,1): Φ_inv 内側和 = 0。 -/
theorem invInner_honest (enc : U64Encoding) (fe : FieldEncoding F) (ko : KeccakSqueeze F) :
    invTerminalInner (mkP enc fe ko [1, 1]) = 0 := by
  rw [invInner_val]
  simp only [List.getD_cons_zero, List.getD_cons_succ, sub_self, add_zero]

/-- 不正な逆元 (a₀,b₀)=(0,2): それでも Φ_inv 内側和 = 0
    (唯一の線形関係 a₀+b₀=2 を満たすため)。 -/
theorem invInner_forged (enc : U64Encoding) (fe : FieldEncoding F) (ko : KeccakSqueeze F) :
    invTerminalInner (mkP enc fe ko [0, 1 + 1]) = 0 := by
  rw [invInner_val]
  -- (0 - 1) + ((1+1) - 1) = 0
  show ((0 : F) - 1) + ((1 + 1) - 1) = 0
  rw [zero_sub, sub_def, add_assoc' 1 1 (-1), add_neg, add_zero, neg_add_cancel]

/-- 常に [] を返す gate evaluator (gateTerminal を 0 にするため)。 -/
def d3gev : GateEvaluator F := ⟨fun _ _ _ => []⟩

/-- 空の VK。 -/
def d3vk : RustVK F := ⟨[], []⟩

/-- **mkP は検証者を完全に満たす**(Φ_inv 内側和 = 0 を仮定)。 -/
theorem mkP_accepts (enc : U64Encoding) (fe : FieldEncoding F) (ko : KeccakSqueeze F)
    (ih : List F) (hlen : ih.length = 2)
    (hzero : invTerminalInner (mkP enc fe ko ih) = 0) :
    RustVerifyAccepts enc fe ko d3gev d3vk (mkP enc fe ko ih) 0 0 where
  digestOk := rfl
  preBatchROk := rfl
  preRootOk := rfl
  transcriptChallengesOk := trivial
  auxDecompOk := by simp [mkP]
  noLookup := trivial
  combinedSumcheckOk := ⟨⟨[], 0⟩, ⟨[], 0⟩, 0, emptyChecked enc fe ko _⟩
  invDegreeOk := fun _ h => nomatch h
  invSumcheckOk := ⟨⟨[], 0⟩, ⟨[], 0⟩, 0, emptyChecked enc fe ko _⟩
  hDegreeOk := fun _ h => nomatch h
  hSumcheckOk := ⟨⟨[], 0⟩, ⟨[], 0⟩, 0, emptyChecked enc fe ko _⟩
  gateDegreeOk := fun _ h => nomatch h
  gateSumcheckOk := ⟨⟨[], 0⟩, ⟨[], 0⟩, 0, emptyChecked enc fe ko _⟩
  whirOk := trivial
  preBatchOk := rfl
  witBatchOk := rfl
  witBatchRInvOk := rfl
  preBatchRInvOk := rfl
  preLenRInvOk := rfl
  invLenRInvOk := by simpa using hlen
  invLenRHOk := rfl
  witLenRGateV2Ok := rfl
  witBatchRGateV2Ok := rfl
  preLenRGateV2Ok := rfl
  preBatchRGateV2Ok := rfl
  genPowersLenOk := Nat.le_refl 0
  gSubOk := rfl
  combinedTerminalOk := by
    intro finalEval t t' h
    rw [emptyFinal enc fe ko h]; simp [eqEvalList, mkP]
  kIsLenOk := Nat.le_refl 1
  witLenRInvOk := Nat.le_refl 1
  invTerminalOk := by
    intro finalEval t t' h
    rw [emptyFinal enc fe ko h, hzero]; simp [eqEvalList, mkP]
  hTerminalOk := by
    intro finalEval t t' h
    rw [emptyFinal enc fe ko h]; exact hPred_zero enc fe ko ih
  gateTerminalOk := by
    intro finalEval t t' h
    rw [emptyFinal enc fe ko h]
    simp [eqEvalList, flattenExt, fsum, d3gev, mkP]

/-- 強い D3 の命題。 -/
def D3_strong_prop (enc : U64Encoding) (fe : FieldEncoding F) (ko : KeccakSqueeze F) : Prop :=
  ∃ (gev : GateEvaluator F) (vk : RustVK F) (p₁ p₂ : RustMleProof F),
    RustVerifyAccepts enc fe ko gev vk p₁ 0 0 ∧
    RustVerifyAccepts enc fe ko gev vk p₂ 0 0 ∧
    p₁.inverseHelpersEvalsAtRInv ≠ p₂.inverseHelpersEvalsAtRInv ∧
    p₁.witnessRoot = p₂.witnessRoot ∧
    p₁.witnessIndividualEvalsAtRInv = p₂.witnessIndividualEvalsAtRInv

/-- **強い D3(ソウンドネス破れの確定)**: 検証者を完全に満たす 2 proof で、
    片方は正直な逆元 (1,1)、片方は不正な逆元 (0,2) を主張し、witness は同一。
    検証者は両方を受理する ⇒ inverse helpers は PCS 束縛されておらず、置換
    引数の健全性が破れている。 -/
theorem d3_strong (enc : U64Encoding) (fe : FieldEncoding F) (ko : KeccakSqueeze F) :
    D3_strong_prop enc fe ko :=
  ⟨d3gev, d3vk, mkP enc fe ko [1, 1], mkP enc fe ko [0, 1 + 1],
   mkP_accepts enc fe ko [1, 1] rfl (invInner_honest enc fe ko),
   mkP_accepts enc fe ko [0, 1 + 1] rfl (invInner_forged enc fe ko),
   by intro h; injection h with h0 _; exact Field.one_ne_zero h0,
   rfl, rfl⟩

/-! ### 修正の妥当性: batch consistency 検査が gap を閉じる

    修正 (verifier.rs 5g/5h に `ensure! batchedEval(inv_evals, inv_batch_r) ==
    inverse_helpers_eval_value_at_r_inv` を追加) が d3_strong を不可能にする
    ことを示す。非退化な batch チャレンジ `r ≠ 1` の下で、正直な逆元 [1,1] と
    不正な逆元 [0,2] は**異なる** batched 値を与えるため、単一の WHIR 束縛値に
    両方が一致することはできない ⇒ どちらか一方は必ず新しい ensure! で弾かれる。 -/
theorem d3_fix_distinguishes (r : F) (hr : r ≠ 1) :
    batchedEval ([1, 1] : List F) r ≠ batchedEval ([0, 1 + 1] : List F) r := by
  -- batchedEval [1,1] r = 1 + r ;  batchedEval [0,1+1] r = r*(1+1) = r + r
  simp only [batchedEval, List.length_cons, List.length_nil, fsum, fpow,
    Fin.val_zero, Fin.val_succ, Nat.zero_add, List.getD_cons_zero,
    List.getD_cons_succ, mul_one, mul_zero, one_mul, zero_add', add_zero]
  -- goal (簡約後): 1 + r * 1 ≠ 0 + (r * 1) * (1 + 1) 相当 → 1 + r ≠ r + r
  intro h
  apply hr
  -- 1 + r = r*(1+1) = r + r  ⇒  1 = r
  rw [left_distrib', mul_one] at h
  -- h : 1 + r = r + r
  have : (1 : F) = r := by
    have h2 := congrArg (· + -r) h
    simp only at h2
    rw [add_assoc', add_neg, add_zero, add_assoc', add_neg, add_zero] at h2
    exact h2
  exact this.symm

end Audit.Proofs
