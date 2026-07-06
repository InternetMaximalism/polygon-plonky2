/-
  Audit/Proofs/D3.lean — 段階3: 所見 D3 (inverse helpers 未束縛) の反例構成

  段階2最重要所見 D3 の形式的裏付け: witness/preprocessed の個別評価値には
  batch consistency 検査 (verifier.rs 5d/5e/5f) があるのに、inverse helpers
  (a_j, b_j) には対応する束縛が無い。よって inverse helper 評価値だけを
  差し替えても、witness batch consistency 等の検査は同一のまま通る 2 つの
  proof が存在する。

  注: これは「弱い版」(両者が RustVerifyAccepts 全体を満たすことまでは主張
  しない)。強い版 (両 proof が全検査を通り、片方のみ偽ステートメント) が
  Critical 確定の最終形。ここでは束縛の非対称性そのものを構成的に示す。
-/
import Audit.Impl.ImplStatements
import Audit.Proofs.SumcheckCore

namespace Audit.Proofs

open Audit
open Audit.RustImpl
open Audit.ImplStatements

variable {F : Type} [Field F]

/-- すべてのフィールドを既定値 (0 / [] ) にした基底 proof。 -/
def d3base : RustMleProof F where
  circuitDigest := []
  publicInputs := []
  publicInputsHash := []
  preprocessedRoot := []
  witnessRoot := []
  inverseHelpersRoot := []
  auxCommitmentRoot := []
  preprocessedBatchR := 0
  witnessBatchR := 0
  inverseHelpersBatchR := 0
  auxBatchR := 0
  beta := 0
  gamma := 0
  alpha := 0
  tau := []
  tauPerm := []
  lambdaInv := 0
  muInv := 0
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
  witnessIndividualEvalsAtRInv := []
  witnessEvalValueAtRInv := 0
  preprocessedIndividualEvalsAtRInv := []
  preprocessedEvalValueAtRInv := 0
  inverseHelpersEvalsAtRInv := []
  inverseHelpersEvalsAtRH := []
  witnessIndividualEvalsAtRGateV2 := []
  witnessEvalValueAtRGateV2 := 0
  preprocessedIndividualEvalsAtRGateV2 := []
  preprocessedEvalValueAtRGateV2 := 0
  numConstants := 0
  numRoutedWires := 0
  numWires := 0
  kIs := []
  subgroupGenPowers := []
  gSubEvalAtRInv := 0
  whirEvalProof := []

/-- **D3 反例の存在**: inverse helper 評価値のみが異なり (⇒ 片方は
    a_j = 0, 片方は a_j = 1)、witness/preprocessed の評価値と batch
    consistency は完全に一致する 2 つの proof が存在する。
    inverse helper 側にはこの consistency を課す検査が無いことが構成の鍵。 -/
theorem d3_substitutable : D3_inverse_helpers_substitutable_prop (F := F) := by
  refine ⟨{ d3base with inverseHelpersEvalsAtRInv := [0] },
          { d3base with inverseHelpersEvalsAtRInv := [1] }, ?_, rfl, rfl, ?_, ?_⟩
  · -- [0] ≠ [1]
    intro h
    injection h with h0 _
    exact Field.one_ne_zero h0.symm
  · -- batchedEval [] 0 = 0
    rfl
  · rfl

end Audit.Proofs
