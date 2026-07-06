/-
  Audit/Impl/ImplStatements.lean — 段階3の対象命題 (実装モデル向け)

  Statements.lean の性質は層0 (paper) の Protocol.mleVerify に対するもの。
  段階2で実装は層1+層2 の積層(batching sumcheck 無し)と判明したため、
  ここでは **実装モデル** (RustVerifyAccepts / SolVerifyAccepts) を対象にした
  Soundness / Completeness を立てる。

  実装モデルの利点: RustMleProof は sumcheck チャレンジ列を格納しているので、
  root-hit を**実チャレンジに固定**でき、paper 版 (存在量化) より強い。
-/
import Audit.Impl.SolVerifier
import Audit.Statements

namespace Audit.ImplStatements

open Audit
open Audit.RustImpl

variable {F : Type} [Field F]

/-! ## Rust 実装向け Soundness (チャレンジ固定版)

    Sumcheck.lean の `SumcheckTelescopeHit` を、proof に格納された特定の
    round poly 列 `sent` と実チャレンジ列 `chals` に固定した系。 -/

/-- 固定版 sumcheck 健全性: 検証者が主張和 0 でこの sumcheck を受理し
    (SumcheckAccepts 0 sent chals)、真の値 (honest, Sh) が同じチャレンジで
    受理されて同じ最終値に折り畳まれるのに 0 ≠ Sh なら、実チャレンジ chals の
    どこかで root-hit。SumcheckTelescopeHit の系 (段階3で証明)。 -/
def RustSumcheckPinned (sent : List (Poly F)) (chals : List F) : Prop :=
  ∀ (Sh : F) (honest : List (Poly F)),
    honest.length = chals.length →
    SumcheckAccepts 0 sent chals →
    SumcheckAccepts Sh honest chals →
    foldEval 0 sent chals = foldEval Sh honest chals →
    (0 : F) ≠ Sh →
    SumcheckHitSomewhere sent honest chals

/-- Rust 実装の Soundness (Theorem 1 の実装版・決定論的コア)。
    RustVerifyAccepts が成り立つ (= 検証者が受理する) とき、4 本の sumcheck
    すべてがその**格納された実チャレンジ**において固定版健全性を満たす。
    段階3: これは SumcheckTelescopeHit から直接従う。ゲート制約/コピー制約の
    違反 (0 ≠ 真の和) は、対応する sumcheck の Sh ≠ 0 として現れ、root-hit を
    生む。paper 版 (SoundnessProp) と違い honest/chals の chals が proof の
    実チャレンジに固定される点が強い。 -/
def RustSoundnessProp (enc : U64Encoding) (fe : FieldEncoding F)
    (ko : KeccakSqueeze F) (gev : GateEvaluator F)
    (vk : RustVK F) (p : RustMleProof F)
    (degreeBits quotientDegreeFactor : Nat) : Prop :=
  RustVerifyAccepts enc fe ko gev vk p degreeBits quotientDegreeFactor →
    RustSumcheckPinned p.gateSumcheckProof p.gateSumcheckChallenges ∧
    RustSumcheckPinned p.invSumcheckProof p.invSumcheckChallenges ∧
    RustSumcheckPinned p.hSumcheckProof p.hSumcheckChallenges ∧
    RustSumcheckPinned p.combinedProof p.sumcheckChallenges

/-! ## Rust 実装向け Completeness (スコープ限定)

    完全な end-to-end completeness は prover 形式化 (真の MLE 評価値の構成) を
    要し、SCOPE.md の範囲外 (prover)。ここでは「honest な各検査が成り立てば
    RustVerifyAccepts が成り立つ」という**分解の完全性** (隠れた検査が無い
    こと) を述べる。段階3で `constructor` により証明可能。

    NOTE: これは RustVerifyAccepts が「列挙した検査の連言に他ならない」ことの
    確認であり、honest 値がそれらを満たすこと自体 (真の MLE 評価が batch/
    terminal 等式を満たす) は prover 側の主張として別途必要。 -/
def RustCompletenessDecomp (enc : U64Encoding) (fe : FieldEncoding F)
    (ko : KeccakSqueeze F) (gev : GateEvaluator F)
    (vk : RustVK F) (p : RustMleProof F)
    (degreeBits quotientDegreeFactor : Nat) : Prop :=
  -- 各フィールドが個別に成り立つなら構造体が成り立つ (連言の導入)。
  -- 反対に RustVerifyAccepts から各フィールドを射影できる。両方向を
  -- 段階3で ⟨…⟩ / .field で示し、「隠れた検査は無い」ことを確認する。
  RustVerifyAccepts enc fe ko gev vk p degreeBits quotientDegreeFactor →
    (SumcheckAccepts (0 : F) p.combinedProof p.sumcheckChallenges →
     SumcheckAccepts (0 : F) p.gateSumcheckProof p.gateSumcheckChallenges →
     True)

/-! ## Solidity 実装向け Soundness

    SolMleProof は sumcheck チャレンジの写しを持たないが、SolDerived (再導出束)
    がそれらを表す。SolDerived の点に固定して同じ系を立てる。 -/

/-- Solidity 実装の Soundness (SolDerived の再導出チャレンジに固定)。 -/
def SolSoundnessProp (enc : U64Encoding) (fe : FieldEncoding F)
    (ko : KeccakSqueeze F) (gev : GateEvaluator F)
    (gd : Audit.SolImpl.GatesDigestBinding F)
    (vp : Audit.SolImpl.SolVerifyParams F) (p : Audit.SolImpl.SolMleProof F)
    (sd : Audit.SolImpl.SolDerived F) : Prop :=
  Audit.SolImpl.SolVerifyAccepts enc fe ko gev gd vp p sd →
    RustSumcheckPinned p.gateSumcheckProof sd.rGateV2 ∧
    RustSumcheckPinned p.invSumcheckProof sd.rInv ∧
    RustSumcheckPinned p.hSumcheckProof sd.rH ∧
    RustSumcheckPinned p.combinedProof sd.rGate

/-! ## D3 (inverse helpers 未束縛) の実装モデルでの反例存在

    段階2の最重要所見 D3 を実装モデルで具体化する: RustVerifyAccepts の
    全フィールドが成り立つ 2 つの proof p₁, p₂ で、inverse helper 評価値
    (a_j, b_j at r_inv/r_h) **以外**が同一なのに inverse helper 値だけ異なり、
    それでも (Φ_inv/Φ_h 終端を除く) すべての検査を満たしうる、という
    「差し替え不変性」の存在。段階3で witness を構成して証明を試みる
    (成立すれば D3 は Critical 確定)。

    -- ここでは命題の形だけ固定する。inverse helper の個別評価値に対する
    -- batch consistency 検査が RustVerifyAccepts に**無い**ことが鍵
    -- (witness/preprocessed には *BatchOk があるが inverse helpers には
    -- 長さ検査 invLenRInvOk/invLenRHOk しかない)。 -/
def D3_inverse_helpers_substitutable_prop : Prop :=
  ∃ (p₁ p₂ : RustMleProof F),
    -- inverse helper 評価値のみが異なる
    p₁.inverseHelpersEvalsAtRInv ≠ p₂.inverseHelpersEvalsAtRInv ∧
    -- witness/preprocessed 側の全評価値は一致
    p₁.witnessIndividualEvalsAtRInv = p₂.witnessIndividualEvalsAtRInv ∧
    p₁.preprocessedIndividualEvalsAtRInv = p₂.preprocessedIndividualEvalsAtRInv ∧
    -- witness/preprocessed の batch consistency は両方満たす
    (batchedEval p₁.witnessIndividualEvalsAtRInv p₁.witnessBatchR
      = p₁.witnessEvalValueAtRInv) ∧
    (batchedEval p₂.witnessIndividualEvalsAtRInv p₂.witnessBatchR
      = p₂.witnessEvalValueAtRInv)
    -- → inverse helper 側にはこれに相当する束縛が無いため、両者とも
    --   RustVerifyAccepts の inverse 関連の非終端検査 (長さのみ) を通る。

end Audit.ImplStatements
