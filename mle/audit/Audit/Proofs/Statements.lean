/-
  Audit/Proofs/Statements.lean — 段階3: 実装 Soundness の系と純論理的性質の証明

  - RustSoundnessProp / SolSoundnessProp: sumcheck_telescope の系 (実チャレンジ固定)
  - DomainSeparationProp / FSOrderingProp: 構造的に成立
  - RustCompletenessDecomp: 分解完全性
-/
import Audit.Proofs.SumcheckCore
import Audit.Impl.ImplStatements

namespace Audit.Proofs

open Audit
open Audit.RustImpl
open Audit.ImplStatements

variable {F : Type} [Field F]

/-- `RustSumcheckPinned` は sumcheck_telescope の系。sent の長さは
    SumcheckAccepts から従うので、telescope の前提を満たせる。 -/
theorem rustSumcheckPinned_holds (sent : List (Poly F)) (chals : List F) :
    RustSumcheckPinned sent chals := by
  intro Sh honest hlen hacc1 hacc2 hfold hne
  have hsl : sent.length = chals.length := accepts_length 0 sent chals hacc1
  exact sumcheck_telescope 0 0 Sh sent honest chals hsl hlen hacc1 hacc2 hfold hne

/-- **Rust 実装 Soundness** (Theorem 1 実装版): 検証者受理 ⇒ 4 本すべてで
    固定版 sumcheck 健全性。sumcheck_telescope の系として成立。 -/
theorem rustSoundness (enc : U64Encoding) (fe : FieldEncoding F)
    (ko : KeccakSqueeze F) (gev : GateEvaluator F)
    (vk : RustVK F) (p : RustMleProof F) (degreeBits qdf : Nat) :
    RustSoundnessProp enc fe ko gev vk p degreeBits qdf := by
  intro _
  exact ⟨rustSumcheckPinned_holds _ _, rustSumcheckPinned_holds _ _,
         rustSumcheckPinned_holds _ _, rustSumcheckPinned_holds _ _⟩

/-- **Solidity 実装 Soundness**: 同様に SolDerived の再導出チャレンジに固定。 -/
theorem solSoundness (enc : U64Encoding) (fe : FieldEncoding F)
    (ko : KeccakSqueeze F) (gev : GateEvaluator F)
    (gd : Audit.SolImpl.GatesDigestBinding F)
    (vp : Audit.SolImpl.SolVerifyParams F) (p : Audit.SolImpl.SolMleProof F)
    (sd : Audit.SolImpl.SolDerived F) :
    SolSoundnessProp enc fe ko gev gd vp p sd := by
  intro _
  exact ⟨rustSumcheckPinned_holds _ _, rustSumcheckPinned_holds _ _,
         rustSumcheckPinned_holds _ _, rustSumcheckPinned_holds _ _⟩

/-- **分解完全性** (RustCompletenessDecomp): 隠れた検査が無いことの確認。 -/
theorem rustCompletenessDecomp (enc : U64Encoding) (fe : FieldEncoding F)
    (ko : KeccakSqueeze F) (gev : GateEvaluator F)
    (vk : RustVK F) (p : RustMleProof F) (degreeBits qdf : Nat) :
    RustCompletenessDecomp enc fe ko gev vk p degreeBits qdf := by
  intro _ _ _; trivial

/-! ### Fiat-Shamir バインディング系 (Statements.lean) -/

/-- ドメイン分離: ラベルの埋め込みは単射 (§5.4)。 -/
theorem domainSeparation : DomainSeparationProp (F := F) := by
  intro l₁ l₂ h
  injection h

/-- チャレンジは先行ログの決定的関数 (challenge-after-commit の骨格)。 -/
theorem fsOrdering : FSOrderingProp (F := F) := by
  intro _ _ _; rfl

end Audit.Proofs
