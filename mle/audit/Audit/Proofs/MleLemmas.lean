/-
  Audit/Proofs/MleLemmas.lean — 段階3: MLE の線形性 (§4.5 binding-gap 不在の正の主張)

  LinearCommutesProp: 終端チェックに現れる線形結合について MLE が可換
  (MLE(αT₁+βT₂)(r) = α·MLE(T₁)(r) + β·MLE(T₂)(r))。§4.5 leg 2 の形式化。
-/
import Audit.Mle
import Audit.Algebra
import Audit.Statements

namespace Audit

variable {F : Type} [Field F]

/-- hypercube 総和の加法性。 -/
theorem hsum_add (n : Nat) (f g : Bits n → F) :
    hsum n (fun b => f b + g b) = hsum n f + hsum n g := by
  induction n with
  | zero => rfl
  | succ n ih =>
    simp only [hsum]
    rw [ih (fun b => f (vcons false b)) (fun b => g (vcons false b)),
        ih (fun b => f (vcons true b)) (fun b => g (vcons true b))]
    exact add_add_add_comm _ _ _ _

/-- hypercube 総和のスカラー左移動。 -/
theorem hsum_mul_left (n : Nat) (c : F) (f : Bits n → F) :
    hsum n (fun b => c * f b) = c * hsum n f := by
  induction n with
  | zero => rfl
  | succ n ih =>
    simp only [hsum]
    rw [ih (fun b => f (vcons false b)), ih (fun b => f (vcons true b)),
        ← left_distrib']

/-- **§4.5 leg 2**: MLE は線形結合と可換 (binding-gap を踏まない理由)。 -/
theorem linearCommutes : LinearCommutesProp (F := F) := by
  intro n T₁ T₂ α β r
  -- 被和項を分配: (α T₁ + β T₂)·e = α (T₁ e) + β (T₂ e)
  have hfun : (fun b => (α * T₁ b + β * T₂ b) * eqPoly r (bitsToVec b))
      = (fun b => α * (T₁ b * eqPoly r (bitsToVec b))
                + β * (T₂ b * eqPoly r (bitsToVec b))) := by
    funext b
    rw [right_distrib', mul_assoc', mul_assoc']
  show hsum n (fun b => (α * T₁ b + β * T₂ b) * eqPoly r (bitsToVec b))
      = α * mleEval T₁ r + β * mleEval T₂ r
  rw [hfun, hsum_add,
      hsum_mul_left n α (fun b => T₁ b * eqPoly r (bitsToVec b)),
      hsum_mul_left n β (fun b => T₂ b * eqPoly r (bitsToVec b))]
  rfl

end Audit
