/-
  Audit/Proofs/EqPoly.lean — 段階3: eq 多項式・MLE の基本性質

  - eq_diag: eq(b,b) = 1
  - vprod_eq_one: 全因子 1 の積は 1
  - mleEval_bit1: n=1 の MLE 評価の閉形式
  - bindingGapExists: §3 の負の主張 (|F|>2 の下でギャップが実在)
-/
import Audit.Mle
import Audit.Algebra
import Audit.Statements
import Audit.Proofs.MleLemmas

namespace Audit

variable {F : Type} [Field F]

@[simp] theorem boolToF_false : boolToF (F := F) false = 0 := rfl
@[simp] theorem boolToF_true : boolToF (F := F) true = 1 := rfl

/-- 全因子が 1 なら有限積は 1。 -/
theorem vprod_eq_one (n : Nat) (g : Fin n → F) (h : ∀ j, g j = 1) :
    vprod n g = 1 := by
  induction n with
  | zero => rfl
  | succ n ih =>
    show g 0 * vprod n (fun i => g i.succ) = 1
    rw [h 0, ih (fun i => g i.succ) (fun i => h i.succ), one_mul]

/-- eq(b, b) = 1 (paper §8 "eq(b,b)=1")。 -/
theorem eq_diag (n : Nat) (b : Bits n) :
    eqPoly (F := F) (bitsToVec b) (bitsToVec b) = 1 := by
  apply vprod_eq_one
  intro j
  show boolToF (b j) * boolToF (b j)
      + (1 - boolToF (b j)) * (1 - boolToF (b j)) = 1
  cases b j with
  | false => simp only [boolToF_false, zero_mul, sub_zero, mul_one, zero_add']
  | true => simp only [boolToF_true, mul_one, sub_self, zero_mul, mul_zero, add_zero]

/-- n=1 の MLE 評価の閉形式: MLE(f∘·₀)(r) = f(false)·(1−r₀) + f(true)·r₀。 -/
theorem mleEval_bit1 (f : Bool → F) (r : Vec F 1) :
    mleEval (fun b => f (b 0)) r = f false * (1 - r 0) + f true * r 0 := by
  show hsum 1 (fun b => f (b 0) * eqPoly r (bitsToVec b))
      = f false * (1 - r 0) + f true * r 0
  simp only [hsum, eqPoly, vprod, bitsToVec, vcons, Fin.cases_zero,
    boolToF_false, boolToF_true, mul_zero, mul_one, zero_add', add_zero,
    sub_zero, sub_self]

/-- **§3 の負の主張**: |F|>2 (非冪等元 t が存在) の下で、次数2の formula について
    MLE(b ↦ W(b)²)(r) ≠ (MLE(W)(r))² となる W, r が存在する。
    これが adapter 方式が不健全である理由 (ギャップの実在)。
    抽象体では標数2で成立しないため、非冪等元の存在を仮定する
    (Goldilocks は自明に充足)。 -/
theorem bindingGapExists (h : ∃ t : F, t * t ≠ t) : BindingGapExistsProp (F := F) := by
  obtain ⟨t, ht⟩ := h
  have hsq : (fun b : Bits 1 => boolToF (F := F) (b 0) * boolToF (b 0))
           = (fun b : Bits 1 => boolToF (F := F) (b 0)) := by
    funext b; cases b 0 with
    | false => simp
    | true => simp
  refine ⟨fun b => boolToF (b 0), fun _ => t, ?_⟩
  rw [hsq, mleEval_bit1 boolToF (fun _ => t)]
  simp only [boolToF_false, boolToF_true, zero_mul, one_mul, zero_add']
  exact fun hc => ht hc.symm

/-- **テンソル和**: hypercube 総和と座標ごとの積の交換。
    Σ_b Π_j g_j(b_j) = Π_j (g_j(0) + g_j(1))。 -/
theorem hsum_vprod_factor (n : Nat) (g : Fin n → F → F) :
    hsum n (fun b => vprod n (fun j => g j (boolToF (b j))))
      = vprod n (fun j => g j 0 + g j 1) := by
  induction n with
  | zero => rfl
  | succ n ih =>
    simp only [hsum, vprod, vcons, Fin.cases_zero, Fin.cases_succ,
      boolToF_false, boolToF_true]
    rw [hsum_mul_left, hsum_mul_left, ih (fun i => g i.succ), ← right_distrib']

/-- Σ_b eq(τ, b) = 1 (paper §8 "Σ eq = 1")。 -/
theorem eq_sum (n : Nat) (τ : Vec F n) :
    hsum n (fun b => eqPoly τ (bitsToVec b)) = 1 := by
  rw [show (fun b : Bits n => eqPoly τ (bitsToVec b))
        = (fun b => vprod n (fun j =>
            (fun (j : Fin n) (v : F) => τ j * v + (1 - τ j) * (1 - v)) j
              (boolToF (b j)))) from rfl,
      hsum_vprod_factor n (fun j v => τ j * v + (1 - τ j) * (1 - v))]
  apply vprod_eq_one
  intro j
  show (τ j * 0 + (1 - τ j) * (1 - 0)) + (τ j * 1 + (1 - τ j) * (1 - 1)) = 1
  simp only [mul_zero, sub_zero, mul_one, sub_self, zero_add', add_zero]
  rw [sub_def, add_assoc', neg_add_cancel, add_zero]

/-! ### 名前付き命題 (Mle.lean / Statements.lean) との接続 -/

theorem eq_diag_prop_holds : eq_diag_prop (F := F) := fun n b => eq_diag n b
theorem eq_sum_prop_holds : eq_sum_prop (F := F) := fun n τ => eq_sum n τ
theorem bindingGapExists_prop (h : ∃ t : F, t * t ≠ t) :
    BindingGapExistsProp (F := F) := bindingGapExists h
