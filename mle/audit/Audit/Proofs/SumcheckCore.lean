/-
  Audit/Proofs/SumcheckCore.lean — 段階3: sumcheck 健全性コアの証明

  中核定理 `sumcheck_telescope` (Sumcheck.lean の `SumcheckTelescopeHit`) を
  telescoping 論法で証明する。補助として多項式の差の評価等式も証明。

  注: `Poly F` は `List F` の abbrev なので、`cases`/`induction` 後の変数の
  ドット記法は `List.*` に解決される。ここでは `Poly.eval` / `Poly.isZero` を
  明示して書く。
-/
import Audit.Sumcheck
import Audit.Algebra

namespace Audit

variable {F : Type} [Field F]

@[simp] theorem eval_nil (x : F) : Poly.eval ([] : Poly F) x = 0 := rfl

@[simp] theorem eval_cons (c : F) (p : Poly F) (x : F) :
    Poly.eval (c :: p) x = c + x * Poly.eval p x := rfl

/-- 零多項式の評価は 0。 -/
theorem isZero_eval (p : Poly F) (x : F) (h : Poly.isZero p) : Poly.eval p x = 0 := by
  induction p with
  | nil => rfl
  | cons c p ih =>
    have hc : c = 0 := h c (List.mem_cons_self c p)
    have hp : Poly.isZero p := fun c' hc' => h c' (List.mem_cons_of_mem c hc')
    rw [eval_cons, hc, ih hp, mul_zero, add_zero]

/-! ### polySub の簡約補題 (定義の各パターン) -/
theorem polySub_nil (q : Poly F) : polySub [] q = q.map (fun c => 0 - c) := by
  simp only [polySub]
theorem polySub_cons_nil (a : F) (p : Poly F) :
    polySub (a :: p) [] = a :: p := by simp only [polySub]
theorem polySub_cons_cons (a b : F) (p q : Poly F) :
    polySub (a :: p) (b :: q) = (a - b) :: polySub p q := by simp only [polySub]

/-- `List.map (0 - ·)` の評価は評価の符号反転。 -/
theorem map_negC_eval (q : Poly F) (x : F) :
    Poly.eval (q.map (fun c => 0 - c)) x = -(Poly.eval q x) := by
  induction q with
  | nil => simp only [List.map_nil, eval_nil, neg_zero]
  | cons c q ih =>
    rw [List.map_cons, eval_cons, ih, eval_cons, zero_sub, mul_neg, neg_add]

/-- `polySub [] q` の評価は `-(Poly.eval q x)`。 -/
theorem polySub_nil_eval (q : Poly F) (x : F) :
    Poly.eval (polySub [] q) x = -(Poly.eval q x) := by
  rw [polySub_nil]; exact map_negC_eval q x

/-- 多項式の差の評価 = 評価の差。 -/
theorem polySub_eval (p q : Poly F) (x : F) :
    Poly.eval (polySub p q) x = Poly.eval p x - Poly.eval q x := by
  induction p generalizing q with
  | nil => rw [polySub_nil_eval, eval_nil, zero_sub]
  | cons a p ih =>
    cases q with
    | nil =>
      rw [polySub_cons_nil, eval_nil, sub_zero]
    | cons b q =>
      rw [polySub_cons_cons, eval_cons, eval_cons, eval_cons, ih q, mul_sub, sub_add_sub]

/-- SumcheckAccepts が成り立つなら round poly 数 = チャレンジ数。 -/
theorem accepts_length (S : F) (sent : List (Poly F)) (chals : List F)
    (h : SumcheckAccepts S sent chals) : sent.length = chals.length := by
  induction chals generalizing S sent with
  | nil =>
    cases sent with
    | nil => rfl
    | cons g gs => exact h.elim
  | cons r rs ih =>
    cases sent with
    | nil => exact h.elim
    | cons g gs =>
      obtain ⟨_, h'⟩ := h
      simp only [List.length_cons]
      exact congrArg (· + 1) (ih _ gs h')

/-- **中核定理**: sumcheck の telescoping 健全性 (Sumcheck.lean の命題)。 -/
theorem sumcheck_telescope (d : Nat) : SumcheckTelescopeHit (F := F) d := by
  intro Ss Sh sent honest chals
  induction chals generalizing Ss Sh sent honest with
  | nil =>
    intro _ _ hacc hacc2 hfold hne
    cases sent with
    | cons g gs => exact hacc.elim
    | nil =>
      cases honest with
      | cons h hs => exact hacc2.elim
      | nil => exact (hne hfold).elim
  | cons r rs ih =>
    intro hsl hhl hacc hacc2 hfold hne
    cases sent with
    | nil => exact hacc.elim
    | cons g gs =>
      cases honest with
      | nil => exact hacc2.elim
      | cons h hs =>
        obtain ⟨hg, hacc'⟩ := hacc
        obtain ⟨hh, hacc2'⟩ := hacc2
        have hfold' : foldEval (Poly.eval g r) gs rs
            = foldEval (Poly.eval h r) hs rs := hfold
        by_cases hz : Poly.isZero (polySub g h)
        · exfalso
          apply hne
          have e0 : Poly.eval g 0 = Poly.eval h 0 := by
            have h0 := isZero_eval (polySub g h) 0 hz
            rw [polySub_eval] at h0; exact eq_of_sub_eq_zero h0
          have e1 : Poly.eval g 1 = Poly.eval h 1 := by
            have h1 := isZero_eval (polySub g h) 1 hz
            rw [polySub_eval] at h1; exact eq_of_sub_eq_zero h1
          rw [← hg, ← hh, e0, e1]
        · by_cases hr : Poly.eval (polySub g h) r = 0
          · exact ⟨0, Nat.zero_lt_succ _, hz, hr⟩
          · have hne' : Poly.eval g r ≠ Poly.eval h r := by
              intro heq
              apply hr
              rw [polySub_eval, heq, sub_self]
            have hsl' : gs.length = rs.length := by simpa using hsl
            have hhl' : hs.length = rs.length := by simpa using hhl
            have hit := ih (Poly.eval g r) (Poly.eval h r) gs hs
              hsl' hhl' hacc' hacc2' hfold' hne'
            obtain ⟨i, hi, hnz, hrz⟩ := hit
            exact ⟨i + 1, Nat.succ_lt_succ hi, hnz, hrz⟩

end Audit
