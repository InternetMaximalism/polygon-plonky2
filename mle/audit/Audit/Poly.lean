/-
  Audit/Poly.lean — 一変数多項式 (sumcheck ラウンドメッセージの表現)

  対応文書: mle/paper/plonky2_mle_paper_v2.md §2.4
    - ラウンド i で prover が送る次数 ≤ d の一変数多項式 g_i(X)
    - 検証: g_i(0) + g_i(1) = S_{i-1}、更新: S_i = g_i(r_i)

  多項式は係数リスト (低次から) で表す。Rust 実装
  (mle/src/sumcheck/types.rs の RoundPolynomial に相当 — 対照は段階2) 。
-/
import Audit.Prelude

namespace Audit

/-- 一変数多項式 = 係数リスト (定数項が先頭)。 -/
abbrev Poly (F : Type) := List F

variable {F : Type} [Field F]

/-- Horner 法による評価。 -/
def Poly.eval (p : Poly F) (x : F) : F :=
  p.foldr (fun c acc => c + x * acc) 0

/-- 次数 ≤ d (係数の個数 ≤ d + 1)。paper §2.4 "degree at most d"。 -/
def Poly.degLE (p : Poly F) (d : Nat) : Prop := p.length ≤ d + 1

/-- 零多項式 (全係数 0)。 -/
def Poly.isZero (p : Poly F) : Prop := ∀ c ∈ p, c = 0

/-- リストの要素が相異なること (Lean core に Nodup がないため自前定義)。 -/
def Distinct {α : Type} : List α → Prop
  | [] => True
  | a :: l => (∀ b ∈ l, a ≠ b) ∧ Distinct l

/-- AXIOM (標準的数学事実): 次数 ≤ d の非零多項式の相異なる根は高々 d 個。
    Mathlib を使わないため公理化する。Schwartz-Zippel の一変数ケースであり、
    sumcheck の健全性 (paper §2.4, §6.1) のバッドイベントの大きさを与える。
    ここでの定式化: 相異なる (Distinct) 根のリストの長さは d を超えない。 -/
axiom Poly.roots_le_degree {F : Type} [Field F]
    (p : Poly F) (d : Nat) (hdeg : p.degLE d) (hne : ¬ p.isZero)
    (roots : List F) (hnodup : Distinct roots)
    (hroots : ∀ x ∈ roots, p.eval x = 0) :
    roots.length ≤ d

end Audit
