/-
  Audit/Prelude.lean — ベクトル・hypercube・有限和/積のユーティリティ

  対応文書: mle/paper/plonky2_mle_paper_v2.md §2.1
    - `{0,1}^n` (Boolean hypercube) は `Bits n := Fin n → Bool`
    - `F^n` の点は `Vec F n := Fin n → F`
    - `Σ_{b ∈ {0,1}^n}` は `hsum`
-/
import Audit.Field

namespace Audit

/-- 長さ n のベクトル。 -/
abbrev Vec (F : Type) (n : Nat) := Fin n → F

/-- Boolean hypercube {0,1}^n の点。 -/
abbrev Bits (n : Nat) := Fin n → Bool

/-- 先頭に要素を足す。 -/
def vcons {α : Type} {n : Nat} (a : α) (v : Fin n → α) : Fin (n + 1) → α :=
  fun i => Fin.cases a v i

/-- i 番目の座標を差し替える。 -/
def vset {α : Type} {n : Nat} (x : Fin n → α) (i : Fin n) (a : α) : Fin n → α :=
  fun j => if j = i then a else x j

variable {F : Type} [Field F]

/-- hypercube 上の総和 Σ_{b ∈ {0,1}^n} f(b)。paper §2.1 の Σ_b。 -/
def hsum : (n : Nat) → (Bits n → F) → F
  | 0, f => f (fun i => i.elim0)
  | n + 1, f => hsum n (fun b => f (vcons false b)) + hsum n (fun b => f (vcons true b))

/-- 有限積 Π_{j ∈ [n]} g(j)。eq 多項式 (paper §2.3) の Π に使用。 -/
def vprod : (n : Nat) → (Fin n → F) → F
  | 0, _ => 1
  | n + 1, g => g 0 * vprod n (fun i => g i.succ)

/-- Fin n で添字づけられた有限和 Σ_{j ∈ [n]}。 -/
def fsum : (n : Nat) → (Fin n → F) → F
  | 0, _ => 0
  | n + 1, g => g 0 + fsum n (fun i => g i.succ)

/-- hypercube の点を体の点へ持ち上げる (paper §2.1 の同一視 b ↦ (b_1,…,b_n) ∈ F^n)。 -/
def bitsToVec {n : Nat} (b : Bits n) : Vec F n := fun i => boolToF (b i)

end Audit
