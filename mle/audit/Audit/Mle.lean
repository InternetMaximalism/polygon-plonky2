/-
  Audit/Mle.lean — 多重線形拡張 (MLE) と eq 多項式

  対応文書: mle/paper/plonky2_mle_paper_v2.md
    §2.1: n変数多重線形多項式の一意表現
          f(x) = Σ_{b ∈ {0,1}^n} f(b) · Π_j (x_j^{b_j} (1-x_j)^{1-b_j})
    §2.3: eq(τ, x) = Π_j (τ_j x_j + (1-τ_j)(1-x_j)),
          f(r) = Σ_b f(b) · eq(r, b)

  Rust 実装対応 (段階2で対照): mle/src/dense_mle.rs, mle/src/eq_poly.rs
-/
import Audit.Poly

namespace Audit

variable {F : Type} [Field F]

/-- eq 多項式 (paper §2.3)。 -/
def eqPoly {n : Nat} (τ x : Vec F n) : F :=
  vprod n (fun j => τ j * x j + (1 - τ j) * (1 - x j))

/-- 評価表 T : {0,1}^n → F の多重線形拡張の点 r での評価 (paper §2.1, §2.3)。
    MLE(T)(r) = Σ_b T(b) · eq(r, b)。 -/
def mleEval {n : Nat} (T : Bits n → F) (r : Vec F n) : F :=
  hsum n (fun b => T b * eqPoly r (bitsToVec b))

/-- 関数 P : F^n → F が多重線形 (各変数について次数 ≤ 1、すなわちアフィン)
    であること。paper §2.1 "degree-1-per-variable"。 -/
def Multilinear {n : Nat} (P : Vec F n → F) : Prop :=
  ∀ (i : Fin n) (x : Vec F n) (a : F),
    P (vset x i a) = P (vset x i 0) + a * (P (vset x i 1) - P (vset x i 0))

/-! ### MLE の基本性質 (paper §2.1, §2.3, §8 "Correctness" テスト項目に対応)

    証明は段階3 (`Audit/Statements.lean` 以降) で与える。ここでは命題を明文化する。 -/

/-- MLE は hypercube 上で元の表と一致する (MLE の定義的性質、paper §2.1)。
    -- 段階3で証明予定。eq(b, b') = δ_{b,b'} (Kronecker delta) から従う。 -/
def mle_agrees_on_hypercube_prop : Prop :=
  ∀ (n : Nat) (T : Bits n → F) (b : Bits n),
    mleEval T (bitsToVec b) = T b

/-- mleEval は多重線形である (paper §2.1: 一意表現の存在側)。 -/
def mle_is_multilinear_prop : Prop :=
  ∀ (n : Nat) (T : Bits n → F), Multilinear (mleEval (F := F) T)

/-- 一意性 (paper §2.1: "unique representation"): 多重線形な P, Q が
    hypercube 上で一致すれば全点で一致する。 -/
def mle_unique_prop : Prop :=
  ∀ (n : Nat) (P Q : Vec F n → F), Multilinear P → Multilinear Q →
    (∀ b : Bits n, P (bitsToVec b) = Q (bitsToVec b)) →
    ∀ r, P r = Q r

/-- eq(b, b) = 1 (paper §8 Correctness テスト "eq(b,b) = 1")。 -/
def eq_diag_prop : Prop :=
  ∀ (n : Nat) (b : Bits n), eqPoly (F := F) (bitsToVec b) (bitsToVec b) = 1

/-- Σ_b eq(τ, b) = 1 (paper §8 Correctness テスト "Σ eq = 1")。 -/
def eq_sum_prop : Prop :=
  ∀ (n : Nat) (τ : Vec F n), hsum n (fun b => eqPoly τ (bitsToVec b)) = 1

end Audit
