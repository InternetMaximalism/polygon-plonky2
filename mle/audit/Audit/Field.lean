/-
  Audit/Field.lean — 有限体の抽象化

  対応文書: mle/paper/plonky2_mle_paper_v2.md §2.1 (Notation),
            §6.1 (Goldilocks |F| ≈ 2^64, cubic extension |F^3| ≈ 2^192)

  Mathlib を使わない自己完結の体クラス。Goldilocks (p = 2^64 - 2^32 + 1) と
  その3次拡大 GoldilocksExt3 は「この体クラスを満たす何らかの型 + 位数の仮定」
  としてパラメータ化する(具体的な mod p 実装の検証は段階2で Rust/Solidity と
  対照するときに行う)。
-/

namespace Audit

/-- 可換体。`inv 0 = 0` の慣習 (Rust実装 `GoldilocksField::inverse` と同じく
    0 の逆元は使用側で除外する)。 -/
class Field (F : Type) where
  zero : F
  one : F
  add : F → F → F
  mul : F → F → F
  neg : F → F
  inv : F → F
  add_assoc : ∀ a b c : F, add (add a b) c = add a (add b c)
  add_comm : ∀ a b : F, add a b = add b a
  zero_add : ∀ a : F, add zero a = a
  add_neg : ∀ a : F, add a (neg a) = zero
  mul_assoc : ∀ a b c : F, mul (mul a b) c = mul a (mul b c)
  mul_comm : ∀ a b : F, mul a b = mul b a
  one_mul : ∀ a : F, mul one a = a
  left_distrib : ∀ a b c : F, mul a (add b c) = add (mul a b) (mul a c)
  mul_inv_cancel : ∀ a : F, a ≠ zero → mul a (inv a) = one
  inv_zero : inv zero = zero
  one_ne_zero : one ≠ zero
  /-- 等号の決定可能性 (有限体では自明。検証者が等値検査を実行するために必要)。 -/
  deq : DecidableEq F

variable {F : Type} [Field F]

instance : DecidableEq F := Field.deq

instance : Add F := ⟨Field.add⟩
instance : Mul F := ⟨Field.mul⟩
instance : Neg F := ⟨Field.neg⟩
instance : Sub F := ⟨fun a b => a + -b⟩
instance : OfNat F 0 := ⟨Field.zero⟩
instance : OfNat F 1 := ⟨Field.one⟩

/-- 除算 (b = 0 のとき 0)。 -/
instance : Div F := ⟨fun a b => a * Field.inv b⟩

/-- Bool → F の埋め込み。hypercube の点 {0,1}^n を体の点とみなす
    (paper §2.1: `b ∈ {0,1}^n` の同一視)。 -/
def boolToF (b : Bool) : F := if b then 1 else 0

/-- 自然数の体への埋め込み (α^j のべき乗計算等に使用)。 -/
def natToF : Nat → F
  | 0 => 0
  | n + 1 => natToF n + 1

/-- べき乗 (チャレンジ α のべき α^j — paper §4.1 combined constraint)。 -/
def fpow (a : F) : Nat → F
  | 0 => 1
  | n + 1 => a * fpow a n

end Audit
