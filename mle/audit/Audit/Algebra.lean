/-
  Audit/Algebra.lean — 体クラスの基本代数補題 (Mathlib 非依存)

  Field.lean は最小公理集合しか持たないため `ring` が使えない。段階3の証明で
  必要な可換環的等式を公理から導く。まず公理を記法 (`+`, `*`) レベルの
  ラッパー補題にして、`rw` が照合できるようにする。
-/
import Audit.Field

namespace Audit

variable {F : Type} [Field F]

/-! ### 記法レベルのラッパー (defeq で Field.* に一致) -/
theorem add_assoc' (a b c : F) : a + b + c = a + (b + c) := Field.add_assoc a b c
theorem add_comm' (a b : F) : a + b = b + a := Field.add_comm a b
@[simp] theorem zero_add' (a : F) : 0 + a = a := Field.zero_add a
theorem mul_assoc' (a b c : F) : a * b * c = a * (b * c) := Field.mul_assoc a b c
theorem mul_comm' (a b : F) : a * b = b * a := Field.mul_comm a b
theorem one_mul' (a : F) : 1 * a = a := Field.one_mul a
theorem left_distrib' (a b c : F) : a * (b + c) = a * b + a * c := Field.left_distrib a b c

/-! ### 導出される基本補題 -/

@[simp] theorem sub_def (a b : F) : a - b = a + -b := rfl

theorem add_neg (a : F) : a + -a = 0 := Field.add_neg a

theorem neg_add_cancel (a : F) : -a + a = 0 := by
  rw [add_comm']; exact Field.add_neg a

@[simp] theorem add_zero (a : F) : a + 0 = a := by
  rw [add_comm']; exact zero_add' a

@[simp] theorem sub_self (a : F) : a - a = 0 := by
  rw [sub_def]; exact add_neg a

/-- x + y = 0 ならば -x = y (逆元の一意性)。 -/
theorem neg_eq_of_add_eq_zero {x y : F} (h : x + y = 0) : -x = y :=
  calc -x = -x + 0 := (add_zero _).symm
    _ = -x + (x + y) := by rw [h]
    _ = -x + x + y := by rw [add_assoc']
    _ = 0 + y := by rw [neg_add_cancel]
    _ = y := zero_add' _

@[simp] theorem neg_zero : -(0 : F) = 0 := by
  have h := add_neg (0 : F); rw [zero_add'] at h; exact h

@[simp] theorem sub_zero (a : F) : a - 0 = a := by
  rw [sub_def, neg_zero, add_zero]

theorem eq_of_sub_eq_zero {a b : F} (h : a - b = 0) : a = b := by
  rw [sub_def] at h
  calc a = a + 0 := (add_zero _).symm
    _ = a + (-b + b) := by rw [neg_add_cancel]
    _ = a + -b + b := by rw [add_assoc']
    _ = 0 + b := by rw [h]
    _ = b := zero_add' _

theorem sub_eq_zero_of_eq {a b : F} (h : a = b) : a - b = 0 := by
  rw [h]; exact sub_self b

@[simp] theorem mul_zero (a : F) : a * 0 = 0 := by
  have h : a * 0 + a * 0 = a * 0 := by rw [← left_distrib', add_zero]
  calc a * 0 = a * 0 + 0 := (add_zero _).symm
    _ = a * 0 + (a * 0 + -(a * 0)) := by rw [add_neg]
    _ = a * 0 + a * 0 + -(a * 0) := by rw [← add_assoc']
    _ = a * 0 + -(a * 0) := by rw [h]
    _ = 0 := add_neg _

@[simp] theorem zero_mul (a : F) : 0 * a = 0 := by
  rw [mul_comm']; exact mul_zero a

theorem mul_neg (a b : F) : a * (-b) = -(a * b) :=
  (neg_eq_of_add_eq_zero (x := a * b) (y := a * (-b))
    (by rw [← left_distrib', add_neg, mul_zero])).symm

theorem neg_mul (a b : F) : (-a) * b = -(a * b) := by
  rw [mul_comm' (-a) b, mul_neg, mul_comm' b a]

theorem mul_sub (x a b : F) : x * (a - b) = x * a - x * b := by
  simp only [sub_def, left_distrib', mul_neg]

theorem neg_add (a b : F) : -(a + b) = -a + -b := by
  apply neg_eq_of_add_eq_zero
  calc (a + b) + (-a + -b)
      = a + (b + (-a + -b)) := by rw [add_assoc']
    _ = a + (b + -a + -b) := by rw [add_assoc' b (-a) (-b)]
    _ = a + (-a + b + -b) := by rw [add_comm' b (-a)]
    _ = a + (-a + (b + -b)) := by rw [add_assoc' (-a) b (-b)]
    _ = a + (-a + 0) := by rw [add_neg b]
    _ = a + -a := by rw [add_zero]
    _ = 0 := add_neg a

theorem sub_add_sub (a b c d : F) : (a - b) + (c - d) = (a + c) - (b + d) := by
  rw [sub_def a b, sub_def c d, sub_def (a + c) (b + d), neg_add]
  calc (a + -b) + (c + -d)
      = a + (-b + (c + -d)) := by rw [add_assoc']
    _ = a + (-b + c + -d) := by rw [add_assoc' (-b) c (-d)]
    _ = a + (c + -b + -d) := by rw [add_comm' (-b) c]
    _ = a + (c + (-b + -d)) := by rw [add_assoc' c (-b) (-d)]
    _ = a + c + (-b + -d) := by rw [add_assoc']

@[simp] theorem zero_sub (c : F) : 0 - c = -c := by
  rw [sub_def, zero_add']

@[simp] theorem one_mul (a : F) : 1 * a = a := Field.one_mul a

@[simp] theorem mul_one (a : F) : a * 1 = a := by rw [mul_comm']; exact Field.one_mul a

theorem right_distrib' (a b c : F) : (a + b) * c = a * c + b * c := by
  rw [mul_comm' (a + b) c, left_distrib', mul_comm' c a, mul_comm' c b]

/-- 4項の入れ替え: (a+b)+(c+d) = (a+c)+(b+d)。 -/
theorem add_add_add_comm (a b c d : F) : (a + b) + (c + d) = (a + c) + (b + d) := by
  calc (a + b) + (c + d)
      = a + (b + (c + d)) := add_assoc' _ _ _
    _ = a + (b + c + d) := by rw [add_assoc' b c d]
    _ = a + (c + b + d) := by rw [add_comm' b c]
    _ = a + (c + (b + d)) := by rw [add_assoc' c b d]
    _ = (a + c) + (b + d) := by rw [add_assoc' a c (b + d)]

end Audit
