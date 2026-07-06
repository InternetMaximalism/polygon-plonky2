/-
  Audit/Pcs.lean — 多重線形 PCS の抽象インターフェース (WHIR ブラックボックス)

  対応文書: mle/paper/plonky2_mle_paper_v2.md
    §2.5: WHIR は Commit(f) → root, Open(f, r, v) → π,
          Verify(root, r, v, π) ∈ {accept, reject} を公開するブラックボックス。
          split-commit 変種で preprocessed と proof-time 多項式を単一セッションで
          結合コミットする。
    §4.5 leg 3 / §6.1: PCS binding (ε_PCS)。
    §7.4: MultilinearPCS trait (commit / open / verify / split_commit)。
          Rust 対応 (段階2): mle/src/commitment/traits.rs, whir_pcs.rs

  ── 仮定のモデル化について ──
  ε_PCS-binding は確率的な性質だが、Mathlib なしで確率論を持ち込まないため
  「理想化された binding」として構造体フィールドの Prop に置く:
    各コミットメントは一意の評価表 `bound c` を定め、Verify の成功は
    「主張値 = その表の MLE の r での評価」を含意する。
  現実の WHIR ではこの含意は確率 1 - ε_PCS でしか成り立たない。この理想化は
  SCOPE.md の仮定一覧に記載し、Theorem 1 の誤差項 ε_PCS に対応させる。
-/
import Audit.Mle

namespace Audit

/-- 単一ベクトル用の抽象 PCS (paper §2.5 のブラックボックス仕様そのまま)。
    `n` は変数の個数 (2^n 評価点)。 -/
structure PCS (F : Type) [Field F] (n : Nat) where
  /-- コミットメント (WHIR では Merkle ルート)。 -/
  Com : Type
  /-- 評価証明 (WHIR では folding + Merkle パス束)。 -/
  Prf : Type
  /-- Commit(f) → root (paper §2.5)。 -/
  commit : (Bits n → F) → Com
  /-- Verify(root, r, v, π) (paper §2.5)。 -/
  verify : Com → Vec F n → F → Prf → Bool
  /-- 理想化 binding その1: 各コミットメントが一意に定める評価表。
      -- 仮定 (ε_PCS 理想化): 現実には計算量的にのみ成立。 -/
  bound : Com → (Bits n → F)
  /-- 理想化 binding その2: 正直な commit は自分の表にバインドされる。 -/
  commit_bound : ∀ f, bound (commit f) = f
  /-- 理想化 binding その3: Verify が accept したら主張値は束縛された多項式の
      評価に等しい (paper §4.5 leg 3 "the evaluations are determined by the
      commitments")。 -/
  verify_sound : ∀ c r v π, verify c r v π = true → v = mleEval (bound c) r
  /-- 完全性: 正しい評価には受理される証明が存在する (paper §2.5 Open)。 -/
  open_complete : ∀ f r, ∃ π, verify (commit f) r (mleEval f r) π = true

/-- split-commit 変種 (paper §2.5 末尾, §4.3):
    複数ベクトル (preprocessed / witness / inverses) を単一セッションで
    結合コミットし、共通の点 r で全ベクトルの評価を一括オープンする。
    `k` はベクトル本数。 -/
structure SplitPCS (F : Type) [Field F] (n : Nat) (k : Nat) where
  Com : Type
  Prf : Type
  commit : (Fin k → Bits n → F) → Com
  /-- 共通点 r における k 本の主張評価値を一括検証。 -/
  verify : Com → Vec F n → (Fin k → F) → Prf → Bool
  bound : Com → (Fin k → Bits n → F)
  commit_bound : ∀ fs, bound (commit fs) = fs
  verify_sound : ∀ c r vs π, verify c r vs π = true →
    ∀ j, vs j = mleEval (bound c j) r
  open_complete : ∀ fs r, ∃ π,
    verify (commit fs) r (fun j => mleEval (fs j) r) π = true

/-- paper §4.3 (a)/(b): 本プロトコルのコミットメント構成。
    3 グループ = preprocessed (const_j, s_j) / witness (w_j) / inverses (a_j, b_j)。
    -- NOTE: paper は (a) 2セッション と (b) 3ベクトル結合 の両案を挙げ、
       §5.2 step 13 は (preprocessed, witness, inverses) split-commit を採用。
       ここでは (b) を採用してモデル化する。 -/
inductive CommitGroup where
  | preprocessed
  | witness
  | inverses
  deriving DecidableEq

end Audit
