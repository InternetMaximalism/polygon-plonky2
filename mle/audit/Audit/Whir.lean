/-
  Audit/Whir.lean — WHIR の内部構造の抽象化と監査不変量

  対応文書:
    - mle/paper/plonky2_mle_paper_v2.md §2.5 (WHIR ブラックボックス仕様)
    - mle/paper/whir_optimization_report.md §1 (クエリ特性: folding_factor,
      rate, クエリ数 q ≈ λ / log(1/ρ), 検証コスト O(q · n/ff · 2^ff))
    - mle/soundnessgame/SpongefishWhirVerify.vol.md 所見 #1〜#4
      (いずれも round 1 で修正済。ここでは「修正後に成り立っているべき不変量」
       として明文化し、段階2の Solidity 対照でこの不変量が実装から導出できる
       ことを検査する)
    - mle/soundnessgame/SpongefishWhir.vol.md, SpongefishMerkle.vol.md

  ユーザー選択 (SCOPE.md): ブラックボックス PCS + 内部も抽象化。
  ここでは PCS の健全性証明には使わず、PCS 公理 (Pcs.lean) を WHIR 実装が
  満たすための十分条件 (不変量) を記述する層。
-/
import Audit.Sumcheck

namespace Audit

/-- WHIR パラメータ (whir_optimization_report.md §4 / WhirPCS::for_num_vars)。 -/
structure WhirParams where
  /-- 変数の個数 n (2^n 評価点)。 -/
  numVars : Nat
  /-- 1 ラウンドで畳み込む変数の個数 ff (report §1: folding_factor)。 -/
  foldingFactor : Nat
  /-- folding ラウンド数 (≈ n / ff)。 -/
  numRounds : Nat
  /-- 最終ラウンドで直接送られるベクトルの長さ。 -/
  finalSize : Nat
  /-- 最終 sumcheck のラウンド数。 -/
  finalSumcheckRounds : Nat
  /-- 初期 rate の log 逆数 (report §4.1: starting_log_inv_rate = 4 → rate 1/16)。 -/
  startingLogInvRate : Nat
  /-- セキュリティレベル λ (report §1: q ≈ λ / log(1/ρ))。 -/
  securityLevel : Nat

/-- Merkle コミットメントの抽象 (SpongefishMerkle.vol.md 対応 — 段階2)。
    葉のハッシュとルートのみモデル化し、パス検証は述語として置く。 -/
structure MerkleScheme where
  Hash : Type
  Leaf : Type
  hashLeaf : Leaf → Hash
  root : List Hash → Hash
  /-- パス検証の抽象: 「index 位置の葉 leaf がルート r の木に含まれる」。 -/
  verifyPath : Hash → Nat → Leaf → Bool
  /-- 衝突耐性の理想化 (paper §2.5: "collision-resistant hash functions")。
      -- 仮定: 計算量的仮定の理想化。 -/
  binding : ∀ (r : Hash) (i : Nat) (l₁ l₂ : Leaf),
    verifyPath r i l₁ = true → verifyPath r i l₂ = true → l₁ = l₂

/-- 1 つの WHIR クエリ開示 (SpongefishWhirVerify.vol.md の用語で
    challenge index + row data)。 -/
structure WhirQuery (F : Type) where
  /-- squeeze されたクエリ index (葉の位置)。 -/
  index : Nat
  /-- 開示された行 (2^ff 要素のコセット、report §4.2)。 -/
  row : List F

/-- 1 folding ラウンドの抽象 (report §1: 各ラウンドで folding_factor 変数を
    畳み込み、新しいコミットメントに対してクエリで整合性を検査)。 -/
structure WhirRound (F : Type) (M : MerkleScheme) where
  commitmentRoot : M.Hash
  /-- out-of-domain サンプル (SpongefishWhirVerify _receiveCommitmentsAndOod)。 -/
  oodSamples : List F
  /-- ラウンド内 sumcheck メッセージ。 -/
  sumcheckPolys : List (Poly F)
  queries : List (WhirQuery F)

/-- WHIR 証明全体の抽象形。 -/
structure WhirProof (F : Type) (M : MerkleScheme) where
  rounds : List (WhirRound F M)
  /-- 最終ラウンドで直接送られるベクトル (長さ params.finalSize であるべき)。 -/
  finalVector : List F
  finalQueries : List (WhirQuery F)

/-! ### 監査不変量 (SpongefishWhirVerify.vol.md 所見 #1〜#4 の抽象化)

    これらは「修正後の実装が満たすべき WellFormed 条件」。段階2で
    Solidity / Rust 実装の検査条件がこれらを含意することを対照する。 -/

/-- 所見 #2 (HIGH, 修正済): finalSize = 2^finalSumcheckRounds でなければ
    _foldEval の畳み込みが不正 (末尾要素の無音破棄 / 範囲外読み)。 -/
def WhirParams.finalSizeConsistent (p : WhirParams) : Prop :=
  p.finalSize = 2 ^ p.finalSumcheckRounds

/-- 所見 #3 (HIGH, 修正済): クエリ index の一様サンプリングのため、葉数は
    2 の冪であること (または rejection sampling)。modulo バイアスの排除。 -/
def uniformSamplingDomain (numLeaves : Nat) : Prop :=
  ∃ k, numLeaves = 2 ^ k

/-- 所見 #1 (HIGH, 修正済): 評価和に流入する全ての行データは Merkle 検証済み
    でなければならない。index 衝突時の 2 回目以降の出現も、検証済みハッシュと
    同一データであることを検査する。抽象化: 「和に使われる全クエリの行が
    ルートに対しパス検証を通る」。 -/
def allRowsMerkleBound {F : Type} (M : MerkleScheme)
    (root : M.Hash) (encodeRow : List F → M.Leaf)
    (queries : List (WhirQuery F)) : Prop :=
  ∀ q ∈ queries, M.verifyPath root q.index (encodeRow q.row) = true

/-- 所見 #4 (CRITICAL, 修正済): prover 供給の全体要素は canonical
    (raw value < p)。抽象化: 行データのデコードが CanonicalEncoding.decode を
    通ること — 非 canonical バイト列は reject。 -/
def rowsCanonical {F : Type} (ce : CanonicalEncoding F)
    (rawRows : List (List Nat)) : Prop :=
  ∀ raw ∈ rawRows, ∀ b ∈ raw, ∃ v : F, ce.decode [b] = some v

/-- WHIR 証明の well-formedness (上記不変量の束)。
    -- NOTE: これは WHIR の健全性 (proximity soundness) の主張ではない。
    -- WHIR 論文 [4] の soundness は本監査の範囲外 (SCOPE.md) であり、
    -- Pcs.lean の理想化 binding 公理に集約する。ここの不変量は
    -- 「実装が WHIR 論文の前提 (一様クエリ・全データのMerkle束縛・
    -- canonical encoding) を壊していないこと」の検査項目である。 -/
structure WhirWellFormed {F : Type} (M : MerkleScheme)
    (params : WhirParams) (proof : WhirProof F M)
    (encodeRow : List F → M.Leaf) : Prop where
  finalSizeOk : params.finalSizeConsistent
  finalVectorLen : proof.finalVector.length = params.finalSize
  roundRowsBound : ∀ rd ∈ proof.rounds,
    allRowsMerkleBound M rd.commitmentRoot encodeRow rd.queries

end Audit
