/-
  Audit/Sumcheck.lean — sumcheck プロトコルの検証者と健全性の骨格

  対応文書: mle/paper/plonky2_mle_paper_v2.md
    §2.4: n ラウンド。ラウンド i で prover は次数 ≤ d の一変数多項式 g_i を送り、
          検証者は g_i(0) + g_i(1) = S_{i-1} を検査、S_i = g_i(r_i) と更新。
          最後に g(r) = S_n をオラクル (PCS) で検査する。
          zero-check: 主張和 0、被和項は eq(τ, x) · F(x)。
    §5.3 steps 3-6: 4 本の sumcheck (inverse deg 3 / linear-H deg 1 /
          gate deg 1+d / batching deg 1)。

  Rust 対応 (段階2): mle/src/sumcheck/verifier.rs
  Solidity 対応 (段階2): SumcheckVerifier.vol.md
-/
import Audit.Transcript

namespace Audit

variable {F : Type} [Field F]

/-- 1 ラウンドの検査 (paper §2.4):
    次数境界 + g_i(0) + g_i(1) = S_{i-1}。成立すれば S_i = g_i(r_i) を返す。 -/
def sumcheckRound (d : Nat) (S : F) (g : Poly F) (r : F) : Option F :=
  if g.length ≤ d + 1 ∧ g.eval 0 + g.eval 1 = S then
    some (g.eval r)
  else
    none

/-- n ラウンドの検証。msgs と chals を先頭から消費し、全ラウンド成功なら
    最終値 S_n を返す。チャレンジは呼び出し側 (Protocol.lean) が
    Fiat-Shamir で導出して渡す (paper §5.3: "squeeze r_inv,i")。 -/
def sumcheckVerify (d : Nat) : F → List (Poly F) → List F → Option F
  | S, [], [] => some S
  | S, g :: msgs, r :: chals =>
    match sumcheckRound d S g r with
    | some S' => sumcheckVerify d S' msgs chals
    | none => none
  | _, _, _ => none   -- メッセージ数とチャレンジ数の不一致は reject

/-- ラウンド多項式を 1 本ずつ absorb しチャレンジを squeeze する
    Fiat-Shamir 版 sumcheck 検証 (paper §5.3 の実際の検証者)。
    戻り値: (最終値 S_n, チャレンジ列 r (逆順ではなく取得順), 更新後ログ)。 -/
def sumcheckVerifyFS (ro : FSOracle F) (d : Nat) (lbl : Label) :
    F → List (Poly F) → TranscriptLog F → Option (F × List F × TranscriptLog F)
  | S, [], log => some (S, [], log)
  | S, g :: msgs, log =>
    -- ラウンド多項式を absorb してからチャレンジを squeeze (paper §6.2:
    -- "round polynomials are absorbed before the corresponding challenges")
    let log₁ := absorbLabeled log lbl (.bytes (g.map (fun _ => 0)))
    -- NOTE: 上の absorb は「g の係数列を canonical encoding で absorb する」の
    -- 抽象化。エンコーディングの忠実なモデル化は CanonicalEncoding を通じて
    -- 段階2で precise 化する。ここではログ長と順序のみが本質。
    let log₂ := g.foldl (fun acc c => absorb acc (.field c)) log₁
    let (r, log₃) := squeeze1 ro log₂
    match sumcheckRound d S g r with
    | some S' =>
      match sumcheckVerifyFS ro d lbl S' msgs log₃ with
      | some (Sn, rs, log') => some (Sn, r :: rs, log')
      | none => none
    | none => none

/-! ### sumcheck 健全性の決定論的コア (paper §2.4, §6.1)

    「不正 prover は確率 ≤ n·d/|F| でしか成功しない」の**決定論的**中核を、
    自明に充足できない (non-vacuous) 命題として定式化する。証明は段階3。

    直観 (telescoping): prover が送った round poly 列 `sent` と、正直な
    (真の部分和の) round poly 列 `honest` が、同じチャレンジ列 `chals` の下で
    共に検証者の各ラウンド検査を通り (SumcheckAccepts)、最終折り畳み値
    (オラクル検査に渡る値 foldEval) が一致するのに、初期主張が異なる
    (Ss ≠ Sh) なら、あるラウンド i で `sent[i] ≠ honest[i]` (差が非零多項式)
    かつ `chals[i]` がその差の根になっている (SumcheckHitSomewhere)。
    差の次数は ≤ d なので、根は高々 d 個 (Poly.roots_le_degree) — これが
    Theorem 1 の per-round 誤差 d/|F| を与える。 -/

/-- 多項式 (係数リスト) の差。長さは max、短い側は 0 で埋める。 -/
def polySub : Poly F → Poly F → Poly F
  | [],       q       => q.map (fun c => 0 - c)
  | p,        []      => p
  | a :: p,   b :: q  => (a - b) :: polySub p q

/-- 検証者のラウンド折り畳みの最終値 S_n (各 S_i = g_i(r_i))。
    最終オラクル検査 `g(r) = S_n` に渡る値 (paper §2.4 末尾)。 -/
def foldEval : F → List (Poly F) → List F → F
  | _, g :: gs, r :: rs => foldEval (g.eval r) gs rs
  | S, _,       _       => S

/-- 検証者が全ラウンドの検査 `g_i(0) + g_i(1) = S_{i-1}` を通すこと。
    sumcheckVerify の受理条件を Prop として抽出したもの。 -/
def SumcheckAccepts : F → List (Poly F) → List F → Prop
  | S, g :: gs, r :: rs => (g.eval 0 + g.eval 1 = S) ∧ SumcheckAccepts (g.eval r) gs rs
  | _, [],      []      => True
  | _, _,       _       => False

/-- あるラウンド i で送信多項式と正直多項式の差が非零で、その i 番目の
    チャレンジがその差の根になっている、という「命中」の存在。
    getD の既定値は零多項式 [] / 0 (getD i [] / getD i 0)。 -/
def SumcheckHitSomewhere (sent honest : List (Poly F)) (chals : List F) : Prop :=
  ∃ i : Nat, i < sent.length ∧
    ¬ (polySub (sent.getD i []) (honest.getD i [])).isZero ∧
    (polySub (sent.getD i []) (honest.getD i [])).eval (chals.getD i 0) = 0

/-- sumcheck 健全性の決定論的コア (段階3で証明する対象)。
    **非空性**: 結論 SumcheckHitSomewhere は sent/honest/chals に固定されており、
    仮定 (受理 + 最終一致 + 初期主張の相違) なしには導けない。 -/
def SumcheckTelescopeHit (_d : Nat) : Prop :=
  ∀ (Ss Sh : F) (sent honest : List (Poly F)) (chals : List F),
    sent.length = chals.length → honest.length = chals.length →
    SumcheckAccepts Ss sent chals →
    SumcheckAccepts Sh honest chals →
    foldEval Ss sent chals = foldEval Sh honest chals →
    Ss ≠ Sh →
    SumcheckHitSomewhere sent honest chals

/-! 補助補題 (段階3で使用予定、ここでは命題のみ):
    差の評価 = 評価の差、および「和が非零なら非零多項式」。 -/

/-- polySub の評価は評価の差 (段階3で証明; Poly.eval の分配から従う)。 -/
def polySub_eval_prop : Prop :=
  ∀ (p q : Poly F) (x : F), (polySub p q).eval x = p.eval x - q.eval x

end Audit
