/-
  Audit/Protocol.lean — プロトコル本体 (§4, §5)

  対応文書: mle/paper/plonky2_mle_paper_v2.md
    §4.1: gate zero-check       Φ_gate(x) = eq(τ,x) · Σ_j α^j c_j(W(x), const(x))
    §4.2: permutation argument  (logUp + auxiliary inverses A_j, B_j)
    §4.2.2: inverse zero-check  Φ_inv(x) = eq(τ_inv,x) · Σ_j λ^j (Z_j^id + μ Z_j^σ)
    §4.2.3: linear H-sumcheck   Φ_h(x) = Σ_j λ_h^j (A_j(x) − B_j(x))
    §4.4: multi-point batching sumcheck → 単一オープン点 r_open
    §5.1: VerifyingKey / §5.2: Prover / §5.3: Verifier / §5.4: domain separation

  Rust 対応 (段階2): mle/src/verifier.rs, mle/src/prover.rs
  Solidity 対応 (段階2): mle/contracts/src/MleVerifier.sol (MleVerifier.vol.md)
-/
import Audit.Whir

namespace Audit

variable {F : Type} [Field F]

/-! ## 回路 (Plonky2 arithmetization, §2.2) -/

/-- Plonky2 回路の抽象 (§2.2, §5.1)。
    selector は constant MLE に折り込まれている (§7.2 末尾:
    "Selector polynomials, stored within the constant MLE")。 -/
structure Circuit (F : Type) [Field F] where
  /-- degree_bits: N = 2^n 行。 -/
  n : Nat
  /-- W: 1 行あたりのワイヤ数。 -/
  numWires : Nat
  /-- W_R ≤ W: routed wires 数。 -/
  numRouted : Nat
  /-- 定数列 (selector 込み) の本数。 -/
  numConstants : Nat
  /-- d: 最大ゲート次数 (§7.3: Arithmetic 2, Poseidon 7)。 -/
  maxGateDegree : Nat
  /-- 制約多項式 c_j の列 (§2.2)。引数: (ワイヤ値, 定数値)。 -/
  constraints : List ((Fin numWires → F) → (Fin numConstants → F) → F)
  /-- K_j: PLONK コセットシフト (§4.2.1, §5.1)。 -/
  cosetShifts : Fin numRouted → F
  /-- ω: 位数 2^n の乗法部分群の生成元 (§4.2.1)。 -/
  omega : F
  /-- ω^{2^i} (§5.1: subgroup_gen_powers, VK に含まれる)。 -/
  subgroupGenPowers : Fin n → F
  /-- 前処理済み定数表 const_j : {0,1}^n → F (§5.1 preprocessed)。 -/
  constTables : Fin numConstants → Bits n → F
  /-- 前処理済みシグマ表 σ_j : {0,1}^n → F (§2.2, §4.2.1)。 -/
  sigmaTables : Fin numRouted → Bits n → F

/-- hypercube の点を行番号 (Nat) へ (§2.1: b と Σ b_j 2^j の同一視)。 -/
def bitsToNat {n : Nat} (b : Bits n) : Nat :=
  fsumNat n (fun i => if b i then 2 ^ i.val else 0)
where
  fsumNat : (m : Nat) → (Fin m → Nat) → Nat
    | 0, _ => 0
    | m + 1, g => g 0 + fsumNat m (fun i => g i.succ)

/-- ID_j(b) := K_j · ω^b (§4.2.1)。 -/
def idValue (c : Circuit F) (j : Fin c.numRouted) (b : Bits c.n) : F :=
  c.cosetShifts j * fpow c.omega (bitsToNat b)

/-! ## ステートメント (何が証明されるのか) -/

/-- ゲート制約の充足 (§2.2, §4.1): 全行 b で全制約 c_j が 0。
    (α で束ねる前の、行単位の本来のステートメント。) -/
def GateSatisfied (c : Circuit F) (wires : Fin c.numWires → Bits c.n → F) : Prop :=
  ∀ b : Bits c.n, ∀ cj ∈ c.constraints,
    cj (fun k => wires k b) (fun k => c.constTables k b) = 0

/-- Fin m の全要素のリスト。 -/
def enumFin : (m : Nat) → List (Fin m)
  | 0 => []
  | m + 1 => (0 : Fin (m + 1)) :: (enumFin m).map Fin.succ

/-- {0,1}^n の全点のリスト。 -/
def enumBits : (n : Nat) → List (Bits n)
  | 0 => [fun i => i.elim0]
  | n + 1 => (enumBits n).map (vcons false) ++ (enumBits n).map (vcons true)

/-- リストの置換 (Lean core に List.Perm がないため自前定義)。 -/
inductive ListPerm {α : Type} : List α → List α → Prop
  | nil : ListPerm [] []
  | cons (a : α) {l₁ l₂ : List α} : ListPerm l₁ l₂ → ListPerm (a :: l₁) (a :: l₂)
  | swap (a b : α) (l : List α) : ListPerm (a :: b :: l) (b :: a :: l)
  | trans {l₁ l₂ l₃ : List α} : ListPerm l₁ l₂ → ListPerm l₂ l₃ → ListPerm l₁ l₃

/-- コピー制約の充足 (§4.2.4 / Haboeck [6] のマルチセット等価性):
    {(W_j(b), ID_j(b))}_{j,b} と {(W_j(b), σ_j(b))}_{j,b} が
    マルチセットとして等しい。ListPerm で表現する。 -/
def PermSatisfied (c : Circuit F) (wires : Fin c.numWires → Bits c.n → F)
    (hWR : c.numRouted ≤ c.numWires) : Prop :=
  let routedWire : Fin c.numRouted → Bits c.n → F :=
    fun j b => wires ⟨j.val, Nat.lt_of_lt_of_le j.isLt hWR⟩ b
  let idPairs : List (F × F) :=
    (enumFin c.numRouted).bind (fun j =>
      (enumBits c.n).map (fun b => (routedWire j b, idValue c j b)))
  let sigmaPairs : List (F × F) :=
    (enumFin c.numRouted).bind (fun j =>
      (enumBits c.n).map (fun b => (routedWire j b, c.sigmaTables j b)))
  ListPerm idPairs sigmaPairs

/-! ## 検証鍵と証明 (§5.1, §5.2 step 14) -/

/-- プロトコル用 PCS 束 (§4.3 (b) / §5.2 step 13):
    preprocessed / witness / inverses の 3 ルート + 単一の結合オープン証明。
    列の並び (§4.4 の表):
      preprocessed: const_0..const_{C-1}, s_0..s_{WR-1}
      witness:      w_0..w_{W-1}
      inverses:     a_0..a_{WR-1}, b_0..b_{WR-1} -/
structure ProtocolPCS (F : Type) [Field F] (n C WR W : Nat) where
  ComP : Type
  ComW : Type
  ComI : Type
  Prf : Type
  commitP : (Fin (C + WR) → Bits n → F) → ComP
  commitW : (Fin W → Bits n → F) → ComW
  commitI : (Fin (WR + WR) → Bits n → F) → ComI
  /-- WHIR.Verify(preprocessed_root, witness_root, inverse_root, r_open,
      batched_claim, eval_proof) (§5.3 step 7)。claimed evals は列ごと。 -/
  verify : ComP → ComW → ComI → Vec F n →
    (Fin (C + WR) → F) → (Fin W → F) → (Fin (WR + WR) → F) → Prf → Bool
  /-- トランスクリプトへ absorb するためのルートの抽象エンコード (§5.2 step 4,7)。 -/
  idP : ComP → Nat
  idW : ComW → Nat
  idI : ComI → Nat
  /-- 理想化 binding (Pcs.lean の PCS と同じ仮定、ε_PCS 理想化)。 -/
  boundP : ComP → (Fin (C + WR) → Bits n → F)
  boundW : ComW → (Fin W → Bits n → F)
  boundI : ComI → (Fin (WR + WR) → Bits n → F)
  commitP_bound : ∀ fs, boundP (commitP fs) = fs
  commitW_bound : ∀ fs, boundW (commitW fs) = fs
  commitI_bound : ∀ fs, boundI (commitI fs) = fs
  verify_sound : ∀ cP cW cI r vsP vsW vsI π,
    verify cP cW cI r vsP vsW vsI π = true →
    (∀ j, vsP j = mleEval (boundP cP j) r) ∧
    (∀ j, vsW j = mleEval (boundW cW j) r) ∧
    (∀ j, vsI j = mleEval (boundI cI j) r)
  open_complete : ∀ fsP fsW fsI r, ∃ π,
    verify (commitP fsP) (commitW fsW) (commitI fsI) r
      (fun j => mleEval (fsP j) r) (fun j => mleEval (fsW j) r)
      (fun j => mleEval (fsI j) r) π = true

/-- 検証鍵 (§5.1)。 -/
structure VerifyingKey (F : Type) [Field F] (c : Circuit F)
    (P : ProtocolPCS F c.n c.numConstants c.numRouted c.numWires) where
  circuitDigest : Nat
  preprocessedRoot : P.ComP
  /-- VK 整合性の信頼仮定 (SCOPE.md): preprocessedRoot は回路の
      (const, σ) 表への正直なコミットメント。 -/
  preprocessedHonest :
    P.boundP preprocessedRoot = fun j =>
      if h : j.val < c.numConstants then
        c.constTables ⟨j.val, h⟩
      else
        c.sigmaTables ⟨j.val - c.numConstants, by omega⟩

/-- 3 つの sumcheck 点 (§4.4 の表の順): 0 = r_gate, 1 = r_inv, 2 = r_h。 -/
abbrev PointIdx := Fin 3

/-- 証明 π (§5.2 step 14)。
    主張評価値 (…Evals) は §5.3 step 7 の「batched_claim の分解 +
    r_inv / r_h / r_gate への再構成」の出力に相当する。
    -- UNDERSPECIFIED (paper §5.3 step 7): 「inverse of the multi-point
       batching reduction (linear interpolation of the eq-coefficients …)」
       の正確なアルゴリズムは論文に書かれていない。ここでは
       「prover が 3 点それぞれでの主張評価値を証明に含め、batching sumcheck
       + PCS 検証がそれらを束縛する」という §4.4 の記述に忠実な形で
       モデル化する。実装 (verifier.rs) の実際の分解方式は段階2で対照する。 -/
structure MleProof (F : Type) [Field F] (c : Circuit F)
    (P : ProtocolPCS F c.n c.numConstants c.numRouted c.numWires) where
  witnessRoot : P.ComW
  inverseRoot : P.ComI
  /-- Φ_inv のラウンド多項式列 (§5.2 step 9)。 -/
  scInv : List (Poly F)
  /-- Φ_h のラウンド多項式列 (§5.2 step 10)。 -/
  scH : List (Poly F)
  /-- Φ_gate のラウンド多項式列 (§5.2 step 11)。 -/
  scGate : List (Poly F)
  /-- batching sumcheck のラウンド多項式列 (§5.2 step 12)。 -/
  scBatch : List (Poly F)
  /-- w_j の主張評価値: 3 点すべてで必要 (§4.4 の表)。 -/
  wEvals : PointIdx → Fin c.numWires → F
  /-- const_j の主張評価値: r_gate のみ (§4.4 の表)。 -/
  constEvals : Fin c.numConstants → F
  /-- σ_j の主張評価値: r_inv, r_h (§4.4 の表)。
      index 0 = r_inv, 1 = r_h。 -/
  sigmaEvals : Fin 2 → Fin c.numRouted → F
  /-- a_j の主張評価値: r_inv, r_h。 -/
  aEvals : Fin 2 → Fin c.numRouted → F
  /-- b_j の主張評価値: r_inv, r_h。 -/
  bEvals : Fin 2 → Fin c.numRouted → F
  /-- r_open における列ごとの主張評価値 (PCS verify に渡すもの)。 -/
  openEvalsP : Fin (c.numConstants + c.numRouted) → F
  openEvalsW : Fin c.numWires → F
  openEvalsI : Fin (c.numRouted + c.numRouted) → F
  evalProof : P.Prf

/-! ## 終端チェックの述語 (§4.1, §4.2.2, §4.2.3) -/

/-- combined constraint Σ_j α^j c_j(wires, consts) (§4.1 formula)。 -/
def combinedConstraint (c : Circuit F) (α : F)
    (wires : Fin c.numWires → F) (consts : Fin c.numConstants → F) : F :=
  (c.constraints.enum.map (fun (j, cj) => fpow α j * cj wires consts)).foldr (· + ·) 0

/-- g_sub の論文の閉形式 (§4.2.2):
      g_sub(r) := MLE(b ↦ ω^b)(r) = Σ_i r_i · ω^{2^i}
    -- SUSPICION (paper §4.2.2): この閉形式は誤りの疑いが強い。
       ω^b = Π_i (ω^{2^i})^{b_i} の MLE は各変数のアフィン因子の積
         Π_i ((1 - r_i) + r_i · ω^{2^i})
       になるはず (下の gSubMle)。Σ 形式は b の 1 点でしか一致しない。
       予備対照済み (2026-07-06): Rust 実装 mle/src/verifier.rs L466-469 は
         factor = (1 - r_i) + r_i * g_pow_i の積 (= gSubMle)
       を実装しており、論文 §4.2.2 の Σ 閉形式は**仕様書側の誤記**。
       所見として REPORT.md に記録予定 (深刻度: 仕様文書バグ、実装は正)。
       検証者定義には監査方針どおり論文の式 (gSubPaper) をそのまま使い、
       段階3の completeness 証明がここで破綻することを確認する。 -/
def gSubPaper (c : Circuit F) (r : Vec F c.n) : F :=
  fsum c.n (fun i => r i * c.subgroupGenPowers i)

/-- MLE(b ↦ ω^b)(r) の数学的に正しい閉形式 (比較対象として定義)。 -/
def gSubMle (c : Circuit F) (r : Vec F c.n) : F :=
  vprod c.n (fun i => (1 - r i) + r i * c.subgroupGenPowers i)

/-- inverse zero-check の終端予測値 pred_inv (§4.2.2):
    eq(τ_inv, r_inv) · Σ_j λ^j ( [a_j·(β + w_j + γ·K_j·g_sub) − 1]
                               + μ·[b_j·(β + w_j + γ·s_j) − 1] )。
    w_j, s_j, a_j, b_j は r_inv における主張評価値。 -/
def predInv (c : Circuit F) (hWR : c.numRouted ≤ c.numWires)
    (τinv rinv : Vec F c.n) (β γ lam μ : F)
    (wAt : Fin c.numWires → F) (sAt aAt bAt : Fin c.numRouted → F) : F :=
  let gsub := gSubPaper c rinv
  eqPoly τinv rinv *
    fsum c.numRouted (fun j =>
      let wj := wAt ⟨j.val, Nat.lt_of_lt_of_le j.isLt hWR⟩
      fpow lam j.val *
        ((aAt j * (β + wj + γ * (c.cosetShifts j * gsub)) - 1)
          + μ * (bAt j * (β + wj + γ * sAt j) - 1)))

/-- linear H-sumcheck の終端予測値 pred_h (§4.2.3):
    Σ_j λ_h^j (a_j(r_h) − b_j(r_h))。 -/
def predH (WR : Nat) (lamH : F) (aAt bAt : Fin WR → F) : F :=
  fsum WR (fun j => fpow lamH j.val * (aAt j - bAt j))

/-- gate zero-check の終端予測値 pred_gate (§4.1):
    eq(τ, r_gate) · Σ_j α^j c_j(w(r_gate), const(r_gate))。 -/
def predGate (c : Circuit F) (τ rGate : Vec F c.n) (α : F)
    (wAt : Fin c.numWires → F) (constAt : Fin c.numConstants → F) : F :=
  eqPoly τ rGate * combinedConstraint c α wAt constAt

/-! ## 検証者 (§5.3) -/

/-- リストを Vec へ (長さ検査は呼び出し側)。 -/
def listToVec (l : List F) (n : Nat) : Vec F n :=
  fun i => l.getD i.val 0

/-- 検証者 (§5.3 steps 1–11)。受理なら true。
    チャレンジ導出順序は §5.2/§5.3 と §5.4 のラベルに忠実に従う。 -/
def mleVerify (c : Circuit F)
    (P : ProtocolPCS F c.n c.numConstants c.numRouted c.numWires)
    (hWR : c.numRouted ≤ c.numWires)
    (ro : FSOracle F)
    (vk : VerifyingKey F c P)
    (proof : MleProof F c P)
    (publicInputs : List F) : Bool :=
  -- step 1: transcript 再構築 (§5.3 step 1, ラベルは §5.4)
  let log : TranscriptLog F := []
  let log := absorbLabeled log .circuitDigest (.bytes [vk.circuitDigest])
  let log := absorbLabeled log .publicInputs
    (.bytes (publicInputs.map (fun _ => 0)))
  -- NOTE: publicInputs の canonical encoding は CanonicalEncoding で
  -- 精密化予定 (段階2)。ここではログの順序のみが本質。
  let log := publicInputs.foldl (fun acc x => absorb acc (.field x)) log
  let log := absorbLabeled log .witnessRoot (.commitment (P.idW proof.witnessRoot))
  -- squeeze β, γ (§5.2 step 5)
  let log := absorb log (.label .logupChallenges)
  let (β, log) := squeeze1 ro log
  let (γ, log) := squeeze1 ro log
  -- absorb inverse_root (§5.2 step 7)
  let log := absorbLabeled log .inverseRoot (.commitment (P.idI proof.inverseRoot))
  -- squeeze α, λ, μ, λ_h, τ, τ_inv (§5.2 step 8)
  let log := absorb log (.label .constraintChals)
  let (α, log) := squeeze1 ro log
  let (lam, log) := squeeze1 ro log
  let (μ, log) := squeeze1 ro log
  let (lamH, log) := squeeze1 ro log
  let (τ, log) := squeezeVec ro log c.n
  let (τinv, log) := squeezeVec ro log c.n
  -- step 3: inverse zero-check sumcheck、次数境界 3 (§5.3 step 3)
  match sumcheckVerifyFS ro 3 .sumcheckInv 0 proof.scInv log with
  | none => false
  | some (snInv, rInvList, log) =>
  -- step 4: linear H-sumcheck、次数境界 1 (§5.3 step 4)
  match sumcheckVerifyFS ro 1 .sumcheckH 0 proof.scH log with
  | none => false
  | some (snH, rHList, log) =>
  -- step 5: gate zero-check sumcheck、次数境界 1 + d (§5.3 step 5)
  match sumcheckVerifyFS ro (1 + c.maxGateDegree) .sumcheckGate 0 proof.scGate log with
  | none => false
  | some (snGate, rGateList, log) =>
  -- ラウンド数 = n の検査 (§2.4: n ラウンド)
  if rInvList.length ≠ c.n ∨ rHList.length ≠ c.n ∨ rGateList.length ≠ c.n then
    false
  else
  let rInv := listToVec rInvList c.n
  let rH := listToVec rHList c.n
  let rGate := listToVec rGateList c.n
  -- step 6: batching sumcheck (§4.4, §5.3 step 6)。ν_1, ν_2 を squeeze。
  let log := absorb log (.label .batchOpen)
  let (ν₁, log) := squeeze1 ro log
  let (ν₂, log) := squeeze1 ro log
  -- 列結合チャレンジ ρ。
  -- UNDERSPECIFIED (paper §4.4/§5.3 step 6): 複数の列 P を単一の batching
  -- sumcheck にまとめる方法 (列ごとの結合スカラー) が論文に明記されていない。
  -- §4.3 末尾の "per-vector batching scalars derived from the transcript" に
  -- 従い、追加チャレンジ ρ による冪結合と解釈してモデル化する。
  -- 実装の実際の方式は段階2で対照し、この解釈が違えばここを引き直す。
  let (ρ, log) := squeeze1 ro log
  -- batching sumcheck の初期主張 (§4.4):
  --   Σ_cols ρ^col ( ν₁·P(r_inv) + ν₂·P(r_h) + P(r_gate) )
  -- を、証明中の主張評価値から構成する。§4.4 の表の点対応:
  --   witness w: r_gate, r_inv, r_h / const: r_gate / σ: r_inv, r_h /
  --   a, b: r_inv, r_h。表にない (列, 点) の組は 0 扱い。
  let C := c.numConstants
  let WR := c.numRouted
  let W := c.numWires
  let colClaim : Nat → F := fun col =>
    if h : col < C then
      -- const 列: r_gate のみ
      proof.constEvals ⟨col, h⟩
    else if h2 : col < C + WR then
      -- σ 列: ν₁·σ(r_inv) + ν₂·σ(r_h)
      let j : Fin WR := ⟨col - C, by omega⟩
      ν₁ * proof.sigmaEvals 0 j + ν₂ * proof.sigmaEvals 1 j
    else if h3 : col < C + WR + W then
      -- witness 列: r_gate, r_inv, r_h の3点
      let j : Fin W := ⟨col - C - WR, by omega⟩
      proof.wEvals 0 j + ν₁ * proof.wEvals 1 j + ν₂ * proof.wEvals 2 j
    else if h4 : col < C + WR + W + WR then
      -- a 列: r_inv, r_h
      let j : Fin WR := ⟨col - C - WR - W, by omega⟩
      ν₁ * proof.aEvals 0 j + ν₂ * proof.aEvals 1 j
    else if h5 : col < C + WR + W + WR + WR then
      -- b 列: r_inv, r_h
      let j : Fin WR := ⟨col - C - WR - W - WR, by omega⟩
      ν₁ * proof.bEvals 0 j + ν₂ * proof.bEvals 1 j
    else 0
  let totalCols := C + WR + W + WR + WR
  let batchClaim : F :=
    fsum totalCols (fun col => fpow ρ col.val * colClaim col.val)
  -- batching sumcheck、次数境界 1 (§4.4 "degree 1")
  -- SUSPICION (paper §4.4, §7.3): batching sumcheck の被和項は
  --   [ν₁·eq(r_inv,b) + ν₂·eq(r_h,b) + eq(r_gate,b)] · P(b)
  -- で、eq も P も b について多重線形なので積は変数あたり次数 2 のはず。
  -- 論文が "degree 1" と主張しているのは誤りの疑い。ここでは論文どおり
  -- 次数境界 1 で検証者を定義し、段階3の completeness 証明が
  -- この境界で破綻するかを確認する (破綻すれば論文のバグ)。
  match sumcheckVerifyFS ro 1 .batchOpen batchClaim proof.scBatch log with
  | none => false
  | some (snBatch, rOpenList, _log) =>
  if rOpenList.length ≠ c.n then false
  else
  let rOpen := listToVec rOpenList c.n
  -- step 7: PCS verify at r_open (§5.3 step 7)
  if P.verify vk.preprocessedRoot proof.witnessRoot proof.inverseRoot rOpen
      proof.openEvalsP proof.openEvalsW proof.openEvalsI proof.evalProof
    = false then false
  else
  -- step 6/7 の接続: batching sumcheck の終端検査。
  -- 終端値は [ν₁·eq(r_inv,r_open) + ν₂·eq(r_h,r_open) + eq(r_gate,r_open)]
  -- と r_open での PCS-bound 評価値から再構成する (§4.4)。
  let eqInv := eqPoly rInv rOpen
  let eqH := eqPoly rH rOpen
  let eqGate := eqPoly rGate rOpen
  let openColEval : Nat → F := fun col =>
    if h : col < C then
      eqGate * proof.openEvalsP ⟨col, by omega⟩
    else if h2 : col < C + WR then
      (ν₁ * eqInv + ν₂ * eqH) * proof.openEvalsP ⟨col, by omega⟩
    else if h3 : col < C + WR + W then
      (eqGate + ν₁ * eqInv + ν₂ * eqH) * proof.openEvalsW ⟨col - C - WR, by omega⟩
    else if h4 : col < C + WR + W + WR + WR then
      (ν₁ * eqInv + ν₂ * eqH) * proof.openEvalsI ⟨col - C - WR - W, by omega⟩
    else 0
  let predBatch : F :=
    fsum totalCols (fun col => fpow ρ col.val * openColEval col.val)
  if snBatch ≠ predBatch then false
  else
  -- step 8: inverse terminal (§5.3 step 8, 式は §4.2.2)
  let pInv := predInv c hWR τinv rInv β γ lam μ
    (fun j => proof.wEvals 1 j)          -- w_j(r_inv)
    (fun j => proof.sigmaEvals 0 j)      -- σ_j(r_inv)
    (fun j => proof.aEvals 0 j)          -- a_j(r_inv)
    (fun j => proof.bEvals 0 j)          -- b_j(r_inv)
  if snInv ≠ pInv then false
  else
  -- step 9: linear H terminal (§5.3 step 9, 式は §4.2.3)
  let pH := predH c.numRouted lamH
    (fun j => proof.aEvals 1 j)          -- a_j(r_h)
    (fun j => proof.bEvals 1 j)          -- b_j(r_h)
  if snH ≠ pH then false
  else
  -- step 10: gate terminal (§5.3 step 10, 式は §4.1)
  let pGate := predGate c τ rGate α
    (fun j => proof.wEvals 0 j)          -- w_j(r_gate)
    proof.constEvals                     -- const_j(r_gate)
  if snGate ≠ pGate then false
  else
    -- step 11: accept
    true

end Audit
