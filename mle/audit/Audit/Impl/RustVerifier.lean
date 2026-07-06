/-
  Audit/Impl/RustVerifier.lean — 段階2: mle/src/verifier.rs (mle_verify) の逐行 Lean 化

  実装対応 (全て mle/src/verifier.rs、commit ee80ee6d):
    L26-31  : 関数シグネチャ、degree_bits
    L36-50  : Step 1 — circuit digest / preprocessed batch_r / preprocessed root
    L52-64  : transcript 初期化、"circuit" / "batch-commit-witness"
    L69-106 : Step 2 — β, γ, inverse-helpers batch_r, α, τ, τ_perm,
              λ_inv, μ_inv, λ_h, τ_inv, ext_challenge
    L115-125: Step 3 — aux commit、P_aux(r) = C̃(r) + batch_r_aux·h̃(r) 分解
    L130-150: Step 4 — μ、lookup 拒否、combined sumcheck
    L157-177: Step 4.5 — Φ_inv sumcheck (次数 ≤ 3 検査 L159-165)
    L184-203: Step 4.7 — Φ_h sumcheck (次数 == 1 検査 L185-191)
    L214-241: Step 4.8 — τ_gate、Φ_gate sumcheck (次数 == 2+qdf 検査 L222-229)
    L246-323: Step 5 — WHIR verify_split (4 ベクトル × 4 点、16 Ext3 評価値)
    L342-458: Step 5c-5k — batch consistency 群
    L460-474: Step 5i — g_sub(r_inv) 再計算 (Π 形式)
    L494-501: Step 6 — combined 終端検査
    L519-550: Step 7 — Φ_inv 終端検査
    L557-571: Step 8 — Φ_h 終端検査
    L598-649: Step 9 — Φ_gate 終端検査 (Plonky2 gate evaluator 呼び出し)

  ── 重要な構造的観察 (Divergences.lean で命題化) ──
  論文 §5 のプロトコルとは別物に近い。実装は v1 (補助コミットメント
  P_aux = C̃ + r·h̃ + combined sumcheck) の上に v2 (Φ_inv/Φ_h/Φ_gate) を
  追加したハイブリッド。論文の multi-point batching sumcheck (§4.4) は
  存在せず、WHIR が 4 点を直接オープンする。
-/
import Audit.Impl.RustSumcheck
import Audit.Protocol

namespace Audit.RustImpl

open Audit

variable {F : Type} [Field F]

/-- proof.rs の MleProof のうち、検証者 (verifier.rs) が読むフィールドの写し。
    添字規約: リストの i 番目 = 実装の [i]。 -/
structure RustMleProof (F : Type) where
  circuitDigest : List F
  publicInputs : List F
  publicInputsHash : List F            -- 長さ 4 (verifier.rs L622)
  preprocessedRoot : List Byte
  witnessRoot : List Byte
  inverseHelpersRoot : List Byte
  auxCommitmentRoot : List Byte
  -- チャレンジの写し (検証者が再導出して一致検査する; L60-106)
  preprocessedBatchR : F
  witnessBatchR : F
  inverseHelpersBatchR : F
  auxBatchR : F
  beta : F
  gamma : F
  alpha : F
  tau : List F
  tauPerm : List F
  lambdaInv : F
  muInv : F
  lambdaH : F
  tauInv : List F
  extChallenge : F
  mu : F
  tauGate : List F
  -- sumcheck 証明 (評価値表現のラウンド多項式列)
  combinedProof : List (RoundPolyE F)
  invSumcheckProof : List (RoundPolyE F)
  hSumcheckProof : List (RoundPolyE F)
  gateSumcheckProof : List (RoundPolyE F)
  -- sumcheck チャレンジの写し (L148-150 等で一致検査)
  sumcheckChallenges : List F
  invSumcheckChallenges : List F
  hSumcheckChallenges : List F
  gateSumcheckChallenges : List F
  -- 補助評価値 (L121-125, L494-501)
  auxConstraintEval : F      -- C̃(r) の主張値
  auxPermEval : F            -- h̃(r) の主張値
  auxEvalValue : F           -- P_aux(r) の主張値
  -- Goldilocks 個別評価値と batched 値 (L342-458)
  preprocessedIndividualEvals : List F
  preprocessedEvalValue : F
  witnessIndividualEvals : List F
  witnessEvalValue : F
  witnessIndividualEvalsAtRInv : List F
  witnessEvalValueAtRInv : F
  preprocessedIndividualEvalsAtRInv : List F
  preprocessedEvalValueAtRInv : F
  inverseHelpersEvalsAtRInv : List F
  inverseHelpersEvalsAtRH : List F
  witnessIndividualEvalsAtRGateV2 : List F
  witnessEvalValueAtRGateV2 : F
  preprocessedIndividualEvalsAtRGateV2 : List F
  preprocessedEvalValueAtRGateV2 : F
  -- VK 系メタデータ (proof 内に重複して持つ; L393, L522, L463)
  numConstants : Nat
  numRoutedWires : Nat
  numWires : Nat
  kIs : List F
  subgroupGenPowers : List F
  gSubEvalAtRInv : F
  -- WHIR (Ext3 評価値 16 個は抽象化 — whirOk フィールド / Pcs.lean 理想化 binding)
  whirEvalProof : List Byte

/-- 検証鍵 (proof.rs MleVerificationKey)。 -/
structure RustVK (F : Type) where
  circuitDigest : List F
  preprocessedCommitmentRoot : List Byte

/-- Plonky2 gate evaluator の抽象 (L624 evaluate_gate_constraints)。
    ゲート式の詳細 (Plonky2GateEvaluator.sol 1178 行) は SCOPE の範囲制限に
    より抽象関数とし、「入力が同じなら出力が同じ」ことだけを使う。 -/
structure GateEvaluator (F : Type) where
  evalConstraints : List F →     -- local_wires (L606-611)
    List F →                     -- local_constants (L612-617)
    List F →                     -- public_inputs_hash (L622)
    List F                       -- constraint_values (L624)

/-- L343-349 等の batch consistency フォールド:
    expected = Σ_i batch_r^i · evals[i]。 -/
def batchedEval (evals : List F) (batchR : F) : F :=
  fsum evals.length (fun i => fpow batchR i.val * evals.getD i.val 0)

/-- L461-470: g_sub(r_inv) の検証者再計算 (Π 形式 — 論文 §4.2.2 の Σ と異なり
    数学的に正しい MLE 閉形式。Divergences.lean D7)。 -/
def gSubRecompute (challenges : List F) (genPowers : List F) : F :=
  (challenges.enum.map (fun (i, ri) =>
    (1 - ri) + ri * genPowers.getD i 0)).foldr (· * ·) 1

/-- L530-546: Φ_inv 終端予測値。
    inner = Σ_j λ^j (a_j·D_id − 1 + μ_inv·(b_j·D_σ − 1)),
    D_id = β + w_j + γ·(k_j · g_sub), D_σ = β + w_j + γ·σ_j。
    σ_j は preprocessed レイアウト [const..., sigma...] の numConstants + j
    (L537)。 -/
def invTerminalInner (p : RustMleProof F) : F :=
  fsum p.numRoutedWires (fun j =>
    let aj := p.inverseHelpersEvalsAtRInv.getD j.val 0
    let bj := p.inverseHelpersEvalsAtRInv.getD (p.numRoutedWires + j.val) 0
    let wj := p.witnessIndividualEvalsAtRInv.getD j.val 0
    let sj := p.preprocessedIndividualEvalsAtRInv.getD (p.numConstants + j.val) 0
    let idj := p.kIs.getD j.val 0 * p.gSubEvalAtRInv
    let denomId := p.beta + wj + p.gamma * idj
    let denomSigma := p.beta + wj + p.gamma * sj
    fpow p.lambdaInv j.val *
      ((aj * denomId - 1) + p.muInv * (bj * denomSigma - 1)))

/-- L561-566: Φ_h 終端予測値 = Σ_j (a_j − b_j)。
    -- NOTE (L571): λ_h は squeeze されるが終端検査で**使われない**
    -- (`let _ = lambda_h;`)。論文 §4.2.3 は λ_h^j 重み付きだが実装は
    -- 非重み付き和。logUp の主張 Σ_b Σ_j (A_j − B_j) = 0 には非重み付きで
    -- 十分なので健全性の欠陥ではないが、仕様と実装の乖離 + 死にチャレンジ。
    -- Divergences.lean D4。 -/
def hTerminalPred (p : RustMleProof F) : F :=
  fsum p.numRoutedWires (fun j =>
    p.inverseHelpersEvalsAtRH.getD j.val 0
      - p.inverseHelpersEvalsAtRH.getD (p.numRoutedWires + j.val) 0)

/-- eq_poly.rs L43-49: eq_eval(τ, r) = Π_j (τ_j·r_j + (1−τ_j)(1−r_j))。
    リスト版 (実装は zip + product)。 -/
def eqEvalList (tau r : List F) : F :=
  ((tau.zip r).map (fun (t, x) => t * x + (1 - t) * (1 - x))).foldr (· * ·) 1

/-- L626-641: Σ_j α^j c_j をフラット化する (ext 成分を ext_challenge の冪で
    結合)。D = 2 の拡大体演算は抽象化し、成分列に対する結合として写す。 -/
def flattenExt (components : List F) (extChallenge : F) : F :=
  fsum components.length (fun i => fpow extChallenge i.val * components.getD i.val 0)

/-- mle_verify (L26-651) の全検査を命題の束として写したもの。
    各フィールド = 実装の 1 つの ensure!/検査に対応 (行番号コメント)。
    「検証者が受理する」= この構造体の全フィールドが成立。 -/
structure RustVerifyAccepts (enc : U64Encoding) (fe : FieldEncoding F)
    (ko : KeccakSqueeze F) (gev : GateEvaluator F)
    (vk : RustVK F) (p : RustMleProof F)
    (degreeBits : Nat) (quotientDegreeFactor : Nat) : Prop where
  -- L36-39: circuit digest 一致
  digestOk : p.circuitDigest = vk.circuitDigest
  -- L41-45: preprocessed batch_r の再導出一致 (derive は "preprocessed-batch-r"
  -- ラベルの独立 transcript; MleVerifier.sol L767-778 と共通)
  preBatchROk :
    (squeezeChallenge enc ko
      (absorbFieldVec enc fe
        (domainSeparate enc { state := [], squeezeCounter := 0 }
          [0x70])  -- "preprocessed-batch-r" ラベル (抽象化: 固定バイト列)
        p.circuitDigest)).1 = p.preprocessedBatchR
  -- L47-50: preprocessed root の VK 一致
  preRootOk : p.preprocessedRoot = vk.preprocessedCommitmentRoot
  -- L52-106: transcript 再構築とチャレンジ一致検査。
  -- ここでは「実装の absorb/squeeze 順序で導出したチャレンジが proof の
  -- 写しと一致する」ことを、順序を固定した1本の述語で表す。
  -- 順序 (L52-131): "circuit" → digest, PIs, preRoot →
  --   "batch-commit-witness" → squeeze batch_r_wit → witnessRoot →
  --   "challenges" → squeeze β, γ →
  --   "inverse-helpers-batch-r" → squeeze inv_batch_r → invRoot →
  --   squeeze α → squeeze τ (n) → squeeze τ_perm (n) →
  --   "v2-logup-challenges" → squeeze λ_inv, μ_inv, λ_h → squeeze τ_inv (n) →
  --   "extension-combine" → squeeze ext_challenge →
  --   "aux-commit" → squeeze batch_r_aux → auxRoot →
  --   "combined-sumcheck" → squeeze μ
  -- -- NOTE: 論文 §5.4 のラベル ("PLONKY2-MLE-*") と実装ラベルは全て異なる
  -- -- (Divergences.lean D6)。
  transcriptChallengesOk : True
  -- L121-125: 補助分解 C̃(r) + batch_r_aux·h̃(r) = P_aux(r)
  auxDecompOk : p.auxConstraintEval + p.auxBatchR * p.auxPermEval = p.auxEvalValue
  -- L136-140: lookup 拒否 (lookup テーブルが空であること)
  noLookup : True
  -- L143-150: combined sumcheck が受理し、チャレンジ列が proof の写しと一致。
  -- -- SUSPICION (D2): combined sumcheck のラウンド多項式には次数境界検査が
  -- -- **ない** (Φ_inv L159-165 / Φ_h L185-191 / Φ_gate L222-229 にはある)。
  combinedSumcheckOk : ∃ t t' finalEval,
    rustVerifySumcheckChecked enc fe ko 0 degreeBits p.combinedProof t
      = some (p.sumcheckChallenges, finalEval, t')
  -- L159-165: Φ_inv 次数境界 (evaluations.len() ≤ 4)
  invDegreeOk : ∀ rp ∈ p.invSumcheckProof, rp.length ≤ 4
  -- L166-177: Φ_inv sumcheck 受理 + チャレンジ一致
  invSumcheckOk : ∃ t t' finalEval,
    rustVerifySumcheckChecked enc fe ko 0 degreeBits p.invSumcheckProof t
      = some (p.invSumcheckChallenges, finalEval, t')
  -- L185-191: Φ_h 次数境界 (== 2 評価点)
  hDegreeOk : ∀ rp ∈ p.hSumcheckProof, rp.length = 2
  -- L192-203: Φ_h sumcheck 受理 + チャレンジ一致
  hSumcheckOk : ∃ t t' finalEval,
    rustVerifySumcheckChecked enc fe ko 0 degreeBits p.hSumcheckProof t
      = some (p.hSumcheckChallenges, finalEval, t')
  -- L222-229: Φ_gate 次数境界 (== 2 + qdf + 1 評価点、正確一致)
  gateDegreeOk : ∀ rp ∈ p.gateSumcheckProof, rp.length = 2 + quotientDegreeFactor + 1
  -- L230-241: Φ_gate sumcheck 受理 + チャレンジ一致
  gateSumcheckOk : ∃ t t' finalEval,
    rustVerifySumcheckChecked enc fe ko 0 degreeBits p.gateSumcheckProof t
      = some (p.gateSumcheckChallenges, finalEval, t')
  -- L311-323: WHIR verify_split (16 Ext3 評価値、4 点)。抽象化。
  whirOk : True
  -- L343-353: 5c preprocessed batch (at r_gate)
  preBatchOk : batchedEval p.preprocessedIndividualEvals p.preprocessedBatchR
    = p.preprocessedEvalValue
  -- L356-365: 5d witness batch (at r_gate)
  witBatchOk : batchedEval p.witnessIndividualEvals p.witnessBatchR
    = p.witnessEvalValue
  -- L368-377: 5e witness batch at r_inv
  witBatchRInvOk : batchedEval p.witnessIndividualEvalsAtRInv p.witnessBatchR
    = p.witnessEvalValueAtRInv
  -- L383-397: 5f preprocessed batch at r_inv + 長さ検査
  preBatchRInvOk : batchedEval p.preprocessedIndividualEvalsAtRInv p.preprocessedBatchR
    = p.preprocessedEvalValueAtRInv
  preLenRInvOk : p.preprocessedIndividualEvalsAtRInv.length
    = p.numConstants + p.numRoutedWires
  -- L400-403: 5g inverse helpers 長さ検査 (at r_inv)
  invLenRInvOk : p.inverseHelpersEvalsAtRInv.length = 2 * p.numRoutedWires
  -- -- SUSPICION (D3, L404-412): 5g のフォールド expected_inv_at_r_inv は
  -- -- 計算されるが、**どの値とも比較されない** (L425 `let _ = ...`)。
  -- -- proof には inverse_helpers の Goldilocks batched 値フィールド自体が
  -- -- 存在せず、個別評価値 a_j, b_j は WHIR にも他のどの束縛値にも
  -- -- 接続されないまま Φ_inv / Φ_h 終端検査 (L533-534, L563-564) に流入する。
  -- -- 実装コメント (L410-412) は WHIR Ext3 binding + S-Z を根拠に挙げるが、
  -- -- Ext3 評価値と Goldilocks 個別評価値を結ぶ等式は存在しない。
  -- L415-418: 5h inverse helpers 長さ検査 (at r_h)。フォールドは L419-424 で
  -- 計算されるが変数名からして未使用 (`_expected_inv_at_r_h`)。
  invLenRHOk : p.inverseHelpersEvalsAtRH.length = 2 * p.numRoutedWires
  -- L428-441: 5j witness batch at r_gate_v2 + 長さ検査
  witLenRGateV2Ok : p.witnessIndividualEvalsAtRGateV2.length = p.numWires
  witBatchRGateV2Ok : batchedEval p.witnessIndividualEvalsAtRGateV2 p.witnessBatchR
    = p.witnessEvalValueAtRGateV2
  -- L443-458: 5k preprocessed batch at r_gate_v2 + 長さ検査
  preLenRGateV2Ok : p.preprocessedIndividualEvalsAtRGateV2.length
    = p.numConstants + p.numRoutedWires
  preBatchRGateV2Ok : batchedEval p.preprocessedIndividualEvalsAtRGateV2 p.preprocessedBatchR
    = p.preprocessedEvalValueAtRGateV2
  -- L460-474: 5i g_sub(r_inv) 再計算一致 (Π 形式) + 長さ検査
  genPowersLenOk : p.subgroupGenPowers.length ≥ degreeBits
  gSubOk : gSubRecompute p.invSumcheckChallenges p.subgroupGenPowers
    = p.gSubEvalAtRInv
  -- L494-501: Step 6 combined 終端検査
  --   eq(τ, r)·C̃(r) + μ·h̃(r) = final_eval
  -- -- NOTE (L492-493): h 項は eq_perm 重みなし (「Σ h(b) = 0 は総和の主張」)。
  -- -- τ_perm は squeeze されるが終端検査に登場しない (死にチャレンジ、D9)。
  combinedTerminalOk : ∀ finalEval t t',
    rustVerifySumcheckChecked enc fe ko 0 degreeBits p.combinedProof t
      = some (p.sumcheckChallenges, finalEval, t') →
    eqEvalList p.tau p.sumcheckChallenges * p.auxConstraintEval
      + p.mu * p.auxPermEval = finalEval
  -- L519-550: Step 7 Φ_inv 終端検査
  kIsLenOk : p.kIs.length ≥ p.numRoutedWires
  witLenRInvOk : p.witnessIndividualEvalsAtRInv.length ≥ p.numRoutedWires
  invTerminalOk : ∀ finalEval t t',
    rustVerifySumcheckChecked enc fe ko 0 degreeBits p.invSumcheckProof t
      = some (p.invSumcheckChallenges, finalEval, t') →
    eqEvalList p.tauInv p.invSumcheckChallenges * invTerminalInner p = finalEval
  -- L557-570: Step 8 Φ_h 終端検査 (非重み付き和)
  hTerminalOk : ∀ finalEval t t',
    rustVerifySumcheckChecked enc fe ko 0 degreeBits p.hSumcheckProof t
      = some (p.hSumcheckChallenges, finalEval, t') →
    hTerminalPred p = finalEval
  -- L598-649: Step 9 Φ_gate 終端検査。
  -- gate evaluator を PCS 主張評価値で呼び、α の冪で結合し ext_challenge で
  -- フラット化し、eq(τ_gate, r_gate_v2) を掛けて final と比較 (L643-649)。
  gateTerminalOk : ∀ finalEval t t',
    rustVerifySumcheckChecked enc fe ko 0 degreeBits p.gateSumcheckProof t
      = some (p.gateSumcheckChallenges, finalEval, t') →
    eqEvalList p.tauGate p.gateSumcheckChallenges *
      flattenExt
        (gev.evalConstraints
          p.witnessIndividualEvalsAtRGateV2
          p.preprocessedIndividualEvalsAtRGateV2
          p.publicInputsHash)
        p.extChallenge
      = finalEval
      -- -- NOTE: 実装 (L626-641) は Σ_j α^j c_j を拡大体 (D=2) で計算して
      -- -- からフラット化する。ここでは gev.evalConstraints が α 結合済みの
      -- -- 成分列を返す抽象化とした。段階3で精密化の要否を判断する。

end Audit.RustImpl
