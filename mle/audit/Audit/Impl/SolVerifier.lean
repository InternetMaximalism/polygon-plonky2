/-
  Audit/Impl/SolVerifier.lean — 段階2: mle/contracts/src/MleVerifier.sol の逐行 Lean 化

  実装対応 (全て mle/contracts/src/、commit ee80ee6d):
    MleVerifier.sol L15      : P = 2^64 − 2^32 + 1
    MleVerifier.sol L17-123  : struct MleProof
    MleVerifier.sol L129-145 : struct VerifyParams (VK 相当: kIs, subgroupGenPowers 含む)
    MleVerifier.sol L169-178 : verify() エントリ — gatesDigest (C1) +
                               canonical 検査 (C2) + _verifyCore
    MleVerifier.sol L180-256 : _verifyCore — 4 sumcheck + WHIR + 終端検査群
    MleVerifier.sol L262-281 : _checkInvTerminal
    MleVerifier.sol L294-313 : _checkGateTerminal
    MleVerifier.sol L318-370 : _invInner (Yul)
    MleVerifier.sol L375-404 : _checkHTerminal (Yul; C2 self-reduce 付き)
    MleVerifier.sol L406-426 : _evalSubgroupMle (Π 形式)
    MleVerifier.sol L432-484 : _initTranscriptAndChallenges
    MleVerifier.sol L488-565 : _runBatchAndWhir
    MleVerifier.sol L572-592 : _runGateSumcheckAndTerminal
    MleVerifier.sol L617-650 : computeGatesDigest / _requireGatesDigest (C1)
    MleVerifier.sol L663-763 : _requireCanonicalProofInputs (C2)
    MleVerifier.sol L767-778 : _derivePreprocessedBatchR
    MleVerifier.sol L780-793 : _computeBatchedEval
    SumcheckVerifier.sol L32-77 : verify (次数境界 require 付き — Rust との差)
    GoldilocksField.sol      : mod P 演算 (uint256 上の addmod/mulmod)

  ── 表現域の扱い ──
  Solidity の値は uint256。C2 修正 (L663-763) により、検証に使われる
  prover 供給配列は全て P 未満 (canonical) がエントリで強制される。
  そのため本モデルでは「canonical 検査に通った後」の値を体 F の要素として
  扱い、canonical 検査自体を明示的な前提条件として分離する。
  phase2_c2_poc_report.md が示した非 canonical 注入 (K = 2^256 mod P) は
  この前提が**ない**場合の攻撃であり、canonicalOk が実装に存在することが
  その修正の形式的対応物である。
-/
import Audit.Impl.RustVerifier

namespace Audit.SolImpl

open Audit
open Audit.RustImpl

variable {F : Type} [Field F]

/-- MleVerifier.sol L17-123: struct MleProof の検証者可視フィールド。
    Rust 側 (RustMleProof) との構造差分:
    - tau / tauPerm / extChallenge の**写しを持たない** (L40-43 の SECURITY
      note: transcript から再導出のみ。Rust は proof に写しを持ち一致検査)。
    - sumcheck チャレンジの写しも持たない (再導出のみ)。
    - inverse helpers の batched 値フィールドは存在しない (Rust も同様)。 -/
structure SolMleProof (F : Type) where
  circuitDigest : List F                      -- L18 (長さ 4 検査は L185)
  preprocessedRoot : List Byte                -- L21
  witnessRoot : List Byte                     -- L22
  auxCommitmentRoot : List Byte               -- L23
  inverseHelpersCommitmentRoot : List Byte    -- L61
  preprocessedEvalValue : F                   -- L24
  preprocessedBatchR : F                      -- L25
  preprocessedIndividualEvals : List F        -- L26
  witnessEvalValue : F                        -- L27
  witnessBatchR : F                           -- L28
  witnessIndividualEvals : List F             -- L29
  auxBatchR : F                               -- L30
  auxConstraintEval : F                       -- L31
  auxPermEval : F                             -- L32
  auxEvalValue : F                            -- L33
  combinedProof : List (RoundPolyE F)         -- L34
  publicInputs : List F                       -- L35
  alpha : F                                   -- L36
  beta : F                                    -- L37
  gamma : F                                   -- L38
  mu : F                                      -- L39
  inverseHelpersBatchR : F                    -- L62
  invSumcheckProof : List (RoundPolyE F)      -- L63
  hSumcheckProof : List (RoundPolyE F)        -- L64
  lambdaInv : F                               -- L65
  muInv : F                                   -- L66
  lambdaH : F                                 -- L67
  witnessIndividualEvalsAtRInv : List F       -- L76
  preprocessedIndividualEvalsAtRInv : List F  -- L77
  inverseHelpersEvalsAtRInv : List F          -- L78
  inverseHelpersEvalsAtRH : List F            -- L80
  gSubEvalAtRInv : F                          -- L83
  witnessEvalValueAtRInv : F                  -- L85
  preprocessedEvalValueAtRInv : F             -- L86
  extChallenge : F                            -- L104
  gateSumcheckProof : List (RoundPolyE F)     -- L105
  witnessIndividualEvalsAtRGateV2 : List F    -- L109
  preprocessedIndividualEvalsAtRGateV2 : List F -- L110
  witnessEvalValueAtRGateV2 : F               -- L111
  preprocessedEvalValueAtRGateV2 : F          -- L112
  quotientDegreeFactor : Nat                  -- L118
  numSelectors : Nat                          -- L119
  numGateConstraints : Nat                    -- L120
  publicInputsHash : List F                   -- L122 (長さ 4)

/-- MleVerifier.sol L129-145: VerifyParams (VK 相当、caller 供給)。
    -- NOTE (L140-142): kIs と subgroupGenPowers は「回路の VK と整合する値で
    -- なければならない」が transcript には束縛されない (公開回路定数として
    -- caller の責任)。オンチェーン運用では呼び出しラッパが固定することが
    -- 前提 — これは信頼仮定であり SCOPE.md の仮定一覧に該当。 -/
structure SolVerifyParams (F : Type) where
  degreeBits : Nat
  preprocessedCommitmentRoot : List Byte
  numConstants : Nat
  numRoutedWires : Nat
  kIs : List F
  subgroupGenPowers : List F

/-- C2 canonical 検査 (MleVerifier.sol L663-763):
    prover 供給の全 uint256 配列が P 未満であること。
    モデル上は「uint256 → F の変換が well-defined」の前提に対応。
    検査対象 (L667-681): preprocessedIndividualEvals, witnessIndividualEvals,
    preprocessedIndividualEvalsAtRInv, witnessIndividualEvalsAtRInv,
    inverseHelpersEvalsAtRInv, inverseHelpersEvalsAtRH,
    witnessIndividualEvalsAtRGateV2, preprocessedIndividualEvalsAtRGateV2,
    circuitDigest, publicInputs, publicInputsHash。
    -- NOTE: sumcheck ラウンド多項式の evals (combinedProof 等) は
    -- この canonical 検査の対象に**含まれていない**。TranscriptLib の
    -- absorbFieldVec (L100-102) の require(elems[i] < P) が吸収時に検査する
    -- ため到達不能ではないが、防御線が異なる。段階4で網羅性を再確認する。 -/
def canonicalOk (_p : SolMleProof F) : Prop := True
  -- 体 F で書いた本モデルでは構成的に真。uint256 モデルへ落とすときの
  -- 前提条件のプレースホルダとして命名だけ固定する。

/-- C1 gates digest 検査 (MleVerifier.sol L617-650):
    ゲートレイアウトメタデータ (gates, numWires, numSelectors,
    numGateConstraints, qdf) の keccak が caller 供給の gatesDigest と一致。
    phase3_c1_threat_model.md の gate-reinterpretation 偽造への対策。
    ハッシュは抽象化し「メタデータが期待値と一致」で写す。 -/
structure GatesDigestBinding (F : Type) where
  expectedNumWires : Nat
  expectedNumSelectors : Nat
  expectedNumGateConstraints : Nat
  expectedQdf : Nat

def gatesDigestOk (gd : GatesDigestBinding F) (p : SolMleProof F) : Prop :=
  p.witnessIndividualEvalsAtRGateV2.length = gd.expectedNumWires ∧
  p.numSelectors = gd.expectedNumSelectors ∧
  p.numGateConstraints = gd.expectedNumGateConstraints ∧
  p.quotientDegreeFactor = gd.expectedQdf

/-- MleVerifier.sol L406-426: _evalSubgroupMle — Π_i ((1−r_i) + r_i·g^{2^i})。
    Rust (verifier.rs L461-470) と同一 (gSubRecompute を再利用)。 -/
def solEvalSubgroupMle (r gPow : List F) : F := gSubRecompute r gPow

/-- MleVerifier.sol L318-370 (_invInner) の Φ_inv 終端内側和。
    Rust `invTerminalInner` と同一式だが VK 由来の値 (numRoutedWires,
    numConstants, kIs) は VerifyParams から取る。 -/
def solInvInner (p : SolMleProof F) (vp : SolVerifyParams F) : F :=
  fsum vp.numRoutedWires (fun j =>
    let aj := p.inverseHelpersEvalsAtRInv.getD j.val 0
    let bj := p.inverseHelpersEvalsAtRInv.getD (vp.numRoutedWires + j.val) 0
    let wj := p.witnessIndividualEvalsAtRInv.getD j.val 0
    let sj := p.preprocessedIndividualEvalsAtRInv.getD (vp.numConstants + j.val) 0
    let idj := vp.kIs.getD j.val 0 * p.gSubEvalAtRInv
    let denomId := p.beta + wj + p.gamma * idj
    let denomSigma := p.beta + wj + p.gamma * sj
    fpow p.lambdaInv j.val *
      ((aj * denomId - 1) + p.muInv * (bj * denomSigma - 1)))

/-- MleVerifier.sol L375-404 (_checkHTerminal) の Φ_h 終端和 = Σ_j (a_j − b_j)。 -/
def solHPred (p : SolMleProof F) (vp : SolVerifyParams F) : F :=
  fsum vp.numRoutedWires (fun j =>
    p.inverseHelpersEvalsAtRH.getD j.val 0
      - p.inverseHelpersEvalsAtRH.getD (vp.numRoutedWires + j.val) 0)

/-- 検証者が transcript から**再導出**する値の束 (MleVerifier.sol は proof に
    これらの写しを持たない: R2-#5 で proof.tau を削除、tauPerm は読み捨て)。
    終端検査をこれらに固定するために明示パラメータ化する。実際の run では
    _initTranscriptAndChallenges / 各 sumcheck が生成する値に対応。 -/
structure SolDerived (F : Type) where
  tau : List F        -- L460 squeezeChallenges(degreeBits)
  tauInv : List F     -- L467
  tauGate : List F    -- L578
  rGate : List F      -- combined sumcheck 出力点 (L195)
  rInv : List F       -- Φ_inv 出力点 (L201)
  rH : List F         -- Φ_h 出力点 (L207)
  rGateV2 : List F    -- Φ_gate 出力点 (L216)
  combinedFinal : F   -- L195 gateFinal
  invFinal : F        -- L201 invFinal
  hFinal : F          -- L207 hFinal
  gateFinal : F       -- Φ_gate 終端値 (L582 gateFinalV2)

/-- verify() (L169-178) + _verifyCore (L180-256) の全検査の束。
    Rust 版 (RustVerifyAccepts) との差分は Divergences.lean 参照。
    `sd` は検証者が transcript から再導出する値 (上記) を表す。 -/
structure SolVerifyAccepts (enc : U64Encoding) (fe : FieldEncoding F)
    (ko : KeccakSqueeze F) (gev : GateEvaluator F)
    (gd : GatesDigestBinding F)
    (vp : SolVerifyParams F) (p : SolMleProof F) (sd : SolDerived F) : Prop where
  -- L175: C1 gates digest
  c1Ok : gatesDigestOk gd p
  -- L176: C2 canonical (uint256 モデルでの前提条件)
  c2Ok : canonicalOk p
  -- L185: circuitDigest.length == 4
  digestLenOk : p.circuitDigest.length = 4
  -- L187: preprocessedRoot == vp.preprocessedCommitmentRoot (VK binding)
  preRootOk : p.preprocessedRoot = vp.preprocessedCommitmentRoot
  -- L432-484: transcript 再構築 + チャレンジ一致検査。squeeze 順序の忠実
  -- モデル化は段階3の Sol トレース関数に委ねる (Rust の transcriptChallengesOk
  -- と同じく抽象。順序自体は Divergences D6 で Rust と一致を確認済み)。
  -- 再導出束 sd の各点の長さ = degreeBits を最低限固定する。
  derivedLenOk : sd.rGate.length = vp.degreeBits ∧ sd.rInv.length = vp.degreeBits ∧
    sd.rH.length = vp.degreeBits ∧ sd.rGateV2.length = vp.degreeBits ∧
    sd.tau.length = vp.degreeBits ∧ sd.tauInv.length = vp.degreeBits ∧
    sd.tauGate.length = vp.degreeBits
  -- L477-479: aux 分解 (Rust L121-125 と同一式)
  auxDecompOk : p.auxConstraintEval + p.auxBatchR * p.auxPermEval = p.auxEvalValue
  -- L193-196: combined sumcheck、**次数境界 2 を明示的に渡す** (D2: Rust には無い)。
  combinedDegreeOk : solRoundPolyBounds 2 p.combinedProof
  -- 実体化: 格納 round poly 列が主張和 0 の各ラウンド検査を chals=rGate で通す。
  combinedSumcheckOk : SumcheckAccepts 0 p.combinedProof sd.rGate
  -- L199-202: Φ_inv sumcheck、次数境界 3
  invDegreeOk : solRoundPolyBounds 3 p.invSumcheckProof
  invSumcheckOk : SumcheckAccepts 0 p.invSumcheckProof sd.rInv
  -- L205-208: Φ_h sumcheck、次数境界 1
  hDegreeOk : solRoundPolyBounds 1 p.hSumcheckProof
  hSumcheckOk : SumcheckAccepts 0 p.hSumcheckProof sd.rH
  -- L577-588: Φ_gate sumcheck、次数境界 2 + qdf
  gateDegreeOk : solRoundPolyBounds (2 + p.quotientDegreeFactor) p.gateSumcheckProof
  gateSumcheckOk : SumcheckAccepts 0 p.gateSumcheckProof sd.rGateV2
  -- L495-499/500-503: pre batch (at r_gate) + 長さ検査
  preBatchOk : batchedEval p.preprocessedIndividualEvals p.preprocessedBatchR
    = p.preprocessedEvalValue
  preLenOk : p.preprocessedIndividualEvals.length = vp.numConstants + vp.numRoutedWires
  -- L504-508: wit batch (at r_gate)
  witBatchOk : batchedEval p.witnessIndividualEvals p.witnessBatchR
    = p.witnessEvalValue
  -- L511-515: pre batch at r_inv
  preBatchRInvOk : batchedEval p.preprocessedIndividualEvalsAtRInv p.preprocessedBatchR
    = p.preprocessedEvalValueAtRInv
  -- L245-249: wit batch at r_inv
  witBatchRInvOk : batchedEval p.witnessIndividualEvalsAtRInv p.witnessBatchR
    = p.witnessEvalValueAtRInv
  -- L541-551: wit/pre batch at r_gate_v2
  witBatchRGateV2Ok : batchedEval p.witnessIndividualEvalsAtRGateV2 p.witnessBatchR
    = p.witnessEvalValueAtRGateV2
  preBatchRGateV2Ok : batchedEval p.preprocessedIndividualEvalsAtRGateV2 p.preprocessedBatchR
    = p.preprocessedEvalValueAtRGateV2
  -- -- SUSPICION (D3): inverse helpers 個別評価値の batch consistency 検査が
  -- -- Solidity には存在しない (長さ検査のみ)。a_j,b_j は WHIR 個別値に非接続。
  -- L553-564: WHIR verify (proof 内の 16 Ext3 評価値、抽象化 — Rust と同様)
  whirOk : True
  -- L232-236: combined 終端検査 eq(τ, r_gate)·C̃(r) + μ·h̃(r) = combinedFinal
  combinedTerminalOk :
    eqEvalList sd.tau sd.rGate * p.auxConstraintEval + p.mu * p.auxPermEval
      = sd.combinedFinal
  -- L239-242: g_sub(r_inv) 一致 (Π 形式)
  gSubOk : solEvalSubgroupMle sd.rInv vp.subgroupGenPowers = p.gSubEvalAtRInv
  -- L252 → L262-281: Φ_inv 終端検査 + 長さ検査
  invLenOk : p.witnessIndividualEvalsAtRInv.length ≥ vp.numRoutedWires ∧
    p.preprocessedIndividualEvalsAtRInv.length = vp.numConstants + vp.numRoutedWires ∧
    p.inverseHelpersEvalsAtRInv.length = 2 * vp.numRoutedWires ∧
    vp.kIs.length ≥ vp.numRoutedWires
  invTerminalOk : eqEvalList sd.tauInv sd.rInv * solInvInner p vp = sd.invFinal
  -- L253 → L375-404: Φ_h 終端検査 (非重み付き Σ_j (a_j − b_j)、λ_h 未使用)
  hLenOk : p.inverseHelpersEvalsAtRH.length = 2 * vp.numRoutedWires
  hTerminalOk : solHPred p vp = sd.hFinal
  -- L591 → L294-313: Φ_gate 終端検査 (Plonky2GateEvaluator.evalCombinedFlat)。
  -- gate evaluator は wire/const(r_gate_v2), publicInputsHash を入力に取る。
  gateTerminalOk :
    eqEvalList sd.tauGate sd.rGateV2 *
      flattenExt
        (gev.evalConstraints
          p.witnessIndividualEvalsAtRGateV2
          p.preprocessedIndividualEvalsAtRGateV2
          p.publicInputsHash)
        p.extChallenge
      = sd.gateFinal

end Audit.SolImpl
