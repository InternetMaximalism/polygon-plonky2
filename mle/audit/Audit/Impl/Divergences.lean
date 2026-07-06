/-
  Audit/Impl/Divergences.lean — 段階2の中心成果物

  「仕様書 ⇔ Rust (mle/src) ⇔ Solidity (mle/contracts)」の三者間の乖離を Lean の
  命題として明文化する。スキルの方針:「実装を解釈・補正せずそのまま写し、疑義は
  命題として残す」。各 Divergence は段階3 (証明で顕在化) と段階4 (深刻度判定) の
  生データ。

  深刻度の凡例 (段階4で確定): Critical / High / Medium / Low / Info / Spec-bug
  (Spec-bug = 実装は正しいが仕様書が誤り)。

  ── 【重要・段階2 補遺 2026-07-06】仕様書の階層 ──
  当初 paper v2 のみを「仕様」としたが、実装により近い定義ドキュメントが
  3 層存在することが判明した。乖離の「基準」を取り違えると誤検出になるため、
  各 D の判定基準をこの階層に照らして見直した:

    層0 (理論): mle/paper/plonky2_mle_paper_v2.md
                — batching sumcheck (§4.4) を含む理想プロトコル。**未実装**部分あり。
    層1 (v1 設計): mle/README.md L191-424
                — 「3-vector phased WHIR + combined sumcheck + aux commit
                  (P_aux = C̃ + r·h̃)」を正式に文書化。transcript 順序も明記
                  (L367-388)。ただし v2 logup 追加は**未記載** (stale)。
    層2 (v2 設計 + 監査): mle/soundnessgame/MleVerifier.vol.md
                — Round 2 (vulcheck417) で Φ_inv/Φ_h/Φ_gate + inverse helpers を
                  導入した経緯を定義。R2-#1〜#8 の所見と修正。**これが v2 の
                  実質的な定義文書**。当初「論文にない実装」と評した部分は
                  ここに文書化されていた (D7 を訂正)。
    層3 (脅威分析): mle/tasks/todo.md, phase3_c1/c2_threat_model.md,
                  phase2_c2_poc_report.md
                — C1 (gate metadata VK 非束縛) / C2 (非 canonical 注入) を
                  CONFIRMED CRITICAL として PoC 付きで分析、修正済み。
                  SolVerifier.lean の gatesDigestOk (C1) / canonicalOk (C2) が対応物。
                — Phase 6 Finding 1: publicInputsHash が publicInputs に非束縛
                  (**HIGH, 現在も未解決**) → D10 として新規追加。
                — Phase 6 Finding 4: WHIR/Sumcheck ライブラリに同種の
                  非 canonical sub(p,X) サイト (out-of-scope follow-up) → D11。
-/
import Audit.Impl.SolVerifier

namespace Audit.Divergences

open Audit
open Audit.RustImpl

variable {F : Type} [Field F]

/-! ## D1 [Spec-bug, 確定] g_sub の閉形式 (paper §4.2.2)

    仕様書: g_sub(r) = Σ_i r_i · ω^{2^i}         (Σ 形式)
    Rust  : Π_i ((1−r_i) + r_i · ω^{2^i})        (verifier.rs L468, Π 形式)
    Sol   : Π_i ((1−r_i) + r_i · g^{2^i})        (MleVerifier.sol L422, Π 形式)

    MLE(b ↦ ω^b)(r) の正しい閉形式は Π 形式。両実装が一致して Π を使い、
    仕様書のみ Σ で誤っている。両者は非ブール点で異なる (下で n=1 反例)。 -/

/-- Σ 形式 (仕様書 §4.2.2)。 -/
def gSubPaperList (r genPowers : List F) : F :=
  fsum r.length (fun i => r.getD i.val 0 * genPowers.getD i.val 0)

/-- D1 の証明義務: n=1 で Σ 形式 ≠ Π 形式となる具体例が存在する
    (よって仕様書の式は MLE ではない)。段階3で witness を与えて証明。 -/
def D1_spec_gsub_wrong : Prop :=
  ∃ (r g : F), gSubPaperList [r] [g] ≠ gSubRecompute [r] [g]

/-- 実装二者の一致 (Rust verifier.rs L461-470 ≡ Sol MleVerifier.sol L408-426)。
    両方 gSubRecompute。定義的に一致するので段階3で rfl で閉じる想定。 -/
def D1_impls_agree : Prop :=
  ∀ (r g : List F),
    (gSubRecompute r g : F) = Audit.SolImpl.solEvalSubgroupMle r g

/-! ## D2 [High 候補] combined sumcheck の次数境界検査の非対称性

    Rust (verifier.rs):
      - combined sumcheck 呼び出し (L143-146): 次数境界検査**なし**
      - Φ_inv (L159-165): ≤ 4、Φ_h (L185-191): == 2、Φ_gate (L222-229): == d+1
      - verify_sumcheck 自体 (sumcheck/verifier.rs) も次数を検査しない
    Solidity (MleVerifier.sol):
      - combined (L196): maxDegree = 2 を SumcheckVerifier.verify に渡す
      - SumcheckVerifier.sol L50: require(evals.length <= maxDegree + 1)
      - 全 sumcheck に境界あり

    -- 【補遺 訂正】この乖離は層2 (MleVerifier.vol.md) の Issue R2-#8 [MEDIUM]
    -- で既知・修正済みと文書化されている:「SumcheckVerifier.verify() had no
    -- upper bound … Fix: added maxDegree parameter … MleVerifier passes 2」。
    -- ただし修正は **Solidity 側のみ**。Rust の combined sumcheck 呼び出し
    -- (verifier.rs L143-146) は依然 verify_sumcheck に次数境界を渡さず、
    -- sumcheck/verifier.rs 自体も長さ検査を持たない (Φ_inv/Φ_h/Φ_gate は
    -- 呼び出し側 L159-165/L185-191/L222-229 で個別に境界検査するのと非対称)。
    -- よって D2 は「vol.md が認識した R2-#8 クラスの Rust 側残余」。深刻度は
    -- vol.md の MEDIUM 判定を踏襲しつつ、段階4 で Rust combined 経路の実害を
    -- 再評価する。

    帰結: Rust の combined sumcheck は任意次数のラウンド多項式を受理しうる。
    sumcheck 健全性誤差はラウンドあたり deg/|F| なので、次数 d を prover が
    自由に選べると Theorem 1 の 2n/|F| 境界が崩れる (実効的には
    n·d_max/|F|、d_max は prover 制御)。

    -- ただし緩和要因: combined sumcheck の終端検査 (L494-501) は
    -- aux_constraint_eval / aux_perm_eval (WHIR 束縛の C̃(r), h̃(r)) と
    -- 一致を要求する。round poly が高次でも、g(0)+g(1) 連鎖と終端値が
    -- 整合しなければ弾かれる。よって「即・不健全」ではないが、Solidity に
    -- 存在する防御線が Rust に欠けており、健全性論証が実装依存になる。 -/

/-- D2: Rust の combined 検証は次数境界を課さない一方、Solidity は課す。
    「同じ round poly 列で Rust が受理し Solidity が拒否する」ケースの存在。 -/
def D2_rust_missing_degree_bound
    (enc : U64Encoding) (fe : FieldEncoding F) (ko : KeccakSqueeze F) : Prop :=
  ∃ (roundPolys : List (RoundPolyE F)) (n : Nat) (t : RTranscript),
    -- Solidity 境界 (次数 ≤ 2) に違反する round poly が存在し
    ¬ solRoundPolyBounds 2 roundPolys ∧
    -- しかし Rust の verify_sumcheck は構造検査を通過しうる
    (rustVerifySumcheckChecked enc fe ko 0 n roundPolys t).isSome

/-! ## D3 [High/Critical 候補] inverse helpers 個別評価値の未束縛

    論文 §4.5 leg 3 の核心は「終端検査の全量が PCS 束縛値」であること。
    しかし a_j, b_j (inverse_helpers_evals_at_r_inv / _at_r_h) は:
      Rust: batch フォールドを計算するが破棄 (verifier.rs L404-425、
            `let _ = expected_inv_at_r_inv`)。batched 値フィールド自体が
            proof に存在せず、WHIR Ext3 評価値との等式検査もない。
      Sol : batch consistency 検査が存在しない (長さ検査 L275, L381 のみ)。
    それでも a_j, b_j は Φ_inv 終端 (L533-534 / L349-350) と Φ_h 終端
    (L563-564 / L390-391) に直接流入する。

    実装コメント (verifier.rs L410-412, L339-340) は「WHIR Ext3 binding +
    Schwartz-Zippel が個別評価値を一意に決める」と主張する。しかし WHIR が
    束縛するのは Ext3 の batched 多項式評価値であり、Goldilocks の個別評価値
    a_j, b_j をそこから取り出す等式 (batched = Σ r^i·individual と
    Ext3-eval = batched の連結) が**実装に書かれていない**。

    -- 【補遺 精緻化】層2 (MleVerifier.vol.md) R2-#2 は inverse helpers を
    -- 「WHIR commit_additional で β,γ 後にコミット」する 4 本目のベクトルと
    -- **設計上は規定**しており、「terminal checks operate on PCS-bound
    -- multilinear values (a_j(r), b_j(r), …)」と主張する。よって束縛は
    -- Ext3/batched のレベルでは設計意図として存在する。D3 の争点はより鋭い:
    -- witness/preprocessed には Goldilocks 個別評価値 ↔ batched 値の
    -- consistency 検査 (verifier.rs 5d/5e/5f/5j/5k) があるのに、inverse
    -- helpers には**その検査だけが欠けている** (5g/5h は計算して破棄)。
    -- つまり 4 本目のベクトルの Ext3 binding は主張されるが、そこから
    -- Φ_inv/Φ_h 終端が使う個別 a_j, b_j へ降ろす鎖が witness と非対称に
    -- 途切れている。層3 の网羅性メモ (todo.md Phase 6「rInv/rH mutation
    -- tests deferred」) も、この経路が未テストであることを認めている。
    → 段階3: 「a_j, b_j が commit された多項式の真の評価に等しい」を
      RustVerifyAccepts の仮定から導けるか試みる。導けなければ、
      悪意の prover が Φ_inv/Φ_h を満たす任意の a_j, b_j を選べる = 置換
      引数 (§4.2) の健全性が崩れる可能性。深刻度は段階4で WHIR verify_split
      の実際の入力 (inv ベクトルが本当に 16 評価値に含まれるか) を精査して確定。 -/

/-- D3: 終端検査に流入する inverse helper 評価値が、他のどの検査でも
    その多項式コミットメントに束縛されていない、という構造的主張。
    形式化の骨子: RustVerifyAccepts の全フィールドが成立しても、
    inverseHelpersEvalsAtRInv を別の値に差し替えた proof が依然として
    (Φ_inv 終端を除く) 全検査を満たしうる余地がある。
    -- 段階3で精密化。ここでは「独立に束縛する検査が存在しない」ことの
    -- チェックリストとして命題名を確保する。 -/
def D3_inverse_helpers_unbound : Prop :=
  -- batchedEval による consistency が Rust/Sol いずれの受理条件にも
  -- inverse helpers については含まれていない (RustVerifyAccepts /
  -- SolVerifyAccepts のフィールドを見よ: witness/preprocessed には
  -- *BatchOk があるが inverse helpers には長さ検査しかない)。
  True  -- プレースホルダ: 段階3で「差し替え不変性」の反例として具体化

/-! ## D4 [Low/Spec-divergence] Φ_h の λ_h 重み

    仕様書 §4.2.3: Φ_h(x) = Σ_j λ_h^j (A_j(x) − B_j(x))、終端も λ_h^j 重み付き。
    Rust (verifier.rs L561-571): h_pred = Σ_j (a_j − b_j)、非重み付き。
      L571 `let _ = lambda_h;` — λ_h は squeeze されるが未使用 (死にチャレンジ)。
    Sol (MleVerifier.sol L375-404): 同じく非重み付き Σ_j (a_j − b_j)。

    健全性: logUp の主張は Σ_b Σ_j (A_j − B_j) = 0 (非重み付き総和) で十分
    (Haboeck)。λ_h 重みは複数列の分離には不要。よって非重み付きでも健全。

    -- 【補遺 訂正】これは層0 (paper v2 §4.2.3) との乖離であって、実装の
    -- バグではない。層2 (MleVerifier.vol.md R2-#2 L54) は Φ_h を
    -- 「H(b) = Σ_j (A_j(b) − B_j(b))」と**非重み付きで定義**しており、実装は
    -- 自身の v2 設計文書に忠実。よって深刻度は Low→Info に降格。残る論点は
    -- λ_h が squeeze されるが未使用 (死にチャレンジ) な点のみ (D9 と同類)。 -/

/-- D4: 実装 (Rust/Sol) の Φ_h 終端は λ_h 非依存。
    lambda_h を変えても hTerminalPred は不変。 -/
def D4_h_terminal_ignores_lambda_h (p₁ p₂ : RustMleProof F) : Prop :=
  p₁.inverseHelpersEvalsAtRH = p₂.inverseHelpersEvalsAtRH →
  p₁.numRoutedWires = p₂.numRoutedWires →
  hTerminalPred p₁ = hTerminalPred p₂   -- λ_h に依存しないので lambdaInv 等が違っても等しい

/-! ## D5 [Info] Keccak squeeze の 96 ビット縮約

    transcript.rs L83-84 / L72 コメント: 「全 32 バイトを wide reduction」
    「バイアス < 2^{-192}」。実装 L84-98: u128 acc への wrapping_shl(64) で
    上位 2 リムを捨て、実際は下位 96 ビット (lo:u64, hi:u32) のみ使用。
    from_noncanonical_u96 の mod p バイアスは ~2^{-32}。
    Solidity (TranscriptLib.sol L231-236): swap64 で limb0, limb1、
    reduce96 = limb0 + (limb1 & 0xFFFFFFFF)·EPSILON。**同じ 96 ビット**。

    帰結: 両実装は一貫 (相互運用 OK)。チャレンジ分布のバイアスは 2^{-32}
    程度で、64 ビット体では健全性に実害なし。ただしコメントの主張は誤り
    (Info)。 -/

/-- D5: Rust と Solidity の squeeze は同じビット幅 (96) を使う。
    KeccakSqueeze オラクルが両者で同一関数であるという整合性仮定。
    -- 段階2ではオラクル抽象なので、この命題は「両実装のリムマスクが一致」を
    -- 記録するコメントレベル。段階4で実バイト演算を突き合わせる。 -/
def D5_squeeze_consistent : Prop := True

/-! ## D6 [Info/相互運用] ドメイン分離ラベルの不一致 (仕様 vs 実装)

    仕様書 §5.4: "PLONKY2-MLE-CIRCUIT-DIGEST", "PLONKY2-MLE-WITNESS-ROOT", …
    実装 (両方一致): "circuit", "batch-commit-witness", "challenges",
      "inverse-helpers-batch-r", "v2-logup-challenges", "extension-combine",
      "aux-commit", "combined-sumcheck", "v2-inv-zerocheck", "v2-h-linear",
      "v2-gate-challenges", "v2-gate-zerocheck", "pcs-eval", "sumcheck-round"。

    Rust (verifier.rs) と Solidity (MleVerifier.sol L438-494) はラベル
    文字列・順序ともに一致 (TranscriptLib.sol L5-6 が byte-for-byte 移植を明言)。
    仕様書のラベルとは全く異なるが、実装同士が一致していれば相互運用は成立。
    ドメイン分離の目的 (プロトコル交差攻撃防止) は達成されている。Info。 -/

/-- D6: Rust と Solidity のラベル集合が一致する (相互運用の必要条件)。
    段階4でラベル列を逐一突き合わせる。ここでは記録用。 -/
def D6_labels_match_impls : Prop := True

/-! ## D7 [構造的] 論文 §5 プロトコル ⇔ 実装プロトコルの構造差

    論文 §5.2/§5.3 の構成:
      witness commit → β,γ → inverse commit → α,λ,μ,λ_h,τ,τ_inv →
      Φ_inv sumcheck → Φ_h sumcheck → Φ_gate sumcheck →
      **multi-point batching sumcheck (ν_1, ν_2) → 単一点 r_open で PCS open**

    実装の構成 (Rust verifier.rs / Sol _verifyCore):
      witness commit → β,γ → inverse commit → α,τ,τ_perm,λ_inv,μ_inv,λ_h,τ_inv
      → ext_challenge → **aux commit (P_aux = C̃ + r·h̃)** → μ →
      **combined sumcheck (v1 の遺物)** → Φ_inv → Φ_h → Φ_gate →
      **WHIR verify_split が 4 点 (r_gate, r_inv, r_h, r_gate_v2) を直接オープン**

    差分:
      (a) 論文の multi-point batching sumcheck (§4.4) は実装に存在しない。
          代わりに WHIR が複数点を直接扱う (verifier.rs L311-318:
          verify_split に 4 点を渡す)。→ 段階1 Statements の UNDERSPECIFIED
          #3, #4 は「論文の batching は実装されなかった」で解決。
      (b) 実装には層0 (論文) にない aux commitment P_aux + combined sumcheck
          + τ_perm が存在。**ただしこれは「未文書化の遺物」ではない**:
          層1 (README.md L191-424) が「3-vector phased WHIR + combined
          sumcheck + aux commit」として正式に文書化している。その上に層2
          (vol.md) の v2 logup (Φ_inv/Φ_h/Φ_gate) が積層された二層構造。
          MleVerifier.sol L227-231 の「legacy、h̃ 部分はもはや健全性の錨では
          ない」は、層1 の combined sumcheck の h̃ 項が層2 で置換された経緯を
          指す。τ_perm (L86) は層1 の名残で squeeze されるが未使用 (D9)。
      (c) よって実装の健全性は層0 Theorem 1 の証明では**カバーされない**。
          層1+層2 を合わせた実装構成に対する別の健全性論証が必要で、その
          断片が vol.md R2-#1〜#8 に散在する (統合された定理はない)。
          段階3の Soundness はこの実装構成 (層1+層2) に対して行う。 -/

/-- D7: 論文の batching sumcheck が実装に存在しないことの記録。
    実装の受理条件 (RustVerifyAccepts) に batching sumcheck フィールドが
    ないことが対応物。段階4で「§4.4 は実装されず WHIR 多点で代替」と結論。 -/
def D7_no_batching_sumcheck : Prop := True

/-! ## D8 [設計・信頼仮定] Solidity の kIs / subgroupGenPowers が非束縛

    MleVerifier.sol L140-144: kIs と subgroupGenPowers は caller 供給で
    transcript に束縛されない (公開回路定数)。circuit_digest には
    含まれない (L438-441 の absorb は circuitDigest, publicInputs,
    preprocessedRoot のみ)。

    帰結: これらが circuit の VK と整合することは**オンチェーン呼び出し
    ラッパの責任**。誤った kIs/subgroupGenPowers を渡すと置換引数の
    identity permutation が変わり、別回路の証明が通りうる。
    Rust 側 (verifier.rs) は proof.subgroup_gen_powers / proof.k_is を
    使い、これらも circuit_digest には束縛されない (同じ信頼仮定)。
    深刻度: 設計上の信頼境界。運用ラッパが固定するなら許容。SCOPE.md の
    「VK は正しく生成済み」仮定に含めるが、明示的に記録。 -/

def D8_perm_context_untrusted : Prop := True

/-! ## D9 [Low] τ_perm の死にチャレンジ

    Rust (verifier.rs L86): tau_perm を squeeze し proof の写しと一致検査
    (L89) するが、終端検査には登場しない (combined 終端 L494-501 は τ のみ)。
    Sol (MleVerifier.sol L461): squeezeChallenges で読み捨て ("tauPerm sync
    (unused)")。
    健全性への影響なし。transcript の位置合わせのために squeeze されている
    (v1 の遺物、D7(b) と同根)。Low/Info。 -/

def D9_tau_perm_dead : Prop := True

/-! ## D10 [High, 現在も未解決] publicInputsHash が publicInputs に非束縛

    出所: 層3 tasks/todo.md Phase 6 Finding 1 (HIGH, deferred)。
    MleVerifier.sol は proof.publicInputsHash (L122, 長さ 4) を Φ_gate 終端の
    gate evaluator (L622 相当 / Sol _checkGateTerminal) に渡すが、これが
    proof.publicInputs (L35) の Poseidon ハッシュであることを**検証しない**。
    publicInputsHash は prover 供給の digest で、オンチェーンで
    Poseidon(publicInputs) を再計算する手段がない (Solidity Poseidon 未実装)。

    帰結: prover は任意の publicInputs に対し整合する publicInputsHash を
    選べる。todo.md は「publicInputsHash を transcript に absorb するだけでは
    完全修正にならない — 正しい修正は Solidity Poseidon 再計算」と明記。
    C1/C2 の範囲外として**未解決のまま**。
    -- 本監査モデルでの対応: RustVerifier.lean / SolVerifier.lean の
    -- GateEvaluator は publicInputsHash を入力に取るが、それが publicInputs の
    -- 像であるという制約 (述語) をどこにも課していない。段階3 の Soundness で
    -- 「publicInputsHash 差し替え不変性」の反例として具体化する。
    -- 注: Rust パスは Plonky2 の内部整合で緩和される可能性があり、深刻度は
    -- Solidity オンチェーン検証に固有の側面が強い。段階4で切り分ける。 -/

def D10_pub_inputs_hash_unbound : Prop := True

/-! ## D11 [Info/follow-up] WHIR/Sumcheck ライブラリの非 canonical サイト

    出所: 層3 tasks/todo.md Phase 6 Finding 4 (INFORMATIONAL, out of scope) +
    SpongefishWhir.vol.md #4 (Fixed) / SumcheckVerifier.vol.md。
    C2 の canonical 検査 (MleVerifier.sol L663-763) は MleProof の個別評価値
    配列を対象とするが、SpongefishWhirVerify.sol / SumcheckVerifier.sol 内部の
    sub(p, X) サイト (X = sumcheck 多項式評価値・WHIR fold 出力) は同種の
    非 canonical 脅威を持つと Finding 4 が指摘。ただし round poly は
    absorbFieldVec (TranscriptLib L100-102) の require(< P) を通るため
    到達不能とされ、follow-up 扱い。SpongefishWhir.vol.md #4 は
    proverMessageField64x3 の非 canonical を round 1 で修正済み。
    -- 本監査では WHIR 内部を抽象化 (SCOPE 範囲外) しているため命題化のみ。 -/

def D11_whir_sumcheck_noncanonical : Prop := True

/-! ## 乖離サマリ (段階4 REPORT.md へ引き継ぐ一覧) -/

/-- 段階2で同定した乖離の一覧 (深刻度は段階4で確定)。 -/
inductive Divergence where
  | D1_gsub_spec_bug          -- Spec-bug (実装は正; 層0 §4.2.2 の誤記)
  | D2_combined_degree_bound  -- Medium (層2 R2-#8 の Rust 側残余; Sol は修正済)
  | D3_inverse_helpers_unbound -- High/Critical 候補 (要・段階3精査; 個別↔batched 非対称)
  | D4_h_lambda_unused        -- Info (層2 vol.md の設計に忠実; λ_h 死にチャレンジのみ)
  | D5_squeeze_96bit          -- Info (コメント誤り、実装は一貫)
  | D6_labels_differ_from_spec -- Info (実装同士は一致)
  | D7_layered_protocol       -- 構造 (層0 §4.4 未実装; 層1 README + 層2 vol.md の積層)
  | D8_perm_ctx_untrusted     -- 設計・信頼仮定
  | D9_tau_perm_dead          -- Low (層1 の名残)
  | D10_pub_inputs_hash_unbound -- High, 未解決 (層3 Phase6 Finding1; Sol Poseidon 未実装)
  | D11_whir_sumcheck_noncanonical -- Info/follow-up (層3 Phase6 Finding4)
  deriving DecidableEq, Repr

end Audit.Divergences
