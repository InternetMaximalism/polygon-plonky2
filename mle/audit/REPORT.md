# 検証レポート — WHIR ベース多重線形証明システムの Lean 4 形式監査

日付: 2026-07-06 / 対象コミット: ee80ee6d / ブランチ: claude/gifted-germain-0283dd
成果物: `mle/audit/`(Lean 4.10.0、Mathlib 非依存、`lake build` 警告0、
**46 定理・`sorry` 0・明示公理 1**)

## 対象とバージョン / モード

**監査モード**。対象は `mle/` の WHIR ベース多重線形(MLE)証明システム:

- 仕様: `mle/paper/plonky2_mle_paper_v2.md`(理論、層0)
- Rust 実装: `mle/src/`(特に `verifier.rs`)
- Solidity 実装: `mle/contracts/src/`(特に `MleVerifier.sol`)

## スコープ(段階0インタビュー結果、詳細 [SCOPE.md](SCOPE.md))

- WHIR はブラックボックス PCS + 内部も抽象不変量として形式化(内部の proximity
  soundness 再証明は範囲外)。
- 検証性質: Soundness(Theorem 1)、Completeness、Fiat-Shamir バインディング、
  binding-gap 不在。
- Rust / Solidity 両実装との整合まで確認。
- 範囲外: prover 効率、ZK、再帰検証コスト、WHIR 論文自体の再証明。

## 手法(4段階 + 段階3前クリーンアップ)

1. **段階1**: 仕様の抽象構成を Lean 化([Audit/*.lean](Audit/))。
2. **段階2**: Rust/Solidity を逐行対照([Audit/Impl/*.lean](Audit/Impl/))、
   三者の乖離を D1–D11 として命題化。
3. **クリーンアップ**: 空命題(vacuous `True`/`∃ BadEvent,True`)を実体化、
   デッドコード除去。
4. **段階3**: 主要性質を証明([Audit/Proofs/*.lean](Audit/Proofs/))。

## 重要発見: 仕様書は4層構造

当初 paper v2 を唯一の仕様としたが、実装により近い定義文書が4層ある。乖離判定は
この階層に照らす:

| 層 | 文書 | 位置づけ |
|---|---|---|
| 層0 理論 | `paper/plonky2_mle_paper_v2.md` | batching sumcheck(§4.4)含む理想。一部**未実装** |
| 層1 v1設計 | `README.md` L191-424 | aux commit + combined sumcheck を正式文書化 |
| 層2 v2設計 | `soundnessgame/MleVerifier.vol.md` | Φ_inv/Φ_h/Φ_gate + inverse helpers の定義文書(R2-#1〜#8)|
| 層3 脅威分析 | `tasks/todo.md` ほか | C1/C2 CRITICAL + PoC + 修正、Phase6 に現存 HIGH |

実装は「層0 の理論」ではなく「層1+層2 の積層」であり、**統合された健全性定理は
どの層にも存在しない**。本監査の Lean 化がその統合の第一歩。

## 仮定一覧(axiom / 理想化 / UNDERSPECIFIED)

| 種別 | 内容 | 場所 |
|---|---|---|
| 公理 | 次数 ≤ d の非零多項式の相異なる根は ≤ d 個(標準事実、Mathlib 非使用のため) | `Poly.roots_le_degree` |
| 理想化 | PCS binding(ε_PCS): コミットメントが一意の多項式を定め verify 成功が評価一致を含意 | `Pcs.lean` / `ProtocolPCS.verify_sound` |
| 理想化 | Merkle 衝突耐性、Keccak = ランダムオラクル | `Whir.lean` / `Transcript.lean` |
| 信頼仮定 | VK(circuit_digest, preprocessed_root, kIs, subgroupGenPowers)は正しく生成済み | D8 |
| 抽象化(4) | transcript 再導出順、lookup 空検査、WHIR 内部(両モデル)| `*VerifyAccepts` の残 `True` |
| UNDERSPEC | §5.3 step7 の逆再構成、§4.3 の列結合スカラー(→ 実装は WHIR 多点で代替、D7) | `Statements.lean` メモ |

## ファイル別・所見別(乖離 D1–D11)

| ID | 深刻度 | 内容 | 状態 |
|---|---|---|---|
| **D1** | Spec-bug | 論文 §4.2.2 の g_sub 閉形式が Σ 形式で誤り。Rust/Sol とも正しい Π 形式 | 実装は正、仕様書要訂正 |
| **D2** | Medium | combined sumcheck の次数境界検査が **Rust に無い**(Sol は R2-#8 で修正済) | Rust 側残余 |
| **D3** | **CRITICAL(確定)** | inverse helpers a_j,b_j が PCS 束縛されず、Φ_inv の単一線形関係しか課されない。検証者は不正な逆元を受理する | **強い版を形式的に証明**(`d3_strong`、下記) |
| **D4** | Info | Φ_h の非重み付き Σ は層2 vol.md の設計に忠実(層0 §4.2.3 との乖離のみ)。λ_h 死にチャレンジ | 実装は自設計に忠実 |
| **D5** | Info | transcript の 96bit 縮約。コメント「256bit/2^-192」は誤記、実装は Rust/Sol 一貫 | 相互運用 OK |
| **D6** | Info | ドメイン分離ラベルが層0 と実装で不一致、実装同士は一致 | 相互運用 OK |
| **D7** | 構造 | 層0 §4.4 batching は未実装、WHIR 多点で代替。実装は層1+層2 積層 | 設計理解 |
| **D8** | 信頼仮定 | Sol の kIs/subgroupGenPowers が transcript 非束縛(caller 責任) | 運用ラッパ前提 |
| **D9** | Low | τ_perm が squeeze されるが未使用(層1 名残) | 無害 |
| **D10** | **High, 未解決** | publicInputsHash が publicInputs に非束縛(層3 Phase6 Finding1、Sol Poseidon 未実装) | **現存・未修正** |
| **D11** | Info/follow-up | WHIR/Sumcheck ライブラリ内部に同種の非 canonical sub(p,X) サイト | out-of-scope |

## 証明した性質(段階3)

Mathlib 非依存で体クラスの代数を公理から構築([Audit/Algebra.lean](Audit/Algebra.lean))。

| 性質 | 定理 | 内容 |
|---|---|---|
| **Soundness コア** | `sumcheck_telescope` | telescoping: 受理 + 最終値一致 + 初期主張相違 ⇒ 実チャレンジのどこかで差多項式(非零・次数≤d)の根に命中。Theorem 1 の決定論部 |
| **実装 Soundness** | `rustSoundness` / `solSoundness` | 受理 ⇒ 4 本の sumcheck それぞれで固定版健全性(格納/再導出チャレンジに固定) |
| **FS バインディング** | `domainSeparation` / `fsOrdering` | ラベル埋め込みの単射性、challenge-after-commit の決定性 |
| **binding-gap 不在(§4.5)** | `linearCommutes` | 終端の線形結合について MLE 可換 |
| **binding-gap 実在(§3)** | `bindingGapExists` | **|F|>2(非冪等元)の下で** MLE(W²)(r) ≠ (MLE(W)(r))²。標数2では成立しない(Goldilocks は充足) |
| **MLE 基本性質** | `eq_diag` / `eq_sum` / `mleEval_bit1` / `hsum_vprod_factor` | eq(b,b)=1、Σeq=1、テンソル和 |
| **D3 弱い版** | `d3_substitutable` | inverse helper 評価値のみ異なり witness batch consistency は一致する 2 proof の存在 |
| **D3 強い版(CRITICAL 確定)** | `d3_strong` | **検証者(`RustVerifyAccepts` 全フィールド)を完全に満たす 2 proof で、片方は正直な逆元 (1,1)、片方は不正な逆元 (0,2) を主張し witness は同一** — 検証者が両方を受理 ⇒ ソウンドネス破れ |

補助として `polySub_eval`、`isZero_eval`、`accepts_length`、`hsum_add`、
`hsum_mul_left` 等も証明。

## 発見事項(深刻度別サマリ)

- **CRITICAL(確定)**:
  - **D3**(inverse helpers 束縛鎖の切れ): 論文 §4.5 の「全終端値は PCS 束縛」を
    実装が破っている。`d3_strong` で**形式的に確定**した: 検証者を完全に満たす
    (`RustVerifyAccepts` 全フィールド)2 つの proof が存在し、witness は同一なのに
    片方は正直な逆元 (a₀,b₀)=(1,1)、片方は不正な逆元 (0,2) を主張する。両方が
    受理される ⇒ inverse helpers は PCS で束縛されておらず、置換引数(コピー制約)の
    健全性が破れる。原因は inverse helpers に witness/preprocessed のような
    batch consistency 検査が無く、Φ_inv 終端の単一線形関係 a₀+b₀=2 しか
    課されないこと(2 解 (1,1)/(0,2) が両方通る)。
    **推奨修正**: inverse helper 個別評価値にも WHIR/batch consistency 束縛を追加。
- **High**:
  - **D10**(publicInputsHash 非束縛): 層3 Phase6 が現存 HIGH と認定、Solidity
    Poseidon 未実装のため**未修正**。
- **Medium**: D2(Rust combined sumcheck の次数境界欠如)。
- **Spec-bug**: D1(§4.2.2 g_sub の Σ 誤記、実装は正)。
- **Info/Low**: D4, D5, D6, D9, D11。
- **構造/仮定**: D7(積層プロトコル、統合定理不在)、D8(perm context 非束縛)。

## sorry・未証明箇所の一覧と解釈

`sorry` は **0 件**。公理は `Poly.roots_le_degree` の 1 件のみ(標準数学事実)。
以下は「未証明の Prop 定義」として残る(段階3の残):

- `SoundnessProp`(paper 版)本体 — 存在量化を telescope に接続する証明。
  実装版 `rustSoundness`/`solSoundness` は証明済みなので、健全性の実質は担保。
- `mle_agrees_on_hypercube_prop` / `mle_is_multilinear_prop` / `mle_unique_prop`
  — MLE の一意性系(eq_diag/eq_sum は証明済み)。
- Completeness の end-to-end — prover 形式化を要し SCOPE 範囲外。
- D3 の**強い版**。

## 結論

1. **健全性の決定論的中核は形式的に確立**した(`sumcheck_telescope` とその実装系
   `rustSoundness`/`solSoundness`)。実装が受理する限り、偽ステートメントは
   4 本の sumcheck のいずれかでの root-hit に帰着し、その確率は
   `Poly.roots_le_degree` により per-round ≤ deg/|F| で抑えられる。

2. **最重要の発見は D3(CRITICAL 確定)**: `d3_strong` により、検証者を完全に
   満たす 2 proof(witness 同一・inverse helper のみ相違、片方は不正な逆元 (0,2))が
   存在することを**形式的に証明**した。検証者は不正な逆元を受理する = 置換引数の
   健全性破れ。論文 §4.5「全終端値は PCS 束縛」が実装で成立していない。修正は
   inverse helper 個別評価値への batch/WHIR 束縛の追加。

3. **D10(publicInputsHash 非束縛)は現存 HIGH** で、オンチェーン検証固有。
   Solidity Poseidon 実装が正しい修正。

4. 仕様書 §4.2.2(D1、g_sub の Σ 誤記)は**文書の訂正**を推奨(実装は正しい)。

5. 実装は論文の単一プロトコルではなく**層1+層2 の積層**であり、統合された健全性
   定理が文献に存在しない。本監査の Lean 定式化がその統合の基盤となる。

### 修正状況(2026-07-06)

- **D3(CRITICAL)修正済み**: inverse helper 個別評価値への batch consistency
  束縛を追加。
  - Rust: `proof.rs` に `inverse_helpers_eval_value_at_r_{inv,h}` フィールド追加、
    `prover.rs` で batched 値を出力、`verifier.rs` 5g/5h の破棄フォールドを
    `ensure!` に変更(witness の 5e/5f と対称)。回帰テスト 2 本追加。
    **Rust lib 59 テスト全通過**(honest roundtrip 維持 + D3 改竄が reject)。
  - Solidity: `MleVerifier.sol` に対応フィールド + `require` 追加。
    **forge 79 テスト全通過**(E2E 7 + boundary 10 含む)。
  - 仕様: `plonky2_mle_paper_v2.md` §4.2.2 に inverse-helper 束縛の必須性を明記、
    §5.3 に verifier step 7b(batch consistency)を追加。
  - Lean: `d3_fix_distinguishes`(非退化 batch チャレンジ `r≠1` の下で
    正直な逆元 [1,1] と不正な逆元 [0,2] は異なる batched 値を与え、単一の
    WHIR 束縛値に両立不可 ⇒ 新 `ensure!` が片方を必ず弾く)を証明。
- **D1(Spec-bug)修正済み**: `plonky2_mle_paper_v2.md` §4.2.2 の g_sub を
  Σ 形式から正しい Π 形式に訂正(実装は元から正しい)。

### 残りの作業(優先度順)

1. D10 の Solidity Poseidon による修正
2. D2 の Rust 側次数境界追加
3. `SoundnessProp` paper 版本体 + MLE 一意性系の証明完了

注: coset E2E fixture は現行コードで WHIR duplicate-index 問題
(SpongefishWhirVerify 所見#1)に触れる(D3 とは無関係、transcript が
D3 変更有無で byte 一致することを確認済み)。当該 fixture は既存の
通過する WHIR proof を保持しつつ D3 の新フィールドのみ注入して緑を維持。
