# Lean 形式検証スコープ (lean-formal-audit 段階0 成果物)

日付: 2026-07-06 / 対象コミット: ee80ee6d (branch claude/gifted-germain-0283dd)

## モード

**監査モード**(既存仕様・実装の形式化)。

### 仕様書の階層(段階2で判明・2026-07-06 追記)

当初 paper v2 のみを仕様としたが、実装により近い定義ドキュメントが4層存在する。
乖離判定は必ずこの階層に照らす(基準を取り違えると誤検出になる):

- **層0(理論)**: `mle/paper/plonky2_mle_paper_v2.md` — batching sumcheck(§4.4)を
  含む理想プロトコル。**一部未実装**。
- **層1(v1設計)**: `mle/README.md` L191-424 — 「3-vector phased WHIR + combined
  sumcheck + aux commit(P_aux = C̃ + r·h̃)」を正式文書化。transcript順序も明記。
  ただし v2 logup 追加は**未記載**(stale)。
- **層2(v2設計+監査)**: `mle/soundnessgame/MleVerifier.vol.md` — Round 2
  (vulcheck417)で Φ_inv/Φ_h/Φ_gate + inverse helpers を導入した経緯を定義。
  R2-#1〜#8。**これが v2 の実質的な定義文書**。
- **層3(脅威分析)**: `mle/tasks/todo.md`, `phase3_c1/c2_threat_model.md`,
  `phase2_c2_poc_report.md` — C1(gate metadata VK非束縛)/ C2(非canonical注入)を
  CONFIRMED CRITICAL として PoC付き分析・修正済み。Phase 6 Finding 1
  (publicInputsHash 非束縛, HIGH, **未解決**)含む。

補助: `mle/paper/whir_optimization_report.md`(WHIRクエリ特性)、
`mle/soundnessgame/*.vol.md`(各コンポーネントの監査所見)。

ユーザー指示により Rust / Solidity 両実装との整合まで確認する。

## 対象の構成要素

paper v2 の構成に従う:

| 構成要素 | 論文節 | Leanファイル |
|---|---|---|
| 有限体 (Goldilocks / Ext3) | §2.1, §6.1 | `Audit/Field.lean` |
| MLE・eq多項式・hypercube | §2.1, §2.3 | `Audit/Mle.lean` |
| 一変数多項式(sumcheckラウンドメッセージ) | §2.4 | `Audit/Poly.lean` |
| Sumcheck検証者 | §2.4, §5.3 | `Audit/Sumcheck.lean` |
| PCS抽象インターフェース (WHIRブラックボックス) | §2.5, §7.4 | `Audit/Pcs.lean` |
| WHIR内部の抽象構造+監査不変量 | §2.5, SpongefishWhir*.vol.md | `Audit/Whir.lean` |
| Fiat-Shamirトランスクリプト | §5.4, §6.2 | `Audit/Transcript.lean` |
| プロトコル本体 (VK / Proof / Verifier §5.3) | §5 | `Audit/Protocol.lean` |
| 検証したい性質(命題) | §3, §4.5, §6 | `Audit/Statements.lean` |

## 検証したい性質

1. **Soundness (Theorem 1, §6.1)** — 決定論的コア:
   検証者が受理 ∧ ステートメント不成立 ⇒ 列挙されたSchwartz-Zippel型
   バッドイベントのいずれかが発生(各イベントの「大きさ」= 誤り確率の分子を記録)。
2. **Completeness** — 正直なproverの証明は必ず受理される。
3. **Fiat-Shamirバインディング (§6.2)** — チャレンジが先行absorbの決定的関数で
   あること、ドメイン分離、canonical encoding単射性。
4. **バインディングギャップ不在 (§3, §4.5)** —
   `MLE(b ↦ formula(W(b)))(r) ≠ formula(MLE(W)(r))` が一般に成り立つこと(§3の
   ギャップの存在)と、本構成の全終端チェックが「PCSにバインドされた多項式の
   同一点評価」なのでギャップを踏まないこと(§4.5)の両方。

## 前提・脅威モデル(公理・仮定として一元管理)

- **敵対的prover**: 証明・トランスクリプトメッセージは全て敵対的。
- **PCS binding**: WHIRは ε_PCS-binding。Lean上は「各コミットメントが一意の
  多項式表を定め、verify成功は評価一致を含意する」理想化として仮定に置き、
  ε_PCS 誤差はバッドイベントとして記録(`Pcs.lean` の構造体フィールド)。
- **Random Oracle**: Keccak256スポンジをオラクル構造体 `FSOracle` として
  パラメータ化。ROMでの性質(先行absorb確定後のチャレンジの予測不能性)は
  仮定として明示。
- **数学的事実の公理化**: Mathlib不使用のため「次数dの非零一変数多項式の根は
  高々d個」等の標準事実は明示コメント付きで公理化し、仮定一覧に載せる。
- **信頼するもの**: 検証鍵(circuit_digest, preprocessed_root)は正しく生成済み。

## 範囲外

- Prover側の計算効率・メモリ(§7の性能記述)
- WHIRの近接性(proximity)ギャップの定量解析(WHIR論文自体の再証明はしない —
  ブラックボックス+抽象不変量まで)
- Zero-knowledge性(§9で明示的に将来課題)
- 再帰検証(recursive verification)の回路コスト
- `whir_optimization_report.md` の改善提案(P0-P3)自体の検証は範囲外だが、
  §7.1のOn-the-fly方式のsoundness注意点は Statements にコメントで言及

## 環境

Lean 4.10.0 (elan)、Mathlib不使用(自己完結)。`mle/audit/` に lake パッケージ。
