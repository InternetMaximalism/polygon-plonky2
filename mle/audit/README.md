# mle/audit — Lean 4 形式検証 (lean-formal-audit)

`mle/paper/plonky2_mle_paper_v2.md` の WHIR ベース多重線形証明システムの
Lean 4 形式化。スコープ・仮定・脅威モデルは [SCOPE.md](SCOPE.md)。

## ビルド

```
cd mle/audit && lake build   # Lean 4.10.0, Mathlib 不使用 (自己完結)
```

現状: **段階1+2 完了 + 段階3前クリーンアップ済み。全ファイルがビルド成功
(警告0)、`sorry` 0 件、明示公理 1 件**

### 段階3前クリーンアップ (2026-07-06)

段階3(証明着手)前に、命題の非空化とデッドコード除去を実施:

1. **`SoundnessProp` の非空化**: 旧版の結論 `∃ _e : BadEvent, True` は
   BadEvent が無条件 inhabited なため空証明可能だった。`SumcheckHitInProof`
   (proof の round poly 列に固定した root-hit) と `logupSum` collision の
   選言に差し替え、自明充足を排除。
2. **sumcheck 健全性コアの実体化**: [Sumcheck.lean](Audit/Sumcheck.lean) に
   `polySub` / `foldEval` / `SumcheckAccepts` / `SumcheckHitSomewhere` /
   `SumcheckTelescopeHit`(telescoping による決定論的健全性の実命題)を追加。
   弱いプレースホルダ `sumcheck_soundness_core_prop` を除去。
3. **Solidity モデルの実体化**: `SolVerifyAccepts` の `True` 12個を、再導出束
   `SolDerived` を導入して終端検査(Φ_inv/Φ_h/Φ_gate/combined/g_sub)+ sumcheck
   受理に固定。残る `True` は WHIR 内部(範囲外)の `whirOk` のみ。
4. **実装ターゲット命題の新設**: [Impl/ImplStatements.lean](Audit/Impl/ImplStatements.lean)
   に `RustSoundnessProp`(proof 格納の実チャレンジに固定)/`SolSoundnessProp`
   (SolDerived に固定)/`RustCompletenessDecomp`/D3 の反例存在命題
   `D3_inverse_helpers_substitutable_prop` を追加。
5. **デッドコード削除**: `lsum` / `IsPolyOfDegLE` / `honestRoundValue` /
   `WhirBinding` / `BadEvent`(inductive)を除去。

残る抽象 `True`(計4)は正当な抽象化のみ: transcript 再導出順(Rust/Sol)、
lookup 空検査、WHIR 内部(両モデル、SCOPE 範囲外)。

### 段階3: 証明 / 段階4: レポート (2026-07-06)

Mathlib 非依存で証明を実施。**54 定理、`sorry` 0、公理 1**(`Poly.roots_le_degree`)。
最終レポートは [REPORT.md](REPORT.md)。

| ファイル | 証明内容 |
|---|---|
| [Audit/Algebra.lean](Audit/Algebra.lean) | 体クラスの基本代数(記法ラッパー + sub/neg/mul の分配則等)を公理から導出 |
| [Audit/Proofs/SumcheckCore.lean](Audit/Proofs/SumcheckCore.lean) | **中核 `sumcheck_telescope`**(telescoping による決定論的健全性)、`polySub_eval`、`isZero_eval`、`accepts_length` |
| [Audit/Proofs/Statements.lean](Audit/Proofs/Statements.lean) | **`rustSoundness` / `solSoundness`**(実チャレンジ固定、telescope の系)、`domainSeparation`、`fsOrdering`、`rustCompletenessDecomp` |
| [Audit/Proofs/MleLemmas.lean](Audit/Proofs/MleLemmas.lean) | **`linearCommutes`**(§4.5 leg 2: MLE の線形結合可換 = binding-gap 不在の正の主張)、`hsum_add`、`hsum_mul_left` |
| [Audit/Proofs/EqPoly.lean](Audit/Proofs/EqPoly.lean) | **`eq_diag`**(eq(b,b)=1)、**`eq_sum`**(Σeq=1)、`hsum_vprod_factor`(テンソル和)、`mleEval_bit1`、**`bindingGapExists`**(§3: \|F\|>2 でギャップ実在) |
| [Audit/Proofs/D3.lean](Audit/Proofs/D3.lean) | **`d3_substitutable`**(所見 D3 弱い版: inverse helper 値のみ異なり witness batch consistency 一致の 2 proof) |
| [Audit/Proofs/D3Strong.lean](Audit/Proofs/D3Strong.lean) | **`d3_strong`(CRITICAL 確定)**: `RustVerifyAccepts` 全フィールドを満たす 2 proof で witness 同一・inverse helper のみ相違、片方は不正な逆元 (0,2) を主張し受理される |

**証明済みの主要性質**:
- Soundness コア(Theorem 1 決定論部): sumcheck telescoping。受理 + 最終値一致 + 初期主張相違 ⇒ 実チャレンジのどこかで差多項式の根に命中。
- 実装 Soundness: Rust / Solidity の受理から 4 本の sumcheck それぞれで固定版健全性(格納/再導出チャレンジに固定)。
- FS バインディング: ドメイン分離ラベルの単射性、challenge-after-commit の決定性。
- Binding-gap 不在(§4.5): 終端の線形結合について MLE 可換。

**段階3の残**(今後):
- `SoundnessProp`(paper 版)本体の証明(存在量化を telescope に接続)。
  実装版 `rustSoundness`/`solSoundness` は証明済みなので健全性の実質は担保。
- MLE 一意性系(`mle_agrees_on_hypercube_prop` / `mle_is_multilinear_prop` /
  `mle_unique_prop`)— `eq_diag`/`eq_sum` は証明済み。
- Completeness の end-to-end(prover 形式化、SCOPE 範囲外)

**D3(CRITICAL)は `d3_strong` で確定済み**: 検証者を完全に満たす 2 proof で
witness 同一・inverse helper のみ相違、片方は不正な逆元 (0,2) を主張し受理される。
(`Poly.roots_le_degree` — 次数 ≤ d の非零多項式の根は高々 d 個。標準的
数学事実、Mathlib 不使用のため公理化)。その他の暗号学的仮定 (PCS binding、
Merkle 衝突耐性、canonical encoding 単射性) は公理ではなく構造体フィールドの
Prop として持ち、利用箇所で明示的な仮定になる設計。

## ファイル構成 (段階1: 抽象設計の Lean 化)

| ファイル | 内容 | 論文対応 |
|---|---|---|
| `Audit/Field.lean` | 体クラス (Goldilocks/Ext3 の抽象) | §2.1, §6.1 |
| `Audit/Prelude.lean` | Vec / Bits / hypercube 和・積 | §2.1 |
| `Audit/Poly.lean` | 一変数多項式 (sumcheck メッセージ) + 根の個数公理 | §2.4 |
| `Audit/Mle.lean` | eq 多項式・MLE 評価・多重線形性、基本性質の命題 | §2.1, §2.3 |
| `Audit/Pcs.lean` | PCS 抽象 (WHIR ブラックボックス) + split-commit | §2.5, §4.3, §7.4 |
| `Audit/Transcript.lean` | Fiat-Shamir スポンジ抽象 + §5.4 ラベル + canonical encoding | §5.4, §6.2 |
| `Audit/Sumcheck.lean` | ラウンド検査・FS 版 sumcheck 検証者 | §2.4, §5.3 |
| `Audit/Whir.lean` | WHIR 内部の抽象構造 + soundnessgame 所見#1〜#4 の不変量化 | §2.5, SpongefishWhirVerify.vol.md |
| `Audit/Protocol.lean` | 回路・ステートメント・VK・Proof・検証者 §5.3 全11ステップ | §4, §5 |
| `Audit/Statements.lean` | 検証対象4性質の命題 + 段階1所見メモ | §3, §4.5, §6 |

### 段階2: 実装対照 (Rust mle/src + Solidity mle/contracts)

| ファイル | 内容 | 実装対応 |
|---|---|---|
| `Audit/Impl/RustTranscript.lean` | Keccak トランスクリプトの逐行写し | `mle/src/transcript.rs` |
| `Audit/Impl/RustSumcheck.lean` | 評価値表現 round poly + Lagrange 補間 + verify_sumcheck | `mle/src/sumcheck/{types,verifier}.rs` |
| `Audit/Impl/RustVerifier.lean` | mle_verify 全 11 ステップを命題束 `RustVerifyAccepts` に写す | `mle/src/verifier.rs` (849行) |
| `Audit/Impl/SolVerifier.lean` | MleVerifier.sol の verify を `SolVerifyAccepts` に写す | `mle/contracts/src/MleVerifier.sol` (853行) |
| `Audit/Impl/Divergences.lean` | **仕様⇔Rust⇔Solidity の乖離 D1〜D9 を命題化** | 三者対照 |

### 仕様書は4層(段階2補遺・2026-07-06)

乖離判定は必ずこの階層に照らす。詳細は [SCOPE.md](SCOPE.md):
- **層0(理論)**: `paper/plonky2_mle_paper_v2.md`(§4.4 batching は未実装)
- **層1(v1設計)**: `README.md` L191-424(aux commit + combined sumcheck を正式文書化)
- **層2(v2設計)**: `soundnessgame/MleVerifier.vol.md`(Φ_inv/Φ_h/Φ_gate の定義文書)
- **層3(脅威分析)**: `tasks/todo.md` ほか(C1/C2 CRITICAL + PoC + 修正)

### 段階2で同定した乖離 (D1〜D11、詳細は `Audit/Impl/Divergences.lean`)

| ID | 深刻度(暫定) | 内容 |
|---|---|---|
| **D1** | Spec-bug | 層0 §4.2.2 の g_sub が Σ 形式で誤り。Rust/Sol とも正しい Π 形式 |
| **D2** | Medium | combined sumcheck の次数境界検査が **Rust に無い**。層2 R2-#8 で認識され **Sol は修正済**、Rust 側が残余 |
| **D3** | **High/Critical 候補** | inverse helpers 個別評価値 a_j,b_j の 個別↔batched consistency 検査だけが witness/preproc と非対称に欠落。Ext3 binding は設計(R2-#2)で主張されるが個別評価値へ降ろす鎖が途切れる |
| **D4** | Info | Φ_h の非重み付き Σ は層2 vol.md の設計に忠実(層0 §4.2.3 との乖離のみ)。λ_h は死にチャレンジ |
| **D5** | Info | transcript の 96bit 縮約。コメント「256bit/バイアス2^-192」は誤記。Rust/Sol 一貫 |
| **D6** | Info | ドメイン分離ラベルが層0 と実装で不一致。実装同士は一致 |
| **D7** | 構造 | 層0 §4.4 batching は未実装。実装は層1(aux+combined、README文書化)+層2(v2 logup)の**積層**。統合された健全性定理は存在しない |
| **D8** | 信頼仮定 | Solidity の kIs / subgroupGenPowers が transcript 非束縛(caller 責任) |
| **D9** | Low | τ_perm が squeeze されるが未使用(層1 の名残) |
| **D10** | **High, 未解決** | publicInputsHash が publicInputs に非束縛。層3 Phase6 Finding1、Solidity Poseidon 未実装のため**現在も未修正** |
| **D11** | Info/follow-up | WHIR/Sumcheck ライブラリ内部に同種の非 canonical sub(p,X) サイト(層3 Phase6 Finding4、out-of-scope) |

**最重要**: D3(inverse helpers の束縛鎖切れ)と D10(publicInputsHash 非束縛、
層3が現存 HIGH と認めている)。段階3 の Soundness 証明でこの2つが破綻点になる見込み。

## 段階1で既に出た所見 (詳細: `Audit/Statements.lean` 末尾)

1. **確定 — 仕様書誤記 (§4.2.2)**: `g_sub` の閉形式が論文では
   `Σ_i r_i·ω^{2^i}` だが、MLE の正しい閉形式は `Π_i ((1-r_i) + r_i·ω^{2^i})`。
   Rust 実装 (`mle/src/verifier.rs` L466-469) は正しい Π 形式。
2. **SUSPICION (§4.4/§7.3)**: batching sumcheck の次数を論文は「1」と
   主張するが、被和項 `eq(r_*,b)·P(b)` は変数あたり次数 2 のはず。
3. **UNDERSPECIFIED (§5.3 step 7)**: batched claim から 3 点評価への
   逆再構成アルゴリズムが論文に未記載。
4. **UNDERSPECIFIED (§4.3)**: 複数列を単一 batching sumcheck に結合する
   スカラー導出が未記載 (ρ 冪と解釈してモデル化)。
5. **NOTE (§6.1)**: Theorem 1 の誤差項 `3/|F|` (τ, τ_inv, β·γ) の集計に疑義
   (τ ∈ F^n の SZ は n/|F| のはず)。

## 次工程

- **段階2**: Rust (`mle/src/`) / Solidity (`mle/contracts/src/`) の逐行対照
  Lean 化 (行番号コメント付き)。
- **段階3**: Completeness / Soundness / FS binding / binding-gap 不在の証明
  (`Soundness.lean`, `Safety.lean`)。所見 1・2 が completeness 証明の破綻点
  として顕在化する見込み。
- **段階4**: ファイル別総点検 + `REPORT.md`。
