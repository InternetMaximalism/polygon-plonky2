# WHIR/MLE構成の最適性分析レポート

## 概要

本レポートでは、`plonky2_mle_paper.pdf` に記述されたマルチリニア・ネイティブ証明システムの構成を、WHIRのクエリ特性の観点から分析し、改善案を提示する。

現在の構成は **2つのWHIRプルーフ** を必要とする：
1. **メインWHIR**: preprocessed + witness 多項式の split-commit（チャレンジ導出前にコミット）
2. **補助WHIR**: C̃ + h̃ のバッチコミット（チャレンジ導出後にコミット）

結論として、**補助WHIRプルーフの完全な除去が可能**であり、これにより検証コスト約50%削減、プルーフサイズの大幅削減が達成できる。

---

## 1. WHIRのクエリ特性の整理

WHIRは以下の特性を持つマルチリニアPCS：

| 特性 | 詳細 |
|------|------|
| コミット | ハイパーキューブ上の評価値のMerkle化 → ルートハッシュ |
| オープン | 指定点 r での評価値 f(r) を証明 |
| フォールディング | 各ラウンドで `folding_factor` 変数を一度に畳み込み |
| クエリ数 | q ≈ λ / log(1/ρ)、ρ=rate（現在 1/16 → q ≈ λ/4） |
| 検証コスト | O(q · n/ff · 2^ff) ハッシュ評価（ff=folding_factor） |
| プルーフサイズ | O(q · n/ff) Merkleパス + フォールディングデータ |
| バッチ対応 | 同一点での複数多項式のバッチオープンはネイティブサポート |

**重要な観察**: WHIRの検証コストはプルーフ1件あたり固定的に高い。2件のWHIRプルーフは単純に2倍のコストがかかる。Sumcheckラウンド多項式のサイズ増加（数百バイト）と比較して、WHIRプルーフ1件（数KB〜数十KB）のコスト差は桁違いに大きい。

---

## 2. 現在の構成の分析

### 2.1 なぜ補助コミットメントが存在するか

現在の設計では C̃ (制約MLE) と h̃ (置換MLE) をハイパーキューブ上で**事前実体化**している：

```
C̃(b) = Σ_j α^j · c_j(wires(b), consts(b))   ∀b ∈ {0,1}^n
h̃(b) = Σ_j [1/(β + w_j(b) + γ·id_j(b)) - 1/(β + w_j(b) + γ·σ_j(b))]
```

C̃ と h̃ はチャレンジ (α, β, γ) に依存するため、メインコミットメント時には計算できない。このため補助WHIRコミットメントが必要となる。

事前実体化の利点は、Sumcheckの次数が **変数あたり2** に固定されること（2つのマルチリニアの積）。1ラウンドあたり3個の評価点で済む。

### 2.2 コスト構造

```
現在の検証コスト:
  Sumcheck検証:  n ラウンド × 3 評価点 = 3n フィールド演算
  メインWHIR:    ~q₁ · (n/ff) Merkleパス検証
  補助WHIR:      ~q₂ · (n/ff) Merkleパス検証
  最終チェック:  数回のフィールド演算

  → WHIRが支配的（全体の80-90%）
```

**Solidityにおけるガスコスト概算 (n=16, ff=4, λ=90)**:
- Sumcheck: ~48 フィールド乗算 ≈ ~5,000 gas
- WHIR 1件: ~23 クエリ × 4ラウンド × Merkle検証 ≈ ~200,000-400,000 gas
- **WHIR 2件合計: ~400,000-800,000 gas**

---

## 3. 改善案

### 3.1 【主要提案】On-the-fly制約評価によるC̃コミットメントの除去

**核心的洞察**: C̃を事前実体化する代わりに、Sumcheck中にゲート制約を直接評価する。

```
現在:
  Sumcheck多項式: g(x) = eq(τ,x) · C̃(x) + μ · h̃(x)
  C̃はMLEなので次数1/変数 → g は次数2/変数

提案:
  Sumcheck多項式: g(x) = eq(τ,x) · Σ_j α^j c_j(wire(x), const(x)) + μ · h̃(x)
  制約 c_j の次数は最大 d_gate → g は次数 (1 + d_gate)/変数
```

**最終チェックでの違い**:

- **現在**: 検証者は C̃(r) を補助WHIRから取得
- **提案**: 検証者は `C_raw(r) = Σ_j α^j c_j(wire_j(r), const_j(r))` をメインWHIRの個別評価値から**自ら計算**

これが可能な理由: Plonky2のゲート制約 `c_j` は既知の多項式関数（ArithmeticGate: `a·b - c`、PoseidonGate: `x^7 - y` 等）であり、wire(r) と const(r) の値がWHIR-boundであれば、検証者は C_raw(r) を信頼できる形で再構成できる。

**重要な注意**: C̃(r)（ハイパーキューブ上の制約評価テーブルのMLE）と C_raw(r)（制約関数のMLE引数での直接評価）は一般に**異なる値**である。しかしSumcheckの対象多項式を変更することで、最終チェックで必要な値も変わり、C_raw(r) で十分になる。

#### 次数への影響

| ゲートタイプ | 制約次数 d_gate | Sumcheck次数/変数 | 評価点/ラウンド |
|-------------|----------------|-------------------|----------------|
| Arithmetic  | 2              | 3                 | 4              |
| Poseidon    | 7              | 8                 | 9              |
| BaseSumGate | 3              | 4                 | 5              |

Poseidonを含む回路では1ラウンドあたり9評価点（現在の3から増加）。ただし:
- 追加コスト: n ラウンド × 6追加フィールド要素 = 6n × 8 bytes
- n=16 の場合: 768 bytes の追加プルーフサイズ
- **WHIRプルーフ1件の削減による節約: 数KB〜数十KB**

#### Prover側の変更

現在のProver (`prover.rs:242-253`) は C̃ を事前計算している：
```rust
let combined_ext = compute_combined_constraints(...);
let padded_constraints = flatten_extension_constraints(...);
```

提案では、Sumcheckの各ラウンドで制約を直接評価する。Plonky2の `eval_unfiltered(vars: EvaluationVars)` インターフェースは任意のフィールド点で動作するため（論文 §7.2）、インフラは既に存在する。

Proverの計算量は変わらない（O(2^n · #constraints)）が、メモリ使用量が O(2^n) から O(2^{n-round}) に減少する（事前実体化テーブルが不要）。

### 3.2 【主要提案】GKRベースの置換チェックによるh̃コミットメントの除去

h̃ の除去はより困難だが、**GKR (Goldwasser-Kalai-Rothblum) プロトコル**を用いることで可能。

#### 現在のLogUp置換チェック

```
Σ_b h(b) = 0
h(b) = Σ_j [1/(β + w_j(b) + γ·id_j(b)) - 1/(β + w_j(b) + γ·σ_j(b))]
```

h̃ は分数式のテーブルのMLEであり、wire(r) と sigma(r) から h̃(r) を再構成できない。

#### GKRベースの代替

マルチセット等価性チェック: `{w_j(b) + γ·id_j(b)} = {w_j(b) + γ·σ_j(b)}` をGKR形式で証明する。

具体的には、grand product の対数版：

```
Π_{b,j} (β + w_j(b) + γ·id_j(b)) / (β + w_j(b) + γ·σ_j(b)) = 1
```

これを sumcheck-over-hyperplane に分解：

1. **レイヤー0**: 各 (b,j) に対して `f(b,j) = (β + w_j(b) + γ·id_j(b))` と `g(b,j) = (β + w_j(b) + γ·σ_j(b))` を定義
2. **GKR帰納**: 積の等価性を sumcheck の連鎖で wire(r), sigma(r), id(r) の評価に帰着
3. **最終チェック**: メインWHIRにバインドされた wire(r), sigma(r) の値で検証

これにより **h̃ のコミットメントが完全に不要**になる。

#### GKRの追加コスト

- 追加 sumcheck ラウンド: O(log(W_R)) ラウンド（W_R = routed wires 数）
- 各ラウンド: degree-2 per variable
- 典型的な W_R = 80 の場合: ~7 追加ラウンド × n 変数 = 7n フィールド演算

**WHIRプルーフ1件（~200,000-400,000 gas）に対して、GKR追加コストは ~10,000 gas 程度**。

### 3.3 【統合案】単一WHIRプルーフ構成

提案3.1と3.2を組み合わせると：

```
改善後の構成:
  1. メインWHIR: preprocessed + witness をコミット（唯一のWHIRプルーフ）
  2. チャレンジ導出: α, β, γ, τ
  3. On-the-fly制約 Sumcheck: 次数 (1+d_gate)/変数
  4. GKRベース置換チェック: 追加 sumcheck ラウンド
  5. メインWHIR: 点 r でオープン
  6. 最終チェック: 検証者がメインWHIR評価値から全てを再構成

  WHIRプルーフ: 1個（現在の2個から削減）
```

#### コスト比較

| 項目 | 現在 | 提案 | 差分 |
|------|------|------|------|
| WHIRプルーフ数 | 2 | 1 | **-50%** |
| Sumcheck次数/変数 | 2 | 8 (Poseidon) | +6 |
| Sumcheck評価点/ラウンド | 3 | 9 | +6 |
| 追加Sumcheckラウンド | 0 | ~7n (GKR) | +7n |
| プルーフサイズ (n=16) | ~2 WHIR + 48 elements | ~1 WHIR + ~200 elements | **-30〜40%** |
| Solidity検証ガス概算 | ~500K-900K | ~300K-500K | **-35〜45%** |
| Proverメモリ | O(2^n) for C̃, h̃ | O(2^n) for wire MLEs | **-40%** |

---

## 4. WHIRパラメータの最適化

現在のパラメータ (`WhirPCS::for_num_vars`):
```
folding_factor = min(num_vars, 4)
starting_log_inv_rate = 4  (rate = 1/16)
security_level = min(90, num_vars * 5 + 10)
pow_bits = 0
```

### 4.1 On-chain最適化のためのrate調整

Ethereumでのハッシュコスト:
- Keccak256: ~30 gas (base) + 6 gas/32-byte word
- SHA256 precompile: 60 gas (base) + 12 gas/32-byte word

クエリ数 q = λ / log₂(1/ρ) なので:
- rate 1/16 (k=4): q = 90/4 ≈ 23 クエリ
- rate 1/64 (k=6): q = 90/6 = 15 クエリ  ← **35%削減**
- rate 1/256 (k=8): q = 90/8 ≈ 12 クエリ ← **48%削減**

トレードオフ: rate を下げると初期コミットメントサイズ（Merkle木の葉数）が増加するが、calldataコスト(16 gas/byte) はハッシュコストより安い。

**推奨**: on-chain検証には `starting_log_inv_rate = 6` (rate 1/64) が最適バランス。

### 4.2 Folding factorの調整

現在 ff=4。WHIRの各ラウンドで 2^ff = 16 要素のコセットを読み取る。

- ff=3: 5-6 ラウンド、コセット8要素 → ラウンド数増加だがラウンドあたりコスト減
- ff=4: 4 ラウンド、コセット16要素 → 現在のバランス
- ff=5: 3 ラウンド、コセット32要素 → ラウンド数減だがラウンドあたりコスト増

Solidityでは Merkle パス検証のループオーバーヘッドが大きいため、**ラウンド数を減らす方向（ff=5）**が有利な場合がある。実測でのチューニングを推奨。

---

## 5. 追加の改善案

### 5.1 Sumcheck-WHIR融合

WHIRの内部構造もSumcheckベース（フォールディング = Sumcheckの一種）。外部Sumcheck（zero-check）とWHIRの内部Sumcheck（proximity test）を**融合**できる可能性がある。

具体的には: Sumcheckの最終ラウンドでの評価点 r をWHIRのフォールディングの開始点として使用し、WHIRの「オープン」フェーズの一部をSumcheckの延長として実行する。これにより数ラウンドのフォールディングを省略できる可能性がある。

これは研究課題レベルだが、実現すれば追加で ~15-20% の検証コスト削減が見込める。

### 5.2 Preprocessedバッチの検証キーへの埋め込み

現在、preprocessed多項式はメインWHIRのsplit-commitに含まれている。Preprocessedは回路固定（verifier keyに含まれる）なので、WHIRプルーフから除外してVKにMerkleルートのみ保持し、メインWHIRをwitness専用にすることで、WHIRプルーフサイズをさらに削減できる。

ただしこれは現在の `verify_split` が2ベクトルを同時証明する構造に依存しているため、WHIRの内部APIの変更が必要。

### 5.3 Extension field embedding の最適化

現在、Goldilocks (64-bit) を `Basefield<Field64_3>` (192-bit cubic extension) にembedしている。WHIRのセキュリティはチャレンジ空間のサイズに依存するが、Goldilocksの64-bitフィールドは sumcheck のセキュリティには十分（soundness error ≈ n·d/2^64）。

Extension fieldの使用がWHIR内部のフォールディング精度に必要なのか、あるいはbase fieldで十分なのかの精査を推奨。Base fieldで動作可能であれば、フィールド演算コストが ~3倍削減される。

---

## 6. 実装優先度の提案

| 優先度 | 改善案 | 期待効果 | 実装難度 |
|--------|--------|----------|----------|
| **P0** | On-the-fly制約評価 (§3.1) | WHIR 2→1.5 (C̃除去) | 中 |
| **P0** | Rate parameter tuning (§4.1) | 検証ガス ~35%削減 | 低 |
| **P1** | GKRベース置換 (§3.2) | WHIR 2→1 (h̃除去) | 高 |
| **P1** | Folding factor tuning (§4.2) | 検証ガス ~10-15%削減 | 低 |
| **P2** | Sumcheck-WHIR融合 (§5.1) | 追加 ~15-20%削減 | 非常に高 |
| **P2** | Preprocessed分離 (§5.2) | プルーフサイズ削減 | 中 |
| **P3** | Extension field精査 (§5.3) | フィールド演算 ~3倍削減 | 中 |

**P0を実装するだけでも、on-chain検証コスト30-40%の削減が見込める。**

---

## 7. セキュリティに関する注意

### 7.1 On-the-fly制約評価のサウンドネス

On-the-fly方式では、Sumcheckの対象多項式が変わる：

```
現在:  g(x) = eq(τ,x) · C̃_MLE(x)        (C̃_MLEはマルチリニア)
提案:  g(x) = eq(τ,x) · C_raw(x)         (C_rawは次数d_gate)
```

`C̃_MLE(x)` と `C_raw(x)` は {0,1}^n 上では一致する（どちらも C(b) = Σ α^j c_j(wires(b),...)）が、非ブール点では異なる。Sumcheckのサウンドネスは Schwartz-Zippel に依存し、次数 d の多項式に対して soundness error ≤ n·d/|F|。d が増加しても |F| = 2^64 なので十分。

### 7.2 GKRベース置換のサウンドネス

GKRプロトコルのサウンドネスは標準的だが、以下に注意：
- 各GKRレイヤーの sumcheck チャレンジは Fiat-Shamir で正しくバインドされること
- Grand productの分子・分母が正しくドメイン分離されること
- β, γ チャレンジがすべてのwireコミットメント確定後に導出されること

---

## 8. 結論

現在の構成は「C̃とh̃の事前実体化 → 補助WHIRコミット → 低次数Sumcheck」という設計思想に基づいている。これはSumcheckの次数を最小化する点では最適だが、**WHIRのクエリコストが支配的な状況では最適ではない**。

WHIRプルーフ1件のコストはSumcheckラウンド多項式の次数増加コストを大幅に上回るため、**Sumcheck次数を犠牲にしてでもWHIRプルーフ数を削減する方が全体最適となる**。

最も効果的な改善は:
1. On-the-fly制約評価によるC̃除去（WHIRプルーフサイズ削減 + Proverメモリ削減）
2. GKRベース置換チェックによるh̃除去（補助WHIRプルーフの完全除去）
3. WHIR rateパラメータのon-chain最適化

これらにより、検証コストを現在の **35-50%** に削減できると見込まれる。
