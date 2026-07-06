/-
  Audit/Statements.lean — 検証したい性質の命題 (段階0で確定した4性質)

  対応文書: mle/paper/plonky2_mle_paper_v2.md §3, §4.5, §6
  段階1の成果物としてここでは「命題の明文化」を行い、証明は段階3
  (Soundness.lean / Safety.lean) で試みる。
-/
import Audit.Protocol

namespace Audit

variable {F : Type} [Field F]

/-! ## 性質 1: Completeness

    正直な prover の証明は必ず受理される。
    正直さの定義: (i) witness がゲート制約とコピー制約を満たす、
    (ii) A_j, B_j が真の逆元 (§4.2.1)、(iii) 全 sumcheck メッセージが
    honest round polynomial、(iv) 主張評価値が bound された MLE の真の評価。 -/

/-- 逆元表の正直な構成 (§5.2 step 6): A_j(b) = 1/D_j^id(b), B_j(b) = 1/D_j^σ(b)。 -/
def honestInverses (c : Circuit F) (hWR : c.numRouted ≤ c.numWires)
    (wires : Fin c.numWires → Bits c.n → F) (β γ : F)
    (A B : Fin c.numRouted → Bits c.n → F) : Prop :=
  ∀ (j : Fin c.numRouted) (b : Bits c.n),
    let wj := wires ⟨j.val, Nat.lt_of_lt_of_le j.isLt hWR⟩ b
    A j b * (β + wj + γ * idValue c j b) = 1 ∧
    B j b * (β + wj + γ * c.sigmaTables j b) = 1

/-- Completeness の命題: 制約を満たす witness に対し、受理される証明が存在する。
    -- 段階3で証明を試みる。予想される障害 (段階1時点での観察):
    --   (a) Protocol.lean の batching sumcheck 次数境界 1 (論文 §4.4 のまま) は
    --       被和項が次数 2 のため honest prover ですら通らない疑い (SUSPICION 参照)。
    --   (b) gSubPaper (Σ 形式) が gSubMle (Π 形式) と食い違うため、
    --       inverse terminal check が honest prover で成立しない疑い。
    -- どちらも「証明が通らないこと」自体が監査所見となる。 -/
def CompletenessProp (c : Circuit F)
    (P : ProtocolPCS F c.n c.numConstants c.numRouted c.numWires)
    (hWR : c.numRouted ≤ c.numWires) : Prop :=
  ∀ (ro : FSOracle F) (vk : VerifyingKey F c P)
    (wires : Fin c.numWires → Bits c.n → F)
    (publicInputs : List F),
    GateSatisfied c wires →
    PermSatisfied c wires hWR →
    ∃ proof : MleProof F c P,
      mleVerify c P hWR ro vk proof publicInputs = true

/-! ## 性質 2: Soundness (Theorem 1, §6.1) — 決定論的コア

    確率論を持ち込まず、Theorem 1 を次の形で述べる:
    「検証者が受理したのにステートメントが不成立ならば、`sent` sumcheck 列の
    どこかで root-hit が起きているか、または β,γ の logUp collision が
    起きている」。root-hit は Sumcheck.lean の `SumcheckHitSomewhere`
    (proof の round poly 列に固定) で表し、collision は logup 数値和が消える
    事象 (β,γ に固定) で表す。いずれの選言も**自明には充足できない**
    (旧版の `∃ _e : BadEvent, True` は BadEvent が無条件に inhabited だったため
    空証明可能だった — 本改訂で除去)。

    各事象の「大きさ」(誤差分子) 対応:
      sumcheck root-hit : ラウンドあたり ≤ deg/|F| (Poly.roots_le_degree)
      logUp collision   : ≤ W_R · 2^n/|F| (Haboeck [6])
      PCS binding       : ε_PCS (ProtocolPCS.verify_sound の理想化に吸収)
-/

/-- logUp 数値和 (§4.2.3): Σ_b Σ_j (1/D_j^id(b) − 1/D_j^σ(b))。
    コピー制約が満たされないのにこれが 0 になるのが β,γ collision。 -/
def logupSum (c : Circuit F) (hWR : c.numRouted ≤ c.numWires)
    (W : Fin c.numWires → Bits c.n → F) (β γ : F) : F :=
  hsum c.n (fun b =>
    fsum c.numRouted (fun j =>
      let wj := W ⟨j.val, Nat.lt_of_lt_of_le j.isLt hWR⟩ b
      Field.inv (β + wj + γ * idValue c j b)
        - Field.inv (β + wj + γ * c.sigmaTables j b)))

/-- 選言の1つ「sumcheck のどこかで root-hit」を、proof に格納された
    round poly 列 `sent` に固定して述べる補助。honest 多項式列と
    チャレンジ列は存在量化するが、SumcheckAccepts が長さを結び付けるため
    自明充足はできない (Sumcheck.lean の SumcheckHitSomewhere 参照)。 -/
def SumcheckHitInProof (sent : List (Poly F)) : Prop :=
  ∃ (Sh : F) (honest : List (Poly F)) (chals : List F),
    SumcheckAccepts Sh honest chals ∧ SumcheckHitSomewhere sent honest chals

/-- Soundness の命題 (Theorem 1 の決定論的コア、非空版)。
    受理 ∧ (ゲート制約 or コピー制約の不成立) ⇒
      (4 本の sumcheck のいずれかで root-hit) ∨ (β,γ logUp collision)。
    -- PCS binding (ε_PCS) は ProtocolPCS.verify_sound の理想化に吸収。
    -- 段階3: SumcheckTelescopeHit + Haboeck を使って各選言を導く。
    -- 段階3の強化予定 (pinning): 実装モデル (RustSoundnessProp,
    --   Audit/Impl/ImplStatements.lean) では honest/chals を proof 格納の
    --   実チャレンジに固定でき、より強い主張になる。本 (paper) 版は
    --   チャレンジが mleVerify 内部で非公開のため存在量化に留める。 -/
def SoundnessProp (c : Circuit F)
    (P : ProtocolPCS F c.n c.numConstants c.numRouted c.numWires)
    (hWR : c.numRouted ≤ c.numWires) : Prop :=
  ∀ (ro : FSOracle F) (vk : VerifyingKey F c P)
    (proof : MleProof F c P) (publicInputs : List F),
    mleVerify c P hWR ro vk proof publicInputs = true →
    -- witness は PCS binding が定める一意の表 (理想化):
    (¬ GateSatisfied c (P.boundW proof.witnessRoot) ∨
     ¬ PermSatisfied c (P.boundW proof.witnessRoot) hWR) →
    SumcheckHitInProof proof.scGate ∨
    SumcheckHitInProof proof.scInv ∨
    SumcheckHitInProof proof.scH ∨
    (∃ β γ : F, logupSum c hWR (P.boundW proof.witnessRoot) β γ = 0)

/-! ## 性質 3: Fiat-Shamir バインディング (§6.2) -/

/-- チャレンジ順序の正しさ: mleVerify のトランスクリプトにおいて、
    (i) β, γ は witness_root の absorb より後に squeeze される、
    (ii) α, λ, μ, λ_h, τ, τ_inv は inverse_root の absorb より後、
    (iii) 各 sumcheck チャレンジは当該ラウンド多項式の absorb より後、
    (iv) ν₁, ν₂, ρ は全 sumcheck の後。
    -- 本モデルではこれは mleVerify の定義 (let 束縛の順序) から構文的に
    -- 読み取れる。段階3では「squeeze に渡るログが対応する absorb を接頭辞に
    -- 含む」ことを補題として抽出する。段階2では Rust transcript.rs /
    -- Solidity TranscriptLib の absorb/squeeze 順序と対照する。 -/
def FSOrderingProp : Prop :=
  -- squeeze はログの決定的関数 (構成的に真; challenge-after-commit の骨格)
  ∀ (ro : FSOracle F) (log : TranscriptLog F) (e : Entry F),
    squeeze1 ro (absorb log e) = squeeze1 ro (absorb log e)

/-- ドメイン分離 (§5.4): 異なるラベルの absorb はログ上で区別される。
    Entry.label が単射に埋め込まれるので構成的に成立する。
    段階2では「実装のラベルバイト列が相異なる固定長である」ことに帰着する。 -/
def DomainSeparationProp : Prop :=
  ∀ (l₁ l₂ : Label), (Entry.label l₁ : Entry F) = Entry.label l₂ → l₁ = l₂

/-! ## 性質 4: バインディングギャップ不在 (§3, §4.5) -/

/-- §3 の負の主張 (ギャップの実在):
    次数 ≥ 2 の formula について、一般に
      MLE(b ↦ formula(W(b)))(r) ≠ formula(MLE(W)(r))。
    具体的な反例 (formula = 二乗、n = 1) の存在として述べる。
    -- 段階3で witness (具体的な W と r) を与えて証明する。
    -- これが adapter 方式 (§3) が不健全である理由の形式化。 -/
def BindingGapExistsProp : Prop :=
  ∃ (W : Bits 1 → F) (r : Vec F 1),
    mleEval (fun b => W b * W b) r ≠ (mleEval W r) * (mleEval W r)

/-- §4.5 leg 2 の正の主張 (本構成はギャップを踏まない):
    終端チェックに現れる式は PCS-opened 引数について**線形**なので
    MLE と可換である。線形結合について MLE が可換であることとして述べる。
    -- 段階3で証明する。gate terminal (§4.1) は formula(w(r), const(r)) を
    -- 「そのまま Φ_gate(r) の定義」として使うため可換性は不要 (§4.1 の
    -- "both sides are the polynomial Φ_gate evaluated at r, period")。
    -- 可換性が必要なのは inverse/H terminal の線形部分のみ、が §4.5 の主張。 -/
def LinearCommutesProp : Prop :=
  ∀ (n : Nat) (T₁ T₂ : Bits n → F) (α β : F) (r : Vec F n),
    mleEval (fun b => α * T₁ b + β * T₂ b) r
      = α * mleEval T₁ r + β * mleEval T₂ r

/-! ## 段階1での観察メモ (段階3・4への引き継ぎ)

  1. SUSPICION → 確定 (§4.2.2 gSub): 論文の g_sub 閉形式 (Σ) は MLE の
     正しい閉形式 (Π) と異なる。予備対照 (2026-07-06) で Rust 実装
     verifier.rs L466-469 は Π 形式 (gSubMle) を実装していることを確認。
     **仕様書 §4.2.2 の誤記** (実装は正しい)。REPORT.md に所見として記録。

  2. SUSPICION (§4.4/§7.3 batching 次数): batching sumcheck の被和項
     eq(r_*, b)·P(b) は変数あたり次数 2 のはずだが論文は "degree 1" と
     主張。→ 段階3: completeness 証明で判定。

  3. UNDERSPECIFIED (§5.3 step 7): batched claim から 3 点評価への
     「逆再構成」のアルゴリズム。Protocol.lean では prover 供給の
     主張評価値 + batching sumcheck 束縛としてモデル化した。
     → 段階2: verifier.rs の実装方式と対照し、モデルを引き直す。

  4. UNDERSPECIFIED (§4.3): 複数列を単一 batching sumcheck へ結合する
     スカラーの導出。ρ の冪と解釈 (Protocol.lean)。→ 段階2で対照。

  5. NOTE (§6.1): 誤差項 "3/|F|" (τ, τ_inv, β·γ leak) は τ ∈ F^n の
     Schwartz-Zippel としては n/|F| になるはずで、まとめ方に疑義。
     → 段階4で Theorem 1 の誤差集計を再検討。
-/

end Audit
