/-
  Audit/Transcript.lean — Fiat-Shamir トランスクリプト (Keccak スポンジの抽象化)

  対応文書: mle/paper/plonky2_mle_paper_v2.md
    §5.4: 単一 Keccak256 トランスクリプト、absorb は固定長ラベル接頭辞付き、
          体要素は canonical little-endian Goldilocks encoding (raw bytes < p)。
    §6.2: 全チャレンジは commitments / round polys が absorb された後に squeeze。
          canonical encoding の強制で encoding malleability を防ぐ。

  Rust 対応 (段階2): mle/src/transcript.rs (Spongefish)
  Solidity 対応 (段階2): SpongefishWhir.vol.md, TranscriptLib.vol.md,
    Keccak256Chain.vol.md — 特に SpongefishWhirVerify.vol.md 所見#4
    (canonical range check 欠如、round 1 で修正済) がここでの
    `CanonicalEncoding.inj` 仮定の実装対応物。

  ── モデル化 ──
  スポンジ状態を「absorb されたエントリの列 (ログ)」で表し、squeeze を
  ログからチャレンジへの決定的関数 (オラクル) とする。Random Oracle Model の
  仮定は `FSOracle` の利用側で明示的な仮定として置く。
-/
import Audit.Pcs

namespace Audit

/-- ドメイン分離ラベル (paper §5.4 の一覧をそのまま列挙)。 -/
inductive Label where
  | circuitDigest      -- "PLONKY2-MLE-CIRCUIT-DIGEST"
  | publicInputs       -- "PLONKY2-MLE-PUBLIC-INPUTS"
  | witnessRoot        -- "PLONKY2-MLE-WITNESS-ROOT"
  | logupChallenges    -- "PLONKY2-MLE-LOGUP-CHALLENGES"
  | inverseRoot        -- "PLONKY2-MLE-INVERSE-ROOT"
  | constraintChals    -- "PLONKY2-MLE-CONSTRAINT-CHALS"
  | sumcheckInv        -- "PLONKY2-MLE-SUMCHECK-INV"
  | sumcheckH          -- "PLONKY2-MLE-SUMCHECK-H"
  | sumcheckGate       -- "PLONKY2-MLE-SUMCHECK-GATE"
  | batchOpen          -- "PLONKY2-MLE-BATCH-OPEN"
  | whir               -- "PLONKY2-MLE-WHIR"
  deriving DecidableEq

/-- トランスクリプトに absorb されるエントリ。
    `data` は canonical encoding 済みのバイト列を抽象化した自然数列
    (体要素は canonical encoding で単射に写る、§5.4 末尾)。 -/
inductive Entry (F : Type) where
  | label : Label → Entry F
  | field : F → Entry F
  | commitment : Nat → Entry F   -- Merkle ルート等 (ハッシュ値の抽象 id)
  | bytes : List Nat → Entry F

/-- スポンジの状態 = absorb 履歴 (先頭が最新)。 -/
abbrev TranscriptLog (F : Type) := List (Entry F)

/-- squeeze オラクル: ログ全体からチャレンジを決定的に導出する関数。
    Keccak256 スポンジの抽象。ROM の性質は利用側の仮定として置く。 -/
structure FSOracle (F : Type) where
  squeeze : TranscriptLog F → F

variable {F : Type} [Field F]

/-- absorb: エントリをログへ追加。 -/
def absorb (log : TranscriptLog F) (e : Entry F) : TranscriptLog F := e :: log

/-- ラベル付き absorb (paper §5.4: 各 absorb は固定長ラベル接頭辞付き)。 -/
def absorbLabeled (log : TranscriptLog F) (l : Label) (e : Entry F) : TranscriptLog F :=
  absorb (absorb log (.label l)) e

/-- squeeze: チャレンジを1つ取り出し、それ自身もログへ吸収する
    (逐次 squeeze の distinctness、paper §8 "sequential squeeze distinctness")。 -/
def squeeze1 (ro : FSOracle F) (log : TranscriptLog F) : F × TranscriptLog F :=
  let c := ro.squeeze log
  (c, absorb log (.field c))

/-- n 個のチャレンジ列を squeeze (τ ∈ F^n 等)。 -/
def squeezeVec (ro : FSOracle F) (log : TranscriptLog F) :
    (n : Nat) → (Vec F n × TranscriptLog F)
  | 0 => (fun i => i.elim0, log)
  | n + 1 =>
    let (c, log') := squeeze1 ro log
    let (rest, log'') := squeezeVec ro log' n
    (vcons c rest, log'')

/-! ### Fiat-Shamir バインディングの命題 (paper §6.2) — 証明/検討は段階3 -/

/-- 命題 (定義的に真であるべき): チャレンジは先行する absorb 列のみの関数である。
    本モデルでは squeeze がログの関数なので構成的に成立する。段階3で
    「Verifier の全チャレンジがコミットメント absorb の後に squeeze される」
    (paper §6.2 前段) をプロトコル定義 (Protocol.lean) に対して検査する。 -/
def fs_challenge_after_commit_prop : Prop :=
  ∀ (ro : FSOracle F) (log₁ log₂ : TranscriptLog F),
    log₁ = log₂ → ro.squeeze log₁ = ro.squeeze log₂

/-- canonical encoding の単射性 (paper §5.4 末尾 / §6.2 後段):
    2 つの異なるバイト表現が同じ体要素を表すことを禁止する。
    -- 仮定: 実装では「raw bytes < p の検査」で保証する。
       Solidity 側の対応: SpongefishWhirVerify.vol.md 所見#4 (round 1 修正)。 -/
structure CanonicalEncoding (F : Type) where
  encode : F → List Nat
  inj : ∀ a b : F, encode a = encode b → a = b
  /-- decode は canonical な表現のみ受理する (非 canonical 値は拒否)。 -/
  decode : List Nat → Option F
  decode_encode : ∀ a, decode (encode a) = some a

end Audit
