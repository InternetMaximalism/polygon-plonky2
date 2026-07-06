/-
  Audit/Impl/RustTranscript.lean — 段階2: mle/src/transcript.rs の逐行 Lean 化

  実装対応 (2026-07-06 時点の worktree, commit ee80ee6d):
    mle/src/transcript.rs L13-18  : struct Transcript { state: Vec<u8>, squeeze_counter: u64 }
    mle/src/transcript.rs L22-29  : new() — domain_separate("plonky2-mle-v0")
    mle/src/transcript.rs L32-39  : domain_separate — 長さ u64 LE 接頭辞 + ラベル、counter リセット
    mle/src/transcript.rs L42-46  : absorb_field — to_canonical_u64 の LE 8 バイト
    mle/src/transcript.rs L49-58  : absorb_field_vec — 長さ接頭辞 + 各要素 8 バイト
    mle/src/transcript.rs L61-66  : absorb_bytes — 長さ接頭辞 + 生バイト
    mle/src/transcript.rs L73-99  : squeeze_challenge — keccak(state ‖ counter) → 96bit 縮約
    mle/src/transcript.rs L102-104: squeeze_challenges — 逐次 squeeze

  Solidity 対応: mle/contracts/src/TranscriptLib.sol は本実装の byte-for-byte
  移植 (L5-6 の @notice)。差分は Impl/Divergences.lean で扱う。
-/
import Audit.Transcript

namespace Audit.RustImpl

open Audit

/-- バイトの抽象 (0-255 の値制約はここでは付けない — 段階2では列の構造のみ)。 -/
abbrev Byte := Nat

/-- transcript.rs L13-18: state はバイト列、squeeze_counter は u64。 -/
structure RTranscript where
  state : List Byte
  squeezeCounter : Nat

variable {F : Type} [Field F]

/-- u64 の LE 8 バイトエンコード (transcript.rs L36, L44, L55, L63 の
    `to_le_bytes`)。単射性が Fiat-Shamir バインディングに本質的。 -/
structure U64Encoding where
  encode : Nat → List Byte
  encode_len : ∀ n, (encode n).length = 8
  encode_inj : ∀ a b, a < 2 ^ 64 → b < 2 ^ 64 → encode a = encode b → a = b

/-- 体要素の canonical エンコード (transcript.rs L43 `to_canonical_u64`)。
    Rust 側では型レベルで canonical が保証される (PrimeField64)。 -/
structure FieldEncoding (F : Type) [Field F] where
  toU64 : F → Nat
  toU64_lt : ∀ x, toU64 x < 2 ^ 64
  toU64_inj : ∀ a b, toU64 a = toU64 b → a = b

/-- Keccak256 + 96bit 縮約の抽象オラクル
    (transcript.rs L78-98: keccak(bytes) → from_noncanonical_u96)。

    -- NOTE (transcript.rs L83-84, L72): コメントは「全 32 バイトを wide
    -- reduction で使用」「バイアス < 2^{-192}」と主張するが、実装 (L84-98) は
    -- u128 accumulator への wrapping_shl(64) で上位 2 リムを破棄し、
    -- 実際には hash の下位 96 ビット (lo: u64, hi: u32) しか使わない。
    -- from_noncanonical_u96 による mod p 縮約のバイアスは ~2^{-32}。
    -- 64 ビット体のチャレンジとしては許容範囲だが、コメントの主張は誤り。
    -- 深刻度 Info/Low として REPORT.md に記録予定。
    -- Solidity 側 (TranscriptLib.sol L231-236) も同じ 96 ビット縮約で、
    -- クロス実装の一貫性自体は保たれている。 -/
structure KeccakSqueeze (F : Type) [Field F] where
  squeeze : List Byte → F

/-- transcript.rs L32-39: domain_separate。
    長さ u64 LE 接頭辞 + ラベルバイトを state へ追加、counter を 0 にリセット。 -/
def domainSeparate (enc : U64Encoding) (t : RTranscript) (label : List Byte) : RTranscript :=
  { state := t.state ++ enc.encode label.length ++ label
    squeezeCounter := 0 }

/-- transcript.rs L42-46: absorb_field。
    -- NOTE: absorb_field には長さ接頭辞が**ない** (8 バイト固定なので曖昧性は
    -- ないが、absorb_bytes / absorb_field_vec とは形式が異なる)。 -/
def absorbField (enc : U64Encoding) (fe : FieldEncoding F)
    (t : RTranscript) (x : F) : RTranscript :=
  { state := t.state ++ enc.encode (fe.toU64 x)
    squeezeCounter := 0 }

/-- transcript.rs L49-58: absorb_field_vec (長さ接頭辞つき)。 -/
def absorbFieldVec (enc : U64Encoding) (fe : FieldEncoding F)
    (t : RTranscript) (xs : List F) : RTranscript :=
  { state := t.state ++ enc.encode xs.length
      ++ xs.foldr (fun x acc => enc.encode (fe.toU64 x) ++ acc) []
    squeezeCounter := 0 }

/-- transcript.rs L61-66: absorb_bytes (長さ接頭辞つき)。 -/
def absorbBytes (enc : U64Encoding) (t : RTranscript) (data : List Byte) : RTranscript :=
  { state := t.state ++ enc.encode data.length ++ data
    squeezeCounter := 0 }

/-- transcript.rs L22-29: Transcript::new()。 -/
def newTranscript (enc : U64Encoding) : RTranscript :=
  domainSeparate enc { state := [], squeezeCounter := 0 }
    -- "plonky2-mle-v0" のバイト列 (L27)。抽象化: ラベルは固定バイト列。
    [0x70, 0x6C, 0x6F, 0x6E, 0x6B, 0x79, 0x32, 0x2D, 0x6D, 0x6C, 0x65, 0x2D, 0x76, 0x30]

/-- transcript.rs L73-99: squeeze_challenge。
    keccak(state ‖ counter_LE) を体要素へ縮約し counter をインクリメント。
    **state は変化しない** (counter のみ)。

    -- NOTE (段階1モデルとの差): Audit/Transcript.lean の squeeze1 は
    -- チャレンジ自体をログへ吸収するモデルだったが、実装はチャレンジを
    -- state に残さない。counter は次の absorb でリセットされる (L38, L45,
    -- L57, L65)。つまり「squeeze したかどうか」は以後の absorb 後の
    -- チャレンジ列に影響しない (transcript.rs L193-216 のテスト
    -- test_absorb_resets_squeeze_counter が この挙動を確認している)。
    -- prover / verifier が同一スクリプトを辿る限り健全だが、段階3の
    -- FS バインディング証明はこの実装モデルに対して行う必要がある。 -/
def squeezeChallenge (enc : U64Encoding) (ko : KeccakSqueeze F)
    (t : RTranscript) : F × RTranscript :=
  (ko.squeeze (t.state ++ enc.encode t.squeezeCounter),
   { t with squeezeCounter := t.squeezeCounter + 1 })

/-- transcript.rs L102-104: squeeze_challenges (n 個逐次)。 -/
def squeezeChallenges (enc : U64Encoding) (ko : KeccakSqueeze F) :
    RTranscript → Nat → (List F × RTranscript)
  | t, 0 => ([], t)
  | t, n + 1 =>
    let (c, t') := squeezeChallenge enc ko t
    let (rest, t'') := squeezeChallenges enc ko t' n
    (c :: rest, t'')

end Audit.RustImpl
