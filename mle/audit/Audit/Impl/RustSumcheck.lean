/-
  Audit/Impl/RustSumcheck.lean — 段階2: sumcheck の逐行 Lean 化

  実装対応:
    mle/src/sumcheck/types.rs   L9-12  : RoundPolynomial { evaluations: Vec<F> }
                                          — **評価値表現** (0..d での値)。
                                          段階1モデル (Audit/Poly.lean) は係数
                                          表現だったので、ここで評価値表現を導入。
    mle/src/sumcheck/types.rs   L25-27 : evaluate = Lagrange 補間 (整数ノード)
    mle/src/sumcheck/types.rs   L33-68 : lagrange_interpolate_over_integers
    mle/src/sumcheck/verifier.rs L22-57: verify_sumcheck
    mle/contracts/src/SumcheckVerifier.sol L32-77: Solidity 版 verify
-/
import Audit.Impl.RustTranscript

namespace Audit.RustImpl

open Audit

variable {F : Type} [Field F]

/-- types.rs L9-12: ラウンド多項式 = ノード {0,1,…,d} での評価値リスト。 -/
abbrev RoundPolyE (F : Type) := List F

/-- types.rs L33-68: 整数ノード {0,…,d} 上の Lagrange 補間評価。
      f(x) = Σ_i evals[i] · Π_{j≠i} (x − j) / (i − j)
    実装はノード一致 (x = i) の早期 return (L47-50) を持つが、
    数学的には同じ関数なので閉形式で写す。
    Solidity 版 (SumcheckVerifier.sol L84-232) は barycentric + batch-invert
    だが評価結果は同一 (ノード一致の早期 return は L91-93)。 -/
def lagrangeEval (evals : RoundPolyE F) (x : F) : F :=
  let d := evals.length
  fsum d (fun i =>
    (evals.getD i.val 0) *
      vprod d (fun j =>
        if j.val = i.val then 1
        else (x - natToF j.val) * Field.inv (natToF i.val - natToF j.val)))

/-- sumcheck/verifier.rs L22-57: verify_sumcheck。

    - L28-33: round_polys.len() ≠ num_vars → reject
    - L40   : sum = evaluations[0] + evaluations[1]
              -- NOTE: 長さ ≥ 2 の検査なし。len < 2 で Rust は panic
              -- (index out of bounds)。健全性でなく可用性 (DoS) の問題。
              -- Solidity 版は require(evals.length >= 2) がある
              -- (SumcheckVerifier.sol L48)。ここでは getD で 0 を返す形で
              -- 写し、長さ検査の欠如を Divergences.lean D2 で扱う。
    - L41-43: sum ≠ current_claim → reject
    - L46-47: "sumcheck-round" ドメイン分離 + 評価値列を absorb
    - L50   : チャレンジ squeeze
    - L54   : current_claim = round_poly.evaluate(r_i)

    -- SUSPICION (次数境界): verify_sumcheck 自体は round poly の長さ
    -- (= 次数 + 1) を**一切検査しない**。次数境界は呼び出し側の責任だが、
    -- mle/src/verifier.rs の combined sumcheck 呼び出し (L143-146) には
    -- 次数検査が**存在しない** (Φ_inv L159-165 は ≤4、Φ_h L185-191 は ==2、
    -- Φ_gate L222-229 は ==d+1 の検査があるのと対照的)。
    -- prover は combined sumcheck に任意次数のラウンド多項式を送れる。
    -- sumcheck の健全性誤差はラウンドあたり deg/|F| なので、次数無制限は
    -- 主張された 2n/|F| の健全性境界を破る。Divergences.lean D2 参照。 -/
def rustVerifySumcheck (enc : U64Encoding) (fe : FieldEncoding F)
    (ko : KeccakSqueeze F) :
    F → List (RoundPolyE F) → RTranscript →
    Option (List F × F × RTranscript)
  | claim, [], t => some ([], claim, t)
  | claim, evals :: rest, t =>
    -- L40-43: g_i(0) + g_i(1) = claim
    if evals.getD 0 0 + evals.getD 1 0 ≠ claim then
      none
    else
      -- L46-47: absorb
      let t₁ := domainSeparate enc t
        [0x73, 0x75, 0x6D, 0x63, 0x68, 0x65, 0x63, 0x6B, 0x2D, 0x72,
         0x6F, 0x75, 0x6E, 0x64]  -- "sumcheck-round"
      let t₂ := absorbFieldVec enc fe t₁ evals
      -- L50: squeeze
      let (r, t₃) := squeezeChallenge enc ko t₂
      -- L54: 次の主張
      let claim' := lagrangeEval evals r
      match rustVerifySumcheck enc fe ko claim' rest t₃ with
      | some (rs, fin, t') => some (r :: rs, fin, t')
      | none => none

/-- ラウンド数検査 (sumcheck/verifier.rs L28-33) を含む完全版。 -/
def rustVerifySumcheckChecked (enc : U64Encoding) (fe : FieldEncoding F)
    (ko : KeccakSqueeze F) (claim : F) (numVars : Nat)
    (roundPolys : List (RoundPolyE F)) (t : RTranscript) :
    Option (List F × F × RTranscript) :=
  if roundPolys.length ≠ numVars then none
  else rustVerifySumcheck enc fe ko claim roundPolys t

/-- Solidity 版との差分を命題化するための次数境界付き述語
    (SumcheckVerifier.sol L44-50: require(evals.length <= maxDegree + 1) と
     require(evals.length >= 2))。Rust 側にこの検査はない。 -/
def solRoundPolyBounds (maxDegree : Nat) (roundPolys : List (RoundPolyE F)) : Prop :=
  ∀ evals ∈ roundPolys, 2 ≤ evals.length ∧ evals.length ≤ maxDegree + 1

end Audit.RustImpl
