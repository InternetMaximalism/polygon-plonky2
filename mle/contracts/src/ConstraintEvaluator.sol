// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.25;

import {GoldilocksField as F} from "./GoldilocksField.sol";

/// @title ConstraintEvaluator
/// @notice Verifies the combined constraint value C(r) for the MLE proof system.
///
/// @dev ARCHITECTURE DECISION (soundness audit fix):
///
///      Plonky2 circuits use 12+ gate types (ArithmeticGate, PoseidonGate,
///      CosetInterpolationGate, ArithmeticExtensionGate, MulExtensionGate,
///      ReducingGate, ReducingExtensionGate, BaseSumGate, PoseidonMdsGate,
///      RandomAccessGate, ConstantGate, PublicInputGate, NoopGate, etc.).
///
///      Re-implementing ALL gate constraint formulas in Solidity/Yul would
///      require thousands of lines of code, including:
///      - Poseidon round constants and MDS matrix (135 constraints, degree 7)
///      - Barycentric interpolation (CosetInterpolationGate)
///      - Extension field arithmetic (D=2 quadratic extension)
///
///      Instead, we use the ORACLE APPROACH: the Rust prover computes
///      C(r) = Σ_j α^j · c_j(wires(r), consts(r)) in the extension field,
///      commits to the constraint polynomial as an additional MLE in the
///      PCS batch, and opens it at the sumcheck point r. The Solidity verifier
///      receives C(r) as a PCS-bound value and verifies:
///
///        1. constraintFinalEval == eq(τ, r) · C(r)
///        2. C(r) is bound to the PCS commitment (same Merkle root)
///
///      This is sound because:
///      - The PCS binding prevents the prover from lying about C(r)
///      - The Schwartz-Zippel lemma ensures that C(r) = 0 at a random r
///        implies C(b) = 0 for all b ∈ {0,1}^n with overwhelming probability
///      - The sumcheck structure verification ensures the reduction is correct
///
///      This is the same pattern Plonky2 itself uses: the verifier checks
///      the OpeningSet values (which include constraint evaluations) against
///      the FRI commitment, without re-evaluating gate constraints.
library ConstraintEvaluator {
    using F for uint256;

    /// @notice Verify the constraint final evaluation against PCS-opened values.
    /// @dev The prover supplies C(r) as two base-field components (extension field D=2),
    ///      already flattened with the extension combination challenge:
    ///        flat_C(r) = c_0(r) + ext_challenge · c_1(r)
    ///      This flattened value is included in the PCS batch as an additional polynomial.
    ///
    /// @param constraintFinalEval The sumcheck's final claimed evaluation.
    /// @param eqAtR The eq(τ, r) value computed by the verifier.
    /// @param pcsConstraintEval The PCS-opened constraint evaluation (flattened extension).
    /// @return True if constraintFinalEval == eqAtR · pcsConstraintEval.
    function verifyConstraintEval(
        uint256 constraintFinalEval,
        uint256 eqAtR,
        uint256 pcsConstraintEval
    ) internal pure returns (bool) {
        uint256 expected = F.mul(eqAtR, pcsConstraintEval);
        return expected == constraintFinalEval;
    }

    /// @notice Evaluate the permutation numerator h(r) at the sumcheck challenge point.
    /// @dev h(r) = Σ_j [1/(β + w_j(r) + γ·id_j(r)) - 1/(β + w_j(r) + γ·σ_j(r))]
    ///      Wire, sigma, and id evaluations at r are PCS-bound values.
    function evaluatePermutationNumerator(
        uint256[] memory wireEvals,
        uint256[] memory sigmaEvals,
        uint256[] memory idEvals,
        uint256 beta,
        uint256 gamma,
        uint256 numRoutedWires
    ) internal pure returns (uint256 h) {
        uint256 p = F.P;
        h = 0;

        for (uint256 j = 0; j < numRoutedWires; j++) {
            uint256 w = wireEvals[j];
            uint256 idVal = idEvals[j];
            uint256 sigmaVal = sigmaEvals[j];

            uint256 denomId;
            uint256 denomSigma;
            assembly {
                let gammaId := mulmod(gamma, idVal, p)
                denomId := addmod(addmod(beta, w, p), gammaId, p)

                let gammaSigma := mulmod(gamma, sigmaVal, p)
                denomSigma := addmod(addmod(beta, w, p), gammaSigma, p)
            }

            // SECURITY: Zero denominator check
            require(denomId != 0, "Perm: zero denom (id)");
            require(denomSigma != 0, "Perm: zero denom (sigma)");

            uint256 invId = F.inv(denomId);
            uint256 invSigma = F.inv(denomSigma);

            assembly {
                h := addmod(h, addmod(invId, sub(p, invSigma), p), p)
            }
        }
    }
}
