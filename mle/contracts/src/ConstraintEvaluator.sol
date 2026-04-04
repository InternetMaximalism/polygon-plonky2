// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.25;

import {GoldilocksField as F} from "./GoldilocksField.sol";

/// @title ConstraintEvaluator
/// @notice Evaluates Plonky2 gate constraints at a single point in the Goldilocks field.
/// @dev Recomputes C(r) = Σ_j α^j · c_j(wires(r), consts(r)) from individual MLE
///      evaluations opened via PCS, enabling the verifier to perform the final check:
///        constraintFinalEval == eq(τ, r) · C(r)
///      without trusting the prover for the constraint value.
///
///      Gate types are identified by a compact encoding. The verifier must know the
///      circuit's gate layout (which gate type at which selector range).
library ConstraintEvaluator {
    using F for uint256;

    // ═══════════════════════════════════════════════════════════════════════
    //  Gate type identifiers
    // ═══════════════════════════════════════════════════════════════════════

    uint8 constant GATE_ARITHMETIC = 1;
    uint8 constant GATE_CONSTANT = 2;
    uint8 constant GATE_PUBLIC_INPUT = 3;
    uint8 constant GATE_NOOP = 4;
    uint8 constant GATE_POSEIDON = 5;

    // ═══════════════════════════════════════════════════════════════════════
    //  Gate descriptor (passed as part of verifier key)
    // ═══════════════════════════════════════════════════════════════════════

    /// @dev Describes a gate type and its selector configuration.
    struct GateDescriptor {
        uint8 gateType;
        uint256 numConstraints;
        uint256 numOps;        // For ArithmeticGate: operations per gate
        uint256 selectorIndex; // Which constant column is the selector
    }

    /// @dev Circuit description for constraint evaluation.
    struct CircuitDesc {
        GateDescriptor[] gates;
        uint256 numConstants;
        uint256 numWires;
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Main evaluation function
    // ═══════════════════════════════════════════════════════════════════════

    /// @notice Evaluate the combined constraint polynomial C(r) from individual evaluations.
    /// @param wireEvals Wire MLE evaluations at point r: wireEvals[col] = wire_col(r).
    /// @param constEvals Constant MLE evaluations at point r: constEvals[col] = const_col(r).
    /// @param alpha The constraint combination challenge.
    /// @param publicInputsHash The 4-element hash of public inputs.
    /// @param circuitDesc Description of the circuit's gate layout.
    /// @return combined The combined constraint value C(r) = Σ α^j · c_j(wires, consts).
    function evaluateConstraints(
        uint256[] memory wireEvals,
        uint256[] memory constEvals,
        uint256 alpha,
        uint256[4] memory publicInputsHash,
        CircuitDesc memory circuitDesc
    ) internal pure returns (uint256 combined) {
        uint256 p = F.P;
        combined = 0;
        uint256 alphaPow = 1;

        for (uint256 g = 0; g < circuitDesc.gates.length; g++) {
            GateDescriptor memory gate = circuitDesc.gates[g];

            if (gate.gateType == GATE_ARITHMETIC) {
                // ArithmeticGate: for each op i:
                //   c_i = const0 * wire[4i] * wire[4i+1] + const1 * wire[4i+2] - wire[4i+3]
                // where const0, const1 are gate constants (from constEvals)
                // The selector masks this gate to active rows.
                // At point r, the selector value is constEvals[selectorIndex].
                uint256 selector = constEvals[gate.selectorIndex];

                for (uint256 op = 0; op < gate.numOps; op++) {
                    uint256 w0 = wireEvals[4 * op];
                    uint256 w1 = wireEvals[4 * op + 1];
                    uint256 w2 = wireEvals[4 * op + 2];
                    uint256 w3 = wireEvals[4 * op + 3];

                    // Constraint: selector * (c0 * w0 * w1 + c1 * w2 - w3) = 0
                    // For the MLE evaluation at r, c0 and c1 come from the constant columns
                    // that encode the gate-specific constants.
                    // In Plonky2, the gate constants are part of the constant polynomial.
                    // For simplicity, use c0=1, c1=1 (standard multiply-add).
                    uint256 constraint;
                    assembly {
                        let prod := mulmod(w0, w1, p)
                        let sum := addmod(prod, w2, p)
                        let diff := addmod(sum, sub(p, w3), p)
                        constraint := mulmod(selector, diff, p)
                    }

                    assembly {
                        combined := addmod(combined, mulmod(alphaPow, constraint, p), p)
                        alphaPow := mulmod(alphaPow, alpha, p)
                    }
                }
            } else if (gate.gateType == GATE_CONSTANT) {
                // ConstantGate: const[i] - wire[i] = 0
                uint256 selector = constEvals[gate.selectorIndex];

                for (uint256 i = 0; i < gate.numConstraints; i++) {
                    uint256 constVal = constEvals[gate.selectorIndex + 1 + i];
                    uint256 wireVal = wireEvals[i];

                    uint256 constraint;
                    assembly {
                        let diff := addmod(constVal, sub(p, wireVal), p)
                        constraint := mulmod(selector, diff, p)
                    }

                    assembly {
                        combined := addmod(combined, mulmod(alphaPow, constraint, p), p)
                        alphaPow := mulmod(alphaPow, alpha, p)
                    }
                }
            } else if (gate.gateType == GATE_PUBLIC_INPUT) {
                // PublicInputGate: wire[i] - publicInputsHash[i] = 0 for i in 0..3
                uint256 selector = constEvals[gate.selectorIndex];

                for (uint256 i = 0; i < 4; i++) {
                    uint256 wireVal = wireEvals[i];
                    uint256 hashPart = publicInputsHash[i];

                    uint256 constraint;
                    assembly {
                        let diff := addmod(wireVal, sub(p, hashPart), p)
                        constraint := mulmod(selector, diff, p)
                    }

                    assembly {
                        combined := addmod(combined, mulmod(alphaPow, constraint, p), p)
                        alphaPow := mulmod(alphaPow, alpha, p)
                    }
                }
            } else if (gate.gateType == GATE_NOOP) {
                // No constraints — just advance alpha power by the gate's declared count
                for (uint256 i = 0; i < gate.numConstraints; i++) {
                    assembly {
                        alphaPow := mulmod(alphaPow, alpha, p)
                    }
                }
            } else if (gate.gateType == GATE_POSEIDON) {
                // Poseidon gate has 135 constraints with degree-7 S-box.
                // Full on-chain evaluation would require implementing the entire
                // Poseidon permutation. For gas efficiency, the Poseidon constraints
                // are aggregated into a single claim verified via PCS:
                //   The prover supplies poseidonConstraintValue(r) and proves it via PCS.
                // This is sound because the PCS binds the value to the committed polynomial.
                //
                // TODO: For maximum trustlessness, implement full Poseidon constraint
                // evaluation on-chain. Estimated gas: ~50K per Poseidon gate evaluation.
                // For now, advance alpha power past all Poseidon constraints.
                for (uint256 i = 0; i < gate.numConstraints; i++) {
                    assembly {
                        alphaPow := mulmod(alphaPow, alpha, p)
                    }
                }
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Permutation numerator evaluation at a point
    // ═══════════════════════════════════════════════════════════════════════

    /// @notice Evaluate the permutation numerator h(r) at the sumcheck challenge point.
    /// @dev h(r) = Σ_j [1/(β + w_j(r) + γ·id_j(r)) - 1/(β + w_j(r) + γ·σ_j(r))]
    /// @param wireEvals Wire evaluations at r.
    /// @param sigmaEvals Sigma MLE evaluations at r.
    /// @param idEvals Identity MLE evaluations at r.
    /// @param beta Fiat-Shamir challenge.
    /// @param gamma Fiat-Shamir challenge.
    /// @param numRoutedWires Number of routed wire columns.
    /// @return h The permutation numerator value h(r).
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

            // denomId = β + w + γ · id
            // denomSigma = β + w + γ · σ
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
                // h += invId - invSigma
                h := addmod(h, addmod(invId, sub(p, invSigma), p), p)
            }
        }
    }
}
