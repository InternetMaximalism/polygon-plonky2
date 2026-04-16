// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.25;

import {TranscriptLib} from "../src/TranscriptLib.sol";

/// @title TranscriptE2ETrace
/// @notice Replays the exact E2E protocol flow from the Rust trace test
///         and verifies challenges match at each checkpoint.
///         Uses the EXACT same values output by test_e2e_transcript_trace.
contract TranscriptE2ETrace {

    uint256 constant P = 0xFFFFFFFF00000001;

    // ── Reference values from Rust E2E trace (x*y=z circuit, x=3, y=7) ──
    uint256 constant REF_BATCH_R = 13000817457220507840;
    uint256 constant REF_BETA    = 5105579209847347908;
    uint256 constant REF_GAMMA   = 6829627859309895561;
    uint256 constant REF_ALPHA   = 2625265939556182796;

    // tau[0], tau[1]
    uint256 constant REF_TAU_0 = 14362172647613188170;
    uint256 constant REF_TAU_1 = 9811034851755430947;

    // tau_perm[0], tau_perm[1]
    uint256 constant REF_TAU_PERM_0 = 15204296456026753167;
    uint256 constant REF_TAU_PERM_1 = 904746669985617526;

    // Permutation sumcheck round 0 challenges
    uint256 constant REF_PERM_CHALLENGE_0 = 10451401905595039645;
    uint256 constant REF_PERM_CHALLENGE_1 = 7042810521573000773;

    // Perm round poly evaluations
    uint256 constant REF_PERM_ROUND0_E0 = 18089690094123470162;
    uint256 constant REF_PERM_ROUND0_E1 = 357053975291114159;
    uint256 constant REF_PERM_ROUND1_E0 = 3027652981674785684;
    uint256 constant REF_PERM_ROUND1_E1 = 16327628916633708956;

    // Extension challenge
    uint256 constant REF_EXT_CHALLENGE = 3454431597239652108;

    // Constraint sumcheck challenges
    uint256 constant REF_CONSTR_CHALLENGE_0 = 15116282078906310646;
    uint256 constant REF_CONSTR_CHALLENGE_1 = 7743046497487479633;

    // pcs_perm_numerator_eval
    uint256 constant REF_PCS_PERM_EVAL = 16690732370890981149;

    function test_e2e_protocol_flow() external pure {
        TranscriptLib.Transcript memory t;
        TranscriptLib.init(t);

        // Step 1: circuit + public inputs
        TranscriptLib.domainSeparate(t, "circuit");
        uint256[] memory pubInputs = new uint256[](1);
        pubInputs[0] = 21;
        TranscriptLib.absorbFieldVec(t, pubInputs);

        // Step 2: batch-commit
        TranscriptLib.domainSeparate(t, "batch-commit");
        uint256 batchR = TranscriptLib.squeezeChallenge(t);
        require(batchR == REF_BATCH_R, "batch_r mismatch");

        // Absorb commitment root
        bytes memory commitRoot = hex"b182ef64afbc4575089635721ba397427f435c3934c63030170a57daf9b73da3";
        TranscriptLib.absorbBytes(t, commitRoot);

        // Step 3: challenges
        TranscriptLib.domainSeparate(t, "challenges");
        uint256 beta = TranscriptLib.squeezeChallenge(t);
        uint256 gamma = TranscriptLib.squeezeChallenge(t);
        uint256 alpha = TranscriptLib.squeezeChallenge(t);

        require(beta == REF_BETA, "beta mismatch");
        require(gamma == REF_GAMMA, "gamma mismatch");
        require(alpha == REF_ALPHA, "alpha mismatch");

        // tau (2 challenges for degree_bits=2)
        uint256 tau0 = TranscriptLib.squeezeChallenge(t);
        uint256 tau1 = TranscriptLib.squeezeChallenge(t);
        require(tau0 == REF_TAU_0, "tau[0] mismatch");
        require(tau1 == REF_TAU_1, "tau[1] mismatch");

        // tau_perm (2 challenges)
        uint256 tauPerm0 = TranscriptLib.squeezeChallenge(t);
        uint256 tauPerm1 = TranscriptLib.squeezeChallenge(t);
        require(tauPerm0 == REF_TAU_PERM_0, "tau_perm[0] mismatch");
        require(tauPerm1 == REF_TAU_PERM_1, "tau_perm[1] mismatch");

        // Step 4: Permutation sumcheck
        TranscriptLib.domainSeparate(t, "permutation");

        // Round 0
        TranscriptLib.domainSeparate(t, "sumcheck-round");
        uint256[] memory round0 = new uint256[](2);
        round0[0] = REF_PERM_ROUND0_E0;
        round0[1] = REF_PERM_ROUND0_E1;
        TranscriptLib.absorbFieldVec(t, round0);
        uint256 permChallenge0 = TranscriptLib.squeezeChallenge(t);
        require(permChallenge0 == REF_PERM_CHALLENGE_0, "perm_challenge[0] mismatch");

        // Round 1
        TranscriptLib.domainSeparate(t, "sumcheck-round");
        uint256[] memory round1 = new uint256[](2);
        round1[0] = REF_PERM_ROUND1_E0;
        round1[1] = REF_PERM_ROUND1_E1;
        TranscriptLib.absorbFieldVec(t, round1);
        uint256 permChallenge1 = TranscriptLib.squeezeChallenge(t);
        require(permChallenge1 == REF_PERM_CHALLENGE_1, "perm_challenge[1] mismatch");

        // Step 5: Extension combine
        TranscriptLib.domainSeparate(t, "extension-combine");
        uint256 extChallenge = TranscriptLib.squeezeChallenge(t);
        require(extChallenge == REF_EXT_CHALLENGE, "ext_challenge mismatch");

        // Step 6: Constraint sumcheck (rounds are all zeros for valid circuit)
        TranscriptLib.domainSeparate(t, "zero-check");

        // Round 0 (all zeros)
        TranscriptLib.domainSeparate(t, "sumcheck-round");
        uint256[] memory cRound0 = new uint256[](3);
        cRound0[0] = 0; cRound0[1] = 0; cRound0[2] = 0;
        TranscriptLib.absorbFieldVec(t, cRound0);
        uint256 constrChallenge0 = TranscriptLib.squeezeChallenge(t);
        require(constrChallenge0 == REF_CONSTR_CHALLENGE_0, "constr_challenge[0] mismatch");

        // Round 1 (all zeros)
        TranscriptLib.domainSeparate(t, "sumcheck-round");
        uint256[] memory cRound1 = new uint256[](3);
        cRound1[0] = 0; cRound1[1] = 0; cRound1[2] = 0;
        TranscriptLib.absorbFieldVec(t, cRound1);
        uint256 constrChallenge1 = TranscriptLib.squeezeChallenge(t);
        require(constrChallenge1 == REF_CONSTR_CHALLENGE_1, "constr_challenge[1] mismatch");
    }
}
