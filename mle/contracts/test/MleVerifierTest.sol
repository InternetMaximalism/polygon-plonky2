// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.25;

import {GoldilocksField as F} from "../src/GoldilocksField.sol";
import {TranscriptLib} from "../src/TranscriptLib.sol";
import {SumcheckVerifier} from "../src/SumcheckVerifier.sol";
import {EqPolyLib} from "../src/EqPolyLib.sol";
import {MleVerifier} from "../src/MleVerifier.sol";

/// @title MleVerifierTest
/// @notice Test and gas benchmark contract for the MLE verification system.
/// @dev Uses Foundry's forge-std for testing. Since we can't import forge-std
///      without lib installation, we write standalone tests callable externally.
contract MleVerifierTest {
    using F for uint256;

    uint256 constant P = 0xFFFFFFFF00000001;

    // ═══════════════════════════════════════════════════════════════════════
    //  Goldilocks field tests
    // ═══════════════════════════════════════════════════════════════════════

    function testFieldAdd() external pure returns (bool) {
        uint256 a = 3;
        uint256 b = 5;
        uint256 c = F.add(a, b);
        require(c == 8, "add failed");

        // Test wraparound
        uint256 pMinus1 = P - 1;
        uint256 d = F.add(pMinus1, 2);
        require(d == 1, "add wraparound failed");

        return true;
    }

    function testFieldMul() external pure returns (bool) {
        uint256 a = 7;
        uint256 b = 11;
        uint256 c = F.mul(a, b);
        require(c == 77, "mul failed");

        // Test large values
        uint256 x = P - 1; // -1
        uint256 y = P - 1; // -1
        uint256 z = F.mul(x, y); // (-1)*(-1) = 1
        require(z == 1, "mul -1*-1 failed");

        return true;
    }

    function testFieldInv() external pure returns (bool) {
        uint256 a = 7;
        uint256 aInv = F.inv(a);
        uint256 product = F.mul(a, aInv);
        require(product == 1, "inv failed: a * a^-1 != 1");

        // Test another value
        uint256 b = 12345;
        uint256 bInv = F.inv(b);
        require(F.mul(b, bInv) == 1, "inv failed for 12345");

        return true;
    }

    function testFieldSub() external pure returns (bool) {
        uint256 a = 10;
        uint256 b = 3;
        require(F.sub(a, b) == 7, "sub failed");

        // Underflow: 3 - 10 = p - 7
        uint256 c = F.sub(b, a);
        require(c == P - 7, "sub underflow failed");

        return true;
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  EqPoly tests
    // ═══════════════════════════════════════════════════════════════════════

    function testEqEvalBooleanPoint() external pure returns (bool) {
        // eq((1,0), (1,0)) should be 1
        uint256[] memory tau = new uint256[](2);
        tau[0] = 1;
        tau[1] = 0;

        uint256[] memory r = new uint256[](2);
        r[0] = 1;
        r[1] = 0;

        uint256 result = EqPolyLib.eqEval(tau, r);
        require(result == 1, "eq(b,b) should be 1");

        // eq((1,0), (0,1)) should be 0
        r[0] = 0;
        r[1] = 1;
        result = EqPolyLib.eqEval(tau, r);
        require(result == 0, "eq(b,b') should be 0 for b != b'");

        return true;
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Sumcheck verifier tests
    // ═══════════════════════════════════════════════════════════════════════

    function testSumcheckTrivial() external pure returns (bool) {
        // Trivial case: 1 variable, g(X) = 3X + 2
        // g(0) = 2, g(1) = 5, sum = 7
        SumcheckVerifier.RoundPoly[] memory roundPolys = new SumcheckVerifier.RoundPoly[](1);
        roundPolys[0].evals = new uint256[](2);
        roundPolys[0].evals[0] = 2;
        roundPolys[0].evals[1] = 5;

        SumcheckVerifier.SumcheckProof memory proof;
        proof.roundPolys = roundPolys;

        TranscriptLib.Transcript memory transcript;
        TranscriptLib.init(transcript);

        (uint256[] memory challenges, uint256 finalEval) =
            SumcheckVerifier.verify(proof, 7, 1, transcript);

        require(challenges.length == 1, "Should have 1 challenge");
        // finalEval = g(r) = 2 + (5-2)*r = 2 + 3r, for whatever r was squeezed
        // We can't predict r, but finalEval should be consistent
        require(finalEval < P, "finalEval out of range");

        return true;
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Gas benchmarks
    // ═══════════════════════════════════════════════════════════════════════

    /// @notice Benchmark Goldilocks field operations.
    /// @return addGas Gas for 100 additions.
    /// @return mulGas Gas for 100 multiplications.
    /// @return invGas Gas for 1 inversion.
    function benchmarkFieldOps()
        external
        view
        returns (uint256 addGas, uint256 mulGas, uint256 invGas)
    {
        uint256 a = 12345;
        uint256 b = 67890;
        uint256 g;

        g = gasleft();
        for (uint256 i = 0; i < 100; i++) {
            a = F.add(a, b);
        }
        addGas = g - gasleft();

        a = 12345;
        g = gasleft();
        for (uint256 i = 0; i < 100; i++) {
            a = F.mul(a, b);
        }
        mulGas = g - gasleft();

        a = 12345;
        g = gasleft();
        a = F.inv(a);
        invGas = g - gasleft();
    }

    /// @notice Benchmark eq polynomial evaluation for n variables.
    function benchmarkEqEval(uint256 n) external view returns (uint256 gasUsed) {
        uint256[] memory tau = new uint256[](n);
        uint256[] memory r = new uint256[](n);
        for (uint256 i = 0; i < n; i++) {
            tau[i] = i + 3;
            r[i] = i + 7;
        }

        uint256 g = gasleft();
        EqPolyLib.eqEval(tau, r);
        gasUsed = g - gasleft();
    }

    /// @notice Benchmark sumcheck verification for a given number of rounds.
    /// @dev Builds a consistent mock proof by constructing round polys that satisfy
    ///      g_i(0) + g_i(1) = claim_i, then setting claim_{i+1} = g_i(r_i)
    ///      where r_i is the actual transcript challenge.
    function benchmarkSumcheck(uint256 numRounds)
        external
        view
        returns (uint256 gasUsed)
    {
        // We need to simulate the prover to build consistent round polys.
        // First pass: build the transcript and derive challenges,
        // then construct round polys that are consistent.

        // For degree-1 round polys (simplest case): g(X) = a + bX
        // g(0) = a, g(1) = a + b, claim = 2a + b
        // Given claim, pick a = claim/3, b = claim/3, so g(0) = claim/3, g(1) = 2*claim/3
        // Actually simpler: g(0) = 0, g(1) = claim for each round.
        // Then g(r) = claim * r, and next claim = claim * r.
        SumcheckVerifier.RoundPoly[] memory roundPolys =
            new SumcheckVerifier.RoundPoly[](numRounds);

        // Pre-build: we need to know the challenges, but they depend on the round polys.
        // Chicken-and-egg. Solution: use degree-1 polys where g(0) = 0, g(1) = claim.
        // Then: absorb [0, claim], squeeze r_i, next_claim = claim * r_i.
        // We must build this iteratively.

        TranscriptLib.Transcript memory buildTranscript;
        TranscriptLib.init(buildTranscript);

        uint256 claim = 100;
        for (uint256 i = 0; i < numRounds; i++) {
            roundPolys[i].evals = new uint256[](2);
            roundPolys[i].evals[0] = 0;
            roundPolys[i].evals[1] = claim;

            // Absorb into transcript (matching verifier behavior)
            uint256[] memory evals = new uint256[](2);
            evals[0] = 0;
            evals[1] = claim;
            TranscriptLib.domainSeparate(buildTranscript, "sumcheck-round");
            TranscriptLib.absorbFieldVec(buildTranscript, evals);

            uint256 r_i = TranscriptLib.squeezeChallenge(buildTranscript);

            // Next claim = g(r_i) = claim * r_i (since g(X) = claim * X for degree-1)
            // Actually g(X) interpolating (0, 0) and (1, claim) gives g(X) = claim * X
            // g(r_i) = claim * r_i
            claim = F.mul(claim, r_i);
        }

        SumcheckVerifier.SumcheckProof memory proof;
        proof.roundPolys = roundPolys;

        TranscriptLib.Transcript memory verifyTranscript;
        TranscriptLib.init(verifyTranscript);

        uint256 g = gasleft();
        SumcheckVerifier.verify(proof, 100, numRounds, verifyTranscript);
        gasUsed = g - gasleft();
    }

}
