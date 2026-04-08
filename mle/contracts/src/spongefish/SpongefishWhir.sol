// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Keccak256Chain} from "./Keccak256Chain.sol";
import {GoldilocksExt3} from "./GoldilocksExt3.sol";
import {SpongefishMerkle} from "./SpongefishMerkle.sol";

/// @title SpongefishWhir
/// @notice WHIR polynomial commitment verifier for WizardOfMenlo/whir (spongefish transcript).
///
///   Verifies a WHIR proof by replaying the spongefish Fiat-Shamir transcript:
///   - prover_message: read N bytes from transcript, absorb into sponge
///   - verifier_message: squeeze N bytes from sponge
///   - prover_hint: read N bytes from hints (NOT absorbed into sponge)
///
///   Field: Goldilocks 64-bit (p = 2^64 - 2^32 + 1) with cubic extension
///   Hash:  Keccak-f[1600] duplex sponge
///
///   This is a work-in-progress implementation. The full WHIR verification
///   algorithm involves sumcheck, Merkle openings, and constraint evaluation
///   in the Goldilocks cubic extension field.
library SpongefishWhir {
    using Keccak256Chain for Keccak256Chain.Sponge;

    uint64 constant GL_P = 0xFFFFFFFF00000001; // Goldilocks prime

    struct TranscriptState {
        Keccak256Chain.Sponge sponge;
        uint256 transcriptPos;
        uint256 hintPos;
    }

    // -----------------------------------------------------------------------
    // Transcript operations (matching spongefish exactly)
    // -----------------------------------------------------------------------

    /// @dev Initialize transcript with domain separator.
    ///      Matches: spongefish::DomainSeparator::new(protocol_id).session(session_id).instance(&Empty)
    function initTranscript(
        bytes memory protocolId,
        bytes memory sessionId,
        bytes memory instance
    ) internal pure returns (TranscriptState memory ts) {
        ts.sponge = Keccak256Chain.init();
        // public_message(&protocol_id) → absorb 64 bytes
        ts.sponge.absorb(protocolId);
        // public_message(&session_id) → absorb 32 bytes
        ts.sponge.absorb(sessionId);
        // public_message(&instance) → absorb instance bytes
        // NOTE: Even empty absorb changes state in Keccak256Chain: keccak256(state || "")
        ts.sponge.absorb(instance);
    }

    /// @dev Read N bytes from transcript and absorb into sponge.
    ///      Matches: verifier_state.prover_message::<T>()
    function proverMessage(
        TranscriptState memory ts,
        bytes memory transcript,
        uint256 numBytes
    ) internal pure returns (bytes memory data) {
        require(ts.transcriptPos + numBytes <= transcript.length, "transcript underflow");
        data = _memSlice(transcript, ts.transcriptPos, numBytes);
        ts.transcriptPos += numBytes;
        ts.sponge.absorb(data);
    }

    /// @dev Read a 32-byte hash from transcript and absorb.
    function proverMessageHash(
        TranscriptState memory ts,
        bytes memory transcript
    ) internal pure returns (bytes32 h) {
        bytes memory data = proverMessage(ts, transcript, 32);
        assembly { h := mload(add(data, 32)) }
    }

    /// @dev Read a Goldilocks field element (8 bytes LE) from transcript and absorb.
    function proverMessageField64(
        TranscriptState memory ts,
        bytes memory transcript
    ) internal pure returns (uint64 val) {
        bytes memory data = proverMessage(ts, transcript, 8);
        // Little-endian decode: load 8 bytes at data+0x20, mask, and byte-swap
        assembly {
            let raw := mload(add(data, 0x20))
            // raw has our 8 bytes in the HIGH 64 bits (big-endian memory layout)
            // Shift right by 192 bits to get them in the low 64 bits
            raw := shr(192, raw)
            // Byte-swap from BE to LE: abcdefgh -> hgfedcba
            raw := or(shl(32, and(raw, 0x00000000FFFFFFFF)), shr(32, and(raw, 0xFFFFFFFF00000000)))
            raw := or(shl(16, and(raw, 0x0000FFFF0000FFFF)), shr(16, and(raw, 0xFFFF0000FFFF0000)))
            raw := or(shl(8,  and(raw, 0x00FF00FF00FF00FF)), shr(8,  and(raw, 0xFF00FF00FF00FF00)))
            val := mod(raw, 0xFFFFFFFF00000001) // GL_P
        }
    }

    /// @dev Squeeze N bytes from sponge (verifier challenge).
    ///      Matches: verifier_state.verifier_message::<T>()
    function verifierMessage(
        TranscriptState memory ts,
        uint256 numBytes
    ) internal pure returns (bytes memory) {
        return ts.sponge.squeeze(numBytes);
    }

    /// @dev Squeeze a Goldilocks field element.
    ///      Matches Field64's Decoding impl: squeeze (MODULUS_BIT_SIZE/8 + 32) = 8 + 32 = 40 bytes.
    ///      Interpret as LE 320-bit integer, reduce mod GL_P.
    function verifierMessageField64(
        TranscriptState memory ts
    ) internal pure returns (uint64 val) {
        bytes memory data = ts.sponge.squeeze(40);
        val = _leModReduce64(data, 0, 40);
    }

    /// @dev Read a Field64_3 (cubic extension) from transcript: 3 × 8 = 24 bytes.
    ///      Each 8-byte chunk is LE-encoded Field64.
    function proverMessageField64x3(
        TranscriptState memory ts,
        bytes memory transcript
    ) internal pure returns (uint64 c0, uint64 c1, uint64 c2) {
        bytes memory data = proverMessage(ts, transcript, 24);
        c0 = _leModReduce64(data, 0, 8);
        c1 = _leModReduce64(data, 8, 8);
        c2 = _leModReduce64(data, 16, 8);
    }

    /// @dev Squeeze a Field64_3: 3 × (8 + 32) = 120 bytes.
    ///      Each 40-byte chunk is reduced mod GL_P.
    function verifierMessageField64x3(
        TranscriptState memory ts
    ) internal pure returns (uint64 c0, uint64 c1, uint64 c2) {
        bytes memory data = ts.sponge.squeeze(120);
        c0 = _leModReduce64(data, 0, 40);
        c1 = _leModReduce64(data, 40, 40);
        c2 = _leModReduce64(data, 80, 40);
    }

    /// @dev Read N bytes from hints (NOT absorbed into sponge).
    ///      Matches: verifier_state.prover_hint::<T>()
    function proverHint(
        TranscriptState memory ts,
        bytes memory hints,
        uint256 numBytes
    ) internal pure returns (bytes memory data) {
        require(ts.hintPos + numBytes <= hints.length, "hints underflow");
        data = _memSlice(hints, ts.hintPos, numBytes);
        ts.hintPos += numBytes;
    }

    /// @dev Read a 32-byte hash from hints.
    function proverHintHash(
        TranscriptState memory ts,
        bytes memory hints
    ) internal pure returns (bytes32 h) {
        bytes memory data = proverHint(ts, hints, 32);
        assembly { h := mload(add(data, 32)) }
    }

    // -----------------------------------------------------------------------
    // Challenge generation
    // -----------------------------------------------------------------------

    /// @dev Generate challenge indices by squeezing bytes and reducing mod numLeaves.
    ///      Matches: challenge_indices(transcript, num_leaves, count, deduplicate=true)
    ///      IMPORTANT: Rust squeezes ONE BYTE AT A TIME via verifier_message::<u8>().
    function challengeIndices(
        TranscriptState memory ts,
        uint256 numLeaves,
        uint256 count
    ) internal pure returns (uint256[] memory indices) {
        if (count == 0) return new uint256[](0);
        if (numLeaves == 1) {
            indices = new uint256[](1);
            indices[0] = 0;
            return indices;
        }

        uint256 sizeBytes = _ceilDiv(_log2(numLeaves), 8);
        uint256 totalBytes = count * sizeBytes;

        // Squeeze one byte at a time to match Rust (using SHA3 opcode directly)
        bytes memory entropy = new bytes(totalBytes);
        for (uint256 i = 0; i < totalBytes; i++) {
            entropy[i] = bytes1(ts.sponge.squeezeByte());
        }

        indices = new uint256[](count);
        for (uint256 i = 0; i < count; i++) {
            uint256 val = 0;
            for (uint256 j = 0; j < sizeBytes; j++) {
                val = (val << 8) | uint256(uint8(entropy[i * sizeBytes + j]));
            }
            indices[i] = val % numLeaves;
        }

        // Sort and dedup
        _sortAndDedup(indices);
    }

    /// @dev Geometric challenge: squeeze one Field64_3 value, return [1, x, x^2, ..., x^(count-1)]
    ///      Matches: geometric_challenge(transcript, count) where F = Ext3
    function geometricChallenge(
        TranscriptState memory ts,
        uint256 count
    ) internal pure returns (GoldilocksExt3.Ext3[] memory coeffs) {
        if (count == 0) return new GoldilocksExt3.Ext3[](0);
        if (count == 1) {
            coeffs = new GoldilocksExt3.Ext3[](1);
            coeffs[0] = GoldilocksExt3.one();
            return coeffs;
        }

        (uint64 c0, uint64 c1, uint64 c2) = verifierMessageField64x3(ts);
        coeffs = new GoldilocksExt3.Ext3[](count);
        coeffs[0] = GoldilocksExt3.one();
        for (uint256 i = 1; i < count; i++) {
            coeffs[i] = GoldilocksExt3.zero();
        }
        // Fill geometric sequence in assembly: coeffs[i] = coeffs[i-1] * x
        assembly {
            let p := 0xFFFFFFFF00000001
            let x0 := c0
            let x1 := c1
            let x2 := c2
            let cData := add(coeffs, 0x20)

            for { let i := 1 } lt(i, count) { i := add(i, 1) } {
                let prevPtr := mload(add(cData, mul(sub(i, 1), 0x20)))
                let p0 := mload(prevPtr)
                let p1 := mload(add(prevPtr, 0x20))
                let p2 := mload(add(prevPtr, 0x40))

                let t := addmod(mulmod(p1, x2, p), mulmod(p2, x1, p), p)
                let curPtr := mload(add(cData, mul(i, 0x20)))
                mstore(curPtr, addmod(mulmod(p0, x0, p), mulmod(2, t, p), p))
                mstore(add(curPtr, 0x20), addmod(addmod(mulmod(p0, x1, p), mulmod(p1, x0, p), p), mulmod(2, mulmod(p2, x2, p), p), p))
                mstore(add(curPtr, 0x40), addmod(addmod(mulmod(p0, x2, p), mulmod(p1, x1, p), p), mulmod(p2, x0, p), p))
            }
        }
    }

    // -----------------------------------------------------------------------
    // Sumcheck verification
    // -----------------------------------------------------------------------

    /// @dev Verify a sumcheck proof.
    ///      Matches: sumcheck::Config::verify()
    ///
    ///      For each round:
    ///      1. Read c0, c2 from transcript (prover_message)
    ///      2. Compute c1 = sum - 2*c0 - c2
    ///      3. Verify PoW (if configured)
    ///      4. Squeeze folding randomness r (verifier_message)
    ///      5. Update sum = c0 + r*c1 + r^2*c2
    ///
    /// @return foldingRandomness The folding randomness values from each round
    /// @return newSum The updated sum after all rounds
    function verifySumcheck(
        TranscriptState memory ts,
        bytes memory transcript,
        uint256 numRounds,
        uint64 sum
    ) internal pure returns (uint64[] memory foldingRandomness, uint64 newSum) {
        foldingRandomness = new uint64[](numRounds);
        newSum = sum;

        for (uint256 i = 0; i < numRounds; i++) {
            // Read c0 and c2
            uint64 c0 = proverMessageField64(ts, transcript);
            uint64 c2 = proverMessageField64(ts, transcript);

            // c1 = sum - 2*c0 - c2 (mod GL_P)
            uint64 c1 = _submod64(_submod64(newSum, _addmod64(c0, c0)), c2);

            // PoW check omitted for now (requires additional transcript operations)
            // TODO: Implement PoW verification

            // Squeeze folding randomness
            uint64 r = verifierMessageField64(ts);
            foldingRandomness[i] = r;

            // Update sum: sum = c0 + r*c1 + r^2*c2
            //            = c0 + r*(c1 + r*c2)
            newSum = _addmod64(c0, _mulmod64(r, _addmod64(c1, _mulmod64(r, c2))));
        }
    }

    // -----------------------------------------------------------------------
    // LE byte reduction
    // -----------------------------------------------------------------------

    /// @dev Interpret `len` LE bytes from `data[offset..]` as a big integer, reduce mod GL_P.
    function _leModReduce64(bytes memory data, uint256 offset, uint256 len) private pure returns (uint64) {
        // For len <= 32, we can use a single uint256
        // For len > 32 (e.g., 40 bytes), we need to handle carefully
        uint256 acc = 0;
        // Read in chunks of up to 32 bytes
        for (uint256 i = 0; i < len && i < 32; i++) {
            acc |= uint256(uint8(data[offset + i])) << (i * 8);
        }
        if (len > 32) {
            // Handle remaining bytes (e.g., bytes 32-39 for 40-byte input)
            uint256 hi = 0;
            for (uint256 i = 32; i < len; i++) {
                hi |= uint256(uint8(data[offset + i])) << ((i - 32) * 8);
            }
            // acc = lo + hi * 2^256
            // result = (lo + hi * 2^256) mod GL_P
            // Since GL_P is 64-bit, 2^256 mod GL_P is a constant
            // 2^256 mod (2^64 - 2^32 + 1)
            // We can compute this as: mulmod(hi, 2^256 mod P, P) + acc mod P
            uint256 pow256modP = uint256(2) ** 64; // Simplified — need exact value
            // Actually, for correctness: reduce acc mod P first, then add hi * (2^256 mod P)
            // But since acc is 256 bits and P is 64 bits, acc mod P is at most 64 bits
            // And hi * (2^256 mod P) mod P is at most 64 bits
            // So we can just compute (acc + hi * 2^256) mod P
            // Using Solidity's modular arithmetic:
            acc = addmod(acc % uint256(GL_P), mulmod(hi, _pow256ModP(), uint256(GL_P)), uint256(GL_P));
            return uint64(acc);
        }
        return uint64(acc % uint256(GL_P));
    }

    /// @dev Compute 2^256 mod GL_P (precomputed constant).
    function _pow256ModP() private pure returns (uint256) {
        // GL_P = 2^64 - 2^32 + 1
        // 2^256 mod GL_P:
        // 2^64 ≡ 2^32 - 1 (mod GL_P)
        // 2^128 ≡ (2^32 - 1)^2 = 2^64 - 2^33 + 1 ≡ (2^32 - 1) - 2^33 + 1 = -2^32 (mod GL_P)
        // Actually let's just compute it: 2^256 mod (2^64 - 2^32 + 1)
        // This is a fixed constant, precompute in Python:
        // >>> p = 2**64 - 2**32 + 1
        // >>> pow(2, 256, p)
        // 2^256 mod (2^64 - 2^32 + 1) = 2^32 - 1 = 4294967295
        return 4294967295;
    }

    // -----------------------------------------------------------------------
    // Goldilocks field arithmetic helpers
    // -----------------------------------------------------------------------

    function _addmod64(uint64 a, uint64 b) private pure returns (uint64) {
        return uint64(addmod(uint256(a), uint256(b), uint256(GL_P)));
    }

    function _submod64(uint64 a, uint64 b) private pure returns (uint64) {
        return uint64(addmod(uint256(a), uint256(GL_P) - uint256(b), uint256(GL_P)));
    }

    function _mulmod64(uint64 a, uint64 b) private pure returns (uint64) {
        return uint64(mulmod(uint256(a), uint256(b), uint256(GL_P)));
    }

    // -----------------------------------------------------------------------
    // Utility functions
    // -----------------------------------------------------------------------

    function _log2(uint256 x) private pure returns (uint256 n) {
        while (x > 1) { x >>= 1; n++; }
    }

    function _ceilDiv(uint256 a, uint256 b) private pure returns (uint256) {
        return (a + b - 1) / b;
    }

    /// @dev Copy a slice of a memory bytes array.
    function _memSlice(bytes memory data, uint256 offset, uint256 len) private pure returns (bytes memory result) {
        result = new bytes(len);
        assembly {
            let src := add(add(data, 0x20), offset)
            let dst := add(result, 0x20)
            for { let i := 0 } lt(i, len) { i := add(i, 32) } {
                mstore(add(dst, i), mload(add(src, i)))
            }
        }
    }

    /// @dev Sort array in-place and remove duplicates. Updates array length.
    function _sortAndDedup(uint256[] memory arr) private pure {
        uint256 n = arr.length;
        if (n <= 1) return;

        // Iterative quicksort in assembly — avoids recursive function call overhead
        assembly {
            let base := add(arr, 0x20) // pointer to arr[0]

            // Use scratch memory for an explicit stack (max depth ~64 for any practical size)
            let stackPtr := mload(0x40)
            let stackBase := stackPtr

            // Push initial (lo=0, hi=n-1)
            mstore(stackPtr, 0)
            mstore(add(stackPtr, 0x20), sub(n, 1))
            stackPtr := add(stackPtr, 0x40)

            for { } gt(stackPtr, stackBase) { } {
                // Pop (lo, hi)
                stackPtr := sub(stackPtr, 0x40)
                let lo := mload(stackPtr)
                let hi := mload(add(stackPtr, 0x20))

                if lt(lo, hi) {
                    // Partition: pivot = arr[(lo+hi)/2]
                    let mid := add(lo, shr(1, sub(hi, lo)))
                    let pivot := mload(add(base, mul(mid, 0x20)))
                    let i := lo
                    let j := hi

                    for { } iszero(gt(i, j)) { } {
                        // while arr[i] < pivot: i++
                        for { } lt(mload(add(base, mul(i, 0x20))), pivot) { i := add(i, 1) } { }
                        // while arr[j] > pivot: j--
                        for { } gt(mload(add(base, mul(j, 0x20))), pivot) { } {
                            if iszero(j) { break }
                            j := sub(j, 1)
                        }
                        if iszero(gt(i, j)) {
                            // swap arr[i], arr[j]
                            let pi := add(base, mul(i, 0x20))
                            let pj := add(base, mul(j, 0x20))
                            let tmp := mload(pi)
                            mstore(pi, mload(pj))
                            mstore(pj, tmp)
                            i := add(i, 1)
                            if iszero(j) { break }
                            j := sub(j, 1)
                        }
                    }

                    // Push sub-partitions onto stack
                    if lt(lo, j) {
                        mstore(stackPtr, lo)
                        mstore(add(stackPtr, 0x20), j)
                        stackPtr := add(stackPtr, 0x40)
                    }
                    if lt(i, hi) {
                        mstore(stackPtr, i)
                        mstore(add(stackPtr, 0x20), hi)
                        stackPtr := add(stackPtr, 0x40)
                    }
                }
            }

            // Dedup in-place
            let write := 1
            for { let k := 1 } lt(k, n) { k := add(k, 1) } {
                let curr := mload(add(base, mul(k, 0x20)))
                let prev := mload(add(base, mul(sub(k, 1), 0x20)))
                if iszero(eq(curr, prev)) {
                    mstore(add(base, mul(write, 0x20)), curr)
                    write := add(write, 1)
                }
            }
            // Update array length
            mstore(arr, write)
        }
    }
}
