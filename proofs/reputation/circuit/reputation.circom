pragma circom 2.1.5;

// The reputation proof: "these profiles are mine, and the plain average of their scores is this",
// shown on another profile of mine, without saying which profiles (../README.md).
//
// A slot is one profile: its label's scope, its score in an index's tree, and the Merkle path from
// its leaf, Poseidon(key x, key y, score), to the root. The person fills up to K slots and leaves
// the rest blank. One seed scalar, keys/'s, sits behind every slot: each slot's key is the lowest
// 250 bits of Poseidon(profile prefix, seed scalar, its scope), times Base8, the way keys/ mixes a
// main key and the verification works it out. The profile the proof is shown on comes from the
// same seed scalar in the same way. So only the person whose seed is behind the counted profiles
// can make the proof, and only for a profile of their own: it cannot be lent.
//
// Poseidon, the bits and Baby Jubjub's fixed-base multiplication are circomlib's, and the Merkle
// path is zk-kit's binary-merkle-root 2.0.0: the pieces Semaphore 4.13 uses, unchanged. 2.0.0 takes
// the path's position as one number and splits it into bits itself, so every step of the path is a
// left or a right and nothing else.

include "poseidon.circom";
include "comparators.circom";
include "bitify.circom";
include "binary-merkle-root.circom";
include "escalarmulfix.circom";

// A profile's key from the seed scalar and its label's scope: the lowest 250 bits of
// Poseidon(profile prefix, seed scalar, scope), times Base8. Num2Bits_strict, not Num2Bits(254), so
// the number has one spelling in bits and the scope one key.
template ProfileKey() {
    signal input seedScalar;
    signal input scope;
    signal output out[2];

    // keccak256("forest/v1/profile") >> 8, as keys/'s fieldHash gives it. The text keeps its bytes:
    // everyone's main keys are mixed with it.
    var PROFILE_PREFIX = 1610155941089780199585344681576242252009136950843720704103853393970298181;
    // Baby Jubjub's generator of the prime-order subgroup, as circomlib's own templates have it.
    var BASE8[2] = [
        5299619240641551281634865583518297030282874472190772894086521144482721001553,
        16950150798460657717958625567821834550301663161624707787222815936182638968203
    ];

    signal raw <== Poseidon(3)([PROFILE_PREFIX, seedScalar, scope]);
    signal bits[254] <== Num2Bits_strict()(raw);
    component key = EscalarMulFix(250, BASE8);
    for (var i = 0; i < 250; i++) {
        key.e[i] <== bits[i];
    }
    out <== key.out;
}

template Reputation(K, DEPTH) {
    // Private.
    // The seed scalar keys/'s seedScalar gives. It needs no bound: every slot's key and the
    // profile's key are Poseidon hashes of it, and only one seed scalar gives those hashes.
    signal input seedScalar;
    signal input used[K];
    signal input scopes[K], scores[K];
    signal input pathLengths[K], pathIndices[K], pathSiblings[K][DEPTH];
    signal input profileScope;  // the scope of the label of the profile the proof is shown on

    // Public, in the order score, root, profileX, profileY.
    signal input root;                // the tree's root, which the index signed with a time
    signal input profileX, profileY;  // the key of the profile the proof is shown on
    signal output score;

    // BinaryMerkleRoot answers 0 for a path longer than DEPTH, so a root of 0 would let any leaf in.
    signal rootInverse <-- root == 0 ? 0 : 1 / root;
    root * rootInverse === 1;

    // A score is below 2^32 and at most K slots are used, so the sum is below K * 2^32 and the
    // count below 2^COUNT_BITS, and nothing below wraps around the field.
    var COUNT_BITS = nbits(K);

    signal keys[K][2];
    var scoreSum = 0;
    var usedCount = 0;
    for (var i = 0; i < K; i++) {
        used[i] * (used[i] - 1) === 0;

        // A blank slot's score is 0, so it adds nothing to the sum. Its scope and path are read by
        // nothing.
        (1 - used[i]) * scores[i] === 0;
        _ <== Num2Bits(32)(scores[i]);

        // The slot's key, from the seed scalar and its scope, and its leaf is in the tree.
        keys[i] <== ProfileKey()(seedScalar, scopes[i]);
        var leaf = Poseidon(3)([keys[i][0], keys[i][1], scores[i]]);
        var slotRoot = BinaryMerkleRoot(DEPTH)(leaf, pathLengths[i], pathIndices[i], pathSiblings[i]);
        used[i] * (slotRoot - root) === 0;

        scoreSum += scores[i];
        usedCount += used[i];
    }

    // One profile counts once: two used slots never share a scope, and one scope gives one key.
    signal bothUsed[K][K];
    for (var i = 0; i < K; i++) {
        for (var j = i + 1; j < K; j++) {
            bothUsed[i][j] <== used[i] * used[j];
            var same = IsEqual()([scopes[i], scopes[j]]);
            bothUsed[i][j] * same === 0;
        }
    }

    // score = floor(scoreSum / usedCount), with usedCount at least 1: the remainder is below it.
    // With score below 2^32 and usedCount at most K, both sides stay below the field's order, so
    // exactly one score passes.
    signal remainder <-- usedCount == 0 ? 0 : scoreSum % usedCount;
    score <-- usedCount == 0 ? 0 : scoreSum \ usedCount;
    _ <== Num2Bits(32)(score);
    _ <== Num2Bits(COUNT_BITS)(remainder);
    signal belowCount <== LessThan(COUNT_BITS)([remainder, usedCount]);
    belowCount === 1;
    scoreSum === score * usedCount + remainder;

    // The profile the proof is shown on is the prover's own: its key comes from the same seed
    // scalar.
    signal profile[2] <== ProfileKey()(seedScalar, profileScope);
    profileX === profile[0];
    profileY === profile[1];
}

component main {public [root, profileX, profileY]} = Reputation(8, 20);
