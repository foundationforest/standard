pragma circom 2.1.5;

// The reputation proof: "these profiles are mine, and their count-weighted score is this", shown on
// another profile of mine, without saying which profiles (../README.md).
//
// A slot is one profile: a leaf of an index's tree (the profile's stamp, its label's scope, the
// index's score times ten, the number of reviews) and the Merkle path from it to the root. The
// person fills up to K slots and leaves the rest blank. One seed scalar, keys/'s, sits behind every
// slot: each slot's stamp is Poseidon(scope, issuer secret), the issuer secret is
// Poseidon(issuer tag, seed scalar, the issuer's name hash), and each slot may name its own issuer.
// The profile the proof is shown on comes from the same seed scalar: its key is the lowest 250
// bits of Poseidon(profile tag, seed scalar, its scope), times Base8, as the human proof derives
// it. So only the person whose seed is behind the counted profiles can make the proof, and only
// for a profile of their own: it cannot be lent.
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

template Reputation(K, DEPTH) {
    // Private.
    // The seed scalar keys/'s seedScalar gives. It needs no bound: every stamp and the profile's
    // key come from Poseidon hashes of it, and only one seed scalar gives those hashes.
    signal input seedScalar;
    signal input issuerNameHashes[K];  // each slot's issuer, as keys/'s nameHashOf gives its name
    signal input used[K];
    signal input stamps[K], scopes[K], scores[K], counts[K];
    signal input pathLengths[K], pathIndices[K], pathSiblings[K][DEPTH];
    signal input profileScope;  // the scope of the label of the profile the proof is shown on

    // Public, in the order score, root, profileX, profileY, scope.
    signal input root;                // the tree's root, which the index signed with a time
    signal input profileX, profileY;  // the key of the profile the proof is shown on
    signal input scope;               // the label shown, as keys/'s scopeOf gives it; 0 for none
    signal output score;

    // keccak256(text) >> 8, as keys/'s fieldHash gives it, for "forest/v1/issuer" and
    // "forest/v1/profile"; and Baby Jubjub's Base8, as circomlib's own templates have it.
    var ISSUER_TAG = 148503515730552064242178401621730766485656598654480476289777914049842770921;
    var PROFILE_TAG = 1610155941089780199585344681576242252009136950843720704103853393970298181;
    var BASE8[2] = [
        5299619240641551281634865583518297030282874472190772894086521144482721001553,
        16950150798460657717958625567821834550301663161624707787222815936182638968203
    ];

    // BinaryMerkleRoot answers 0 for a path longer than DEPTH, so a root of 0 would let any leaf in.
    signal rootInverse <-- root == 0 ? 0 : 1 / root;
    root * rootInverse === 1;

    signal hidden <== IsZero()(scope);
    signal shown <== 1 - hidden;

    // A score and a count are each below 2^32, so a sum of K of them is below 2^SUM_BITS, and no sum
    // or product below wraps around the field.
    var SUM_BITS = 32 + nbits(K);

    signal shownApart[K];
    signal weighted[K];
    var weightedSum = 0;
    var countSum = 0;
    for (var i = 0; i < K; i++) {
        used[i] * (used[i] - 1) === 0;

        // A blank slot is all zeros, so it adds nothing below.
        (1 - used[i]) * stamps[i] === 0;
        (1 - used[i]) * scopes[i] === 0;
        (1 - used[i]) * scores[i] === 0;
        (1 - used[i]) * counts[i] === 0;

        _ <== Num2Bits(32)(scores[i]);
        _ <== Num2Bits(32)(counts[i]);

        // The slot's stamp: Poseidon(scope, issuer secret), from the seed scalar and its issuer.
        var issuerScalar = Poseidon(3)([ISSUER_TAG, seedScalar, issuerNameHashes[i]]);
        var stampOfSlot = Poseidon(2)([scopes[i], issuerScalar]);
        used[i] * (stamps[i] - stampOfSlot) === 0;

        // The leaf is in the tree.
        var leaf = Poseidon(4)([stamps[i], scopes[i], scores[i], counts[i]]);
        var slotRoot = BinaryMerkleRoot(DEPTH)(leaf, pathLengths[i], pathIndices[i], pathSiblings[i]);
        used[i] * (slotRoot - root) === 0;

        // A shown scope is every used slot's scope.
        shownApart[i] <== used[i] * (scopes[i] - scope);
        shownApart[i] * shown === 0;

        weighted[i] <== scores[i] * counts[i];
        weightedSum += weighted[i];
        countSum += counts[i];
    }

    // One profile counts once: two used slots never share a scope. With the rule above, a shown
    // scope means exactly one slot is used.
    signal bothUsed[K][K];
    for (var i = 0; i < K; i++) {
        for (var j = i + 1; j < K; j++) {
            bothUsed[i][j] <== used[i] * used[j];
            var same = IsEqual()([scopes[i], scopes[j]]);
            bothUsed[i][j] * same === 0;
        }
    }

    // score = floor(weightedSum / countSum), and countSum is at least 1. With score below 2^32 and
    // the remainder below countSum, both sides stay below the field's order, so exactly one score
    // passes.
    signal remainder <-- countSum == 0 ? 0 : weightedSum % countSum;
    score <-- countSum == 0 ? 0 : weightedSum \ countSum;
    _ <== Num2Bits(32)(score);
    _ <== Num2Bits(SUM_BITS)(remainder);
    signal belowCount <== LessThan(SUM_BITS)([remainder, countSum]);
    belowCount === 1;
    weightedSum === score * countSum + remainder;

    // The profile the proof is shown on is the prover's own: its key comes from the same seed
    // scalar, the way the human proof derives it. Num2Bits_strict, so the number has one spelling
    // in bits and the scope one key.
    signal raw <== Poseidon(3)([PROFILE_TAG, seedScalar, profileScope]);
    signal bits[254] <== Num2Bits_strict()(raw);
    component key = EscalarMulFix(250, BASE8);
    for (var i = 0; i < 250; i++) {
        key.e[i] <== bits[i];
    }
    profileX === key.out[0];
    profileY === key.out[1];
}

component main {public [root, profileX, profileY, scope]} = Reputation(8, 20);
