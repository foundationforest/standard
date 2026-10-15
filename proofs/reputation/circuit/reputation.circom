pragma circom 2.1.5;

// The reputation proof: "these profiles are mine, and their count-weighted score is this", shown on
// a registered profile of mine, without saying which profiles (../README.md).
//
// A slot is one profile: a leaf of an index's tree (the profile's market stamp, its label's scope,
// the index's score times ten, the number of reviews) and the Merkle path from it to the root. The
// person fills up to K slots and leaves the rest blank. Every market stamp must come from the same
// list secret, so only the person who holds it can count those profiles. The stamp the proof shows
// comes from that secret too: it is the registry row of the profile the proof is shown on, so the
// proof lands only on the prover's own registered profile.
//
// Poseidon is circomlib's, and the Merkle path is zk-kit's binary-merkle-root 2.0.0: the pieces
// Semaphore 4.13 uses, unchanged. 2.0.0 takes the path's position as one number and splits it into
// bits itself, so every step of the path is a left or a right and nothing else.

include "poseidon.circom";
include "comparators.circom";
include "bitify.circom";
include "binary-merkle-root.circom";

template Reputation(K, DEPTH) {
    // Private.
    // The person's secret for one list: Semaphore's secret scalar, from keys/'s listSecret. Unlike
    // Semaphore's, this circuit derives no public key from it, so it needs no bound: a market stamp
    // is a Poseidon hash of it, and only one secret gives that hash.
    signal input secret;
    signal input used[K];
    signal input stamps[K], scopes[K], scores[K], counts[K];
    signal input pathLengths[K], pathIndices[K], pathSiblings[K][DEPTH];
    signal input profileScope;  // the scope of the label of the profile the proof is shown on

    // Public, in the order score, root, stamp, scope.
    signal input root;      // the tree's root, which the index signed with a time
    signal input stamp;     // the stamp of the profile the proof is shown on: its registry row's
    signal input scope;     // the label shown, as the registry derives its scope; 0 for none
    signal output score;

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

        // The registry's market stamp: Poseidon(scope, secret), Semaphore's nullifier.
        var marketStamp = Poseidon(2)([scopes[i], secret]);
        used[i] * (stamps[i] - marketStamp) === 0;

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

    // The profile the proof is shown on is the prover's own: its stamp comes from the same secret.
    // The registry wrote a row at that stamp only for a main key whose person proof showed the same,
    // so a reader that finds the row there naming the profile knows the proof is that profile's.
    signal profileStamp <== Poseidon(2)([profileScope, secret]);
    stamp === profileStamp;
}

component main {public [root, stamp, scope]} = Reputation(8, 20);
