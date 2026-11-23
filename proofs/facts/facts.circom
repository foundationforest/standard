pragma circom 2.1.5;

// The facts proof: "a verifier signed a stamp for my seed; these facts are in that stamp; this
// profile's key is the one my seed gives for this label; and I made this for this reader at this
// time" (../README.md, The facts proof).
//
// The verification's statement, step for step as verification.circom has it, and on top of it the
// facts shown. The stamp's facts are the root of a tree of depth DEPTH over its list: a fact's leaf
// is Poseidon(name, value, salt), the name and the value each a text's number, and blank leaves are
// 0. Each slot shows one fact, publicly by its name and value, and proves privately, by its salt and
// its path, that its leaf is in that tree. A slot whose name is 0 is blank: no text's number is 0.
//
// The match number is Poseidon(seed, scope, facts, madeFor): the same for every proof made from one
// stamp, on one profile, for one made for, and different for any other. The seed is in it so that
// only the person can work it out: the verifier knows every facts number it signed, and could
// otherwise match a proof to its stamp. Poseidon of four is never Poseidon of two, so it is never a
// key's number or a stamp number. It also ties madeFor into the proof: Semaphore squares its message
// because nothing else uses it, and here the match number, public, is a hash of it.
//
// Poseidon, the bits, Baby Jubjub's fixed-base multiplication and circomlib's EdDSA check are
// circomlib's; the path is zk-kit's binary-merkle-root 2.0.0, its length fixed at DEPTH: the pieces
// the other two circuits use, unchanged.

include "poseidon.circom";
include "eddsaposeidon.circom";
include "bitify.circom";
include "comparators.circom";
include "escalarmulfix.circom";
include "binary-merkle-root.circom";

template Facts(K, DEPTH) {
    // Private.
    // The seed's number keys/'s seedNumber gives. It needs no bound: everything public that comes
    // from it is a Poseidon hash of it, and only one number gives those hashes.
    signal input seed;
    signal input facts;                 // the stamp's facts, the root of its list's tree
    signal input R8x, R8y, S;           // the verifier's signature on the stamp
    signal input salts[K];              // each shown fact's salt
    signal input pathIndices[K];        // each shown fact's place in the list
    signal input pathSiblings[K][DEPTH];

    // Public, in the order profileX, profileY, verifierX, verifierY, scope, verifierNameHash,
    // madeFor, shown, match: the verification's six first, as the verification has them.
    signal input profileX, profileY;    // the profile's key, a point on Baby Jubjub
    signal input verifierX, verifierY;  // the verifier's key, a point on Baby Jubjub
    signal input scope;                 // the label, as keys/'s scopeOf gives it
    signal input verifierNameHash;      // the verifier's name, as keys/'s nameHashOf gives it
    signal input madeFor;               // whom it was made for, and when
    signal input shown[K][2];           // each slot's fact: its name and its value; 0 and 0 if blank
    signal input match;                 // Poseidon(seed, scope, facts, madeFor)

    // Baby Jubjub's generator of the prime-order subgroup, as circomlib's own templates have it.
    var BASE8[2] = [
        5299619240641551281634865583518297030282874472190772894086521144482721001553,
        16950150798460657717958625567821834550301663161624707787222815936182638968203
    ];

    // The person's stamp number at this verifier.
    signal stampNumber <== Poseidon(2)([seed, verifierNameHash]);

    // The stamp the verifier signed, for that stamp number, under its name.
    signal stamp <== Poseidon(3)([verifierNameHash, stampNumber, facts]);
    component signed = EdDSAPoseidonVerifier();
    signed.enabled <== 1;
    signed.Ax <== verifierX;
    signed.Ay <== verifierY;
    signed.S <== S;
    signed.R8x <== R8x;
    signed.R8y <== R8y;
    signed.M <== stamp;

    // The profile's key: the lowest 250 bits of Poseidon(seed, scope), times Base8, split by
    // Num2Bits_strict so the number has one spelling in bits and the scope one key
    // (verification.circom says why).
    signal raw <== Poseidon(2)([seed, scope]);
    signal bits[254] <== Num2Bits_strict()(raw);
    component key = EscalarMulFix(250, BASE8);
    for (var i = 0; i < 250; i++) {
        key.e[i] <== bits[i];
    }
    profileX === key.out[0];
    profileY === key.out[1];

    // Each slot: blank, with nothing in it, or a fact whose leaf is in the stamp's tree. The path is
    // always DEPTH steps long, so no node inside the tree passes for a leaf.
    for (var i = 0; i < K; i++) {
        var blank = IsZero()(shown[i][0]);
        blank * shown[i][1] === 0;
        var leaf = Poseidon(3)([shown[i][0], shown[i][1], salts[i]]);
        var root = BinaryMerkleRoot(DEPTH)(leaf, DEPTH, pathIndices[i], pathSiblings[i]);
        (1 - blank) * (root - facts) === 0;
    }

    // The match number, from what only the person knows.
    signal matched <== Poseidon(4)([seed, scope, facts, madeFor]);
    match === matched;
}

component main {public [profileX, profileY, verifierX, verifierY, scope, verifierNameHash, madeFor, shown, match]} = Facts(8, 8);
