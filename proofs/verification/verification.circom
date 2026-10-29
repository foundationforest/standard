pragma circom 2.1.5;

// The verification: "a verifier signed a stamp for the stamp number my seed gives at this
// verifier's name, and this profile's key is the one my seed gives for this label"
// (../README.md, The stamp and the verification).
//
// The seed, as a number, ties the two together inside the proof, and only Poseidon mixes of it
// leave: the stamp number, Poseidon(seed, name hash), which the verifier signed; and the profile's
// scalar, the lowest 250 bits of Poseidon(seed, scope), whose public key is the profile's. So one
// seed gives one main key per label, and a stamp counts for no other seed.
//
// The stamp is { stamp number, facts }: facts is one number, whatever the verifier attests, and
// stays private. The verifier signs Poseidon(name hash, stamp number, facts) with its EdDSA key on
// Baby Jubjub, over Poseidon: circomlib's verifier, unchanged.

include "poseidon.circom";
include "eddsaposeidon.circom";
include "bitify.circom";
include "escalarmulfix.circom";

template Verification() {
    // Private.
    // The seed's number keys/'s seedNumber gives. It needs no bound: everything public is a
    // Poseidon hash of it, and only one number gives those hashes.
    signal input seed;
    signal input facts;         // the stamp's facts, a field element the verifier chose
    signal input R8x, R8y, S;   // the verifier's signature on the stamp

    // Public, in the order profileX, profileY, verifierX, verifierY, scope, verifierNameHash.
    signal input profileX, profileY;    // the profile's key, a point on Baby Jubjub
    signal input verifierX, verifierY;  // the verifier's key, a point on Baby Jubjub
    signal input scope;                 // the label, as keys/'s scopeOf gives it
    signal input verifierNameHash;      // the verifier's name, as keys/'s nameHashOf gives it

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

    // The profile's key: the lowest 250 bits of Poseidon(seed, scope), times Base8.
    // Num2Bits_strict, not Num2Bits(254): a number below the field has a second 254-bit spelling,
    // itself plus the field's order, whenever that sum is below 2^254, about a third of all
    // numbers. Its lowest 250 bits differ, so with Num2Bits a prover could pick a second key for one
    // label. The strict form allows only the number's own bits.
    signal raw <== Poseidon(2)([seed, scope]);
    signal bits[254] <== Num2Bits_strict()(raw);
    component key = EscalarMulFix(250, BASE8);
    for (var i = 0; i < 250; i++) {
        key.e[i] <== bits[i];
    }
    profileX === key.out[0];
    profileY === key.out[1];
}

component main {public [profileX, profileY, verifierX, verifierY, scope, verifierNameHash]} = Verification();
