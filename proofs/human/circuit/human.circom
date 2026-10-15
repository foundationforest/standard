pragma circom 2.1.5;

// The human proof: "an issuer signed a note for the note number my seed gives at this issuer; my
// stamp for this label at this issuer is this one; and this profile's key is the one my seed gives
// for this label" (../README.md, The note and the human proof).
//
// One number from the seed, the seed scalar, ties the three together inside the proof, and only
// Poseidon mixes of it leave: the person's secret for the issuer, Poseidon(issuer tag, seed scalar,
// name hash), whose note number the issuer signed and which the stamp comes from; and the profile's
// scalar, the lowest 250 bits of Poseidon(profile tag, seed scalar, scope), whose public key is
// the profile's. So one seed gives one profile key per label, and a note counts for no other seed.
//
// The note is { note number, face embedding, model name, month }. The issuer signs
// Poseidon(note tag, note number, embedding's hash, model's hash, month) with its EdDSA key on
// Baby Jubjub, over Poseidon: circomlib's verifier, unchanged. The embedding and the model enter
// only as their hashes; the circuit never reads them.

include "poseidon.circom";
include "eddsaposeidon.circom";
include "bitify.circom";
include "escalarmulfix.circom";

template Human() {
    // Private.
    // The seed scalar keys/'s seedScalar gives. It needs no bound: everything public is a Poseidon
    // hash of it, and only one seed scalar gives those hashes.
    signal input seedScalar;
    signal input embedding;     // the hash of the note's face embedding
    signal input model;         // the hash of the note's model name
    signal input R8x, R8y, S;   // the issuer's signature on the note

    // Public, in the order stamp, profileX, profileY, issuerX, issuerY, scope, issuerNameHash, month.
    signal input profileX, profileY;  // the profile's key, a point on Baby Jubjub
    signal input issuerX, issuerY;    // the issuer's key, a point on Baby Jubjub
    signal input scope;               // the label, as keys/'s scopeOf gives it
    signal input issuerNameHash;      // the issuer's name, as keys/'s nameHashOf gives it
    signal input month;               // the month the issuer signed in the note, YYYYMM
    signal output stamp;

    // keccak256(text) >> 8, as keys/'s fieldHash gives it, for "forest/v1/note",
    // "forest/v1/issuer" and "forest/v1/profile".
    var NOTE_TAG = 400167441388126881061687584776181816477671862726675254297469311886243976537;
    var ISSUER_TAG = 148503515730552064242178401621730766485656598654480476289777914049842770921;
    var PROFILE_TAG = 1610155941089780199585344681576242252009136950843720704103853393970298181;
    // Baby Jubjub's generator of the prime-order subgroup, as circomlib's own templates have it.
    var BASE8[2] = [
        5299619240641551281634865583518297030282874472190772894086521144482721001553,
        16950150798460657717958625567821834550301663161624707787222815936182638968203
    ];

    // The person's secret for this issuer, and the note number it gives.
    signal issuerScalar <== Poseidon(3)([ISSUER_TAG, seedScalar, issuerNameHash]);
    signal noteNumber <== Poseidon(1)([issuerScalar]);

    // The note the issuer signed, for that note number.
    signal note <== Poseidon(5)([NOTE_TAG, noteNumber, embedding, model, month]);
    component signed = EdDSAPoseidonVerifier();
    signed.enabled <== 1;
    signed.Ax <== issuerX;
    signed.Ay <== issuerY;
    signed.S <== S;
    signed.R8x <== R8x;
    signed.R8y <== R8y;
    signed.M <== note;

    // The stamp for this label at this issuer.
    stamp <== Poseidon(2)([scope, issuerScalar]);

    // The profile's key: the lowest 250 bits of Poseidon(profile tag, seed scalar, scope), times
    // Base8. Num2Bits_strict, not Num2Bits(254): a number below the field has a second 254-bit
    // spelling, itself plus the field's order, whenever that sum is below 2^254, about a third of
    // all numbers. Its lowest 250 bits differ, so with Num2Bits a prover could pick a second key
    // for one label. The strict form allows only the number's own bits.
    signal raw <== Poseidon(3)([PROFILE_TAG, seedScalar, scope]);
    signal bits[254] <== Num2Bits_strict()(raw);
    component key = EscalarMulFix(250, BASE8);
    for (var i = 0; i < 250; i++) {
        key.e[i] <== bits[i];
    }
    profileX === key.out[0];
    profileY === key.out[1];
}

component main {public [profileX, profileY, issuerX, issuerY, scope, issuerNameHash, month]} = Human();
