pragma circom 2.1.5;

// The person proof: "I know an issuer secret and a note signed by this issuer whose note number is
// the hash of that secret; my stamp for this label is the hash of that secret and the label; this
// proof is for this main key" (../README.md, The note and the person proof).
//
// The note is { note number, face embedding, model name, tier }. The issuer signs
// Poseidon(tag, note number, embedding's hash, model's hash, tier) with its EdDSA key on Baby
// Jubjub, over Poseidon: circomlib's verifier, unchanged. The tag is fixed, so nothing the issuer
// signs for another purpose can be turned into a note. The embedding and the model enter only as
// their hashes; the circuit never reads them.

include "poseidon.circom";
include "eddsaposeidon.circom";

template Person() {
    // Private.
    // The person's secret for one issuer: the scalar keys/'s issuerSecret gives. It needs no bound:
    // the note number and the stamp are Poseidon hashes of it, and only one secret gives them.
    signal input secret;
    signal input embedding;     // the hash of the note's face embedding
    signal input model;         // the hash of the note's model name
    signal input R8x, R8y, S;   // the issuer's signature on the note

    // Public, in the order stamp, issuerX, issuerY, scope, message, tier.
    signal input issuerX, issuerY;  // the issuer's key, a point on Baby Jubjub
    signal input scope;             // the label, as the registry derives its scope
    signal input message;           // the main key the proof is for, as the registry derives it
    signal input tier;              // the tier the issuer signed in the note
    signal output stamp;

    // The note's tag: keccak256("forest/v1/note") >> 8, the registry's rule for turning text into a
    // field element, as for the scope and the message.
    var NOTE_TAG = 400167441388126881061687584776181816477671862726675254297469311886243976537;

    // The note the issuer signed, with the note number the secret gives.
    var noteNumber = Poseidon(1)([secret]);
    var note = Poseidon(5)([NOTE_TAG, noteNumber, embedding, model, tier]);

    component signed = EdDSAPoseidonVerifier();
    signed.enabled <== 1;
    signed.Ax <== issuerX;
    signed.Ay <== issuerY;
    signed.S <== S;
    signed.R8x <== R8x;
    signed.R8y <== R8y;
    signed.M <== note;

    // The stamp for this label: Poseidon(scope, secret), the number a registry row sits at.
    stamp <== Poseidon(2)([scope, secret]);

    // The message is not used inside. Squaring it gives it a constraint, as Semaphore does, so it
    // cannot be changed in a proof.
    signal messageSquare <== message * message;
}

component main {public [issuerX, issuerY, scope, message, tier]} = Person();
