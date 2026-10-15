import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { hkdf as nobleHkdf } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { keccak_256 } from '@noble/hashes/sha3.js'
import { blake512 } from '@noble/hashes/blake1.js'
import { base58, bech32, hex } from '@scure/base'
import { ed25519 } from '@noble/curves/ed25519.js'
import { edwards } from '@noble/curves/abstract/edwards.js'
import { MLKEM768X25519 } from '@noble/post-quantum/hybrid.js'
import { Decrypter, Encrypter } from 'age-encryption'
import { Base8, subOrder } from '@zk-kit/baby-jubjub'
import { verifySignature } from '@zk-kit/eddsa-poseidon'
import { poseidon1 } from 'poseidon-lite/poseidon1'
import { poseidon2 } from 'poseidon-lite/poseidon2'
import { poseidon3 } from 'poseidon-lite/poseidon3'
import { poseidon5 } from 'poseidon-lite/poseidon5'
import {
  BN254_R,
  INFO,
  SEED_LENGTH,
  TAG,
  WORD_COUNT,
  addressOf,
  exportWords,
  hkdf,
  importWords,
  inboxKey,
  issuerScalarOf,
  issuerSecret,
  mainKey,
  nameHashOf,
  newSeed,
  payKey,
  pointOf,
  profileScalarOf,
  scopeOf,
  seedScalar,
  signWithScalar,
  stampOf,
  vaultKey,
  verifyWithPublicKey,
  type Point,
} from '../src/index.ts'

const vectors = JSON.parse(readFileSync(new URL('./vectors.json', import.meta.url), 'utf8'))
const seed = hex.decode(vectors.seed)
const otherSeed = new Uint8Array(32).fill(7)
const [seller, buyer] = vectors.mainKeys
const [issuerA, issuerB] = vectors.issuers
const S = BigInt(vectors.seedScalar.scalar)
const utf8 = (text: string) => new TextEncoder().encode(text)
// HKDF-SHA256 from a second implementation: empty salt, 32 bytes.
const mix = (ikm: Uint8Array, info: string) => nobleHkdf(sha256, ikm, undefined, utf8(info), 32)
// keccak256 of the text, shifted right one byte, from a second implementation.
const field = (text: string) => BigInt('0x' + hex.encode(keccak_256(utf8(text)))) >> 8n
// Baby Jubjub from a second implementation: noble's twisted Edwards curves, with circomlib's
// parameters and Base8 as the generator of the prime-order subgroup.
const BJJ = edwards({ p: BN254_R, n: subOrder, h: 8n, a: 168700n, d: 168696n, Gx: Base8[0], Gy: Base8[1] })
const times = (scalar: bigint) => BJJ.BASE.multiply(scalar).toAffine()
// A point packed by hand: y in 32 little-endian bytes, the top bit set when x is above (p - 1) / 2.
const pack = (x: bigint, y: bigint) => {
  const out = new Uint8Array(32)
  for (let i = 0, v = y; i < 32; i++, v >>= 8n) out[i] = Number(v & 0xffn)
  if (x > (BN254_R - 1n) / 2n) out[31] |= 0x80
  return base58.encode(out)
}
const big = (p: string[]): Point => [BigInt(p[0]), BigInt(p[1])]

// The mixing table

test('the info strings and the tags are exactly the standard', () => {
  assert.equal(INFO.seed, 'forest/v1/seed')
  assert.equal(INFO.profile('tutoring/seller'), 'forest/v1/profile/tutoring/seller')
  assert.equal(INFO.read, 'forest/v1/read')
  assert.equal(INFO.pay('tutoring/seller'), 'forest/v1/pay/solana/tutoring/seller')
  assert.equal(INFO.vault, 'forest/v1/vault')
  assert.equal(INFO.seed, vectors.seedScalar.info)
  assert.equal(INFO.vault, vectors.vault.info)
  for (const p of vectors.mainKeys) assert.equal(INFO.profile(p.label), p.info)
  for (const p of vectors.payKeys) assert.equal(INFO.pay(p.label), p.info)
  for (const [name, tag] of Object.entries(vectors.tags) as [keyof typeof TAG, { text: string; value: string }][]) {
    assert.equal(TAG[name], field(tag.text), name)
    assert.equal(TAG[name].toString(), tag.value, name)
  }
})

test('HKDF agrees with an independent implementation', async () => {
  for (const info of [INFO.seed, INFO.profile('tutoring/seller'), INFO.profile(''), INFO.read, INFO.pay('tutoring/seller'), INFO.vault]) {
    assert.equal(hex.encode(await hkdf(seed, info)), hex.encode(mix(seed, info)), info)
  }
})

// The seed

test('the seed is 24 words, pinned, and comes back', () => {
  const words = exportWords(seed)
  assert.equal(WORD_COUNT, 24)
  assert.equal(words.split(' ').length, 24)
  assert.equal(words, vectors.words)
  assert.equal(hex.encode(importWords(words)), vectors.seed)
})

test('spacing and case are forgiven; a wrong or missing word is not', () => {
  const words: string = vectors.words
  const messy = '  ' + words.toUpperCase().replaceAll(' ', '\n   ') + '\n'
  assert.equal(hex.encode(importWords(messy)), vectors.seed)
  const wrongWord = words.split(' ')
  wrongWord[23] = 'abandon'
  assert.throws(() => importWords(wrongWord.join(' ')), /not seed words/)
  assert.throws(() => importWords(words.split(' ').slice(0, 23).join(' ')), /expected 24 words, got 23/)
  assert.throws(() => exportWords(new Uint8Array(16)), /seed must be 32 bytes/)
})

test('a new seed is 32 fresh random bytes, and makes 24 words', () => {
  const one = newSeed()
  const two = newSeed()
  assert.equal(one.length, SEED_LENGTH)
  assert.notEqual(hex.encode(one), hex.encode(two))
  assert.equal(hex.encode(importWords(exportWords(one))), hex.encode(one))
})

// The seed scalar

test('the seed gives the pinned seed scalar, and gives it again', async () => {
  for (let round = 0; round < 2; round++) assert.equal(await seedScalar(seed), S)
  assert.notEqual(await seedScalar(otherSeed), S)
  await assert.rejects(seedScalar(seed.subarray(1)), /seed must be 32 bytes/)
})

test('the seed scalar is the one Semaphore v4 made from the mixed bytes, step by step', () => {
  // HKDF, then BLAKE-512 of the 32 bytes, the first 32, pruned, read little-endian, shifted right
  // 3, mod the subgroup order: done here without zk-kit, so a change in its derivation shows up as
  // a failing test rather than silently.
  const bytes = mix(seed, 'forest/v1/seed')
  assert.equal(hex.encode(bytes), vectors.seedScalar.bytes)
  const h = blake512(bytes).slice(0, 32)
  h[0] &= 0xf8
  h[31] &= 0x7f
  h[31] |= 0x40
  let scalar = 0n
  for (let i = 31; i >= 0; i--) scalar = (scalar << 8n) | BigInt(h[i])
  assert.equal((scalar >> 3n) % subOrder, S)
})

// Main keys

test('each label gives the pinned main key, and gives it again', async () => {
  for (const expected of vectors.mainKeys) {
    for (let round = 0; round < 2; round++) {
      const key = await mainKey(seed, expected.label)
      assert.equal(key.label, expected.label)
      assert.equal(key.scope.toString(), expected.scope)
      assert.equal(key.scalar.toString(), expected.scalar)
      assert.deepEqual(key.publicKey, big(expected.publicKey))
      assert.equal(key.address, expected.address)
      assert.equal(hex.encode(key.secret), expected.secret)
    }
  }
})

test('the main key, recomputed without the library: keccak, Poseidon, the low 250 bits, Baby Jubjub, the packing', () => {
  for (const expected of vectors.mainKeys) {
    const scope = field('forest.foundation/label/v1/' + expected.label)
    assert.equal(scope.toString(), expected.scope)
    const raw = poseidon3([TAG.profile, S, scope])
    assert.equal(raw.toString(), expected.raw)
    const scalar = raw % 2n ** 250n
    assert.equal(scalar.toString(), expected.scalar)
    assert.ok(scalar < subOrder && 2n ** 250n < subOrder, 'a 250-bit number is a scalar already')
    const point = times(scalar)
    assert.deepEqual([point.x, point.y], big(expected.publicKey))
    assert.equal(pack(point.x, point.y), expected.address)
    assert.equal(hex.encode(mix(seed, expected.info)), expected.secret)
  }
  assert.equal(profileScalarOf(S, seller.label).toString(), seller.scalar)
})

test('the label is used exactly: another case, another space, another profile', async () => {
  const addresses = new Set<string>()
  for (const label of ['tutoring/seller', 'Tutoring/Seller', 'tutoring/seller ', 'tutoring/buyer', 'ünïcødé/ラベル', '']) {
    addresses.add((await mainKey(seed, label)).address)
  }
  assert.equal(addresses.size, 6)
})

test('keys of one seed have nothing to do with keys of another seed', async () => {
  assert.notEqual((await mainKey(seed, 'tutoring/seller')).address, (await mainKey(otherSeed, 'tutoring/seller')).address)
  assert.notEqual((await payKey(seed, 'tutoring/seller')).address, (await payKey(otherSeed, 'tutoring/seller')).address)
  assert.notEqual((await issuerSecret(seed, issuerA.name)).noteNumber, (await issuerSecret(otherSeed, issuerA.name)).noteNumber)
})

test('a main key needs a 32-byte seed and a label that is text', async () => {
  await assert.rejects(mainKey(seed.subarray(0, 16), 'tutoring/seller'), /seed must be 32 bytes/)
  await assert.rejects(mainKey(seed, 'tutoring/\ud800seller'), /label must be text/)
  await assert.rejects(mainKey(seed, 7 as unknown as string), /label must be text/)
  assert.throws(() => profileScalarOf(BN254_R, 'tutoring/seller'), /field element/)
})

test('an address names its key and nothing else, in one spelling', () => {
  for (const p of [...vectors.mainKeys, vectors.vault]) {
    assert.deepEqual(pointOf(p.address), big(p.publicKey))
    assert.equal(addressOf(pointOf(p.address)), p.address)
  }
  const bytes = base58.decode(seller.address)
  const flipped = bytes.slice()
  flipped[31] ^= 0x80 // the other x for the same y: the negated point, its own key, not this one
  const negated = pointOf(base58.encode(flipped))
  assert.deepEqual(negated, [BN254_R - BigInt(seller.publicKey[0]), BigInt(seller.publicKey[1])])
  const yIsP = new Uint8Array(32)
  for (let i = 0, v = BN254_R; i < 32; i++, v >>= 8n) yIsP[i] = Number(v & 0xffn) // y = p, the spelling of y = 0 past the field
  const bad: [string, string][] = [
    ['not base58', 'O0Il'],
    ['31 bytes', base58.encode(bytes.subarray(1))],
    ['33 bytes', base58.encode(new Uint8Array([...bytes, 0]))],
    ['y past the field', base58.encode(yIsP)],
    ['no point there', base58.encode(new Uint8Array(32).fill(0x11))],
    ['the identity', base58.encode(new Uint8Array([1, ...new Uint8Array(31)]))],
  ]
  for (const [what, address] of bad) assert.throws(() => pointOf(address), Error, what)
  // A point of order 2, (0, -1), is on the curve but in no key's subgroup.
  const order2 = new Uint8Array(32)
  for (let i = 0, v = BN254_R - 1n; i < 32; i++, v >>= 8n) order2[i] = Number(v & 0xffn)
  assert.throws(() => pointOf(base58.encode(order2)), /subgroup/)
  assert.throws(() => addressOf([0n, BN254_R - 1n]), /subgroup/)
})

// Signatures

test('the main key signs: the pinned signature, again the same, and it holds', () => {
  const v = vectors.signature
  const scalar = BigInt(seller.scalar)
  const message = BigInt(v.message)
  assert.equal(message, field(v.messageText))
  const sig = signWithScalar(scalar, message)
  assert.deepEqual(sig, { R8: big(v.R8), S: BigInt(v.S) })
  assert.deepEqual(signWithScalar(scalar, message), sig, 'deterministic')
  assert.equal(verifyWithPublicKey(big(seller.publicKey), message, sig), true)
  assert.equal(verifyWithPublicKey(seller.address, message, sig), true, 'from its address')
  assert.equal(verifySignature(message, sig, big(seller.publicKey)), true, "zk-kit's own check")
})

test('the signature, checked without the library: S·Base8 = R8 + 8·Poseidon(R8, A, message)·A', () => {
  const v = vectors.signature
  const A = BJJ.fromAffine({ x: BigInt(seller.publicKey[0]), y: BigInt(seller.publicKey[1]) })
  const R8 = BJJ.fromAffine({ x: BigInt(v.R8[0]), y: BigInt(v.R8[1]) })
  const hm = poseidon5([R8.x, R8.y, A.x, A.y, BigInt(v.message)])
  const left = BJJ.BASE.multiply(BigInt(v.S))
  const right = R8.add(A.multiply((8n * hm) % subOrder))
  assert.ok(left.equals(right))
  assert.ok(BigInt(v.S) < subOrder)
})

test('a signature holds for its message and key only', () => {
  const scalar = BigInt(seller.scalar)
  const message = 12345n
  const sig = signWithScalar(scalar, message)
  assert.equal(verifyWithPublicKey(seller.address, message + 1n, sig), false, 'another message')
  assert.equal(verifyWithPublicKey(buyer.address, message, sig), false, 'another key')
  assert.equal(verifyWithPublicKey(seller.address, message, { ...sig, S: sig.S + 1n }), false, 'S changed')
  assert.equal(verifyWithPublicKey(seller.address, message, { ...sig, S: sig.S + subOrder }), false, 'S plus l')
  assert.equal(verifyWithPublicKey(seller.address, message, { ...sig, R8: [sig.R8[0], sig.R8[1] + 1n] }), false, 'R8 off the curve')
  assert.equal(verifyWithPublicKey('not an address', message, sig), false, 'no key')
  assert.equal(verifyWithPublicKey(seller.address, BN254_R, sig), false, 'a message past the field')
  assert.notDeepEqual(signWithScalar(scalar, message + 1n).R8, sig.R8, 'another message, another nonce')
  assert.throws(() => signWithScalar(0n, message), /scalar/)
  assert.throws(() => signWithScalar(subOrder, message), /scalar/)
  assert.throws(() => signWithScalar(scalar, BN254_R), /field element/)
})

// Inbox keys

test("each profile gives the pinned inbox key, from its secret, never from the main key's scalar", async () => {
  for (const expected of vectors.mainKeys) {
    const key = await mainKey(seed, expected.label)
    const { privateKey, ...inbox } = expected.inbox
    assert.deepEqual(await inboxKey(key.secret), inbox)
    assert.equal(hex.encode(await hkdf(key.secret, INFO.read)), privateKey)
  }
})

test("the inbox key, recomputed without the library: HKDF twice, ML-KEM-768 with X25519, age's bech32", () => {
  const privateKey = mix(mix(seed, seller.info), INFO.read)
  assert.equal(hex.encode(privateKey), seller.inbox.privateKey)
  assert.equal(bech32.encodeFromBytes('AGE-SECRET-KEY-PQ-', privateKey).toUpperCase(), seller.inbox.identity)
  // The recipient is the hybrid public key the 32 bytes expand to, in bech32 under age1pq, with
  // no length limit: it is about 1,960 characters.
  const publicKey = MLKEM768X25519.getPublicKey(privateKey)
  assert.equal(bech32.encode('age1pq', bech32.toWords(publicKey), false), seller.inbox.recipient)
  assert.match(seller.inbox.identity, /^AGE-SECRET-KEY-PQ-1[0-9A-Z]+$/)
  assert.match(seller.inbox.recipient, /^age1pq1[0-9a-z]+$/)
})

test('age encrypts to the inbox key, and only that profile opens it', async () => {
  const encrypter = new Encrypter()
  encrypter.addRecipient(seller.inbox.recipient)
  const encrypted = await encrypter.encrypt('only for the seller profile')
  const opener = new Decrypter()
  opener.addIdentity(seller.inbox.identity)
  assert.equal(await opener.decrypt(encrypted, 'text'), 'only for the seller profile')
  const other = new Decrypter()
  other.addIdentity(buyer.inbox.identity)
  await assert.rejects(other.decrypt(encrypted, 'text'))
})

test('an inbox key needs a 32-byte secret', async () => {
  await assert.rejects(inboxKey(new Uint8Array(64)), /secret must be 32 bytes/)
})

// Payment keys

test('each label gives the pinned payment key, recomputed without the library: HKDF, ed25519, base58', async () => {
  for (const expected of vectors.payKeys) {
    const key = await payKey(seed, expected.label)
    assert.equal(hex.encode(key.privateKey), expected.privateKey)
    assert.equal(key.address, expected.address)
    const privateKey = mix(seed, expected.info)
    assert.equal(hex.encode(privateKey), expected.privateKey)
    assert.equal(base58.encode(ed25519.getPublicKey(privateKey)), expected.address)
  }
  assert.notEqual(vectors.payKeys[0].address, vectors.payKeys[1].address)
  for (const p of vectors.payKeys) assert.ok(vectors.mainKeys.every((m: { address: string }) => m.address !== p.address))
  await assert.rejects(payKey(seed, 'tutoring/\ud800seller'), /label must be text/)
})

// The vault key

test('the seed gives the pinned vault key, recomputed without the library, and its inbox key', async () => {
  for (let round = 0; round < 2; round++) {
    const key = await vaultKey(seed)
    assert.equal(key.scalar.toString(), vectors.vault.scalar)
    assert.equal(key.address, vectors.vault.address)
    assert.equal(hex.encode(key.secret), vectors.vault.secret)
    assert.equal('label' in key, false, 'it belongs to no label')
    const { privateKey, ...inbox } = vectors.vault.inbox
    assert.deepEqual(await inboxKey(key.secret), inbox)
    assert.equal(hex.encode(await hkdf(key.secret, INFO.read)), privateKey)
  }
  const raw = poseidon2([TAG.vault, S])
  assert.equal(raw.toString(), vectors.vault.raw)
  const point = times(raw % 2n ** 250n)
  assert.equal(pack(point.x, point.y), vectors.vault.address)
  assert.equal(hex.encode(mix(seed, 'forest/v1/vault')), vectors.vault.secret)
})

test("the vault key is no profile's, and another seed gives another", async () => {
  // Its mix has its own tag and two inputs, a profile's three, so no label can give it.
  assert.notEqual(TAG.vault, TAG.profile)
  for (const label of ['', 'vault', '../vault', 'tutoring/seller']) {
    assert.notEqual((await mainKey(seed, label)).address, vectors.vault.address)
    assert.notEqual(INFO.profile(label), INFO.vault)
  }
  assert.notEqual((await vaultKey(otherSeed)).address, vectors.vault.address)
  await assert.rejects(vaultKey(new Uint8Array(31)), /seed must be 32 bytes/)
})

// Issuer secrets, note numbers and stamps

test('each issuer gives the pinned name hash, secret, note number and stamps, and gives them again', async () => {
  for (const expected of vectors.issuers) {
    for (let round = 0; round < 2; round++) {
      const { name, nameHash, scalar, noteNumber } = await issuerSecret(seed, expected.name)
      assert.equal(name, expected.name)
      assert.equal(nameHash.toString(), expected.nameHash)
      assert.equal(scalar.toString(), expected.scalar)
      assert.equal(noteNumber.toString(), expected.noteNumber)
      for (const [label, stamp] of Object.entries(expected.stamps)) assert.equal(stampOf(scalar, label).toString(), stamp)
    }
  }
})

test('the issuer secret, the note number and a stamp, recomputed without the library', () => {
  for (const expected of vectors.issuers) {
    const nameHash = field('forest/v1/issuer/' + expected.name)
    assert.equal(nameHash.toString(), expected.nameHash)
    assert.equal(nameHashOf(expected.name), nameHash)
    const scalar = poseidon3([TAG.issuer, S, nameHash])
    assert.equal(scalar.toString(), expected.scalar)
    assert.equal(issuerScalarOf(S, expected.name), scalar)
    assert.equal(poseidon1([scalar]).toString(), expected.noteNumber)
    for (const [label, stamp] of Object.entries(expected.stamps)) {
      assert.equal(poseidon2([field('forest.foundation/label/v1/' + label), scalar]).toString(), stamp)
      assert.equal(scopeOf(label), field('forest.foundation/label/v1/' + label))
    }
  }
})

test('two issuers, two unrelated note numbers and stamps; and none of it is a key', async () => {
  const a = await issuerSecret(seed, issuerA.name)
  const b = await issuerSecret(seed, issuerB.name)
  assert.notEqual(a.noteNumber, b.noteNumber)
  assert.notEqual(stampOf(a.scalar, 'tutoring/seller'), stampOf(b.scalar, 'tutoring/seller'))
  const all = [issuerA.scalar, issuerB.scalar, seller.scalar, buyer.scalar, vectors.vault.scalar, vectors.seedScalar.scalar, seller.raw, buyer.raw]
  assert.equal(new Set(all).size, all.length)
})

test('the name is used exactly, and must be text; the seed is 32 bytes', async () => {
  const names = new Set<string>()
  for (const name of ['issuer-a.example', 'Issuer-A.example', 'issuer-a.example ', '']) {
    names.add((await issuerSecret(seed, name)).noteNumber.toString())
  }
  assert.equal(names.size, 4)
  for (const name of ['issuer-\ud800a.example', 7, undefined]) {
    await assert.rejects(issuerSecret(seed, name as string), /issuer name must be text/, String(name))
  }
  await assert.rejects(issuerSecret(seed.subarray(1), issuerA.name), /seed must be 32 bytes/)
  assert.throws(() => stampOf(BN254_R, 'tutoring/seller'), /field element/)
  assert.throws(() => issuerScalarOf(-1n, issuerA.name), /field element/)
})
