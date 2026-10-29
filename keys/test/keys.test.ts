import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { hkdf as nobleHkdf } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { createECDH, createHash, createPublicKey, verify as nodeVerify } from 'node:crypto'
import { keccak_256 } from '@noble/hashes/sha3.js'
import { base58, bech32, hex } from '@scure/base'
import { ed25519 } from '@noble/curves/ed25519.js'
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { MLKEM768X25519 } from '@noble/post-quantum/hybrid.js'
import { Decrypter, Encrypter } from 'age-encryption'
import { Base8, addPoint, inCurve, mulPointEscalar, packPoint as zkPack, subOrder } from '@zk-kit/baby-jubjub'
import { packSignature as zkPackSignature, verifySignature } from '@zk-kit/eddsa-poseidon'
import { poseidon2 } from 'poseidon-lite/poseidon2'
import { poseidon5 } from 'poseidon-lite/poseidon5'
import {
  BN254_R,
  PAY_CHAINS,
  SEED_LENGTH,
  TEXT,
  WORD_COUNT,
  addressOf,
  bytesMessage,
  evmAddressOf,
  exportWords,
  fieldHash,
  hkdf,
  importWords,
  accessKey,
  newAccessKey,
  openingHalf,
  isEvmAddress,
  mainKey,
  nameHashOf,
  newSeed,
  packPoint,
  packSignature,
  payAddresses,
  payKey,
  pointOf,
  profileScalarOf,
  signBytes,
  scopeOf,
  seedNumber,
  serviceKey,
  signWithScalar,
  stampNumberOf,
  unpackPoint,
  unpackSignature,
  checkBytes,
  checkWithPublicKey,
  type Point,
} from '../src/index.ts'

const vectors = JSON.parse(readFileSync(new URL('./vectors.json', import.meta.url), 'utf8'))
const seed = hex.decode(vectors.seed)
const otherSeed = new Uint8Array(32).fill(7)
const [seller, buyer, profilesFolder] = vectors.mainKeys
const [verifierA, verifierB] = vectors.verifiers
const S = BigInt(vectors.seedNumber)
const utf8 = (text: string) => new TextEncoder().encode(text)
// HKDF-SHA256 from a second implementation: empty salt, 32 bytes.
const mix = (ikm: Uint8Array, info: string) => nobleHkdf(sha256, ikm, undefined, utf8(info), 32)
// keccak256 of the text, shifted right one byte, from a second implementation.
const field = (text: string) => BigInt('0x' + hex.encode(keccak_256(utf8(text)))) >> 8n
// Baby Jubjub from a second implementation: zk-kit's, which circomlib's circuits match. keys/ itself
// runs on @noble/curves' twisted Edwards curves.
const times = (scalar: bigint) => {
  const [x, y] = mulPointEscalar(Base8, scalar)
  return { x, y }
}
// A point packed by hand: y in 32 little-endian bytes, the top bit set when x is above (p - 1) / 2.
const pack = (x: bigint, y: bigint) => {
  const out = new Uint8Array(32)
  for (let i = 0, v = y; i < 32; i++, v >>= 8n) out[i] = Number(v & 0xffn)
  if (x > (BN254_R - 1n) / 2n) out[31] |= 0x80
  return base58.encode(out)
}
const big = (p: string[]): Point => [BigInt(p[0]), BigInt(p[1])]
/** Bytes read as a big-endian number, by hand. */
const bigEndian = (bytes: Uint8Array) => BigInt('0x' + hex.encode(bytes))

// The three texts

test('the texts are exactly the standard, three and no more', () => {
  assert.deepEqual(Object.keys(TEXT), ['profile', 'verifier', 'pay'])
  assert.equal(TEXT.profile('tutoring/seller'), 'forest/profile/tutoring/seller')
  assert.equal(TEXT.profile(''), 'forest/profile/', 'the empty label: the Profiles folder')
  assert.equal(TEXT.verifier('verifier-a.example'), 'forest/verifier/verifier-a.example')
  assert.equal(TEXT.pay('solana', 'tutoring/seller'), 'forest/pay/solana/tutoring/seller')
  assert.equal(TEXT.pay('evm', 'tutoring/seller'), 'forest/pay/evm/tutoring/seller')
  for (const p of vectors.mainKeys) assert.equal(TEXT.profile(p.label), p.text)
  for (const p of vectors.payKeys) assert.equal(TEXT.pay(p.chain, p.label), p.text)
  for (const v of vectors.verifiers) assert.equal(TEXT.verifier(v.name), v.text)
})

test('HKDF agrees with an independent implementation', async () => {
  for (const info of [TEXT.profile('tutoring/seller'), TEXT.profile(''), TEXT.pay('solana', 'tutoring/seller'), TEXT.pay('evm', 'tutoring/seller')]) {
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

// The seed's number

test("the seed's number is its 32 bytes read big-endian, mod BN254's order, and nothing else", () => {
  assert.equal(bigEndian(seed) % BN254_R, S)
  assert.equal(seedNumber(seed), S)
  assert.notEqual(seedNumber(otherSeed), S)
  const high = new Uint8Array(32).fill(0xff)
  assert.equal(seedNumber(high), (2n ** 256n - 1n) % BN254_R, 'a seed above the order is reduced')
  assert.ok(seedNumber(high) < BN254_R)
  assert.throws(() => seedNumber(seed.subarray(1)), /seed must be 32 bytes/)
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

test('the main key, recomputed without the library: keccak of its text, Poseidon with the seed, the low 250 bits, Baby Jubjub, the packing; its opening secret HKDF of the seed with the same text', () => {
  for (const expected of vectors.mainKeys) {
    const scope = field('forest/profile/' + expected.label)
    assert.equal(scope.toString(), expected.scope)
    assert.equal(scopeOf(expected.label), scope)
    const raw = poseidon2([S, scope])
    assert.equal(raw.toString(), expected.raw)
    const scalar = raw % 2n ** 250n
    assert.equal(scalar.toString(), expected.scalar)
    assert.ok(scalar < subOrder && 2n ** 250n < subOrder, 'a 250-bit number is a scalar already')
    const point = times(scalar)
    assert.deepEqual([point.x, point.y], big(expected.publicKey))
    assert.equal(pack(point.x, point.y), expected.address)
    assert.equal(hex.encode(mix(seed, 'forest/profile/' + expected.label)), expected.secret)
  }
  assert.equal(profileScalarOf(S, seller.label).toString(), seller.scalar)
})

test("the empty label gives the Profiles folder's key, a main key like any other, and no other label gives it", async () => {
  assert.equal(profilesFolder.label, '')
  const key = await mainKey(seed, '')
  assert.equal(key.address, profilesFolder.address)
  for (const p of [seller, buyer]) assert.ok(p.address !== profilesFolder.address && p.secret !== profilesFolder.secret && p.opening.openKey !== profilesFolder.opening.openKey, p.label)
  assert.notEqual((await mainKey(otherSeed, '')).address, profilesFolder.address)
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
  for (const chain of PAY_CHAINS) assert.notEqual((await payKey(seed, 'tutoring/seller', chain)).address, (await payKey(otherSeed, 'tutoring/seller', chain)).address)
  assert.notEqual(stampNumberOf(seedNumber(seed), verifierA.name), stampNumberOf(seedNumber(otherSeed), verifierA.name))
})

test('a main key needs a 32-byte seed and a label that is text', async () => {
  await assert.rejects(mainKey(seed.subarray(0, 16), 'tutoring/seller'), /seed must be 32 bytes/)
  await assert.rejects(mainKey(seed, 'tutoring/\ud800seller'), /label must be text/)
  await assert.rejects(mainKey(seed, 7 as unknown as string), /label must be text/)
  assert.throws(() => profileScalarOf(BN254_R, 'tutoring/seller'), /field element/)
  assert.throws(() => profileScalarOf(-1n, 'tutoring/seller'), /field element/)
})

test('an address names its key and nothing else, in one spelling', () => {
  for (const p of vectors.mainKeys) {
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
  assert.equal(checkWithPublicKey(big(seller.publicKey), message, sig), true)
  assert.equal(checkWithPublicKey(seller.address, message, sig), true, 'from its address')
  assert.equal(verifySignature(message, sig, big(seller.publicKey)), true, "zk-kit's own check")
})

test('the signature, checked without the library: S·Base8 = R8 + 8·Poseidon(R8, A, message)·A', () => {
  const v = vectors.signature
  const A = big(seller.publicKey)
  const R8 = big(v.R8)
  const hm = poseidon5([R8[0], R8[1], A[0], A[1], BigInt(v.message)])
  const left = mulPointEscalar(Base8, BigInt(v.S))
  const right = addPoint(R8, mulPointEscalar(A, 8n * hm))
  assert.deepEqual(left, right)
  assert.ok(BigInt(v.S) < subOrder)
})

test('the nonce, byte by byte: SHA-512 of the scalar and the message, each 32 bytes little-endian, and nothing else; read little-endian, mod l', () => {
  const v = vectors.signature
  const le32 = (n: bigint) => Buffer.from(n.toString(16).padStart(64, '0'), 'hex').reverse()
  const input = Buffer.concat([le32(BigInt(seller.scalar)), le32(BigInt(v.message))])
  assert.equal(input.length, 64, 'no text, no length')
  const digest = createHash('sha512').update(input).digest()
  const r = BigInt('0x' + Buffer.from(digest).reverse().toString('hex')) % subOrder
  assert.deepEqual(mulPointEscalar(Base8, r), big(v.R8))
})

test('fieldHash: keccak256 of the text and each part joined with nothing between, text as UTF-8 and bytes as they are, read big-endian, shifted right 8 bits', () => {
  assert.equal(fieldHash(seller.text), field(seller.text))
  assert.equal(fieldHash('forest/profile/', 'tutoring/', 'seller'), BigInt(seller.scope), 'parts are joined, not hashed one by one')
  const bytes = Uint8Array.of(0, 0xff, 7)
  const byHand = BigInt('0x' + hex.encode(keccak_256(new Uint8Array([...utf8('ns/é'), ...bytes])))) >> 8n
  assert.equal(fieldHash('ns/', 'é', bytes), byHand)
})

test("a signature in 64 bytes: R8 packed, then S, as zk-kit packs it; and back, strictly", () => {
  const v = vectors.signature
  const sig = { R8: big(v.R8), S: BigInt(v.S) }
  const bytes = packSignature(sig)
  assert.deepEqual(Buffer.from(bytes), Buffer.from(zkPackSignature(sig)))
  assert.deepEqual(unpackSignature(bytes), sig)
  const sPlusL = bytes.slice()
  for (let i = 0, v2 = sig.S + subOrder; i < 32; i++, v2 >>= 8n) sPlusL[32 + i] = Number(v2 & 0xffn)
  assert.equal(unpackSignature(sPlusL), null, 'S plus l')
  const noPoint = bytes.slice()
  noPoint.fill(0x11, 0, 32)
  assert.equal(unpackSignature(noPoint), null, 'R8 not on the curve')
  assert.equal(unpackSignature(bytes.subarray(1)), null, '63 bytes')
  // A point packs as zk-kit packs it, and unpacks to itself.
  for (const p of vectors.mainKeys) {
    const point = big(p.publicKey)
    const packed = packPoint(point)
    let n = 0n
    for (let i = 31; i >= 0; i--) n = (n << 8n) | BigInt(packed[i]!)
    assert.equal(n, zkPack(point))
    assert.deepEqual(unpackPoint(packed), point)
    assert.ok(inCurve(point))
  }
})

test('a signature holds for its message and key only', () => {
  const scalar = BigInt(seller.scalar)
  const message = 12345n
  const sig = signWithScalar(scalar, message)
  assert.equal(checkWithPublicKey(seller.address, message + 1n, sig), false, 'another message')
  assert.equal(checkWithPublicKey(buyer.address, message, sig), false, 'another key')
  assert.equal(checkWithPublicKey(seller.address, message, { ...sig, S: sig.S + 1n }), false, 'S changed')
  assert.equal(checkWithPublicKey(seller.address, message, { ...sig, S: sig.S + subOrder }), false, 'S plus l')
  assert.equal(checkWithPublicKey(seller.address, message, { ...sig, R8: [sig.R8[0], sig.R8[1] + 1n] }), false, 'R8 off the curve')
  assert.equal(checkWithPublicKey('not an address', message, sig), false, 'no key')
  assert.equal(checkWithPublicKey(seller.address, BN254_R, sig), false, 'a message past the field')
  assert.notDeepEqual(signWithScalar(scalar, message + 1n).R8, sig.R8, 'another message, another nonce')
  assert.throws(() => signWithScalar(0n, message), /scalar/)
  assert.throws(() => signWithScalar(subOrder, message), /scalar/)
  assert.throws(() => signWithScalar(scalar, BN254_R), /field element/)
})

// Opening halves

test("each profile gives its main key's pinned opening half: its opening secret, as it is, never the main key's scalar", async () => {
  for (const expected of vectors.mainKeys) {
    const key = await mainKey(seed, expected.label)
    assert.deepEqual(await openingHalf(key.secret), expected.opening)
  }
})

test("an opening half, recomputed without the library: the 32 bytes as they are, ML-KEM-768 with X25519, age's bech32", () => {
  const secret = mix(seed, 'forest/profile/tutoring/seller')
  assert.equal(hex.encode(secret), seller.secret)
  assert.equal(bech32.encodeFromBytes('AGE-SECRET-KEY-PQ-', secret).toUpperCase(), seller.opening.identity)
  // The open key is the hybrid public key the 32 bytes expand to, in bech32 under age1pq, with no
  // length limit: it is about 1,960 characters.
  const publicKey = MLKEM768X25519.getPublicKey(secret)
  assert.equal(bech32.encode('age1pq', bech32.toWords(publicKey), false), seller.opening.openKey)
  assert.match(seller.opening.identity, /^AGE-SECRET-KEY-PQ-1[0-9A-Z]+$/)
  assert.match(seller.opening.openKey, /^age1pq1[0-9a-z]+$/)
})

test('age locks to the open key, and only that key opens it', async () => {
  const encrypter = new Encrypter()
  encrypter.addRecipient(seller.opening.openKey)
  const encrypted = await encrypter.encrypt('only for the seller profile')
  const opener = new Decrypter()
  opener.addIdentity(seller.opening.identity)
  assert.equal(await opener.decrypt(encrypted, 'text'), 'only for the seller profile')
  const other = new Decrypter()
  other.addIdentity(buyer.opening.identity)
  await assert.rejects(other.decrypt(encrypted, 'text'))
})

test('an opening half needs a 32-byte secret', async () => {
  await assert.rejects(openingHalf(new Uint8Array(64)), /secret must be 32 bytes/)
})

// Service keys and access keys: random bytes, from no seed

/** A signing half by hand: the lowest 250 bits of the bytes read big-endian, times Base8 by zk-kit, packed by hand. */
const signingByHand = (bytes: Uint8Array) => {
  const scalar = bigEndian(bytes) % 2n ** 250n
  const point = times(scalar)
  return { scalar: scalar.toString(), publicKey: [point.x.toString(), point.y.toString()], address: pack(point.x, point.y) }
}
/** An opening half by hand: the 32 bytes as age's identity, and the hybrid public key they expand to. */
const openingByHand = (bytes: Uint8Array) => ({
  identity: bech32.encodeFromBytes('AGE-SECRET-KEY-PQ-', bytes).toUpperCase(),
  openKey: bech32.encode('age1pq', bech32.toWords(MLKEM768X25519.getPublicKey(bytes)), false),
})

test("a service key's scalar is the lowest 250 bits of its 32 bytes: the pinned key from 32 bytes of 0x2a, recomputed without the library", () => {
  const v = vectors.serviceKey
  const key = serviceKey(hex.decode(v.secret))
  assert.deepEqual({ scalar: key.scalar.toString(), publicKey: [key.publicKey[0].toString(), key.publicKey[1].toString()], address: key.address }, { scalar: v.scalar, publicKey: v.publicKey, address: v.address })
  assert.deepEqual(signingByHand(hex.decode(v.secret)), { scalar: v.scalar, publicKey: v.publicKey, address: v.address })
  // It signs as a main key does, and zk-kit's own check takes the signature.
  assert.equal(verifySignature(777n, signWithScalar(key.scalar, 777n), key.publicKey), true)
  assert.throws(() => serviceKey(new Uint8Array(31)), /32 bytes/)
  assert.throws(() => serviceKey(new Uint8Array(32)), /scalar/, 'bytes whose lowest 250 bits are 0 are no key')
})

test('an access key is its 64 bytes: the first 32 sign, the last 32 open, each recomputed without the library', async () => {
  const v = vectors.accessKey
  const bytes = hex.decode(v.secret)
  const key = await accessKey(bytes)
  assert.deepEqual([key.scalar.toString(), key.address, key.identity, key.openKey], [v.scalar, v.address, v.opening.identity, v.opening.openKey])
  assert.deepEqual(signingByHand(bytes.subarray(0, 32)), { scalar: v.scalar, publicKey: v.publicKey, address: v.address })
  assert.deepEqual(openingByHand(bytes.subarray(32)), v.opening)
  assert.equal(verifySignature(777n, signWithScalar(key.scalar, 777n), key.publicKey), true, "zk-kit's own check")
  await assert.rejects(accessKey(new Uint8Array(32)), /64 bytes/)
})

test('a new access key is fresh random bytes, from no seed; its halves are its own, and both open and sign', async () => {
  const one = await newAccessKey()
  const two = await newAccessKey()
  assert.equal(one.secret.length, 64)
  assert.notEqual(one.address, two.address)
  assert.deepEqual(await accessKey(one.secret), one, 'its 64 bytes give it back whole')
  // Nothing of one half comes from the other: change one, and only it changes.
  const signing = Uint8Array.from(one.secret)
  signing[0]! ^= 1
  const changed = await accessKey(signing)
  assert.deepEqual([changed.address !== one.address, changed.openKey === one.openKey], [true, true])
  const encrypter = new Encrypter()
  encrypter.addRecipient(one.openKey)
  const opener = new Decrypter()
  opener.addIdentity(one.identity)
  assert.equal(await opener.decrypt(await encrypter.encrypt('for the key'), 'text'), 'for the key')
  assert.equal(checkWithPublicKey(one.address, 5n, signWithScalar(one.scalar, 5n)), true)
})

// Pay keys

/** EIP-55 by hand: a hex letter is upper case where keccak256 of the lower-case hex has a digit of 8 or more. */
const eip55 = (lower: string) => {
  const hash = hex.encode(keccak_256(utf8(lower)))
  return '0x' + [...lower].map((c, i) => (parseInt(hash[i]!, 16) >= 8 ? c.toUpperCase() : c)).join('')
}
/** An EVM address by hand: node:crypto's secp256k1, keccak256 of the uncompressed key without its 04, the last 20 bytes. */
const evmByHand = (privateKey: Uint8Array) => {
  const ecdh = createECDH('secp256k1')
  ecdh.setPrivateKey(privateKey)
  const publicKey = ecdh.getPublicKey()
  return { publicKey: hex.encode(publicKey), address: eip55(hex.encode(keccak_256(publicKey.subarray(1)).subarray(12))) }
}

test('each label gives the pinned pay key on each chain, recomputed without the library: HKDF, then ed25519 and base58, or secp256k1, keccak and EIP-55', async () => {
  assert.deepEqual(PAY_CHAINS, ['solana', 'evm'])
  assert.deepEqual(vectors.payKeys.map((p: { label: string; chain: string }) => `${p.label} ${p.chain}`).sort(), ['tutoring/buyer evm', 'tutoring/buyer solana', 'tutoring/seller evm', 'tutoring/seller solana'])
  for (const expected of vectors.payKeys) {
    const key = await payKey(seed, expected.label, expected.chain)
    assert.deepEqual([key.label, key.chain, hex.encode(key.privateKey), key.address], [expected.label, expected.chain, expected.privateKey, expected.address])
    const privateKey = mix(seed, `forest/pay/${expected.chain}/${expected.label}`)
    assert.equal(hex.encode(privateKey), expected.privateKey)
    if (expected.chain === 'solana') {
      assert.equal(base58.encode(ed25519.getPublicKey(privateKey)), expected.address)
    } else {
      assert.deepEqual(evmByHand(privateKey), { publicKey: expected.publicKey, address: expected.address })
      assert.equal(hex.encode(key.publicKey), expected.publicKey)
      assert.equal(isEvmAddress(key.address), true)
    }
  }
  assert.deepEqual(await payAddresses(seed, seller.label), Object.fromEntries(vectors.payKeys.filter((p: { label: string }) => p.label === seller.label).map((p: { chain: string; address: string }) => [p.chain, p.address])))
  const addresses = vectors.payKeys.map((p: { address: string }) => p.address)
  assert.equal(new Set(addresses).size, 4)
  for (const p of vectors.payKeys) assert.ok(vectors.mainKeys.every((m: { address: string }) => m.address !== p.address))
  await assert.rejects(payKey(seed, 'tutoring/\ud800seller', 'solana'), /label must be text/)
  await assert.rejects(payKey(seed, 'tutoring/seller', 'bitcoin' as 'evm'), /pay chain/)
})

test("an EVM address: key 1's is the well-known one, and EIP-55's checksum is its one written form", () => {
  const one = new Uint8Array(32)
  one[31] = 1
  assert.equal(evmByHand(one).address, '0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf')
  assert.equal(evmAddressOf(Buffer.from(evmByHand(one).publicKey, 'hex')), '0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf')
  // EIP-55's own examples: all upper case, all lower case, and mixed, each its checksum form.
  const examples = [
    '0x52908400098527886E0F7030069857D2E4169EE7',
    '0x8617E340B3D01FA5F11F306F4090FD50E238070D',
    '0xde709f2102306220921060314715629080e2fb77',
    '0x27b1fdb04752bbc536007a920d24acb045561c26',
    '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed',
    '0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359',
    '0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB',
    '0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb',
  ]
  for (const address of examples) {
    assert.equal(eip55(address.slice(2).toLowerCase()), address, address)
    assert.equal(isEvmAddress(address), true, address)
  }
  // Any other spelling is refused: all lower or all upper case where the checksum mixes, one letter changed in case, or no 0x.
  const mixed = examples[4]!
  for (const other of [mixed.toLowerCase(), '0x' + mixed.slice(2).toUpperCase(), mixed.replace('a', 'A'), mixed.slice(2), mixed + '0', mixed.slice(0, -1), '0X' + mixed.slice(2), 7]) {
    assert.equal(isEvmAddress(other), false, String(other))
  }
})

// Stamp numbers

test('each verifier gives the pinned name hash and stamp number, and gives them again', () => {
  for (const expected of vectors.verifiers) {
    for (let round = 0; round < 2; round++) {
      assert.equal(nameHashOf(expected.name).toString(), expected.nameHash)
      assert.equal(stampNumberOf(seedNumber(seed), expected.name).toString(), expected.stampNumber)
    }
  }
})

test('the name hash and the stamp number, recomputed without the library: keccak of its text, Poseidon with the seed', () => {
  for (const expected of vectors.verifiers) {
    const nameHash = field('forest/verifier/' + expected.name)
    assert.equal(nameHash.toString(), expected.nameHash)
    assert.equal(poseidon2([S, nameHash]).toString(), expected.stampNumber)
    assert.equal(stampNumberOf(S, expected.name), poseidon2([S, nameHash]))
  }
})

test('two verifiers, two unrelated stamp numbers; and none of it is a key', () => {
  assert.notEqual(verifierA.stampNumber, verifierB.stampNumber)
  const all = [verifierA.stampNumber, verifierB.stampNumber, ...vectors.mainKeys.flatMap((p: { raw: string; scalar: string }) => [p.raw, p.scalar]), vectors.seedNumber]
  assert.equal(new Set(all).size, all.length)
})

test("the name is used exactly, and must be text; the seed's number is a field element", () => {
  const names = new Set<string>()
  for (const name of ['verifier-a.example', 'Verifier-A.example', 'verifier-a.example ', '']) {
    names.add(stampNumberOf(S, name).toString())
  }
  assert.equal(names.size, 4)
  for (const name of ['verifier-\ud800a.example', 7, undefined]) {
    assert.throws(() => stampNumberOf(S, name as string), /verifier name must be text/, String(name))
  }
  assert.throws(() => stampNumberOf(-1n, verifierA.name), /field element/)
  assert.throws(() => stampNumberOf(BN254_R, verifierA.name), /field element/)
})

// Signing bytes

test('bytes are signed as SHA-256 of them, shifted right one byte', () => {
  const bytes = new TextEncoder().encode('{"root":"1","time":2}')
  const digest = BigInt('0x' + createHash('sha256').update(bytes).digest('hex')) >> 8n
  assert.equal(bytesMessage(bytes), digest)
  assert.ok(digest < BN254_R)
  const scalar = BigInt(seller.scalar)
  const sig = signBytes(scalar, bytes)
  assert.deepEqual(sig, signWithScalar(scalar, digest))
  assert.equal(checkBytes(seller.address, bytes, sig), true)
  assert.equal(verifySignature(digest, sig, big(seller.publicKey)), true, "zk-kit's own check")
  const other = bytes.slice()
  other[0]! ^= 1
  assert.equal(checkBytes(seller.address, other, sig), false)
})
