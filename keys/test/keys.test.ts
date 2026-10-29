import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { hkdf as nobleHkdf } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { createECDH, createHash, createPublicKey, verify as nodeVerify } from 'node:crypto'
import { keccak_256 } from '@noble/hashes/sha3.js'
import { blake512 } from '@noble/hashes/blake1.js'
import { base58, bech32, hex } from '@scure/base'
import { ed25519 } from '@noble/curves/ed25519.js'
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { MLKEM768X25519 } from '@noble/post-quantum/hybrid.js'
import { Decrypter, Encrypter } from 'age-encryption'
import { Base8, addPoint, inCurve, mulPointEscalar, packPoint as zkPack, subOrder } from '@zk-kit/baby-jubjub'
import { derivePublicKey, packSignature as zkPackSignature, signMessage as zkSign, verifySignature } from '@zk-kit/eddsa-poseidon'
import { poseidon1 } from 'poseidon-lite/poseidon1'
import { poseidon3 } from 'poseidon-lite/poseidon3'
import { poseidon5 } from 'poseidon-lite/poseidon5'
import {
  BN254_R,
  INFO,
  PAY_TYPES,
  PREFIX,
  SEED_LENGTH,
  WORD_COUNT,
  addressOf,
  bytesMessage,
  checkPaySig,
  evmAddressOf,
  exportWords,
  fieldHash,
  hkdf,
  importWords,
  inboxKey,
  isEvmAddress,
  verifierScalarOf,
  verifierSecret,
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
  seedScalar,
  serviceKey,
  signPay,
  signWithScalar,
  unpackPoint,
  unpackSignature,
  checkBytes,
  checkWithPublicKey,
  type Point,
} from '../src/index.ts'

const vectors = JSON.parse(readFileSync(new URL('./vectors.json', import.meta.url), 'utf8'))
const seed = hex.decode(vectors.seed)
const otherSeed = new Uint8Array(32).fill(7)
const [seller, buyer] = vectors.mainKeys
const [verifierA, verifierB] = vectors.verifiers
const S = BigInt(vectors.seedScalar.scalar)
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
const base64urlDecode = (text: string) => new Uint8Array(Buffer.from(text, 'base64url'))

// The mixing table

test('the info strings and the prefixes are exactly the standard', () => {
  assert.equal(INFO.seed, 'forest/v1/seed')
  assert.equal(INFO.profile('tutoring/seller'), 'forest/v1/profile/tutoring/seller')
  assert.equal(INFO.inbox, 'forest/v1/inbox')
  assert.equal(INFO.pay('solana', 'tutoring/seller'), 'forest/v1/pay/solana/tutoring/seller')
  assert.equal(INFO.pay('evm', 'tutoring/seller'), 'forest/v1/pay/evm/tutoring/seller')
  assert.equal(INFO.permission, 'forest/v1/permission')
  assert.equal(INFO.seed, vectors.seedScalar.info)
  for (const p of vectors.mainKeys) assert.equal(INFO.profile(p.label), p.info)
  for (const p of vectors.payKeys) assert.equal(INFO.pay(p.type, p.label), p.info)
  for (const [name, prefix] of Object.entries(vectors.prefixes) as [keyof typeof PREFIX, { text: string; value: string }][]) {
    assert.equal(PREFIX[name], field(prefix.text), name)
    assert.equal(PREFIX[name].toString(), prefix.value, name)
  }
})

test('HKDF agrees with an independent implementation', async () => {
  for (const info of [INFO.seed, INFO.profile('tutoring/seller'), INFO.profile(''), INFO.inbox, INFO.pay('solana', 'tutoring/seller'), INFO.pay('evm', 'tutoring/seller'), INFO.permission]) {
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
    const scope = field('forest/v1/label/' + expected.label)
    assert.equal(scope.toString(), expected.scope)
    assert.equal(scopeOf(expected.label), scope)
    const raw = poseidon3([PREFIX.profile, S, scope])
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
  for (const type of PAY_TYPES) assert.notEqual((await payKey(seed, 'tutoring/seller', type)).address, (await payKey(otherSeed, 'tutoring/seller', type)).address)
  assert.notEqual((await verifierSecret(seed, verifierA.name)).stampNumber, (await verifierSecret(otherSeed, verifierA.name)).stampNumber)
})

test('a main key needs a 32-byte seed and a label that is text', async () => {
  await assert.rejects(mainKey(seed.subarray(0, 16), 'tutoring/seller'), /seed must be 32 bytes/)
  await assert.rejects(mainKey(seed, 'tutoring/\ud800seller'), /label must be text/)
  await assert.rejects(mainKey(seed, 7 as unknown as string), /label must be text/)
  assert.throws(() => profileScalarOf(BN254_R, 'tutoring/seller'), /field element/)
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

test('the nonce, byte by byte: SHA-512 of the 15 bytes of forest/v1/nonce as they are, then the scalar and the message, each 32 bytes little-endian; read little-endian, mod l', () => {
  const v = vectors.signature
  const le32 = (n: bigint) => Buffer.from(n.toString(16).padStart(64, '0'), 'hex').reverse()
  const input = Buffer.concat([Buffer.from('forest/v1/nonce'), le32(BigInt(seller.scalar)), le32(BigInt(v.message))])
  assert.equal(input.length, 79, 'no 0xff, no newline, no length')
  const digest = createHash('sha512').update(input).digest()
  const r = BigInt('0x' + Buffer.from(digest).reverse().toString('hex')) % subOrder
  assert.deepEqual(mulPointEscalar(Base8, r), big(v.R8))
})

test('fieldHash: keccak256 of the namespace and each part joined with nothing between, text as UTF-8 and bytes as they are, read big-endian, shifted right 8 bits', () => {
  assert.equal(fieldHash('forest/v1/label/', seller.label), field('forest/v1/label/' + seller.label))
  assert.equal(fieldHash('forest/v1/label/', 'tutoring/', 'seller'), BigInt(seller.scope), 'parts are joined, not hashed one by one')
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

// Inbox keys

test("each profile gives the pinned inbox key, from its secret, never from the main key's scalar", async () => {
  for (const expected of vectors.mainKeys) {
    const key = await mainKey(seed, expected.label)
    const { privateKey, ...inbox } = expected.inbox
    assert.deepEqual(await inboxKey(key.secret), inbox)
    assert.equal(hex.encode(await hkdf(key.secret, INFO.inbox)), privateKey)
  }
})

test("the inbox key, recomputed without the library: HKDF twice, ML-KEM-768 with X25519, age's bech32", () => {
  const privateKey = mix(mix(seed, seller.info), INFO.inbox)
  assert.equal(hex.encode(privateKey), seller.inbox.privateKey)
  assert.equal(bech32.encodeFromBytes('AGE-SECRET-KEY-PQ-', privateKey).toUpperCase(), seller.inbox.identity)
  // What others encrypt to is the hybrid public key the 32 bytes expand to, in bech32 under age1pq,
  // with no length limit: it is about 1,960 characters.
  const publicKey = MLKEM768X25519.getPublicKey(privateKey)
  assert.equal(bech32.encode('age1pq', bech32.toWords(publicKey), false), seller.inbox.encryptTo)
  assert.match(seller.inbox.identity, /^AGE-SECRET-KEY-PQ-1[0-9A-Z]+$/)
  assert.match(seller.inbox.encryptTo, /^age1pq1[0-9a-z]+$/)
})

test('age encrypts to the inbox key, and only that profile opens it', async () => {
  const encrypter = new Encrypter()
  encrypter.addRecipient(seller.inbox.encryptTo)
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

// Permission keys

test("each profile gives the pinned permission key: HKDF of its secret, by an independent implementation", async () => {
  for (const expected of vectors.mainKeys) {
    const key = await mainKey(seed, expected.label)
    assert.equal(hex.encode(await hkdf(key.secret, INFO.permission)), expected.permissionKey)
    assert.equal(hex.encode(mix(mix(seed, expected.info), 'forest/v1/permission')), expected.permissionKey)
  }
  assert.notEqual(seller.permissionKey, buyer.permissionKey)
  assert.notEqual(seller.permissionKey, seller.inbox.privateKey)
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

test('each label gives the pinned pay key of each type, recomputed without the library: HKDF, then ed25519 and base58, or secp256k1, keccak and EIP-55', async () => {
  assert.deepEqual(PAY_TYPES, ['solana', 'evm'])
  assert.deepEqual(vectors.payKeys.map((p: { label: string; type: string }) => `${p.label} ${p.type}`).sort(), ['tutoring/buyer evm', 'tutoring/buyer solana', 'tutoring/seller evm', 'tutoring/seller solana'])
  for (const expected of vectors.payKeys) {
    const key = await payKey(seed, expected.label, expected.type)
    assert.deepEqual([key.label, key.type, hex.encode(key.privateKey), key.address], [expected.label, expected.type, expected.privateKey, expected.address])
    const privateKey = mix(seed, expected.info)
    assert.equal(hex.encode(privateKey), expected.privateKey)
    if (expected.type === 'solana') {
      assert.equal(base58.encode(ed25519.getPublicKey(privateKey)), expected.address)
    } else {
      assert.deepEqual(evmByHand(privateKey), { publicKey: expected.publicKey, address: expected.address })
      assert.equal(hex.encode(key.publicKey), expected.publicKey)
      assert.equal(isEvmAddress(key.address), true)
    }
  }
  assert.deepEqual(await payAddresses(seed, seller.label), Object.fromEntries(vectors.payKeys.filter((p: { label: string }) => p.label === seller.label).map((p: { type: string; address: string }) => [p.type, p.address])))
  const addresses = vectors.payKeys.map((p: { address: string }) => p.address)
  assert.equal(new Set(addresses).size, 4)
  for (const p of vectors.payKeys) assert.ok(vectors.mainKeys.every((m: { address: string }) => m.address !== p.address))
  await assert.rejects(payKey(seed, 'tutoring/\ud800seller', 'solana'), /label must be text/)
  await assert.rejects(payKey(seed, 'tutoring/seller', 'bitcoin' as 'evm'), /pay type/)
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

// Pay signatures

/** What a pay key signs, by hand: 0xff, then "forest/v1/pay\n" and the profile's address in UTF-8. */
const payBytes = (address: string) => new Uint8Array([0xff, ...utf8('forest/v1/pay\n' + address)])
const addressOfLabel = (label: string) => vectors.mainKeys.find((m: { label: string }) => m.label === label).address
const N = secp256k1.Point.CURVE().n
const modN = (v: bigint) => ((v % N) + N) % N
/** a^(n-2) mod n: an inverse mod the prime n. */
const invN = (a: bigint) => {
  let out = 1n
  for (let b = modN(a), e = N - 2n; e > 0n; e >>= 1n, b = (b * b) % N) if (e & 1n) out = (out * b) % N
  return out
}
/** The key an EVM pay signature (r || s || recovery id) recovers, by hand: Q = r^-1 (s R - z G). */
const recoverByHand = (bytes: Uint8Array, sig: Uint8Array) => {
  const r = BigInt('0x' + hex.encode(sig.subarray(0, 32)))
  const s = BigInt('0x' + hex.encode(sig.subarray(32, 64)))
  const z = BigInt('0x' + hex.encode(keccak_256(bytes)))
  const R = secp256k1.Point.fromHex((sig[64]! & 1 ? '03' : '02') + hex.encode(sig.subarray(0, 32)))
  const Q = R.multiply(modN(s)).subtract(secp256k1.Point.BASE.multiply(modN(z))).multiply(invN(r))
  return hex.encode(Q.toBytes(false))
}

test("each pay key's pinned signature over its profile's address, made again and checked without the library: Ed25519 by node:crypto, the EVM key recovered by hand", async () => {
  for (const expected of vectors.payKeys) {
    const profile = addressOfLabel(expected.label)
    const key = await payKey(seed, expected.label, expected.type)
    assert.equal(signPay(key, profile), expected.paySig, 'deterministic, and pinned')
    assert.equal(checkPaySig(expected.type, expected.address, profile, expected.paySig), true)
    const sig = base64urlDecode(expected.paySig)
    if (expected.type === 'solana') {
      assert.equal(sig.length, 64)
      const publicKey = createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(base58.decode(expected.address)).toString('base64url') }, format: 'jwk' })
      assert.equal(nodeVerify(null, payBytes(profile), publicKey, sig), true)
    } else {
      assert.equal(sig.length, 65)
      assert.ok(sig[64]! < 4, 'the recovery id is last, as Ethereum writes it')
      assert.equal(recoverByHand(payBytes(profile), sig), expected.publicKey)
    }
  }
})

test('a pay signature holds for its own address, type and profile only, in its one spelling', async () => {
  for (const expected of vectors.payKeys) {
    const profile = addressOfLabel(expected.label)
    const other = vectors.mainKeys.find((m: { label: string }) => m.label !== expected.label).address
    const otherType = expected.type === 'solana' ? 'evm' : 'solana'
    const sameTypeOther = vectors.payKeys.find((p: { type: string; label: string }) => p.type === expected.type && p.label !== expected.label)
    const sig = base64urlDecode(expected.paySig)
    const flipped = sig.slice()
    flipped[10]! ^= 1
    for (const [what, ok] of [
      ['another profile', checkPaySig(expected.type, expected.address, other, expected.paySig)],
      ['another type', checkPaySig(otherType, expected.address, profile, expected.paySig)],
      ['another pay address', checkPaySig(expected.type, sameTypeOther.address, profile, expected.paySig)],
      ['a byte changed', checkPaySig(expected.type, expected.address, profile, Buffer.from(flipped).toString('base64url'))],
      ['a byte short', checkPaySig(expected.type, expected.address, profile, Buffer.from(sig.subarray(1)).toString('base64url'))],
      ['padded', checkPaySig(expected.type, expected.address, profile, expected.paySig + '=')],
      ['not base64url', checkPaySig(expected.type, expected.address, profile, expected.paySig.replace(/.$/, '!'))],
    ] as const) assert.equal(ok, false, `${expected.type}: ${what}`)
  }
  const evm = vectors.payKeys.find((p: { type: string }) => p.type === 'evm')
  const lower = evm.address.toLowerCase()
  assert.equal(checkPaySig('evm', lower, addressOfLabel(evm.label), evm.paySig), false, 'an EVM address in any spelling but EIP-55')
  // The twin spelling, n - s with the other recovery id, recovers the same key: it is not refused,
  // since only the profile's main key puts a signature in its profile record.
  const sig = base64urlDecode(evm.paySig)
  const twin = new Uint8Array(65)
  twin.set(sig.subarray(0, 32))
  twin.set(hex.decode((N - BigInt('0x' + hex.encode(sig.subarray(32, 64)))).toString(16).padStart(64, '0')), 32)
  twin[64] = sig[64]! ^ 1
  assert.equal(checkPaySig('evm', evm.address, addressOfLabel(evm.label), Buffer.from(twin).toString('base64url')), true)
})

// Verifier secrets and stamp numbers

test('each verifier gives the pinned name hash, secret and stamp number, and gives them again', async () => {
  for (const expected of vectors.verifiers) {
    for (let round = 0; round < 2; round++) {
      const { name, nameHash, scalar, stampNumber } = await verifierSecret(seed, expected.name)
      assert.equal(name, expected.name)
      assert.equal(nameHash.toString(), expected.nameHash)
      assert.equal(scalar.toString(), expected.scalar)
      assert.equal(stampNumber.toString(), expected.stampNumber)
    }
  }
})

test('the verifier secret and the stamp number, recomputed without the library', () => {
  for (const expected of vectors.verifiers) {
    const nameHash = field('forest/v1/issuer/' + expected.name)
    assert.equal(nameHash.toString(), expected.nameHash)
    assert.equal(nameHashOf(expected.name), nameHash)
    const scalar = poseidon3([PREFIX.verifier, S, nameHash])
    assert.equal(scalar.toString(), expected.scalar)
    assert.equal(verifierScalarOf(S, expected.name), scalar)
    assert.equal(poseidon1([scalar]).toString(), expected.stampNumber)
  }
})

test('two verifiers, two unrelated stamp numbers; and none of it is a key', async () => {
  const a = await verifierSecret(seed, verifierA.name)
  const b = await verifierSecret(seed, verifierB.name)
  assert.notEqual(a.stampNumber, b.stampNumber)
  const all = [verifierA.scalar, verifierB.scalar, seller.scalar, buyer.scalar, vectors.seedScalar.scalar, seller.raw, buyer.raw]
  assert.equal(new Set(all).size, all.length)
})

test('the name is used exactly, and must be text; the seed is 32 bytes', async () => {
  const names = new Set<string>()
  for (const name of ['issuer-a.example', 'Issuer-A.example', 'issuer-a.example ', '']) {
    names.add((await verifierSecret(seed, name)).stampNumber.toString())
  }
  assert.equal(names.size, 4)
  for (const name of ['issuer-\ud800a.example', 7, undefined]) {
    await assert.rejects(verifierSecret(seed, name as string), /verifier name must be text/, String(name))
  }
  await assert.rejects(verifierSecret(seed.subarray(1), verifierA.name), /seed must be 32 bytes/)
  assert.throws(() => verifierScalarOf(-1n, verifierA.name), /field element/)
})

// Service keys, and signing bytes

test("a service key's 32 bytes are a zk-kit EdDSA-Poseidon private key: the pinned key, and zk-kit's own", () => {
  const v = vectors.serviceKey
  const key = serviceKey(hex.decode(v.secret))
  assert.equal(key.scalar.toString(), v.scalar)
  assert.equal(key.address, v.address)
  assert.deepEqual(key.publicKey, derivePublicKey(hex.decode(v.secret)), "zk-kit's public key for the same bytes")
  // zk-kit signs with the same bytes; the signature holds under the service key.
  const m = 777n
  assert.equal(checkWithPublicKey(key.address, m, zkSign(hex.decode(v.secret), m)), true)
  assert.throws(() => serviceKey(new Uint8Array(31)), /32 bytes/)
})

test('bytes are signed as SHA-256 of them, shifted right one byte', () => {
  const bytes = new TextEncoder().encode('forest/v1/record\nsome canonical text')
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
