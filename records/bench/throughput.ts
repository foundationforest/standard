// How fast the pieces are, on this machine. One core, Node, pure-JavaScript crypto (noble's curve
// arithmetic with Baby Jubjub's numbers, poseidon-lite).
// Run: node bench/throughput.ts

import { cpus } from 'node:os'
import { verifySignature as zkVerify } from '@zk-kit/eddsa-poseidon'
import { accessKey, bytesMessage, unpackSignature } from '@foundationforest/keys'
import { b64u } from '../src/bytes.ts'
import { canonical } from '../src/canonical.ts'
import { Host } from '../src/host.ts'
import { checkRecord, decodeRecord, encodeRecord, signingInput, unsignedOf, verifySignature } from '../src/record.ts'
import { viewProfile } from '../src/view.ts'
import { ownerRecord } from '../src/write.ts'

// An offer about the size of a short one. Its fields are its market's; `about` stands in for them.
const offer = {
  about: 'One hour of maths tutoring, online, for secondary school students preparing for exams. Thirty a session, paid in a dollar on Solana; evenings and weekends.',
}

function rate(label: string, n: number, run: (i: number) => void): number {
  for (let i = 0; i < Math.min(50, n); i++) run(i) // warm up
  const start = performance.now()
  for (let i = 0; i < n; i++) run(i)
  const perSecond = n / ((performance.now() - start) / 1000)
  console.log(`${label.padEnd(58)} ${Math.round(perSecond).toLocaleString('en-US').padStart(10)} /s`)
  return perSecond
}

const key = accessKey(new Uint8Array(32).fill(5))
const record = ownerRecord(key, 'offer/maths', offer, 1_790_000_000_000)
const wire = encodeRecord(record)
const message = signingInput(unsignedOf(record))
const sig = b64u.decode(record.sig)
console.log(`machine: ${cpus()[0]?.model ?? 'unknown'}, node ${process.version}; one offer record is ${wire.length} bytes on the wire`)

rate('canonical text of a record', 20_000, () => canonical(record))
rate('sign a record (EdDSA-Poseidon on Baby Jubjub)', 1_000, (i) => ownerRecord(key, 'offer/maths', offer, 1_790_000_000_000 + i))
rate('verify, Forest strict (key in the subgroup, R8 on curve)', 1_000, () => verifySignature(sig, message, key.address))
const signature = unpackSignature(sig)!
const hm = bytesMessage(message)
rate('verify, zk-kit (@zk-kit/eddsa-poseidon), for comparison', 10, () => zkVerify(hm, signature, key.publicKey))
rate('read one record off the wire (parse, canonical, strict verify)', 1_000, () => decodeRecord(wire))

// A host taking records: 500 profiles, a profile record and 4 offers each, in batches of 100.
const host = new Host({ now: () => 1_790_000_000_000 })
const lines: string[] = []
for (let p = 0; p < 500; p++) {
  const k = accessKey(new Uint8Array(32).map((_, j) => (p * 13 + j * 7 + 1) & 255))
  lines.push(encodeRecord(ownerRecord(k, 'profile', { market: 'tutoring', role: 'seller' }, 1_790_000_000_000)))
  for (let o = 0; o < 4; o++) lines.push(encodeRecord(ownerRecord(k, `offer/${o}`, offer, 1_790_000_000_000 + o)))
}
let start = performance.now()
for (let i = 0; i < lines.length; i += 100) await host.accept(lines.slice(i, i + 100))
const ingest = lines.length / ((performance.now() - start) / 1000)
console.log(`${'host: check and store, a file per folder, 2,500 records'.padEnd(58)} ${Math.round(ingest).toLocaleString('en-US').padStart(10)} /s`)

start = performance.now()
let served = 0
for (let after = 0; ; ) {
  const page = host.read({ after })
  if (!page.lines.length) break
  served += page.lines.length
  after = page.cursor
}
const read = served / ((performance.now() - start) / 1000)
console.log(`${'host: serve everything, pages of 1,000'.padEnd(58)} ${Math.round(read).toLocaleString('en-US').padStart(10)} /s`)

// The view of a busy profile: 1,000 records.
const busy = Array.from({ length: 1000 }, (_, i) => checkRecord(ownerRecord(key, `offer/${i % 200}`, offer, 1_790_000_000_000 + i)))
rate('the view of a profile of 1,000 records', 200, () => viewProfile(key.address, busy, 1_790_000_000_000 + 10_000))
await host.close()
