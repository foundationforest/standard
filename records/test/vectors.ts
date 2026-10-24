// The spec's test vectors. The keys are keys/'s: its test seed (bytes 00 01 … 1f), and its
// tutoring/seller and tutoring/buyer profiles and their inbox keys, pinned in
// keys/test/vectors.json and not repeated here. EdDSA-Poseidon here is deterministic, and the
// encrypted body is pinned as made, so these never change unless the protocol does. `node
// test/vectors.ts` prints them; vectors.test.ts checks them against test/vectors.json, each with a
// second implementation.

import { pathToFileURL } from 'node:url'
import { sha256 } from '@noble/hashes/sha2.js'
import { hex } from '../src/bytes.ts'
import { canonical } from '../src/canonical.ts'
import { type SignedBlobRequest, type SignedMessage, type SignedPull, blobRequest, blobSigningInput, messageId, messageSigningInput, pullRequest, pullSigningInput, signMessage, unsignedMessageOf } from '../src/message.ts'
import { type SignedRecord, recordId, signingInput, unsignedOf } from '../src/record.ts'
import { hostsRecord, ownerRecord } from '../src/write.ts'
import { KEYS, alice, aliceBuyer } from './fixtures.ts'

const TIME = 1_790_000_000_000 // 2026-09-21T13:33:20Z

/**
 * The message vector's body: { text: 'Is Tuesday at six free?' } encrypted to tutoring/seller's
 * inbox key, made once with makePrivate. age's encryption is random, so it is pinned as made.
 */
const ENCRYPTED = [
  'YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0-IG1sa2VtNzY4eDI1NTE5IEI3dTNhYkpyVUdxRlYwc291dzZjclZ3TGFGTFpDbD',
  'Vyc0Y2MzNnZWpNYll0ZStHUU5kbElpOC9rcVBGc3ZLUEVwNHlLcGFHSzJrWlROS00weS8xY25RanNBYzgzYVdvL1FncVhB',
  'T09yaGpYNHN2aUhOME5RMTIwOUpVeU45WWdCZHVhRTBJZUF4TWdEcVlvdWk4MHd3NDJhSXNUVTVNRXFaTDFFbGhzNFUwcT',
  'NkM1BKU2pYWkFVOWxzcVFnMXUzai9mS0FzRzNZL0VOVnNVMk1tNlU2bFpBVW9GdXNhMngvSWhKR052WVdwOG4vYk1tK0RN',
  'UHU0R0xCNWFPenQycVlvSkIvYkMwS0s2TjdxQlFsUUxpcHVpOE9sUDJjL2FscTBHUHFESUhJSTRZU09GNUtsbEpBVE14Tk',
  'NVckJFZHl4SkxzUlJtY1dXYyt1amFROE1FUUJLSzNsbXZGWWQ2UHhNb3JPWEpUWkdCelFQTzdGTDVUUzIwK0ZTalBhMDFN',
  'NmxuZE5yVGdVVWdzcWF1NE9Ta1ZVQ2VJaTVTMS8yUVFObk1yeGd6OFVFVVoxMGYyWVpaVVFoTEdzSUlRNC9OZmhOQ0puYk',
  'NWcXQwWjBLZEdGQldHaUZOZm1ZbGdSajVmUzcvZUxXU3NRQnlXR0VQRXdRRUJIQUM2ZGxza3ZJRFlnM01HSFRXdE5IUmdI',
  'UDNzY0d0RWw5eWRlVGYxWjlUZHphZS9uQzE3OHhSajNFRWk5Q0FHNHVtWjlUUW1vT0Q1dXYxbldvc25LR0FZcUdaMDNjbU',
  'xkd3FZQUZXTStNMTlBcXJBQXdWdUh0eGh3KzJxU3RhTkI5V1dVQ1pEaFJrbFJDK3pMVFlHRTRkYUdvN2V1ZmJwZ0lMK1lk',
  'L3EybEYxMGNBWWhRcG9PeExtaEdvZDBacU5GS3VqQ21ObGYwRzFSZGlvVU1zKzlTV2RBK3BMSmJWNXpnYm11ditwOXEwaG',
  'sxQnFKa0J6U0licFlXb3lNZ0EzclRHTU9FVlJzamVaODBzMFdERmllMGRCUzE0NXVJYlZxTERnQ2cwaGtrSGNVNDh1aU1L',
  'ZndKb0RJRHNQT1Fnb21xbnJNYnJyUkZNRmNhWTdSaXlWd3RoVWIxWm95SjVuWWpZTTVMbldGRjRnMGw0Ly9udmQ2RklrSH',
  'lTRkoxK0xIM0JPaDBwVW5zanljS25mZkFOSitBelE0blJ2OHB4cW8zQktGUWN4THp3WEtsSjl6azJPbmZHcEI3Y3Y3OTZL',
  'dEtuNlUyYWRXd3RwclV1YnlZZzY4NDdPcVJSS0V5OUZKdVFyd25odWtBT2ZCZjJTQVhyRi9lQzZyMTF1eXNlMURsTlBZek',
  'FsbDI1VFd0UFp6aXd6ZW8wNFBvLytrd2JXMFBzMlloLzZwaWdQY0ZTakRsOWJSZHllcVI4L3M1Rklpa0x4YVZjTCtleHBl',
  'VVVrSVZHWDczUVhkZFJwQnlrVm1RQmxKWEFqZUJPUVFKNTg2SkpjRlY2OCs5Um1KeTRUOU9yTHRwaXkvMktNczNwOHVRSG',
  'FlenJ4WnFMTUZFSkNsUzh0ZGNLbkJJWWRWcHFNNXBBbUV0b3lwNWVIb0NtQTJVYlRUZWhCbzcvMmFpNUh2RkhMQlFWQnZ0',
  'WjhxTk5zbGdHM2U4MUZVMUE2bmZtT0V0a3ZubXBuZ0kzM2JHejA4NWdITjM3VHRDOU9USU9tL1hqNFduZ2FBdkE0MS9ibz',
  'RTdzdPY2haOEx4QkxVOCt5OEwxQnQ2YjhGaVJqSlJJT3dqSHp4QjBZRzZlNG5vaG5wd1RLT1ZZc1hYNFlnamFWWURsOEgr',
  'Sm9tanZtWktOamRTRGNua045TWx3bGJmdEMwS1BtNE16TndodkpnR0pWV2ptK21OU0Rrck9qcFhKb2hYUHZ0WmY3Rm1WWW',
  'RrYzZUOS8rTW9ySmlxYzhOK3plMXlMeGN6QU8zKzdxdUgrZlFMSUJxWUI4bG5odGhueDRLZwo4Nkg0Kzh3NEF1MHcxTmpz',
  'K1FVRFlKbUMxYllxQXRYamtRMHl0V0xSK2pNCi0tLSBLSXQwUlozL3ZYUytSTGxNWFMyeENoOTdTd3NsUVhkR3V5eWVXVk',
  'xQSUZrCkQ59KW40YZUOq13AHRl8zmLXO2etxcf4xfDi7B8vfc746Jwve4YP3SvBu4ryhirQ6RGvu7iVHaSL7O5DqLj04Ti',
  'RQ',
].join('')

const describe = (record: SignedRecord) => ({
  wire: canonical(record),
  signingInputHex: hex.encode(signingInput(unsignedOf(record))),
  id: recordId(unsignedOf(record)),
})

const describeMessage = (message: SignedMessage) => ({
  wire: canonical(message),
  signingInputHex: hex.encode(messageSigningInput(unsignedMessageOf(message))),
  id: messageId(unsignedMessageOf(message)),
})

const describePull = (pull: SignedPull) => {
  const { sig: _sig, ...unsigned } = pull
  return { wire: canonical(pull), signingInputHex: hex.encode(pullSigningInput(unsigned)) }
}

const describeBlob = (request: SignedBlobRequest) => {
  const { sig: _sig, ...unsigned } = request
  return { wire: canonical(request), signingInputHex: hex.encode(blobSigningInput(unsigned)) }
}

/** The blob vectors' bytes: the 26 letters, as text/plain. */
const LETTERS = new TextEncoder().encode('abcdefghijklmnopqrstuvwxyz')

export async function vectors() {
  const inbox = KEYS.mainKeys[0].inbox
  const hostA = 'https://host-a.example'
  // An offer's fields are its market's, and the standard names none (README.md, Folders): `about`
  // stands in for them.
  const offer = { about: 'One hour of maths, online.' }
  const letters = { sha256: hex.encode(sha256(LETTERS)), mimeType: 'text/plain', size: LETTERS.length }
  return {
    about: "Forest records vectors. The profile is keys/'s tutoring/seller profile, from its test seed, and the profile record's inboxKey field is that profile's inbox key, pinned in keys/test/vectors.json. Every signature is EdDSA-Poseidon on Baby Jubjub over SHA-256 of the signed bytes, shifted right one byte, by the main key of the profile it is for. The message is from keys/'s tutoring/buyer profile, from the same seed, to tutoring/seller; its body is encrypted to tutoring/seller's inbox key, made once and pinned as made, since age's encryption is random. The pull is tutoring/seller's, for everything. blobPut is tutoring/seller's main key putting the 26 letters a to z, as text/plain, in its folder; blobDelete is its main key deleting them.",
    profile: alice.address,
    hosts: describe(hostsRecord(alice, [hostA, 'https://host-b.example'], TIME)),
    profileRecord: describe(ownerRecord(alice, 'profile', { market: 'tutoring', role: 'seller', inboxKey: inbox.encryptTo, inbox: { senders: 'anyone' } }, TIME)),
    offer: describe(ownerRecord(alice, 'offer/maths', offer, TIME)),
    deleted: describe(ownerRecord(alice, 'offer/maths', null, TIME + 120_000)),
    message: describeMessage(signMessage(aliceBuyer, alice.address, { private: ENCRYPTED }, TIME + 180_000)),
    pull: describePull(pullRequest(alice, 0, TIME + 240_000)),
    blobPut: describeBlob(blobRequest(alice, { action: 'put', ...letters }, TIME + 480_000)),
    blobDelete: describeBlob(blobRequest(alice, { action: 'delete', sha256: letters.sha256 }, TIME + 540_000)),
  }
}

if (import.meta.url === pathToFileURL(process.argv[1]!).href) console.log(JSON.stringify(await vectors(), null, 2))
