// The spec's test vectors. The keys are keys/'s: its test seed (bytes 00 01 … 1f), its
// tutoring/seller and tutoring/buyer profiles and their inbox keys, and its write key and read key
// (32 bytes of 0x2a and of 0x2b), pinned in keys/test/vectors.json and not repeated here.
// EdDSA-Poseidon here is deterministic, and the two sealed bodies are pinned as made, so these
// never change unless the protocol does.
// `node test/vectors.ts` prints them; vectors.test.ts checks them against test/vectors.json, each
// with a second implementation.

import { sha256 } from '@noble/hashes/sha2.js'
import { hex } from '../src/bytes.ts'
import { canonical } from '../src/canonical.ts'
import { type SignedBlobRequest, type SignedMessage, type SignedPull, blobRequest, blobSigningInput, messageId, messageSigningInput, pullRequest, pullSigningInput, signMessage, unsignedMessageOf } from '../src/message.ts'
import { type SignedRecord, recordId, signingInput, unsignedOf } from '../src/record.ts'
import { accessRecord, hostsRecord, ownerRecord, permissionsRecord } from '../src/write.ts'
import { KEYS, accessKey, alice, aliceBuyer, reader } from './fixtures.ts'

const TIME = 1_790_000_000_000 // 2026-09-21T13:33:20Z

/**
 * The message vector's body: { text: 'Is Tuesday at six free?' } sealed to tutoring/seller's inbox
 * key, made once with makePrivate. age's sealing is random, so it is pinned as made.
 */
const SEALED = [
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

/** The write key's message's body: { text: 'Tuesday at six, yes.' } sealed to tutoring/buyer's inbox key, pinned as made. */
const SEALED_TO_BUYER = [
  'YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0-IG1sa2VtNzY4eDI1NTE5IEFRcW1uVXJVMGRGbDNFa1U5dFEvQ3Nwc1VHazZjbm',
  'ZKWThoenVwaERJWGhjNHg4eUp2SFFMSUZMYU04UkF0cmxEeHluK1JucXpTa055WjhoMEhkdkdKZzBrYzRXaGdWengyUzlU',
  'cU1Qd3Fva0tqWjFOM3ZsNGdOUU5Vby93amRLS1VtcjljdTcvUEl3UDdKbWZlVjVWQVVpYXRCamttbFNyOXZkOWRJand6OW',
  'hlaVdOTitqR3BaeFZlbzZMKzdSeDRpSE15WGc3Vm9MV29PWG5CaWNjbEFlUEs4RWhZWllCWTVlcFFWbHRVd3duRldSUi9h',
  'bk94ZjJ2UXBVbUsxREVYQVRyd0cxakY0d0dkeDBHOEFIWmRzdTBBYUpXa2ZWWjN5dElXQ3NYdUFFUFVlMHdGWXMwRk45Yl',
  'NKTW9ManJJMWFldzZ2K0prSlVzZ3NjOFBHeVpMQ2w1aGYzeDBiczhLY3NsNXJlZXJ5R3RHMndTZWxpQlZwcmc5WUdUMnFI',
  'Skg3NmhHbFFvK2FiWEw1N0JubDByNmJNL2lPVFZodDViMEppYitlaHZ2aVBZU2QwQXk1dDBtOFRnaGNOMHMzWC9EZkQ4bW',
  '9ZN2hTUjhtMmdaVEcycGdCaTY2Z3JWeFlMOHNZZE03b1BrUEhpNUNZRzJwVDlEWGlDeGZ5SFZSTjlnbk5OeU8vZGFDbHJE',
  'Nk5YQkZHRWlnZW1SeVZ6a1MzcDlGNzVTeUc2cEFIcHU2dWhXSzhHVTF4dWNuSEtLd1E3a3RuSmJBWUpkM3lHU2RNRkRySD',
  'dnQ28vbVdzb2dtKy9CcGxrcHZLQThlalNDeUFkcHN3M1B4VXdYTlZEQ29mYVhrZmszQkZFMUtSR0VwdzdXQnBNcnlPRVUv',
  'N0dnRmEvTVVFM3pyYjJ5T0NmWk0wWTdjWUpRZGgwcHB2TDBJVm5CMzR3NFNLN3ZBYW9NcmtadGtjM2J0aGoxRXcvNnNPTE',
  'xCMngrMUhMQW9TVVNnYVpKQzQ1bDd1dWlxUGJNckViQ2VUdnZjSC95QnVxbEJNd2xEQm41R0FjRnBrN0VEdlJmamJHbmVH',
  'L09FSG8vcUpnR3BBeURONEZGQTRQamhLVlRzWVNoSFgrckpHVGpLaUpQdit2R3RNM0hmNnRNS0wzaSs5RHNLd1RXN1BQWE',
  'tKbnRSeHFWc1JIUjNXWGFsVFNtYlJuS29YWGNMOGlEYStrQXpFbEI4M1JDVkRwVE82dUhDekRIczN0M1oycWxaNjFjUHFp',
  'dmpoWVBYT0JjVzQ3dnU2NkdDVEJDVlVuNzVETnExRDdTL05zcWthRXQ5NzRwdklJblRnNGNQcmtBNnhLMG00d3BiakVGOX',
  'U2bHUwM0ZLeG93emtybGxMY0lVUTF6Q0J4WXVyQ1hXYWRJUFdEYUI1eXpHSEgwSGJvVDdXVSttK3djd3hWdlhJTjdEUFZR',
  'YVlpNmN1eS9ndVpPbS90bW5Pb1RNNG1FNHRGam5qb1ozZGxLNTZXMlFGbkpjcUlzK3UzaWsxT3FGRTJnYk0wQnY0REJobE',
  'gvQ3F5dlkrZDJTYmg3YklmRWIvK3RxZERoYTRFcExHMWRVRWwxaCttcDRRbjJhVi9FelFpUFdlUHhpWGpFZE82MnJ2VHdH',
  'aytDRGVPbXRITVBwWEFVZWZ6ZVAxb0xsd05HcGVMTE1WYTNTSWhOQTZWZ0R6ZHR4cEl3a3JPeFZYdjFWZ2dCcmlLU1NUZk',
  'g2STVWWWFoYWNGR0JBOFpaeGFWWkNreDQ1cHQ3U0UxWUd4eEcvYnVQbGNBVmk3eERia2VvK2ZzOWxTWWwvYjhkS0wrVktH',
  'dVR5cDJUNEhzeFAxUnIyOTZrMVVnVVhvaUlWK0JZelhmdVErOE1OcVV1Q2xBdWpyc3NQMVhiY1BvNk44ek5sTzUwWjJ6WW',
  'N4NG4xanFJYlJvTmYwUkw4Rnpub2h2SDQ3WU9LV3Fhb0VuaUFvSnlUK2N3cVVyRTJuRTVEUQpRU1diblMwaTM4QytNYzYw',
  'Q1RvOXhtN2IxdlNvcmlaSmZ5VVlrVldvelBjCi0tLSA4UGx2NUhpM293Uzk1NTZDbE1oUnNFUUx2UHc3amVvUXY4dGgyOW',
  'MvQjI4CkcSB58dBpLiX1WC0cSQNQeiwvMGC-RVmxav39sQseES0F348pulJO9mfwlrjvAPYJPsXYjXVajlEr0PaNvkLQ',
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
  const written = { about: 'Physics, one hour.' }
  const letters = { sha256: hex.encode(sha256(LETTERS)), mimeType: 'text/plain', size: LETTERS.length }
  const writeEntry = { key: accessKey.address, scope: 'write' as const, paths: ['offer', 'inbox'] }
  const readEntry = { key: reader.address, sealTo: reader.sealTo, scope: 'read' as const, paths: ['inbox'] }
  return {
    about: "Forest records vectors. The profile is keys/'s tutoring/seller profile, from its test seed, and the profile record's inboxKey field is that profile's inbox key; the write key and the read key are keys/'s, from 32 bytes of 0x2a and of 0x2b: all pinned in keys/test/vectors.json. Every signature is EdDSA-Poseidon on Baby Jubjub over SHA-256 of the signed bytes, shifted right one byte. The permissions record lists the write key for offers and the inbox, and the read key, with sealTo, for the inbox. The message is from keys/'s tutoring/buyer profile, from the same seed, to tutoring/seller; its body is sealed to tutoring/seller's inbox key. keyMessage is from tutoring/seller, signed by its write key and naming host-a, to tutoring/buyer; its body is sealed to tutoring/buyer's inbox key. Both bodies were made once and are pinned as made, since age's sealing is random. The pull is tutoring/seller's, for everything; keyPull is the same pull signed by its read key. past is a later permissions record in which the write key is past and the read key still listed. blobPut is tutoring/seller's main key putting the 26 letters a to z, as text/plain, in its folder; blobDelete is its write key deleting them.",
    profile: alice.address,
    writeKey: accessKey.address,
    readKey: reader.address,
    hosts: describe(hostsRecord(alice, [hostA, 'https://host-b.example'], TIME)),
    profileRecord: describe(ownerRecord(alice, 'profile', { market: 'tutoring', role: 'seller', inboxKey: inbox.sealTo, inbox: { senders: 'anyone' } }, TIME)),
    offer: describe(ownerRecord(alice, 'offer/maths', offer, TIME)),
    permissions: describe(permissionsRecord(alice, [writeEntry, readEntry], TIME)),
    written: describe(accessRecord(accessKey, alice.address, 'offer/physics', written, TIME + 60_000)),
    deleted: describe(ownerRecord(alice, 'offer/maths', null, TIME + 120_000)),
    message: describeMessage(signMessage(aliceBuyer, alice.address, { private: SEALED }, TIME + 180_000)),
    keyMessage: describeMessage(signMessage({ key: accessKey, from: alice.address, host: hostA }, aliceBuyer.address, { private: SEALED_TO_BUYER }, TIME + 300_000)),
    pull: describePull(pullRequest(alice, 0, TIME + 240_000)),
    keyPull: describePull(pullRequest({ key: reader, profile: alice.address }, 0, TIME + 360_000)),
    past: describe(permissionsRecord(alice, [{ key: accessKey.address, was: 'write', paths: ['offer', 'inbox'] }, readEntry], TIME + 420_000)),
    blobPut: describeBlob(blobRequest(alice, { action: 'put', ...letters }, TIME + 480_000)),
    blobDelete: describeBlob(blobRequest({ key: accessKey, profile: alice.address }, { action: 'delete', sha256: letters.sha256 }, TIME + 540_000)),
  }
}

if (import.meta.url === `file://${process.argv[1]}`) console.log(JSON.stringify(await vectors(), null, 2))
