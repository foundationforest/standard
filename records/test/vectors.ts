// The spec's test vectors. The keys are keys/'s: its test seed (bytes 00 01 … 1f), its
// tutoring/seller and tutoring/buyer profiles and their inbox keys, and its write key and read key
// (32 bytes of 0x2a and of 0x2b), pinned in keys/test/vectors.json and not repeated here.
// EdDSA-Poseidon here is deterministic, and the two sealed bodies are pinned as made, so these
// never change unless the protocol does.
// `node test/vectors.ts` prints them; vectors.test.ts checks them against test/vectors.json, each
// with a second implementation.

import { hex } from '../src/bytes.ts'
import { canonical } from '../src/canonical.ts'
import { type SignedMessage, type SignedPull, messageId, messageSigningInput, pullRequest, pullSigningInput, signMessage, unsignedMessageOf } from '../src/message.ts'
import { type SignedRecord, recordId, signingInput, unsignedOf } from '../src/record.ts'
import { accessRecord, hostsRecord, ownerRecord, permissionsRecord } from '../src/write.ts'
import { KEYS, accessKey, alice, aliceBuyer, reader } from './fixtures.ts'

const TIME = 1_790_000_000_000 // 2026-09-21T13:33:20Z

/**
 * The message vector's body: { text: 'Is Tuesday at six free?' } sealed to tutoring/seller's inbox
 * key, made once with makePrivate. age's sealing is random, so it is pinned as made.
 */
const SEALED = [
  'YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0-IG1sa2VtNzY4eDI1NTE5IHFjMGhpQWYycEVrbGhiVURpWHg4d0tGMUh6Q2Jo',
  'dnZhS3RYS2J0RXlqN0l3VTQzZTJiS1J1RVFIbFJXUElIK2xOWnlINC9FUnpNTm9ReWIxTHlEa0RKNzg1YXREL1J5aW5y',
  'R09Vajg5cGxUL3AvS2l6N3IzU2IxZ1E1aVFpVVN1OUh6NVEyWlVpbmRramlGNzVCZno1NU5pZEtKYm9GVjFsaTNhUmZn',
  'TFh2MTYyZTdxdldVK2U0UzRsWnBKTmZCbUpvOHNqV2JLeDUrTjNYTGxvMll3SThGaWxWVkVzOG8zRzZKQ21aOTdtN0xy',
  'WG9BbjI2cjhqV1Fyck80U0tuSE5JMFhLTmdpY2dkcTBuMlBYSk4wVDA5ZUtaUDEzaXhQVEZTdHBKWUQxS2E5OGRwNFRY',
  'KzBjUTh1aDV0NS9MRDYyRTJVK20xWnBJYjJjbmd5OHNLVVloNkNYMFRybytrUGNUUkhhTExERVVTd3BxMW83N2luL2Fq',
  'Q2FleXJaYXgvQWczM3FoZVlKa2hCVXR4SnFONnpSM0dmejNZMGRzMlZXUDArVEpmc2hlQjFFR3BEVTloK3BmQkhYSEFY',
  'YkhhbW9KTlg4OEtsNnIva0pwYmVudEN2R1c0Y0dZUVN1cExsK2pNU1VObjBVMFZQR1JwNkRSMld3ZEg2SnhtdExRM0Fv',
  'blMwSm5zT1QraFVsT1JJREJpdTdnUmR4UktQUkY2M2JOTUo2bkVjUGJLQjBjSVZORmlTQ2JJQ0pNWGUwSFBRV3hDZmtV',
  'cWdxS0owcjR6MWlqOENjbkZ1Vi9NSnUwTmVkWm1tSlBlaWRSajFjNGVUT0JvQmxlMXRnTVNqbVBIRjRFWS9zcWhXSm5t',
  'aTdRRzVwTnZmTmRxQkJyMkxQajJUUFUwWmthb3JISTlBSTFpcXBRS09ZR0NUWGpMMWdFNVhTTWNsY3RIdEQrY2ltTE16',
  'Ymhlcm12TWNaNDZPa0FZdXhaY0lqNmVsUVZlOGFsZFNsQ3pOcm9tMms1TW10a1BtR2txWWlwSDZhOEl1Q2hyakdxa0Vi',
  'bm95d2xwTVlYUStySDVDbHg2d09VQmNoR1hnU3BlalU4aE8wdy9hekM5V3BOeGRWQTNjemxzdjhzZXhPanN6QmhsenUz',
  'NHR3YjVuY05xWi9rZXZFcmlWaWNKUmlvL1g5blp0NlNJLzcxR09NOUZxR3cwWlBwdjI3SENtMk5BOTVBZjNBL1hoK01W',
  'a1E3WXp0VmNaRSs5UGsyOFVwM0xXdjh1YVBsY2NGSk52WVhvQVhvMU1wbDVUUlFXemg2d0hMaTJWY1FUWEtPSEpnUktj',
  'S0R2alpNOXVhcjg5UnBiVUE5WUpmNmlpRzZ3QXh1ajg0VVhUN2RtNlJiTU5acjBpWjFtRjZmZlpwRXJOalFWejd6Y3l6',
  'REp0Ukh3VkxQYk5GUVhGZi9rcm9CWmxwUERyZ3JYcHlmaWlhNGdKc0x5RHRDMFAzTUFINEtLeXU4UXJOQU1jaVBKdGdp',
  'ZnFZdlJ3czd2dGJrajNkeE84MDQ2R3paZVZtckZtQXhJemRURkpINnVtNGZmWHNFZzF0VHVMWXpBZm95K3JyS0JCM0xp',
  'SStSVDdwOERRd2FWQmswdE1hY2lYcTVaUG01WHY1dFBYT2Y2TTJvckkwbEhYNlFUU3pqWTZqYUt0QzJlcGdxYVBSYUlM',
  'ams3eXcvN2Z1Y3B4VTJVa29pQzhRQU9YWXNTd0Y0Mmd1SWdydGFhdU9LZjQ4clJNVGU0Z29TM1VITExIaVpzZUFGVUpD',
  'SkV2VjloZWxZTklzY0pvQXpmUVpmV1lBZ3FsVVJYaS9WWXJ1S2ptQlhyVU1iZUVuTTVJRUY4NEpyRzRiazNjOFVOdUZy',
  'QWk0RGg5SXRlZDVHTmNSN2M5NzJLeEwvR0xpb0hXVll0eS8xTnZxUVNpZFFDcFkveWNSR1BMc2lFYUxHaFhVY094Sk4y',
  'Qm1HSDNrNFFJc21WTUJBdwowblhnUXBiNFlzQkdGWkRNY2tyRk53UWdtM1lQQzdiSzNQVlZycTY1WDhVCi0tLSBrbUFV',
  'ZzdpL3FoUVRqdkNYNDU5RHVTTGs5Z3EraVFZRkJNaDZKYjVWVGYwCjdh51Myi8XWqVQVJjdnMT7-WF8RLy499VZ21449',
  'FPrTfPVvbgweNd-_g4Gd4X5ON7Rn4GL4ieIWKf5-eubguN49MQ',
].join('')

/** The write key's message's body: { text: 'Tuesday at six, yes.' } sealed to tutoring/buyer's inbox key, pinned as made. */
const SEALED_TO_BUYER = [
  'YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0-IG1sa2VtNzY4eDI1NTE5IHJvN1FtZ2gybHBxMXpSc0p0blVCdVQ0b0pwMENnSG',
  't2SENLd1V2SHY4RXNCM0QwL2lNQXl6SWN1S3dFaXBQbGphaWxiQS9wYmQwNks1anpTaHBzSmVoRXlKOHAxeGlqcmozT0Zk',
  'ZW9uTm1ZRThQcVpqWVhGU1JaclpPNm5oRlNGcW55SXl3SzJvdXltNEMvaVBYZEpsTmNyTStLcHJWQjlDY2tlZ2hKYUcrdU',
  '5aaTBOVnoySVBVZFdtNDRQNG1XaXdLdFBYN3JwVUtka1RaNXJNUTRxVHN0UE55NmJMNk5WUDdMZjd5bTJ2NHVGNjlIR0Rw',
  'VWdrK3p5bVh5WlpDS1BiYnZlUDNyOVRFQlRidmZ0UjYyTWhLZXZibHY1ZmFhak5qanZ5dXdTckQ1elNaSDRXdDluZ0hlb2',
  'pKQVNpT1JWcnptR1J4Ums4RnRWdFBUaUxnYy84UEFISUNBNXBqb0UxeDA3SDYxVkluajh3UHBzNTdCalF2RFRKTWE1cGpD',
  'ZEQ3M2JWdHF3Uk5nMldLYWYzRG1WanozbkFxcUVubk5iSm5HZkFHQ1Arb3plOUlZU0xja1d5d00wNmFLVC9xOXVRTTJnSz',
  'ErT1A2a25tMkpqR1FVQy92bEwzODFpYUpPRjFTZnBnUWtYVThlUGdSdlB2Z003Uk5ROTNveEpJWTRockl0TzlCU0xtekxR',
  'NEJrbktVVG1oN1dkM3hiSjFxaThWazVDSnlSREJDQ2ZSUWlSc1B0RTl5ZUJHTjkxU3laSlJmVkJGTktCL2FSR25ub1VyWU',
  'ZOdmVkTkNFdk1sVmdncDJmT244RU9tUWgyVXdGdWhtZDg4akhwazNMVFlBNDREWmlmL0U4SU16eTRJT05lVjI1MzRVWVp0',
  'T0FnWnpxdys2RFRoVmFjUUFDOWdOc1pjVnlaVWpkeXppMlpyV0NtblI4U1A3QUo2dUVDVFg3ZGhqS20yQksvNk5ZTHk5dV',
  'd2bDRLZGl4UFVOT0FNdjUzRmpPUHoxYkhhWEdGUE5COElac0h1cUJ0MnMxd2JkK0k5WXkxakZWTHIyN0NibzBLSFhIUCtV',
  'TlVoSllXVDZXRVVPUVhpYXBMdWtCQkVCV0JaWnN6UHBtWmI1WXFBM3VCbFRram5xaEE0SkhrQXhvNXZsNm8veEsvVmhNRV',
  'NIeFc4OFFKRVlhM29mb0pwMTRGWWR1elRlaGtEdktvckhiaTdEcnBPRGNiVGV6ZTh1RHZnYW85WlhQOStuaUZMZ1dKR29Q',
  'NnRKVEF1U0s0L2pqVmFBQXpXK1d4MnU3WEl6bEZRNkRoNk5MaU1ma3hnMWtMM1FnVzR2NUxIbFgvaFVXS1dQRG40K0c5Ym',
  '5mOENzZjFKbGtSTnY3VWp1cmRUWC9KbUtoVVB0REFGRXJEaUZWQjJVOUphakk1Y3oxZ2hEYnEwRVcwTnRBLzhsL3VHaXBX',
  'cDhTZFcwMXJURFRPWiswK3NSb1BHMkpwdlRrT0VhRGRtMWF6M2JUNHgxZ09aTXdEVnpPN1JzSDZYQ3FCdmU1V09pRHVycG',
  '8yeDlha0hnRkFSZ252d3ZaUnZLYXV3c3BiZEFoOVpLZURlaHNseENKTHk1NmhQaW9EMTNSUEJoQm54V2ZYbG41cU5scVVp',
  'dTU1UzBQaXAycENEM21NcXVYRWgrTWh3ZjRIYUJLZUlkQUpIdVB1SlZxU2VLaDF3WXh0OEk4Q0tjVGJwaWZlNEhXaHduZV',
  'p5b09BNmNTeFJwUGtJaFJQUDU3NDN2THUyTWVZNitXSVgxb2xOSVdhbkVIZnk2MFJZTzgxczNaakpXYTM1dGNPU0xzMkpG',
  'V1hmUFFRaUNxckUrSE9ONi9BSjhJdzEycVcwejljR3RFWWEzSUtPWXJteHBnckh0enNzOFA5SStDd21LYktZTy93d0kyNF',
  'dUMHllT2NmZlVqK1pMTE9DWW5HdFBJTVZvQ0paN3dvVnl0THR4Wjk4Z2VHWjRuSy9Vc05hQQpzYWJGekU1Q0JMUWExKy96',
  'anVBbVZXRXkvSU9NV0piUjkwZWYySFF4VG1ZCi0tLSBWQWcxbWtJRFJlVkYrWm9ZNzdlQk1FbHFTZFpyaWZVYjdDZTJ1YT',
  'lrZWlVCnK9JqGWN4Ek5Sg4rxookqabPpk0nEFoSWdCfHpY8s1_mvq0xiNgBa5gbdVw6RPNtrY3FRMMqNIMyG_xZ0vdAw',
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

export async function vectors() {
  const inbox = KEYS.mainKeys[0].inbox
  const hostA = 'https://host-a.example'
  const offer = { description: 'One hour of maths tutoring, online.', price: { amount: '30', mint: 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v', per: 'hour' }, createdAt: '2026-09-21T13:33:20Z' }
  const writeEntry = { key: accessKey.address, scope: 'write' as const, paths: ['offer', 'inbox'] }
  const readEntry = { key: reader.address, recipient: reader.recipient, scope: 'read' as const, paths: ['inbox'] }
  return {
    about: "Forest records vectors. The profile is keys/'s tutoring/seller profile, from its test seed, and the profile record's inboxKey field is that profile's inbox key; the write key and the read key are keys/'s, from 32 bytes of 0x2a and of 0x2b: all pinned in keys/test/vectors.json. Every signature is EdDSA-Poseidon on Baby Jubjub over SHA-256 of the signed bytes, shifted right one byte. The permissions record lists the write key for offers and the inbox, and the read key, with its recipient, for the inbox. The message is from keys/'s tutoring/buyer profile, from the same seed, to tutoring/seller; its body is sealed to tutoring/seller's inbox key. keyMessage is from tutoring/seller, signed by its write key and naming host-a, to tutoring/buyer; its body is sealed to tutoring/buyer's inbox key. Both bodies were made once and are pinned as made, since age's sealing is random. The pull is tutoring/seller's, for everything; keyPull is the same pull signed by its read key. past is a later permissions record in which the write key is past and the read key still listed.",
    profile: alice.address,
    writeKey: accessKey.address,
    readKey: reader.address,
    hosts: describe(hostsRecord(alice, [hostA, 'https://host-b.example'], TIME)),
    profileCard: describe(ownerRecord(alice, 'profile', { market: 'tutoring', role: 'seller', inboxKey: inbox.recipient, inbox: { senders: 'anyone' }, createdAt: '2026-09-21T13:33:20Z' }, TIME)),
    offer: describe(ownerRecord(alice, 'offer/maths', offer, TIME)),
    permissions: describe(permissionsRecord(alice, [writeEntry, readEntry], TIME)),
    written: describe(accessRecord(accessKey, alice.address, 'offer/physics', { description: 'Physics, one hour.', createdAt: '2026-09-21T13:34:20Z' }, TIME + 60_000)),
    deleted: describe(ownerRecord(alice, 'offer/maths', null, TIME + 120_000)),
    message: describeMessage(signMessage(aliceBuyer, alice.address, { private: SEALED }, TIME + 180_000)),
    keyMessage: describeMessage(signMessage({ key: accessKey, from: alice.address, host: hostA }, aliceBuyer.address, { private: SEALED_TO_BUYER }, TIME + 300_000)),
    pull: describePull(pullRequest(alice, 0, TIME + 240_000)),
    keyPull: describePull(pullRequest({ key: reader, profile: alice.address }, 0, TIME + 360_000)),
    past: describe(permissionsRecord(alice, [{ key: accessKey.address, was: 'write', paths: ['offer', 'inbox'] }, readEntry], TIME + 420_000)),
  }
}

if (import.meta.url === `file://${process.argv[1]}`) console.log(JSON.stringify(await vectors(), null, 2))
