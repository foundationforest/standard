// The signers vectors. The profile is keys/'s tutoring/seller, from its test seed, with its inbox
// key and permission key, pinned in keys/test/vectors.json and not repeated here. The connection's
// key is 32 bytes of 0x2b; Ed25519 is deterministic, so its signatures never change unless the
// standard does. The permission's body is pinned as made, since age's encryption is random. `node
// test/vectors.ts` prints them; vectors.test.ts checks them against test/vectors.json, each with a
// second implementation.

import { pathToFileURL } from 'node:url'
import { type SignedRecord, b64u, canonical, hex, ownerRecord, recordId, signingInput, unsignedOf } from '@foundationforest/records'
import { connectionOf, loginInput, registerInput, signLogin, signRegister } from '../src/connect.ts'
import { PERMISSION_PREFIX, permissionId } from '../src/permissions.ts'
import { alice } from './fixtures.ts'

const TIME = 1_790_000_000_000 // 2026-09-21T13:33:20Z
export const CONNECTOR = 'https://connector.example'
/** The connection: its key, 32 bytes of 0x2b, and its id, the public key. */
export const CONNECTION = connectionOf(b64u.encode(new Uint8Array(32).fill(0x2b)))
/** A login request as a connector might make one: base64url of its JSON, a dot, then its own part. */
export const REQUEST = `${b64u.encode(new TextEncoder().encode(JSON.stringify({ name: 'My assistant', redirect: 'https://ai.example/back' })))}.the-connector-s-own`
/** A socket's challenge: 32 bytes of 0x07. */
export const CHALLENGE = b64u.encode(new Uint8Array(32).fill(0x07))
/** The permission vector: that connection may read and write as tutoring/seller, and pay $25 a day. */
export const PERMISSION = { who: { connector: CONNECTOR, connection: CONNECTION.connection, key: CONNECTION.key, name: 'My assistant' }, can: ['read', 'write'], limit: { amount: '25', currency: 'USD', per: 'day' } }

/**
 * The permission vector's body: PERMISSION encrypted to tutoring/seller's own inbox key alone, made
 * once with makePrivate, and pinned as made.
 */
const ENCRYPTED = [
  'YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0-IG1sa2VtNzY4eDI1NTE5IG5JTUp2dGszTXltaHdNMGlSdGNjZDdDNE1YTVBXd1ZG',
  'UWdibGROemRvSzBMZmNRWWY1c1lkR2FqNyttT3pUTUJmTVRDSDV5c3RTTGFRWnhoOS84SXlwQmsxd0kyWnlhTTRwcXRZY0oz',
  'c0dUNUZudkl1K21ZU01xc3hMbDR3MTAwcGVUTTZWaWFENWgvSzdVQ3BrMS9QMHFKdC9UUmpwVVJwTnM4OXgxWkFmVlB6anVu',
  'MW1hc1pBbmFqVTBpNkZUSkZvQThVeDZUUUZLZ2c3MHA3ZmVGOTVtRDg3Z1k3U1dsTE9GdEFMRG9hNEVwQVB1ckVFOGhHSEZq',
  'ZHhlb1NiajZER1JCK0tuYWlzRmFTTldaQzl5aDJtbWpRaU5MNmFYV3R1ejFJZmJMaCtlcVV6cUs3MUhTd2UyQUx6cWFteUlv',
  'Y01KSEFDZGgyUXpBdDBVOTAreE9LaW5CVmdIV2VGYWdweVUwMGlvTVh3NHhLaGxpK2VFMFhmV2V5L1NsSjhVMFRqNnY3NGFM',
  'S2FtZ2wrbkYzeUh3TG1VV2ZoZTg3MDBsbTdsb0pGRXRELy82SjhYdlVtNjlHRWIyK0IvYnJMcTBQSEJNb2wrdGxMZ0FUUTRz',
  'aEFZNEd1SWRrT3hYTmJQMUhKYWF4TmtSclhidTBBUU5DNkc0SEU1T3ZObkczYkpINW1lbndMNngyTDNqWHg5ODMrcnBpbzRk',
  'SVY5eVl6RkE2QklaRElQKy9pcndOSEFwWlFqNkE1YURsUjE2ZXRRTnZMZ0NYN3FPbGVsOGd1YnQ4dmNNSmZJMWlnbXNjeGVt',
  'Qm0wcldPNzF1R2xkYUZMVUpIOUZlTWVNSW5raEpXZ2p3N0ZsV3Q0Z1BtRGMxOFkrR2FwenQ3L051eldDRjlTTXNXNFpLb0hK',
  'MXZPc0RMZzhmSytXYVRBbGhVQXdTL0Y2N2dDeGNERW5ZR08xV1hEdVRXM0pOVWs5N2cweWo5MDJIRk90VTJuL0JLcGNIcmpm',
  'R0Qwb0tuUFZEM09hWk4wb3g4d3NYRUpkQm5mYitmQ3NEdkpXb042QURVbjR2RXdvaDVpQkJQaE9pSk5wcitvNFozNXVYQkp3',
  'eDFOaWwzR3VpZFU2cUxadytQRFhGbU9DVTdnNkxWcFFzbTB6OEdwUXBSeVNndy9wYVpVS0lQWTVzcjkvdzJtQ1YxMklYSHJP',
  'ZWFlc05aa21WSDdKcnpHcjZQams4SWx2dzVKOGUySTIrUU50a21MRFlIZE1QNGtGSWRMbHhaS21keEJhNldrQXFHS0tRVk44',
  'UEpoblpjOEFOMW9UcHlXV1VmWS9qUGdlYjE1R01xUjNHMWh2Y0l1KzZ0UkEzQnlHc2hKUVAzNjhEK2h4dUZ0QjBkNkx3R2hF',
  'RUJ1QW5QSHdsWXh3VHR1YzBEVTBrcXVLbTYwS1c4dzBYb1dCOHVQSk9sQVNvUUFvdkQ2VjVZQW9hU2hUWVZQODZrbTRKVkp6',
  'UVIyejFENytOSzNUdE5ETXBMTDhENzA5Nm0wVnBDeHFZUzE0bGZFbWQ0d0FJTE0vUWJ6dXNQZG1jUEZwOWU3dldOK2REWUEx',
  'SlgwL3ZDVHVBM0RlYU5DTFRVKzRTQ2FURk5OdkFXZlRvSzlaS2s0TUk1SDNVT2hHWlRia3B4R1VoRmtnd0tXUDg4dE9MYktW',
  'SGZLZ3ppSVBkcVZYSklyelF2ckovOG1Oa2JkVUxKRm12MlN6QkYrSlNyWFhpVFdWaVR2NHBZb3lyNzdtWTk5SS94QXBubEcw',
  'Ukt2dHV5Zkt5cHJldlYxalNtc2htUWxzclRpWllsUFVDNmwvTkg4dXgxSnBMRWJaSWZkWUJCVysxbFJHWi9mTEdVY05NcWt2',
  'VlhlS2RmbkJkTEJqZlVPN0FmSmErdVJmUzdSWHJZT2k0TEJkVW04elI1aEZaaDI1VmNIRmRDcDhoMWh6eUc0T0xjMVVsc202',
  'VDhTU2l3NWNzMy9ZR2o5cXJMUEhkQQpxZ20vb0lEdithYmczMHQ5d3pUdGkzNlZ1WU50bzRzbWo2UFhaemlzMEFBCi0tLSA3',
  'blQ5R2VLSUd0aWtwVHNIVFlSSkJVbXd5YStYNUpnYTFSNTJIUWtxK0RJCl-BzTNA0SdcE87I5POgULyDOnBX9gxbUhWmPX-e',
  'sj0Sv3gOLuJV-64guZ_lu7iZ_w69zpXLa1UGZ1b_KokvxyGl5hc1BijU5ZlYWQyz5SA0aXxl4g3oIr_D2MN7FPj86Z72Sidj',
  'KzJdkfqsE8sLAYq2qrMG4mlUJJYbDfdDsZgfwf12kM8LsHLFR8Nv0Iq09yLB8EzH-LxQxK09F_oP3_YvM9j-vG-eYKTGUSCG',
  'jjboRluRaVIdy7C6NQzx5oJx73Ni-Rh9_Fi1FE26Yaj9k0R_pVtyWKXtaQZYQ12jvkkaA42XtFTU5LmxTTEMAhbRSvb-SUiJ',
  '8zZP0kDi1ZNvl8FHhzEpm2Reu4nN0b2KdndLo8YQcELHH7wQX0EWbETPIWsq',
].join('')

const describe = (record: SignedRecord) => ({
  wire: canonical(record),
  signingInputHex: hex.encode(signingInput(unsignedOf(record))),
  id: recordId(unsignedOf(record)),
})

export async function vectors() {
  return {
    about: "Forest signers vectors. connection is a connection's key, 32 bytes of 0x2b, and its id, the Ed25519 public key, each in base64url. login is its signature on a login request, over 0xff, forest/v1/login and a newline, then the request; register is its signature to register on a socket, over 0xff, forest/v1/register and a newline, the connector's origin, a newline, then the challenge. permission is one of keys/'s tutoring/seller profile's permissions, for that connection: its path's id is keyed by the profile's permission key, pinned in keys/test/vectors.json, and its body is encrypted to the profile's own inbox key alone, made once and pinned as made.",
    connection: CONNECTION,
    login: { request: REQUEST, signingInputHex: hex.encode(loginInput(REQUEST)), sig: signLogin(CONNECTION.key, REQUEST) },
    register: { connector: CONNECTOR, challenge: CHALLENGE, signingInputHex: hex.encode(registerInput(CONNECTOR, CHALLENGE)), sig: signRegister(CONNECTION.key, CONNECTOR, CHALLENGE) },
    permission: describe(ownerRecord(alice, PERMISSION_PREFIX + (await permissionId(alice, PERMISSION.who)), { private: ENCRYPTED }, TIME)),
  }
}

if (import.meta.url === pathToFileURL(process.argv[1]!).href) console.log(JSON.stringify(await vectors(), null, 2))
