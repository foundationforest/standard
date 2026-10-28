// A profile's permissions: who may ask the person's signers to act as this profile, and for what
// (README.md, Permissions). Each is one private record at `permission/<id>` in the profile's own
// folder, encrypted to its own inbox key alone, so any of the person's signers reads it with the
// seed and no one else learns what it says.
//
// An app keeps every field and value it does not know, and acts on no permission it does not know
// whole (knowsPermission): it asks the person, since what it skipped could be a limit.

import { INFO, hkdf, inboxKey } from '@foundationforest/keys'
import { type Body, type Json, type Key, RecordError, type SignedRecord, type View, canonical, hex, normalizeOrigin, ownerRecord, publicKeyFromAddress } from '@foundationforest/records'
import { makePrivate, openPrivate } from '@foundationforest/records/private'
import { hmac } from '@noble/hashes/hmac.js'
import { sha256 } from '@noble/hashes/sha2.js'
import type { Ask } from './asks.ts'

/** Where a profile's permissions sit in its folder: `permission/<id>`. */
export const PERMISSION_PREFIX = 'permission/'

/**
 * What a permission lets its who ask for without the person's yes: these three, and nothing more.
 * `write` never covers the profile record, the hosts record or a permission (isOwnPath). An action
 * outside the three is kept, as any value this code does not know, and an app acts on no
 * permission that has one (knowsPermission).
 */
export const ACTIONS = ['read', 'write', 'pay'] as const
export type Action = (typeof ACTIONS)[number]
/** A limit's periods, in milliseconds: a day is any 24 hours, a week any 7 days, a month any 30 days. */
export const PERIODS = { day: 86_400_000, week: 7 * 86_400_000, month: 30 * 86_400_000 } as const

/**
 * Who a permission is for. A connection, how an AI app reaches a signer: the origin of the connector
 * it comes through (as a hosts record spells one) and its id; `key`, the connection's private key,
 * kept so any of the person's signers can serve it; and `name`, what the person calls it. Or a
 * profile, by its address: a person or a business, asking by messages its main key signs.
 */
export type Who = { connector: string; connection: string; key?: string; name?: string } | { profile: string }

/** How much the who may pay as this profile, in one currency, in any one period. */
export type Limit = { amount: string; currency: string; per: string }

/**
 * One permission: who, what it can ask for without the person's yes, how much it may pay, and until
 * when (ms). `can`, `currency` and `per` take values the standard does not name, kept as they are;
 * so does every object, for fields.
 */
export type Permission = { who: Who; can: string[]; limit?: Limit; until?: number }

/** A profile's main key, as keys/'s mainKey gives it: with the profile's secret, which its inbox key and permission key come from. */
export type ProfileKey = Key & { secret: Uint8Array }

function fail(message: string): never {
  throw new RecordError('permission', message)
}

const isObject = (v: unknown): v is { [key: string]: unknown } => v !== null && typeof v === 'object' && !Array.isArray(v)

/** A decimal amount: a whole number, then up to six places. */
export const AMOUNT = /^(0|[1-9][0-9]*)(\.[0-9]{1,6})?$/
const B64U = /^[A-Za-z0-9_-]+$/

/** A permission's known fields as they say; any other field is kept as it is. Throws RecordError with code `permission`. */
export function checkPermission(value: unknown): asserts value is Permission {
  if (!isObject(value)) fail('a permission is an object')
  const { who, can, limit, until } = value
  if (!isObject(who)) fail('who is an object')
  if ('connector' in who || 'connection' in who) {
    if ('profile' in who) fail('who is a connection or a profile, not both')
    if (typeof who.connector !== 'string' || normalizeOrigin(who.connector) !== who.connector) fail('a connector is an origin, as a hosts record writes it')
    if (typeof who.connection !== 'string' || !who.connection) fail('a connection is its id: text')
    if ('key' in who && (typeof who.key !== 'string' || !B64U.test(who.key))) fail('a connection’s key is base64url')
    if ('name' in who && typeof who.name !== 'string') fail('a name is text')
  } else if ('profile' in who && !publicKeyFromAddress(who.profile)) fail('a profile is an address')
  if (!Array.isArray(can) || can.some((a) => typeof a !== 'string')) fail('can is a list of actions')
  if ('limit' in value) {
    if (!isObject(limit)) fail('a limit is an object')
    if (typeof limit.amount !== 'string' || !AMOUNT.test(limit.amount)) fail('an amount is decimal text, up to 6 places')
    if (typeof limit.currency !== 'string' || !limit.currency) fail('a currency is a code, as text')
    if (typeof limit.per !== 'string') fail('per is a period: day, week or month')
  }
  if ('until' in value && (!Number.isSafeInteger(until) || (until as number) < 0)) fail('until is a time, ms since 1970')
}

const known = (value: object, fields: string[]) => Object.keys(value).every((key) => fields.includes(key))

/**
 * Whether an app knows a permission whole: every field at every level, every action, the limit's
 * period, the kind of who, and the limit's currency among `currencies`, those the app pays in. An
 * app acts on no permission it does not know whole: it asks the person, since what it skipped
 * could be a limit.
 */
export function knowsPermission(permission: Permission, currencies: Iterable<string>): boolean {
  const who = permission.who as { [key: string]: unknown }
  if (!known(permission, ['who', 'can', 'limit', 'until'])) return false
  if (!('connector' in who ? known(who, ['connector', 'connection', 'key', 'name']) : 'profile' in who && known(who, ['profile']))) return false
  if (!permission.can.every((a) => (ACTIONS as readonly string[]).includes(a))) return false
  const limit = permission.limit
  return limit === undefined || (known(limit, ['amount', 'currency', 'per']) && [...currencies].includes(limit.currency) && Object.hasOwn(PERIODS, limit.per))
}

/** The paths no permission covers, which a write always asks the person for: the profile record, the hosts record and a permission. */
export function isOwnPath(path: string): boolean {
  return path === 'profile' || path === 'hosts' || path.split('/')[0] === PERMISSION_PREFIX.slice(0, -1)
}

/** Decimal text, up to six places, as whole millionths. */
function micros(amount: string): bigint {
  const [whole, part = ''] = amount.split('.')
  return BigInt(whole!) * 1_000_000n + BigInt(part.padEnd(6, '0'))
}

/**
 * Whether `permission`, on the profile an ask is for, lets the app do the ask without asking the
 * person, at `now`: a permission it knows whole, not ended, whose `can` covers the ask. A read with
 * nothing named needs no action. A write never covers the profile record, the hosts record or a
 * permission. A pay is within the limit only in its currency, with `spent`, what this who already
 * paid as this profile in that currency over the limit's period up to now, which the app counts.
 */
export function allows(permission: Permission, ask: Ask, options: { now: number; currencies: Iterable<string>; spent?: string }): boolean {
  if (!knowsPermission(permission, options.currencies)) return false
  if (permission.until !== undefined && options.now > permission.until) return false
  if (ask.ask === 'read') return ask.label === undefined || permission.can.includes('read')
  if (ask.ask === 'write') return permission.can.includes('write') && ('to' in ask || !isOwnPath(ask.path))
  if (!permission.can.includes('pay')) return false
  const limit = permission.limit
  return limit === undefined || (ask.currency === limit.currency && micros(options.spent ?? '0') + micros(ask.amount) <= micros(limit.amount))
}

/**
 * A permission's id, the last segment of its path: the first 32 hex characters of HMAC-SHA256,
 * keyed by the profile's permission key (keys/'s `hkdf(secret, INFO.permission)`), of the canonical
 * text of `who` without `key` and `name`. So one who has one permission per profile, whatever the
 * person calls it; and since only the person's signers hold the permission key, a path names no
 * who, and one who's permissions on two profiles never share a path.
 */
export async function permissionId(owner: { secret: Uint8Array }, who: Who): Promise<string> {
  const { key: _key, name: _name, ...named } = who as { [field: string]: Json }
  return hex.encode(hmac(sha256, await hkdf(owner.secret, INFO.permission), new TextEncoder().encode(canonical(named)))).slice(0, 32)
}

/**
 * A permission's record: the permission, checked, encrypted to the profile's own inbox key alone,
 * at `permission/<id>` in its folder, signed by its main key. Write it at a time past the current
 * one's at that path (records' nextTime). A null body at the same path removes the permission.
 */
export async function permissionRecord(owner: ProfileKey, permission: Permission, time: number): Promise<SignedRecord> {
  checkPermission(permission)
  const { encryptTo } = await inboxKey(owner.secret)
  return ownerRecord(owner, PERMISSION_PREFIX + (await permissionId(owner, permission.who)), await makePrivate(permission as unknown as Body, [encryptTo]), time)
}

/**
 * A profile's permissions, by id, from its view (records' readProfile, read by POST), opened with
 * its inbox key. One that does not open, does not check, or sits at a path its who does not give is
 * left out: a permission an app cannot read is none, so it asks the person, as for any ask none
 * covers. An app reads them before it acts on any ask for the profile, so one removed on another
 * device stops here too.
 */
export async function readPermissions(view: View, owner: { secret: Uint8Array }): Promise<Map<string, Permission>> {
  const { identity } = await inboxKey(owner.secret)
  const permissions = new Map<string, Permission>()
  for (const [path, { record }] of view.current) {
    if (!path.startsWith(PERMISSION_PREFIX) || record.body === null) continue
    const id = path.slice(PERMISSION_PREFIX.length)
    try {
      const permission = await openPrivate(record.body, identity)
      checkPermission(permission)
      if ((await permissionId(owner, permission.who)) === id) permissions.set(id, permission)
    } catch {
      // Left out: none, so the app asks.
    }
  }
  return permissions
}
