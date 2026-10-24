// The vault: what a new device needs and the seed alone cannot give back, kept on hosts in a folder
// of the person's own (README.md, The vault). The folder's main key is keys/'s vault key, mixed from
// the seed, so a new device finds the vault with the seed and one host's address. The folder holds
// its hosts record and one private record at `vault`, encrypted to the vault's own inbox key alone
// (vaultRecord and openVault in private.ts). Inside: the labels of the person's profiles and where
// each lives, their verifiers' stamps, the person's permissions, and apps' settings.
//
// An app keeps every field it does not know, at the top and inside `settings`, so two apps, or an
// older and a newer one, share one vault without erasing each other's. A permission keeps its
// unknown fields and values too, and a signer acts on none it does not know whole
// (knowsPermission): it asks the person.

import type { Json } from './canonical.ts'
import { publicKeyFromAddress } from './keys.ts'
import { MAX_HOSTS, RecordError, normalizeOrigin } from './record.ts'

/** The fixed path of the vault's one private record, in the vault's own folder. */
export const VAULT_PATH = 'vault'

/** One of the person's profiles: its label, and the hosts its folder lived on when written. */
export type VaultProfile = { label: string; hosts: string[] }

/** A verifier's stamp: the verifier's name, as keys/'s recipe takes it, and the signed stamp, as JSON (proofs/stamp/client's stampToJson). */
export type VerifierStamp = { verifier: string; stamp: { [key: string]: Json } }

/**
 * What a permission lets its who ask a signer to do: these four, and nothing more. `post` writes any
 * record, whatever its kind, but never a profile's profile record, its hosts record or the vault: for
 * those a signer always asks the person (README.md, Permissions). An action outside the four is kept,
 * as any value this code does not know, and a signer acts on no entry that has one (knowsPermission).
 */
export const ACTIONS = ['post', 'message', 'read', 'pay'] as const
export type Action = (typeof ACTIONS)[number]
/** The currencies a limit is counted in. */
export const CURRENCIES = ['USD'] as const
/** A limit's periods, in milliseconds: a day is any 24 hours, a week any 7 days, a month any 30 days. */
export const PERIODS = { day: 86_400_000, week: 7 * 86_400_000, month: 30 * 86_400_000 } as const

/**
 * Who a permission is for: a connection, named by the address of the connector it comes through (an
 * origin, as a hosts record spells one) and the id the signer gave it, with what the person calls it;
 * or a profile, by its address, which asks by messages its main key signs.
 */
export type Who = { connector: string; connection: string; name?: string } | { profile: string }

/** How much a who may pay, in one currency, in any one period: on one profile the entry covers, or across all it covers. */
export type Limit = { amount: string; currency: string; per: string; profile?: string }

/**
 * One permission: who may ask the person's signers to act, for which of the person's profiles (by
 * label, or all), to do what, how much it may pay, and until when (ms). `can` and `currency` and
 * `per` take values the standard does not name, kept as they are; so does every object, for fields.
 */
export type Permission = { who: Who; profiles: 'all' | string[]; can: string[]; limits?: Limit[]; until?: number }

export type Vault = {
  /** The person's profiles, each label once. */
  profiles?: VaultProfile[]
  stamps?: VerifierStamp[]
  /** The person's permissions: what others may ask their signers to do. */
  permissions?: Permission[]
  /** Apps' settings: any fields, each an app's own. */
  settings?: { [key: string]: Json }
  /** Fields an app does not know: kept as they are. */
  [field: string]: Json | VaultProfile[] | VerifierStamp[] | Permission[] | undefined
}

function fail(message: string): never {
  throw new RecordError('vault', message)
}

const isObject = (v: unknown): v is { [key: string]: unknown } => v !== null && typeof v === 'object' && !Array.isArray(v)

/** A vault's shape: the fields above as they say, any other field kept as it is. Throws RecordError with code `vault`. */
export function checkVault(value: unknown): asserts value is Vault {
  if (!isObject(value)) fail('a vault is an object')
  if ('profiles' in value) {
    if (!Array.isArray(value.profiles)) fail('profiles is a list')
    const labels = new Set<string>()
    for (const p of value.profiles as unknown[]) {
      if (!isObject(p)) fail('a profile is an object')
      for (const key of Object.keys(p)) if (key !== 'label' && key !== 'hosts') fail(`unknown profile field ${key}`)
      if (typeof p.label !== 'string') fail('a label is text')
      if (labels.has(p.label)) fail(`the label ${p.label} twice`)
      labels.add(p.label)
      const hosts = p.hosts
      if (!Array.isArray(hosts) || hosts.length < 1 || hosts.length > MAX_HOSTS) fail(`hosts is 1 to ${MAX_HOSTS} origins`)
      for (const h of hosts as unknown[]) if (typeof h !== 'string' || normalizeOrigin(h) !== h) fail('each host is an origin, as a hosts record writes it')
      if (new Set(hosts).size !== hosts.length) fail('hosts repeat')
    }
  }
  if ('stamps' in value) {
    if (!Array.isArray(value.stamps)) fail('stamps is a list')
    for (const n of value.stamps as unknown[]) {
      if (!isObject(n)) fail('a stamp is an object')
      for (const key of Object.keys(n)) if (key !== 'verifier' && key !== 'stamp') fail(`unknown stamp field ${key}`)
      if (typeof n.verifier !== 'string' || !n.verifier) fail("a stamp names its verifier, by the name keys/'s recipe takes")
      if (!isObject(n.stamp)) fail('a stamp is an object')
    }
  }
  if ('permissions' in value) {
    if (!Array.isArray(value.permissions)) fail('permissions is a list')
    const whos = new Set<string>()
    for (const p of value.permissions as unknown[]) {
      const who = checkPermission(p)
      if (who === null) continue
      if (whos.has(who)) fail('one who twice in the permissions')
      whos.add(who)
    }
  }
  if ('settings' in value && !isObject(value.settings)) fail('settings is an object')
}

/** A decimal amount: a whole number, then up to six places. */
const AMOUNT = /^(0|[1-9][0-9]*)(\.[0-9]{1,6})?$/

/**
 * One permission's known fields as they say. Returns who it is for, as one text, so a vault lists
 * each who once; null for a kind of who this code does not know, which it cannot tell twice.
 */
function checkPermission(p: unknown): string | null {
  if (!isObject(p)) fail('a permission is an object')
  const { who, profiles, can, limits, until } = p
  if (!isObject(who)) fail('who is an object')
  let named: string | null = null
  if ('connector' in who || 'connection' in who) {
    if ('profile' in who) fail('who is a connection or a profile, not both')
    if (typeof who.connector !== 'string' || normalizeOrigin(who.connector) !== who.connector) fail('a connector is an origin, as a hosts record writes it')
    if (typeof who.connection !== 'string' || !who.connection) fail('a connection is the id its signer gave it: text')
    if ('name' in who && typeof who.name !== 'string') fail('a name is text')
    named = `connection ${who.connector} ${who.connection}`
  } else if ('profile' in who) {
    if (!publicKeyFromAddress(who.profile)) fail('a profile is an address')
    named = `profile ${who.profile as string}`
  }
  if (profiles !== 'all' && (!Array.isArray(profiles) || profiles.some((l) => typeof l !== 'string'))) fail('profiles is all, or a list of labels')
  const covers = (label: string) => profiles === 'all' || (profiles as string[]).includes(label)
  if (!Array.isArray(can) || can.some((a) => typeof a !== 'string')) fail('can is a list of actions')
  if ('limits' in p) {
    if (!Array.isArray(limits)) fail('limits is a list')
    for (const l of limits as unknown[]) {
      if (!isObject(l)) fail('a limit is an object')
      if (typeof l.amount !== 'string' || !AMOUNT.test(l.amount)) fail('an amount is decimal text, up to 6 places')
      if (typeof l.currency !== 'string') fail('a currency is text')
      if (typeof l.per !== 'string') fail('per is a period: day, week or month')
      if ('profile' in l && (typeof l.profile !== 'string' || !covers(l.profile))) fail('a limit on one profile names a label its permission covers')
    }
  }
  if ('until' in p && (!Number.isSafeInteger(until) || (until as number) < 0)) fail('until is a time, ms since 1970')
  return named
}

const known = (value: { [key: string]: unknown }, fields: string[]) => Object.keys(value).every((key) => fields.includes(key))

/**
 * Whether this code knows a permission whole: every field at every level, every action, the
 * currency and the period of every limit, and the kind of who. A signer acts on no permission it
 * does not know whole: it asks the person, since what it skipped could be a limit.
 */
export function knowsPermission(p: Permission): boolean {
  const who = p.who as { [key: string]: unknown }
  const connection = 'connector' in who
  if (!known(p, ['who', 'profiles', 'can', 'limits', 'until'])) return false
  if (!(connection ? known(who, ['connector', 'connection', 'name']) : 'profile' in who && known(who, ['profile']))) return false
  if (!p.can.every((a) => (ACTIONS as readonly string[]).includes(a))) return false
  return (p.limits ?? []).every((l) => known(l, ['amount', 'currency', 'per', 'profile']) && (CURRENCIES as readonly string[]).includes(l.currency) && Object.hasOwn(PERIODS, l.per))
}
