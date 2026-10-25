// A profile's rules: who may ask the person's signers to act as this profile, and for what
// (README.md, Rules). Each rule is one private record at `rule/<id>` in the profile's own folder,
// encrypted to its own inbox key alone, so any of the person's signers reads it with the seed and
// no one else learns what it says. ruleId, ruleRecord and readRules need keys/ and age: they are in
// private.ts.
//
// An app keeps every field and value it does not know, and a signer acts on no rule it does not
// know whole (knowsRule): it asks the person, since what it skipped could be a limit.

import { publicKeyFromAddress } from './keys.ts'
import { RecordError, normalizeOrigin } from './record.ts'

/** Where a profile's rules sit in its folder: `rule/<id>`. */
export const RULE_PREFIX = 'rule/'

/**
 * What a rule lets its who ask a signer to do as the profile: these four, and nothing more. `post`
 * writes any record, whatever its kind, but never the profile record, the hosts record or a rule: for
 * those a signer always asks the person (README.md, Rules). An action outside the four is kept, as
 * any value this code does not know, and a signer acts on no rule that has one (knowsRule).
 */
export const ACTIONS = ['post', 'message', 'read', 'pay'] as const
export type Action = (typeof ACTIONS)[number]
/** The currencies a limit is counted in. */
export const CURRENCIES = ['USD'] as const
/** A limit's periods, in milliseconds: a day is any 24 hours, a week any 7 days, a month any 30 days. */
export const PERIODS = { day: 86_400_000, week: 7 * 86_400_000, month: 30 * 86_400_000 } as const

/**
 * Who a rule is for. A connection, how an AI app reaches a signer: the origin of the connector it
 * comes through (as a hosts record spells one) and the id the signer gave it; `key`, the
 * connection's own key, kept so any of the person's signers can serve it; and `name`, what the person
 * calls it. Or a profile, by its address: a person or a business, asking by messages its main key
 * signs.
 */
export type Who = { connector: string; connection: string; key?: string; name?: string } | { profile: string }

/** How much the who may pay as this profile, in one currency, in any one period. */
export type Limit = { amount: string; currency: string; per: string }

/**
 * One rule: who, what it can ask for, how much it may pay, and until when (ms). `can`, `currency` and
 * `per` take values the standard does not name, kept as they are; so does every object, for fields.
 */
export type Rule = { who: Who; can: string[]; limit?: Limit; until?: number }

function fail(message: string): never {
  throw new RecordError('rule', message)
}

const isObject = (v: unknown): v is { [key: string]: unknown } => v !== null && typeof v === 'object' && !Array.isArray(v)

/** A decimal amount: a whole number, then up to six places. */
const AMOUNT = /^(0|[1-9][0-9]*)(\.[0-9]{1,6})?$/
const B64U = /^[A-Za-z0-9_-]+$/

/** A rule's known fields as they say; any other field is kept as it is. Throws RecordError with code `rule`. */
export function checkRule(value: unknown): asserts value is Rule {
  if (!isObject(value)) fail('a rule is an object')
  const { who, can, limit, until } = value
  if (!isObject(who)) fail('who is an object')
  if ('connector' in who || 'connection' in who) {
    if ('profile' in who) fail('who is a connection or a profile, not both')
    if (typeof who.connector !== 'string' || normalizeOrigin(who.connector) !== who.connector) fail('a connector is an origin, as a hosts record writes it')
    if (typeof who.connection !== 'string' || !who.connection) fail('a connection is the id its signer gave it: text')
    if ('key' in who && (typeof who.key !== 'string' || !B64U.test(who.key))) fail('a connection’s key is base64url')
    if ('name' in who && typeof who.name !== 'string') fail('a name is text')
  } else if ('profile' in who && !publicKeyFromAddress(who.profile)) fail('a profile is an address')
  if (!Array.isArray(can) || can.some((a) => typeof a !== 'string')) fail('can is a list of actions')
  if ('limit' in value) {
    if (!isObject(limit)) fail('a limit is an object')
    if (typeof limit.amount !== 'string' || !AMOUNT.test(limit.amount)) fail('an amount is decimal text, up to 6 places')
    if (typeof limit.currency !== 'string') fail('a currency is text')
    if (typeof limit.per !== 'string') fail('per is a period: day, week or month')
  }
  if ('until' in value && (!Number.isSafeInteger(until) || (until as number) < 0)) fail('until is a time, ms since 1970')
}

const known = (value: object, fields: string[]) => Object.keys(value).every((key) => fields.includes(key))

/**
 * Whether this code knows a rule whole: every field at every level, every action, the limit's
 * currency and period, and the kind of who. A signer acts on no rule it does not know whole: it asks
 * the person, since what it skipped could be a limit.
 */
export function knowsRule(rule: Rule): boolean {
  const who = rule.who as { [key: string]: unknown }
  if (!known(rule, ['who', 'can', 'limit', 'until'])) return false
  if (!('connector' in who ? known(who, ['connector', 'connection', 'key', 'name']) : 'profile' in who && known(who, ['profile']))) return false
  if (!rule.can.every((a) => (ACTIONS as readonly string[]).includes(a))) return false
  const limit = rule.limit
  return limit === undefined || (known(limit, ['amount', 'currency', 'per']) && (CURRENCIES as readonly string[]).includes(limit.currency) && Object.hasOwn(PERIODS, limit.per))
}
