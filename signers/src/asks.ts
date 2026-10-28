// Asks and answers (README.md, Asks, Answers): what anyone asks the person's app, as one of their
// profiles named by its label, and what the app answers. Three asks, read, write and pay, and
// three answers, done, waiting and refused. An app refuses an ask with a field it does not know, so
// a later field never passes unread; a connector passes on only an answer's known fields, so an app
// cannot hand an AI app anything else by mistake. An answer carries no address of the person's
// own: an app leaves them out (leaveOut).

import { type Body, type Json, RecordError, checkPath, checkValue, publicKeyFromAddress } from '@foundationforest/records'
import { AMOUNT } from './permissions.ts'

export type ReadAsk = { ask: 'read'; label?: string; path?: string; inbox?: true }
export type WriteAsk = { ask: 'write'; label: string; path: string; body: Body | null }
export type MessageAsk = { ask: 'write'; label: string; to: string; body: Body }
export type PayAsk = { ask: 'pay'; label: string; to: string; amount: string; currency: string }
export type Ask = ReadAsk | WriteAsk | MessageAsk | PayAsk

/** What a read with nothing named answers for each profile: its label and what the asker may do there. */
export type Seen = { label: string; can: string[]; limit?: { amount: string; currency: string; per: string }; until?: number }
/** A message as a read of the inbox answers it: from an address, or from another of the person's own profiles, by its label. */
export type Read = ({ from: string } | { fromLabel: string }) & { time: number; body: Body }
export type Done = { status: 'done'; profiles?: Seen[]; body?: Body | null; time?: number; messages?: Read[] }
export type Answer = Done | { status: 'waiting'; link?: string; why?: string } | { status: 'refused'; why: string }

const isObject = (v: unknown): v is { [key: string]: unknown } => v !== null && typeof v === 'object' && !Array.isArray(v)
const only = (value: object, fields: string[], fail: (why: string) => never) => {
  for (const key of Object.keys(value)) if (!fields.includes(key)) fail(`no field ${key}`)
}
const asBody = (value: unknown, fail: (why: string) => never): Body => {
  if (!isObject(value)) fail('a body is an object')
  try {
    checkValue(value, 1)
  } catch (err) {
    fail((err as Error).message)
  }
  return value as Body
}

/** A post's full address, `<address>/<path>`: the profile whose folder holds it, and its path. Null if it is not one. */
export function postAddressOf(text: unknown): { profile: string; path: string } | null {
  if (typeof text !== 'string') return null
  const at = text.indexOf('/')
  if (at < 0) return null
  const [profile, path] = [text.slice(0, at), text.slice(at + 1)]
  try {
    checkPath(path)
  } catch {
    return null
  }
  return publicKeyFromAddress(profile) ? { profile, path } : null
}

/** An ask, checked: one of the three, with its fields and no other. Throws RecordError with code `ask`. */
export function checkAsk(value: unknown): Ask {
  const fail = (why: string): never => {
    throw new RecordError('ask', why)
  }
  if (!isObject(value)) return fail('an ask is an object')
  if ('label' in value && typeof value.label !== 'string') fail('a label is text')
  if (value.ask === 'read') {
    only(value, ['ask', 'label', 'path', 'inbox'], fail)
    if ('path' in value && 'inbox' in value) fail('a read names a path or the inbox, not both')
    if (('path' in value || 'inbox' in value) !== 'label' in value) fail('a read names nothing, or a label with a path or the inbox')
    if ('path' in value) {
      try {
        checkPath(value.path)
      } catch {
        fail('a path is 1 to 4 segments of [a-z0-9][a-z0-9._-]')
      }
    }
    if ('inbox' in value && value.inbox !== true) fail('inbox is true')
    return value as ReadAsk
  }
  if (value.ask === 'write') {
    if (!('label' in value)) fail('a write names the profile’s label')
    if ('to' in value) {
      only(value, ['ask', 'label', 'to', 'body'], fail)
      if (!publicKeyFromAddress(value.to)) fail('a message is to an address')
      asBody(value.body, fail)
      return value as MessageAsk
    }
    only(value, ['ask', 'label', 'path', 'body'], fail)
    try {
      checkPath(value.path)
    } catch {
      fail('a write names a path, or `to` for a message')
    }
    if (value.body !== null) asBody(value.body, fail)
    return value as WriteAsk
  }
  if (value.ask === 'pay') {
    only(value, ['ask', 'label', 'to', 'amount', 'currency'], fail)
    if (!('label' in value)) fail('a pay names the profile’s label')
    if (!publicKeyFromAddress(value.to) && !postAddressOf(value.to)) fail('a pay is to an address, or a post’s full address')
    if (typeof value.amount !== 'string' || !AMOUNT.test(value.amount)) fail('an amount is decimal text, up to 6 places')
    if (typeof value.currency !== 'string' || !value.currency) fail('a currency is a code, as text')
    return value as PayAsk
  }
  return fail('an ask is read, write or pay')
}

/**
 * An answer to `ask`, checked, with only the fields the standard names for it: done with what the
 * ask returns, waiting with an https link and why if any, refused with why. Throws RecordError with
 * code `answer`.
 */
export function checkAnswer(value: unknown, ask: Ask): Answer {
  const fail = (why: string): never => {
    throw new RecordError('answer', why)
  }
  if (!isObject(value)) return fail('an answer is an object')
  const text = (v: unknown, name: string): string => (typeof v === 'string' ? v : fail(`${name} is text`))
  const whole = (v: unknown, name: string): number => (Number.isSafeInteger(v) && (v as number) >= 0 ? (v as number) : fail(`${name} is ms since 1970`))
  if (value.status === 'refused') return { status: 'refused', why: text(value.why, 'why') }
  if (value.status === 'waiting') {
    if (value.link !== undefined && (typeof value.link !== 'string' || !URL.canParse(value.link) || new URL(value.link).protocol !== 'https:')) fail('a link is an https address')
    return { status: 'waiting', ...(value.link !== undefined && { link: value.link as string }), ...(value.why !== undefined && { why: text(value.why, 'why') }) }
  }
  if (value.status !== 'done') return fail('an answer is done, waiting or refused')
  if (ask.ask === 'read' && ask.label === undefined) {
    if (!Array.isArray(value.profiles)) fail('a read with nothing named answers profiles')
    const profiles = (value.profiles as unknown[]).map((p): Seen => {
      if (!isObject(p) || !Array.isArray(p.can)) return fail('each profile is { label, can, limit?, until? }')
      const limit = p.limit
      if (limit !== undefined && (!isObject(limit) || typeof limit.amount !== 'string' || typeof limit.currency !== 'string' || typeof limit.per !== 'string')) fail('a limit is { amount, currency, per }')
      return {
        label: text(p.label, 'label'),
        can: (p.can as unknown[]).map((a) => text(a, 'an action')),
        ...(isObject(limit) && { limit: { amount: limit.amount as string, currency: limit.currency as string, per: limit.per as string } }),
        ...(p.until !== undefined && { until: whole(p.until, 'until') }),
      }
    })
    return { status: 'done', profiles }
  }
  if (ask.ask === 'read' && ask.inbox) {
    if (!Array.isArray(value.messages)) fail('a read of the inbox answers messages')
    const messages = (value.messages as unknown[]).map((m): Read => {
      if (!isObject(m) || 'from' in m === 'fromLabel' in m) return fail('each message is from an address, or from a label')
      const from = 'from' in m ? { from: publicKeyFromAddress(m.from) ? (m.from as string) : fail('from is an address') } : { fromLabel: text(m.fromLabel, 'fromLabel') }
      return { ...from, time: whole(m.time, 'time'), body: asBody(m.body, fail) }
    })
    return { status: 'done', messages }
  }
  if (ask.ask === 'read') {
    if (value.body !== null && !isObject(value.body)) fail('a read of a path answers its body, or null')
    return { status: 'done', body: value.body === null ? null : asBody(value.body, fail), ...(value.time !== undefined && { time: whole(value.time, 'time') }) }
  }
  return { status: 'done' }
}

/**
 * `value` without a single address of the person's own: each object field or array item whose
 * text holds one of `addresses` (the person's profiles' addresses and pay addresses) is left out,
 * and so is each field named by one. What an app does to an answer before it sends it.
 */
export function leaveOut<T extends Json>(value: T, addresses: Iterable<string>): T {
  const own = [...addresses].filter((a) => a.length > 0)
  const holds = (v: unknown) => typeof v === 'string' && own.some((a) => v.includes(a))
  const walk = (v: Json): Json => {
    if (Array.isArray(v)) return v.filter((x) => !holds(x)).map(walk)
    if (v !== null && typeof v === 'object') return Object.fromEntries(Object.entries(v).filter(([k, x]) => !holds(k) && !holds(x)).map(([k, x]) => [k, walk(x)]))
    return v
  }
  return walk(value) as T
}
