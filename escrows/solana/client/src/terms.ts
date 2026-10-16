// From an offer's terms to the terms an escrow is created with, and back: what a person checks
// before they work or pay, which window is in force, when the default can run, whether a stop or a
// take-back would land, and what a split pays.
//
// The escrow's two options, each off unless set: `arbiter`, a key that may decide any split, and
// `schedule`, `{ windows: [{ until, payerShare }], end }` (the format in `escrows/README.md`).
// Their shape is defined here, since the program defines what they mean; an offer field that
// carries them is the market's to suggest (foundationforest/markets). Everything else about a deal
// (the recipient, the amount, the token) comes from the deal itself. Nothing here reads a market
// file.

import { PublicKey } from '@solana/web3.js'

import {
  BPS,
  MAX_WINDOWS,
  randomId,
  share,
  validateSchedule,
  type EscrowAccount,
  type Schedule,
  type Terms,
  type Window,
} from './program.ts'

/**
 * The escrow's options, as an offer may carry them: the schedule in the format's own JSON, its
 * times in unix seconds. Records stay open, so they may sit beside other keys: those are ignored
 * and mean nothing to an escrow.
 */
export type PostTerms = {
  /** A Solana key, base58, that may decide any split. Absent: no arbiter. */
  arbiter?: string
  /** Absent: no schedule. */
  schedule?: { windows: { until: number; payerShare: number }[]; end: 'pay' | 'refund' }
  [other: string]: unknown
}

/** The two options, as an escrow holds them. */
export type Options = { arbiter: PublicKey | null; schedule: Schedule | null }

/**
 * The options a post's terms turn on. Absent, null or empty terms turn on nothing. Throws on a
 * malformed option rather than guess: a key that is not a key, a schedule that is not one to four
 * windows of whole-second times rising and whole shares from 0 to 10,000, or a default that is
 * neither "pay" nor "refund".
 */
export function optionsFromPost(terms: PostTerms | null | undefined): Options {
  if (terms === null || terms === undefined) return { arbiter: null, schedule: null }
  if (typeof terms !== 'object' || Array.isArray(terms)) throw new TypeError("a post's terms are an object")
  let arbiter: PublicKey | null = null
  if (terms.arbiter !== undefined) {
    if (typeof terms.arbiter !== 'string') throw new TypeError('terms.arbiter is a base58 key')
    arbiter = new PublicKey(terms.arbiter)
    if (arbiter.equals(PublicKey.default)) throw new Error('EmptyKey: the arbiter cannot be the zero key')
  }
  let schedule: Schedule | null = null
  if (terms.schedule !== undefined) {
    const s = terms.schedule
    if (typeof s !== 'object' || s === null || !Array.isArray(s.windows)) throw new TypeError('terms.schedule is { windows, end }')
    if (s.windows.length > MAX_WINDOWS) throw new RangeError(`terms.schedule has at most ${MAX_WINDOWS} windows, not ${s.windows.length}`)
    const windows: Window[] = s.windows.map((w, i) => {
      if (typeof w !== 'object' || w === null) throw new TypeError(`terms.schedule.windows[${i}] is { until, payerShare }`)
      if (!Number.isSafeInteger(w.until)) throw new RangeError(`terms.schedule.windows[${i}].until is a whole number of unix seconds, not ${String(w.until)}`)
      if (!Number.isInteger(w.payerShare) || w.payerShare < 0 || w.payerShare > BPS) {
        throw new RangeError(`terms.schedule.windows[${i}].payerShare is a whole number from 0 to ${BPS}, not ${String(w.payerShare)}`)
      }
      return { until: BigInt(w.until), payerShare: w.payerShare }
    })
    if (s.end !== 'pay' && s.end !== 'refund') throw new RangeError(`terms.schedule.end is "pay" or "refund", not ${String(s.end)}`)
    schedule = { windows, end: s.end }
    validateSchedule(schedule)
  }
  return { arbiter, schedule }
}

/**
 * The terms for one deal: the post's options, plus the deal's own recipient, amount and id (a
 * fresh random one unless given). Per hour or per job is the app multiplying before this; any
 * token the program accepts works. The program's own rules are checked when the instruction is
 * built.
 */
export function termsFor(post: PostTerms | null | undefined, deal: { recipient: PublicKey; amount: bigint; id?: bigint }): Terms {
  const { arbiter, schedule } = optionsFromPost(post)
  return { id: deal.id ?? randomId(), recipient: deal.recipient, amount: deal.amount, arbiter, schedule }
}

/**
 * One way an escrow's options differ from what a person agreed to. `added`: the escrow turns on
 * an option the person did not set. `changed`: it names another arbiter, or another schedule, than
 * the person set. `removed`: the person set an option the escrow does not carry.
 *
 * An arbiter is never either party (the program refuses it), and who holds a third key nobody can
 * tell from the chain. These are facts for the app to put in words, the schedule's dates among
 * them; none of them is copy.
 */
export type OptionDifference =
  | { option: 'arbiter'; kind: 'added' | 'changed'; arbiter: PublicKey }
  | { option: 'arbiter'; kind: 'removed'; expected: PublicKey }
  | { option: 'schedule'; kind: 'added' | 'changed'; schedule: Schedule }
  | { option: 'schedule'; kind: 'removed'; expected: Schedule }

/**
 * What a person checks before they work (the recipient) or pay (the payer): whether the escrow, as
 * read from the chain, names an arbiter or a schedule they did not set. The program accepts any
 * option its creator chose; this is where the other side sees them. Returns every difference, or
 * an empty list when the escrow carries exactly the options agreed.
 *
 * `agreed` is what the person set or accepted: the options of the post they answered, or of the
 * offer they wrote. Null means they agreed to none.
 */
export function optionsNotAgreed(args: { escrow: Pick<EscrowAccount, 'arbiter' | 'schedule'>; agreed: Options | PostTerms | null }): OptionDifference[] {
  const { escrow } = args
  const agreed = isOptions(args.agreed) ? args.agreed : optionsFromPost(args.agreed)
  const out: OptionDifference[] = []

  if (escrow.arbiter && !(agreed.arbiter && agreed.arbiter.equals(escrow.arbiter))) {
    out.push({ option: 'arbiter', kind: agreed.arbiter ? 'changed' : 'added', arbiter: escrow.arbiter })
  } else if (!escrow.arbiter && agreed.arbiter) {
    out.push({ option: 'arbiter', kind: 'removed', expected: agreed.arbiter })
  }

  if (escrow.schedule && !(agreed.schedule && sameSchedule(agreed.schedule, escrow.schedule))) {
    out.push({ option: 'schedule', kind: agreed.schedule ? 'changed' : 'added', schedule: copy(escrow.schedule) })
  } else if (!escrow.schedule && agreed.schedule) {
    out.push({ option: 'schedule', kind: 'removed', expected: copy(agreed.schedule) })
  }
  return out
}

function sameSchedule(a: Schedule, b: Schedule): boolean {
  return a.end === b.end && a.windows.length === b.windows.length && a.windows.every((w, i) => w.until === b.windows[i].until && w.payerShare === b.windows[i].payerShare)
}

function copy(s: Schedule): Schedule {
  return { windows: s.windows.map((w) => ({ ...w })), end: s.end }
}

/** `Options` carry both keys, the arbiter as a key object or null; a post's terms carry a string or nothing. */
function isOptions(x: Options | PostTerms | null): x is Options {
  return x !== null && 'schedule' in x && (x.arbiter === null || x.arbiter instanceof PublicKey)
}

/** The same check, throwing with every difference: for code paths that must not continue. */
export function assertOptionsAgreed(args: Parameters<typeof optionsNotAgreed>[0]): void {
  const diffs = optionsNotAgreed(args)
  if (diffs.length === 0) return
  const say = (d: OptionDifference) =>
    d.option === 'arbiter'
      ? d.kind === 'removed'
        ? `no arbiter, though ${d.expected.toBase58()} was agreed`
        : `an arbiter not agreed: ${d.arbiter.toBase58()}`
      : d.kind === 'removed'
        ? `no schedule, though one of ${d.expected.windows.length} windows was agreed`
        : `a schedule not agreed: ${d.schedule.windows.map((w) => `${w.payerShare} until ${w.until}`).join(', ')}, then ${d.schedule.end}`
  throw new Error(`the escrow's options differ from what was agreed: ${diffs.map(say).join('; ')}`)
}

type Timing = Pick<EscrowAccount, 'schedule' | 'status' | 'stop'>

const nowSeconds = () => BigInt(Math.floor(Date.now() / 1000))

/** The end time, in unix seconds: the last window's `until`. Null with no schedule. */
export function endTime(e: Pick<EscrowAccount, 'schedule'>): bigint | null {
  return e.schedule ? e.schedule.windows[e.schedule.windows.length - 1].until : null
}

/** The window in force at `now` (unix seconds; default: now): the first whose `until` is still ahead. Null from the end time on, and with no schedule. */
export function windowAt(e: Pick<EscrowAccount, 'schedule'>, now: bigint = nowSeconds()): Window | null {
  return e.schedule?.windows.find((w) => now < w.until) ?? null
}

/**
 * Whether a stop lands at `now` (unix seconds; default: now), from either party: the escrow is
 * live, nobody stopped it yet, and its end time, if it has one, is still ahead. The chain's clock
 * decides; a stop sent in the last seconds may land after them.
 */
export function canStop(e: Timing, now: bigint = nowSeconds()): boolean {
  if (e.status === 'ended' || e.stop) return false
  const end = endTime(e)
  return end === null || now < end
}

/** Whether `mark_funded` lands at `now`, the balance aside: not yet marked, and the end time, if any, still ahead. */
export function canMark(e: Pick<EscrowAccount, 'schedule' | 'status'>, now: bigint = nowSeconds()): boolean {
  if (e.status !== 'open') return false
  const end = endTime(e)
  return end === null || now < end
}

/** Whether `take_back` lands at `now`, the balance aside: live, never stopped, and a window in force whose share is above 0. */
export function canTakeBack(e: Timing, now: bigint = nowSeconds()): boolean {
  if (e.status === 'ended' || e.stop) return false
  const w = windowAt(e, now)
  return w !== null && w.payerShare > 0
}

/** Whether `end` lands at `now`, the balance aside: marked, never stopped, and the end time come. */
export function canEnd(e: Timing, now: bigint = nowSeconds()): boolean {
  const end = endTime(e)
  return e.status === 'funded' && !e.stop && end !== null && now >= end
}

/**
 * What a split pays, stated as the payer's share: `payerShare` of the whole balance to the payer,
 * rounded down, the rest to the recipient. A take-back pays the window's share the same way;
 * `pay` is the same at 0, and `refund` at 10,000.
 */
export function split(balance: bigint, payerShare: number): { toPayer: bigint; toRecipient: bigint } {
  const toPayer = share(balance, payerShare)
  return { toPayer, toRecipient: balance - toPayer }
}

/** Whether a deposit account's balance funds an escrow: at least the amount. */
export function funds(balance: bigint, amount: bigint): boolean {
  return balance >= amount
}

export { BPS }
