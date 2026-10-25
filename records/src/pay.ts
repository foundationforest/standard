// A profile record's pay addresses, as a reader counts them: each type whose pay key signed the
// profile's address in `paySig` (README.md, Folders), so a profile cannot list an address that is
// not its own. keys/'s pay module alone, not all of keys/, whose inbox keys load age.

import { PAY_TYPES, type PayType, checkPaySig } from '@foundationforest/keys/pay'
import type { Body } from './record.ts'

const isObject = (v: unknown): v is { [key: string]: unknown } => v !== null && typeof v === 'object' && !Array.isArray(v)

/** The address types in a profile record's `pay` whose signature in its `paySig` holds for `profileAddress`. */
export function checkPay(body: Body | null | undefined, profileAddress: string): PayType[] {
  const pay = body?.pay
  const sigs = body?.paySig
  if (!isObject(pay) || !isObject(sigs)) return []
  return PAY_TYPES.filter((type) => {
    const address = pay[type]
    const sig = sigs[type]
    return typeof address === 'string' && typeof sig === 'string' && checkPaySig(type, address, profileAddress, sig)
  })
}
