// A profile entry's pay addresses, as a reader counts them: each type whose pay key signed the
// profile's address in `paySig` (README.md, The profile entry), so a profile cannot list an address
// that is not its own. keys/'s pay module alone, not all of keys/, whose opening halves load age.

import { PAY_TYPES, type PayType, checkPaySig } from '@foundationforest/keys/pay'
import type { Body } from './entry.ts'

const isObject = (v: unknown): v is { [key: string]: unknown } => v !== null && typeof v === 'object' && !Array.isArray(v)

/** The address types in a profile entry's `pay` whose signature in its `paySig` holds for `profileAddress`. */
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
