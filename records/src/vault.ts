// The vault: what a new device needs and the seed alone cannot give back, kept on hosts in a folder
// of the person's own (README.md, The vault). The folder's main key is keys/'s vault key, mixed from
// the seed, so a new device finds the vault with the seed alone. The folder holds its hosts record
// and one private record at `vault`, made for the vault's own inbox key alone (vaultRecord and
// openVault in private.ts). Inside: the labels of the person's profiles and where each lives, the
// grants they received, their issuers' notes, and apps' settings.
//
// An app keeps every field it does not know, at the top and inside `settings`, so two apps, or an
// older and a newer one, share one vault without erasing each other's.

import type { Json } from './canonical.ts'
import { type Grant, checkGrant } from './grant.ts'
import { MAX_HOSTS, RecordError, normalizeOrigin } from './record.ts'

/** The fixed path of the vault's one private record, in the vault's own folder. */
export const VAULT_PATH = 'vault'

/** One of the person's profiles: its label, and the hosts its folder lived on when written. */
export type VaultProfile = { label: string; hosts: string[] }

/** An issuer's note: the issuer's name, as keys/'s recipe takes it, and the signed note, as JSON (registry/client's noteToJson). */
export type IssuerNote = { issuer: string; note: { [key: string]: Json } }

export type Vault = {
  /** The person's profiles, each label once. */
  profiles?: VaultProfile[]
  /** The grants the person received, through their profiles' inboxes. */
  grants?: Grant[]
  issuerNotes?: IssuerNote[]
  /** Apps' settings: any fields, each an app's own. */
  settings?: { [key: string]: Json }
  /** Fields an app does not know: kept as they are. */
  [field: string]: Json | Grant[] | VaultProfile[] | IssuerNote[] | undefined
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
  if ('grants' in value) {
    if (!Array.isArray(value.grants)) fail('grants is a list')
    for (const g of value.grants as unknown[]) checkGrant(g)
  }
  if ('issuerNotes' in value) {
    if (!Array.isArray(value.issuerNotes)) fail('issuerNotes is a list')
    for (const n of value.issuerNotes as unknown[]) {
      if (!isObject(n)) fail('an issuer note is an object')
      for (const key of Object.keys(n)) if (key !== 'issuer' && key !== 'note') fail(`unknown issuer note field ${key}`)
      if (typeof n.issuer !== 'string' || !n.issuer) fail("an issuer note names its issuer, by the name keys/'s recipe takes")
      if (!isObject(n.note)) fail('a note is an object')
    }
  }
  if ('settings' in value && !isObject(value.settings)) fail('settings is an object')
}
