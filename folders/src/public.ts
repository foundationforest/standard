// Reaching a host a stranger named, and only on the public internet. A service that follows the
// hosts a profile entry names goes to an origin someone else chose: one that may lead into the
// service's own network, a cloud's metadata service, or a machine behind a router. publicFetch
// refuses all of those before anything is sent, and follows no redirect, so a public host cannot
// hand the request on to a private one.
//
// Node only: it uses undici and Node's DNS. Everything else in folders runs in a browser too.

import { type LookupAddress, lookup as dnsLookup } from 'node:dns'
import { BlockList, isIP } from 'node:net'
import { Agent, fetch as undiciFetch } from 'undici'

/**
 * What a public address is not: the ranges IANA's special-purpose registries mark as not globally
 * reachable. An IPv4 address written as IPv6 (`::ffff:127.0.0.1`) is checked as IPv4; so is one
 * inside NAT64 or 6to4, by refusing those ranges whole.
 */
export const NOT_PUBLIC: ReadonlyArray<readonly [network: string, prefix: number, what: string]> = [
  ['0.0.0.0', 8, 'this network'],
  ['10.0.0.0', 8, 'private'],
  ['100.64.0.0', 10, 'carrier-grade NAT'],
  ['127.0.0.0', 8, 'loopback'],
  ['169.254.0.0', 16, 'link-local'],
  ['172.16.0.0', 12, 'private'],
  ['192.0.0.0', 24, 'IETF protocol assignments'],
  ['192.0.2.0', 24, 'documentation'],
  ['192.168.0.0', 16, 'private'],
  ['198.18.0.0', 15, 'benchmarking'],
  ['198.51.100.0', 24, 'documentation'],
  ['203.0.113.0', 24, 'documentation'],
  ['224.0.0.0', 3, 'multicast, reserved and broadcast'],
  ['::', 96, 'unspecified, loopback and IPv4-compatible'],
  ['64:ff9b::', 96, 'NAT64'],
  ['64:ff9b:1::', 48, 'local NAT64'],
  ['100::', 64, 'discard'],
  ['2001::', 23, 'IETF protocol assignments, Teredo among them'],
  ['2001:db8::', 32, 'documentation'],
  ['2002::', 16, '6to4'],
  ['3fff::', 20, 'documentation'],
  ['5f00::', 16, 'segment routing'],
  ['fc00::', 7, 'unique local'],
  ['fe80::', 10, 'link-local'],
  ['ff00::', 8, 'multicast'],
]

const BLOCKED = new BlockList()
for (const [network, prefix] of NOT_PUBLIC) BLOCKED.addSubnet(network, prefix, isIP(network) === 6 ? 'ipv6' : 'ipv4')

/** Whether `address` is an IP address, and a public one. */
export function isPublic(address: string): boolean {
  const family = isIP(address)
  return family !== 0 && !BLOCKED.check(address, family === 6 ? 'ipv6' : 'ipv4')
}

/**
 * fetch, to addresses `allowed` passes only, and never after a redirect, whatever the caller asks.
 * An address written in the URL is checked before anything is sent; a name's, every one it
 * resolves to, when connecting, so the connection goes to an address that was checked. A Request
 * is refused: give its URL. `publicFetch` is this with `isPublic`; a test may pass another check.
 */
export function reachOnly(allowed: (address: string) => boolean): typeof fetch {
  const lookup = (hostname: string, options: { all?: boolean }, callback: (err: Error | null, address: string | LookupAddress[], family?: number) => void): void => {
    dnsLookup(hostname, { ...options, all: true }, (err, addresses) => {
      if (err) return callback(err, '')
      const refused = addresses.find((a) => !allowed(a.address))
      if (refused || !addresses.length) return callback(new Error(`${hostname} leads to ${refused?.address ?? 'no address'}, not a public address`), '')
      if (options.all) return callback(null, addresses)
      callback(null, addresses[0]!.address, addresses[0]!.family)
    })
  }
  const dispatcher = new Agent({ connect: { lookup: lookup as never } })
  return (async (input: string | URL | Request, init?: RequestInit) => {
    if (typeof input !== 'string' && !(input instanceof URL)) throw new TypeError('give a URL, not a Request')
    const url = new URL(input)
    const host = url.hostname.replace(/^\[|\]$/g, '')
    if (isIP(host) && !allowed(host)) throw new TypeError(`${url.origin} is not a public address`)
    return undiciFetch(url, { ...init, redirect: 'error', dispatcher } as never)
  }) as typeof fetch
}

/** fetch, to public addresses only, and never after a redirect. */
export const publicFetch = reachOnly(isPublic)
