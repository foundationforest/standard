// publicFetch: every range that is not public is refused, whether written in the URL or reached
// through a name, before anything is sent; and no redirect is followed, even when asked.

import assert from 'node:assert/strict'
import { type Server, createServer } from 'node:http'
import { test } from 'node:test'
import { NOT_PUBLIC, isPublic, publicFetch, reachOnly } from '../src/public.ts'

/** A local server that counts what reaches it, and answers with `answer`. */
async function serve(answer: (url: string) => { status: number; headers?: Record<string, string> }): Promise<{ url: string; seen: string[]; server: Server }> {
  const seen: string[] = []
  const server = createServer((req, res) => {
    seen.push(req.url ?? '')
    const { status, headers } = answer(req.url ?? '')
    res.writeHead(status, headers).end('hello')
  })
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
  return { url: `http://127.0.0.1:${(server.address() as { port: number }).port}`, seen, server }
}
const close = (server: Server) => new Promise((resolve) => server.close(resolve))

test('one address from every range that is not public is refused, and its first and last', () => {
  const inside: Record<string, string[]> = {
    '0.0.0.0/8': ['0.0.0.0', '0.255.255.255'],
    '10.0.0.0/8': ['10.0.0.1', '10.255.255.255'],
    '100.64.0.0/10': ['100.64.0.1', '100.127.255.255'],
    '127.0.0.0/8': ['127.0.0.1', '127.255.255.254'],
    '169.254.0.0/16': ['169.254.169.254', '169.254.0.1'],
    '172.16.0.0/12': ['172.16.0.1', '172.31.255.255'],
    '192.0.0.0/24': ['192.0.0.8', '192.0.0.255'],
    '192.0.2.0/24': ['192.0.2.1'],
    '192.168.0.0/16': ['192.168.1.1', '192.168.255.255'],
    '198.18.0.0/15': ['198.18.0.1', '198.19.255.255'],
    '198.51.100.0/24': ['198.51.100.7'],
    '203.0.113.0/24': ['203.0.113.9'],
    '224.0.0.0/3': ['224.0.0.1', '239.255.255.250', '240.0.0.1', '255.255.255.255'],
    '::/96': ['::', '::1', '::127.0.0.1'],
    '64:ff9b::/96': ['64:ff9b::7f00:1', '64:ff9b::808:808'],
    '64:ff9b:1::/48': ['64:ff9b:1::a00:1'],
    '100::/64': ['100::1'],
    '2001::/23': ['2001::1', '2001:0:4136:e378:8000:63bf:3fff:fdd2', '2001:2::1'],
    '2001:db8::/32': ['2001:db8::1'],
    '2002::/16': ['2002:7f00:1::1', '2002:808:808::1'],
    '3fff::/20': ['3fff::1'],
    '5f00::/16': ['5f00::1'],
    'fc00::/7': ['fc00::1', 'fd12:3456::1'],
    'fe80::/10': ['fe80::1', 'febf::1'],
    'ff00::/8': ['ff02::1'],
  }
  assert.deepEqual(Object.keys(inside), NOT_PUBLIC.map(([network, prefix]) => `${network}/${prefix}`), 'every range is tried')
  for (const [range, addresses] of Object.entries(inside)) for (const a of addresses) assert.equal(isPublic(a), false, `${a} in ${range}`)
})

test('an IPv4 address written as IPv6 is checked as IPv4', () => {
  for (const a of ['::ffff:127.0.0.1', '::ffff:7f00:1', '::ffff:10.0.0.1', '::ffff:169.254.169.254', '::ffff:192.168.0.1']) assert.equal(isPublic(a), false, a)
  assert.equal(isPublic('::ffff:8.8.8.8'), true)
})

test('public addresses pass; text that is no address does not', () => {
  for (const a of ['8.8.8.8', '1.1.1.1', '100.63.255.255', '100.128.0.0', '172.32.0.1', '192.0.1.1', '2606:4700:4700::1111', '2a00:1450:4001::1']) assert.equal(isPublic(a), true, a)
  for (const a of ['', 'localhost', 'example.com', '127.1', '::g', '10.0.0.1/8']) assert.equal(isPublic(a), false, a)
})

test('an address written in the URL is refused before anything is sent', async () => {
  const s = await serve(() => ({ status: 200 }))
  try {
    const port = new URL(s.url).port
    for (const url of [s.url, `http://[::1]:${port}/`, `http://[::ffff:127.0.0.1]:${port}/`, `http://0x7f.1:${port}/`, `http://2130706433:${port}/`]) {
      await assert.rejects(publicFetch(url), /not a public address/, url)
    }
    await assert.rejects(publicFetch('http://169.254.169.254/latest/meta-data/'), /not a public address/)
    await assert.rejects(publicFetch(new Request(s.url)), /give a URL/)
    assert.deepEqual(s.seen, [])
  } finally {
    await close(s.server)
  }
})

test('a name that leads to a private address is refused when connecting, and nothing reaches it', async () => {
  const s = await serve(() => ({ status: 200 }))
  try {
    await assert.rejects(publicFetch(`http://localhost:${new URL(s.url).port}/`))
    assert.deepEqual(s.seen, [])
  } finally {
    await close(s.server)
  }
})

test('no redirect is followed, even when the caller asks for it', async () => {
  const anywhere = reachOnly(() => true) // only so a test can reach loopback
  const target = await serve(() => ({ status: 200 }))
  const away = await serve(() => ({ status: 302, headers: { location: `${target.url}/inside` } }))
  try {
    assert.equal(await (await anywhere(`${target.url}/plain`)).text(), 'hello', 'an answer that is no redirect comes back')
    await assert.rejects(anywhere(`${away.url}/a`))
    await assert.rejects(anywhere(`${away.url}/b`, { redirect: 'follow' }))
    assert.deepEqual(away.seen, ['/a', '/b'])
    assert.deepEqual(target.seen, ['/plain'], 'never /inside')
  } finally {
    await close(away.server)
    await close(target.server)
  }
})
