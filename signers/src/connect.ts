// Connecting an AI app, and the live link (README.md, Connecting an AI app, The live link). A
// connection is an Ed25519 key pair the person's app makes on the connect page; its public key, 32
// bytes in base64url, is the connection's id. The key signs two texts and nothing else: a login, so
// only the person's app can make one for its connection, and a socket's challenge, so only the
// person's signers serve it. Each signed text begins with 0xff and its own text, as every signed
// text in the standard does, so no signature is ever two of them.
//
// Ed25519 and not Baby Jubjub: a connection key is no profile's and no service's, and Ed25519 is in
// every browser and in Node.

import { RecordError, b64u } from '@foundationforest/records'
import { ed25519 } from '@noble/curves/ed25519.js'
import { type Answer, type Ask, checkAsk } from './asks.ts'

const utf8 = (text: string) => new TextEncoder().encode(text)
const prefix = (text: string) => Uint8Array.of(0xff, ...utf8(text))

/** What a connection key signs for a login: this, then the login request as the connector gave it. */
export const LOGIN_PREFIX = prefix('forest/v1/login\n')
/** What a connection key signs to register on a socket: this, the connector's origin, a newline, then the socket's challenge. */
export const REGISTER_PREFIX = prefix('forest/v1/register\n')

/** A connection: its id, the public key, and its key, the private one, each 32 bytes in base64url. */
export type Connection = { connection: string; key: string }

/** Whether `text` is 32 bytes in base64url, in its one spelling. */
function is32(text: unknown): text is string {
  if (typeof text !== 'string' || text.length !== 43) return false
  try {
    return b64u.encode(b64u.decode(text)) === text
  } catch {
    return false
  }
}

/** Whether `id` is a connection's id: an Ed25519 public key, 32 bytes in base64url, in its one spelling. */
export const isConnection = (id: unknown): id is string => is32(id)

/** The connection a private key gives. */
export function connectionOf(key: string): Connection {
  if (!is32(key)) throw new RecordError('connection', 'a connection’s key is 32 bytes in base64url')
  return { connection: b64u.encode(ed25519.getPublicKey(b64u.decode(key))), key }
}

/** A new connection, from 32 random bytes. */
export function newConnection(): Connection {
  return connectionOf(b64u.encode(crypto.getRandomValues(new Uint8Array(32))))
}

const concat = (a: Uint8Array, text: string) => {
  const out = new Uint8Array(a.length + utf8(text).length)
  out.set(a)
  out.set(utf8(text), a.length)
  return out
}

/** The bytes a login's signature is over. */
export const loginInput = (request: string) => concat(LOGIN_PREFIX, request)
/** The bytes a registration's signature is over. */
export const registerInput = (connector: string, challenge: string) => concat(REGISTER_PREFIX, `${connector}\n${challenge}`)

const sign = (key: string, bytes: Uint8Array) => b64u.encode(ed25519.sign(bytes, b64u.decode(connectionOf(key).key)))
function signedBy(connection: unknown, bytes: Uint8Array, sig: unknown): boolean {
  if (!isConnection(connection) || typeof sig !== 'string') return false
  try {
    const signature = b64u.decode(sig)
    return signature.length === 64 && ed25519.verify(signature, bytes, b64u.decode(connection), { zip215: false })
  } catch {
    return false
  }
}

/** The connection key's signature on a login request, exactly as received: 64 bytes in base64url. */
export const signLogin = (key: string, request: string) => sign(key, loginInput(request))
/** Whether `sig` is the connection's signature on the login request. */
export const checkLogin = (connection: unknown, request: string, sig: unknown) => signedBy(connection, loginInput(request), sig)
/** The connection key's signature to register on a socket of `connector` (its origin) with `challenge`. */
export const signRegister = (key: string, connector: string, challenge: string) => sign(key, registerInput(connector, challenge))
/** Whether `sig` is the connection's registration on a socket of `connector` with `challenge`. */
export const checkRegister = (connection: unknown, connector: string, challenge: string, sig: unknown) => signedBy(connection, registerInput(connector, challenge), sig)

/**
 * What the connect page shows from a login request: the AI app's `name`, and `redirect`, where it
 * is sent back. The request is base64url of a JSON object, a `.`, then whatever the connector adds.
 * Throws RecordError with code `request`.
 */
export function readRequest(request: string): { name: string; redirect: string } {
  let body: unknown
  try {
    body = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(b64u.decode(request.split('.')[0]!)))
  } catch {
    throw new RecordError('request', 'a login request is base64url of a JSON object, then a dot')
  }
  const { name, redirect } = (body ?? {}) as { [key: string]: unknown }
  if (typeof name !== 'string' || typeof redirect !== 'string' || !URL.canParse(redirect)) throw new RecordError('request', 'a login request names the AI app and where it is sent back')
  return { name, redirect }
}

/** Where a signer opens the live link to a connector: its origin, https as wss, then /signer. */
export const linkUrl = (connector: string) => `${connector.replace(/^http/, 'ws')}/signer`

/** A frame on the live link: one JSON object as text, with a type. */
export type Frame =
  | { type: 'challenge'; challenge: string }
  | { type: 'register'; connection: string; sig: string }
  | { type: 'registered'; connection: string }
  | { type: 'refused'; connection: string; why: string }
  | ({ type: 'ask'; id: string; connection: string } & Ask)
  | ({ type: 'answer'; id: string } & Answer)

/** An ask as its frame: the ask, with its type, id and connection beside it. */
export const askFrame = (id: string, connection: string, ask: Ask) => JSON.stringify({ type: 'ask', id, connection, ...ask })
/** An answer as its frame: the answer, with its type and the ask's id beside it. */
export const answerFrame = (id: string, answer: Answer) => JSON.stringify({ type: 'answer', id, ...answer })

/**
 * A frame off the live link, checked: its type and the fields of that type, an ask's by checkAsk,
 * and an answer's status. A connector checks an answer's fields with checkAnswer, knowing its ask.
 * Throws RecordError with code `frame`: whoever reads one closes the socket.
 */
export function readFrame(text: string): Frame {
  const fail = (why: string): never => {
    throw new RecordError('frame', why)
  }
  let frame: unknown
  try {
    frame = JSON.parse(text)
  } catch {
    return fail('a frame is JSON')
  }
  if (frame === null || typeof frame !== 'object' || Array.isArray(frame)) return fail('a frame is an object')
  const { type, ...rest } = frame as { [key: string]: unknown }
  const text_ = (name: string) => (typeof rest[name] === 'string' ? (rest[name] as string) : fail(`a ${String(type)} frame has ${name}, text`))
  if (type === 'challenge') return is32(rest.challenge) ? { type, challenge: rest.challenge } : fail('a challenge is 32 bytes in base64url')
  if (type === 'register') return { type, connection: isConnection(rest.connection) ? rest.connection : fail('a connection is 32 bytes in base64url'), sig: text_('sig') }
  if (type === 'registered') return { type, connection: text_('connection') }
  if (type === 'refused') return { type, connection: text_('connection'), why: text_('why') }
  if (type === 'ask') {
    const { id, connection, ...ask } = rest
    if (typeof id !== 'string' || typeof connection !== 'string') return fail('an ask frame has id and connection, text')
    try {
      return { type, id, connection, ...checkAsk(ask) }
    } catch (err) {
      return fail((err as Error).message)
    }
  }
  if (type === 'answer') {
    const { id, ...answer } = rest
    if (typeof id !== 'string') return fail('an answer frame has id, text')
    if (!['done', 'waiting', 'refused'].includes(answer.status as string)) return fail('an answer is done, waiting or refused')
    return { type, id, ...(answer as Answer) }
  }
  return fail(`no frame of type ${String(type)}`)
}
