// Connecting an AI app and the live link: a connection key, its login and registration signatures
// checked again with Node's own Ed25519, the request the connect page reads, and each frame.

import assert from 'node:assert/strict'
import { createPublicKey, verify } from 'node:crypto'
import { describe, test } from 'node:test'
import { MESSAGE_PREFIX, PULL_PREFIX, RecordError, SIGN_PREFIX, b64u } from '@foundationforest/records'
import { LOGIN_PREFIX, REGISTER_PREFIX, answerFrame, askFrame, checkLogin, checkRegister, connectionOf, isConnection, linkUrl, newConnection, readFrame, readRequest, registerInput, signLogin, signRegister } from '../src/connect.ts'
import { bob } from './fixtures.ts'

const code = (c: string) => (err: unknown) => err instanceof RecordError && err.code === c
const connector = 'https://connector.example'
const request = `${b64u.encode(new TextEncoder().encode(JSON.stringify({ client: 'c', name: 'My assistant', redirect: 'https://ai.example/back', exp: 1 })))}.the-connector-s-own`
/** Node's own Ed25519 check, from the connection's id as the key. */
const nodeChecks = (connection: string, bytes: Uint8Array, sig: string) => verify(null, bytes, createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: connection }, format: 'jwk' }), b64u.decode(sig))

describe('a connection', () => {
  test('an Ed25519 key pair; its public key, 32 bytes in base64url, is its id', () => {
    const c = newConnection()
    assert.equal(c.connection.length, 43)
    assert.equal(isConnection(c.connection), true)
    assert.deepEqual(connectionOf(c.key), c)
    assert.notDeepEqual(newConnection(), c)
    for (const id of ['', 'x'.repeat(43), c.connection + 'A', c.connection.slice(1), 7]) assert.equal(isConnection(id), false, String(id))
    assert.throws(() => connectionOf('short'), code('connection'))
  })

  test('it signs a login: 0xff, forest/v1/login and a newline, then the request exactly as received; Node checks it too', () => {
    const c = newConnection()
    const sig = signLogin(c.key, request)
    assert.equal(b64u.decode(sig).length, 64)
    assert.equal(checkLogin(c.connection, request, sig), true)
    const bytes = new Uint8Array([...LOGIN_PREFIX, ...new TextEncoder().encode(request)])
    assert.deepEqual([...LOGIN_PREFIX], [0xff, ...new TextEncoder().encode('forest/v1/login\n')])
    assert.equal(nodeChecks(c.connection, bytes, sig), true)
    assert.equal(checkLogin(c.connection, request + 'x', sig), false, 'a request changed on the way')
    assert.equal(checkLogin(newConnection().connection, request, sig), false, 'another connection')
    assert.equal(checkLogin(c.connection, request, sig.slice(1)), false)
    assert.equal(checkLogin(c.connection, request, 7), false)
  })

  test('it registers on a socket: 0xff, forest/v1/register and a newline, the connector’s origin, a newline, the challenge', () => {
    const c = newConnection()
    const challenge = b64u.encode(new Uint8Array(32).fill(9))
    const sig = signRegister(c.key, connector, challenge)
    assert.equal(checkRegister(c.connection, connector, challenge, sig), true)
    assert.equal(nodeChecks(c.connection, registerInput(connector, challenge), sig), true)
    assert.deepEqual([...registerInput(connector, challenge)], [...REGISTER_PREFIX, ...new TextEncoder().encode(`${connector}\n${challenge}`)])
    assert.equal(checkRegister(c.connection, 'https://other.example', challenge, sig), false, 'another connector')
    assert.equal(checkRegister(c.connection, connector, b64u.encode(new Uint8Array(32)), sig), false, 'another socket')
    assert.equal(checkLogin(c.connection, `${connector}\n${challenge}`, sig), false, 'a registration is never a login')
  })

  test('each signed text begins with 0xff and its own text, so no signature is ever a record’s, a message’s or a pull’s', () => {
    const texts = [LOGIN_PREFIX, REGISTER_PREFIX, SIGN_PREFIX, MESSAGE_PREFIX, PULL_PREFIX]
    for (const [i, a] of texts.entries()) {
      for (const [j, b] of texts.entries()) if (i !== j) assert.notDeepEqual(a.subarray(0, Math.min(a.length, b.length)), b.subarray(0, Math.min(a.length, b.length)))
    }
  })
})

describe('the connect page and the live link', () => {
  test('the request: the page reads the AI app’s name and where it is sent back, and leaves the rest', () => {
    assert.deepEqual(readRequest(request), { name: 'My assistant', redirect: 'https://ai.example/back' })
    for (const bad of ['', 'not base64.x', `${b64u.encode(new TextEncoder().encode('{"name":"x"}'))}.y`, `${b64u.encode(new TextEncoder().encode('[1]'))}.y`]) assert.throws(() => readRequest(bad), code('request'), bad)
  })

  test('the link: the connector’s origin, https as wss, then /signer', () => {
    assert.equal(linkUrl(connector), 'wss://connector.example/signer')
    assert.equal(linkUrl('http://127.0.0.1:8080'), 'ws://127.0.0.1:8080/signer')
  })

  test('the frames: each type and its fields; an ask is checked whole, and an answer by its status', () => {
    const c = newConnection()
    const challenge = b64u.encode(new Uint8Array(32).fill(1))
    const ask = { ask: 'pay' as const, label: 'tutoring/seller', to: bob.address, amount: '30', currency: 'USD' }
    const frames = [
      { type: 'challenge', challenge },
      { type: 'register', connection: c.connection, sig: signRegister(c.key, connector, challenge) },
      { type: 'registered', connection: c.connection },
      { type: 'refused', connection: c.connection, why: 'not this key' },
      { type: 'ask', id: '01ab', connection: c.connection, ...ask },
      { type: 'answer', id: '01ab', status: 'waiting', link: 'https://app.example/yes/1' },
    ]
    for (const frame of frames) assert.deepEqual(readFrame(JSON.stringify(frame)), frame, frame.type)
    assert.deepEqual(JSON.parse(askFrame('01ab', c.connection, ask)), frames[4])
    assert.deepEqual(JSON.parse(answerFrame('01ab', { status: 'waiting', link: 'https://app.example/yes/1' })), frames[5])
    const bad = ['not json', '[]', '{}', '{"type":"hello"}', JSON.stringify({ type: 'challenge', challenge: 'short' }), JSON.stringify({ type: 'register', connection: 'x', sig: 'y' }), JSON.stringify({ type: 'ask', id: '1', connection: c.connection, ask: 'post' }), JSON.stringify({ type: 'ask', connection: c.connection, ...ask }), JSON.stringify({ type: 'answer', id: '1', status: 'approval' })]
    for (const text of bad) assert.throws(() => readFrame(text), code('frame'), text)
  })
})
