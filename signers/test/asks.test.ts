// Asks and answers: each of the three asks and what it may hold; each answer, with only the fields
// the standard names for its ask; and an answer with every address of the person's own left out.

import assert from 'node:assert/strict'
import { describe, test } from 'node:test'
import { payAddresses } from '@foundationforest/keys'
import { RecordError } from '@foundationforest/records'
import { type Ask, checkAnswer, checkAsk, leaveOut, postAddressOf } from '../src/asks.ts'
import { SEED, T0, alice, bob } from './fixtures.ts'

const code = (c: string) => (err: unknown) => err instanceof RecordError && err.code === c
const label = 'tutoring/seller'

describe('asks', () => {
  test('the three asks, as an AI or a person writes them', () => {
    const asks: Ask[] = [
      { ask: 'read' },
      { ask: 'read', label, path: 'offer/maths' },
      { ask: 'read', label, inbox: true },
      { ask: 'write', label, path: 'offer/maths', body: { about: 'One hour of maths' } },
      { ask: 'write', label, path: 'offer/maths', body: null },
      { ask: 'write', label: 'tutoring/new', path: 'profile', body: { market: 'tutoring', role: 'new' } },
      { ask: 'write', label, to: bob.address, body: { text: 'Is Tuesday at six free?' } },
      { ask: 'pay', label, to: bob.address, amount: '30', currency: 'USD' },
      { ask: 'pay', label, to: `${bob.address}/offer/maths`, amount: '0.5', currency: 'USDC' },
    ]
    for (const ask of asks) assert.deepEqual(checkAsk(JSON.parse(JSON.stringify(ask))), ask, JSON.stringify(ask))
  })

  test('refused: a field it does not know, a shape that is no ask', () => {
    const bad: [string, unknown][] = [
      ['no ask', { label }],
      ['an ask the standard does not name', { ask: 'post', label, path: 'offer/a', body: {} }],
      ['a field on a read', { ask: 'read', label, path: 'offer/a', after: 5 }],
      ['a path with no label', { ask: 'read', path: 'offer/a' }],
      ['the inbox with no label', { ask: 'read', inbox: true }],
      ['a label with no path and no inbox', { ask: 'read', label }],
      ['a path and the inbox', { ask: 'read', label, path: 'offer/a', inbox: true }],
      ['inbox as text', { ask: 'read', label, inbox: 'yes' }],
      ['a path that is no path', { ask: 'read', label, path: 'Offer/A' }],
      ['a label that is no text', { ask: 'read', label: 7, path: 'offer/a' }],
      ['a write with no label', { ask: 'write', path: 'offer/a', body: {} }],
      ['a write with no path', { ask: 'write', label, body: {} }],
      ['a write with a path and to', { ask: 'write', label, path: 'offer/a', to: bob.address, body: {} }],
      ['a body that is no object', { ask: 'write', label, path: 'offer/a', body: 'text' }],
      ['a body with a key the records do not take', { ask: 'write', label, path: 'offer/a', body: { Bad: 1 } }],
      ['a message to no address', { ask: 'write', label, to: 'bob', body: { text: 'hi' } }],
      ['a message with no body', { ask: 'write', label, to: bob.address, body: null }],
      ['a pay with no label', { ask: 'pay', to: bob.address, amount: '1', currency: 'USD' }],
      ['a pay to nothing', { ask: 'pay', label, to: 'bob', amount: '1', currency: 'USD' }],
      ['an amount as a number', { ask: 'pay', label, to: bob.address, amount: 1, currency: 'USD' }],
      ['an amount with seven places', { ask: 'pay', label, to: bob.address, amount: '0.0000001', currency: 'USD' }],
      ['no currency', { ask: 'pay', label, to: bob.address, amount: '1' }],
      ['a field on a pay', { ask: 'pay', label, to: bob.address, amount: '1', currency: 'USD', memo: 'x' }],
      ['an ask that is no object', 'read'],
    ]
    for (const [why, ask] of bad) assert.throws(() => checkAsk(ask), code('ask'), why)
  })

  test('a post’s full address: its profile’s address, a slash, its path', () => {
    assert.deepEqual(postAddressOf(`${alice.address}/offer/maths`), { profile: alice.address, path: 'offer/maths' })
    for (const text of [alice.address, `${alice.address}/`, `${alice.address}/Offer`, `x/offer/maths`, 7]) assert.equal(postAddressOf(text), null, String(text))
  })
})

describe('answers', () => {
  const list: Ask = { ask: 'read' }
  const record: Ask = { ask: 'read', label, path: 'offer/maths' }
  const inbox: Ask = { ask: 'read', label, inbox: true }
  const write: Ask = { ask: 'write', label, path: 'offer/maths', body: null }

  test('done: only the fields the standard names for the ask', () => {
    const profiles = [{ label, can: ['read', 'write'], limit: { amount: '25', currency: 'USD', per: 'day' }, until: T0 }, { label: 'tutoring/buyer', can: [] }]
    assert.deepEqual(checkAnswer({ status: 'done', profiles: profiles.map((p) => ({ ...p, address: alice.address })), address: alice.address }, list), { status: 'done', profiles })
    assert.deepEqual(checkAnswer({ status: 'done', body: { about: 'maths' }, time: T0, path: 'offer/maths', profile: alice.address }, record), { status: 'done', body: { about: 'maths' }, time: T0 })
    assert.deepEqual(checkAnswer({ status: 'done', body: null }, record), { status: 'done', body: null }, 'nothing there')
    const messages = [{ from: bob.address, time: T0, body: { text: 'hi' } }, { fromLabel: 'tutoring/buyer', time: T0 + 1, body: { text: 'from my other profile' } }]
    assert.deepEqual(checkAnswer({ status: 'done', messages: messages.map((m) => ({ ...m, to: alice.address, id: 'x' })) }, inbox), { status: 'done', messages })
    assert.deepEqual(checkAnswer({ status: 'done', profile: alice.address }, write), { status: 'done' }, 'a write returns nothing more')
  })

  test('waiting carries an https link and why, if any; refused carries why', () => {
    assert.deepEqual(checkAnswer({ status: 'waiting' }, write), { status: 'waiting' })
    assert.deepEqual(checkAnswer({ status: 'waiting', link: 'https://app.example/yes/1', why: 'a profile record', extra: 1 }, write), { status: 'waiting', link: 'https://app.example/yes/1', why: 'a profile record' })
    assert.deepEqual(checkAnswer({ status: 'refused', why: 'no profile under that label' }, write), { status: 'refused', why: 'no profile under that label' })
  })

  test('refused as answers: anything else', () => {
    const bad: [string, unknown, Ask][] = [
      ['no status', {}, write],
      ['a status the standard does not name', { status: 'approval', link: 'https://app.example' }, write],
      ['a link that is not https', { status: 'waiting', link: 'http://app.example/yes' }, write],
      ['refused with no why', { status: 'refused' }, write],
      ['a list with no profiles', { status: 'done' }, list],
      ['a profile with no label', { status: 'done', profiles: [{ can: [] }] }, list],
      ['a record read with no body', { status: 'done' }, record],
      ['a message from an address and a label', { status: 'done', messages: [{ from: bob.address, fromLabel: label, time: T0, body: {} }] }, inbox],
      ['a message from no address', { status: 'done', messages: [{ from: 'bob', time: T0, body: {} }] }, inbox],
      ['a message with no time', { status: 'done', messages: [{ from: bob.address, body: {} }] }, inbox],
    ]
    for (const [why, answer, ask] of bad) assert.throws(() => checkAnswer(answer, ask), code('answer'), why)
  })

  test('leaveOut: every field and item that holds an address of the person’s own goes, and nothing else', async () => {
    const pay = await payAddresses(SEED, label)
    const own = [alice.address, pay.solana, pay.evm]
    const body = {
      market: 'tutoring',
      role: 'seller',
      pay: { solana: pay.solana, evm: pay.evm },
      offer: `${alice.address}/offer/maths`,
      subject: bob.address,
      notes: ['plain', alice.address, { at: pay.evm, keep: 'yes' }],
    }
    const out = leaveOut({ status: 'done', body }, own) as { body: typeof body }
    assert.deepEqual(out.body.pay, {})
    assert.equal('offer' in out.body, false, 'a post’s full address holds its profile’s address')
    assert.equal(out.body.subject, bob.address, 'someone else’s address stays')
    assert.deepEqual(out.body.notes, ['plain', { keep: 'yes' }])
    assert.ok(!JSON.stringify(out).includes(alice.address) && own.every((a) => !JSON.stringify(out).includes(a)))
    assert.deepEqual(leaveOut({ [alice.address]: 1, ok: 2 }, own), { ok: 2 }, 'a field named by one goes too')
  })
})
