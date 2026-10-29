// Test helpers: real HTTP hosts on loopback ports, and a clock tests can move.

import { TestHost } from './host.ts'

export async function startHost(options: { now?: () => number } = {}): Promise<TestHost> {
  const host = new TestHost(options)
  await host.listen()
  return host
}

export class Clock {
  t: number
  constructor(t: number) {
    this.t = t
  }
  now = () => this.t
  advance(ms: number) {
    this.t += ms
    return this.t
  }
}
