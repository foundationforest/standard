// snarkjs ships no types. Only the two calls the client makes are declared.
declare module 'snarkjs' {
  export const groth16: {
    fullProve(
      input: Record<string, unknown>,
      wasm: string | Uint8Array,
      zkey: string | Uint8Array,
    ): Promise<{ proof: unknown; publicSignals: string[] }>
    verify(verificationKey: unknown, publicSignals: string[], proof: unknown): Promise<boolean>
  }
}
