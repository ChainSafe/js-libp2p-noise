/**
 * ML-KEM-768 WASM backend — currently stubbed to pure-JS noble.
 *
 * The WASM binary was compiled for X-Wing. To restore WASM acceleration after
 * migration, update src-wasm/src/lib.rs to export mlkem768_keygen/encapsulate/
 * decapsulate and run `pnpm run build:wasm`.
 *
 * The stub exports satisfy all callers without behavioural change — wire
 * format is identical to pqcKem since both use the same ML-KEM-768 operations.
 */

import { pureJsCrypto } from './js.js'
import { pqcKem } from './pqc.js'
import type { ICryptoInterface } from '../crypto.js'
import type { IKem } from '../kem.js'

export async function initWasmKem (): Promise<void> {
  // No-op: pure-JS backend needs no initialisation.
}

export const pqcKemWasm: IKem = pqcKem

export const pqcCryptoWasm: ICryptoInterface & IKem = {
  ...pureJsCrypto,
  ...pqcKem
}
