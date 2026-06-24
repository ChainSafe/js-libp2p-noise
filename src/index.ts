/**
 * @packageDocumentation
 *
 * This package contains a TypeScript implementation of the Noise protocol for use in libp2p. It ships two connection encrypters:
 *
 * - `noise()` - classical `Noise_XX_25519_ChaChaPoly_SHA256`, the default libp2p encryption
 * - `noiseHFS()` - post-quantum hybrid `Noise_XXhfs_25519+ML-KEM-768_ChaChaPoly_SHA256` (quantum-safe forward secrecy via ML-KEM-768)
 *
 * ## Usage (classical)
 *
 * Install with `pnpm add @chainsafe/libp2p-noise` or `npm i @chainsafe/libp2p-noise`.
 *
 * ```ts
 * import { createLibp2p } from 'libp2p'
 * import { noise } from '@chainsafe/libp2p-noise'
 *
 * const libp2p = await createLibp2p({
 *   connectionEncrypters: [noise()],
 *   // ... other options
 * })
 * ```
 *
 * See the [NoiseInit](https://github.com/ChainSafe/js-libp2p-noise/blob/master/src/noise.ts#L22-L30) interface for configuration options.
 *
 * ## Usage (post-quantum hybrid)
 *
 * Swap `noise()` for `noiseHFS()` to use the XXhfs handshake pattern. Both peers must use `noiseHFS` -- it is not backward-compatible with the classical `/noise` protocol because the handshake message layout differs.
 *
 * ```ts
 * import { createLibp2p } from 'libp2p'
 * import { noiseHFS } from '@chainsafe/libp2p-noise'
 *
 * const libp2p = await createLibp2p({
 *   connectionEncrypters: [noiseHFS()],
 *   // ... other options
 * })
 * ```
 *
 * The libp2p protocol ID is `/noise-mlkem768-hfs/0.1.0`. Connections negotiated with `noiseHFS()` have quantum-safe forward secrecy: the handshake is secure if either X25519 or ML-KEM-768 is unbroken.
 *
 * ### Custom KEM backend
 *
 * You can swap in a different KEM by passing a `kemBackend` that conforms to `IKem`:
 *
 * ```ts
 * import { noiseHFS } from '@chainsafe/libp2p-noise'
 * import type { IKem } from '@chainsafe/libp2p-noise'
 *
 * const myKem: IKem = { ... }
 *
 * const libp2p = await createLibp2p({
 *   connectionEncrypters: [noiseHFS({ kemBackend: myKem })],
 * })
 * ```
 *
 * ## API
 *
 * This module exposes implementations of the [ConnectionEncrypter](https://libp2p.github.io/js-libp2p/interfaces/_libp2p_interface.ConnectionEncrypter.html) interface.
 *
 * ## Bring your own crypto
 *
 * You can provide a custom crypto implementation (instead of the default, based on [@noble](https://paulmillr.com/noble/)) by adding a `crypto` field to the init argument.
 *
 * The implementation must conform to the `ICryptoInterface`, defined in <https://github.com/ChainSafe/js-libp2p-noise/blob/master/src/crypto.ts>
 *
 * ## Protocol spec
 *
 * See [NOISE_HFS_SPEC.md](https://github.com/ChainSafe/js-libp2p-noise/blob/master/NOISE_HFS_SPEC.md) for the full wire format, token ordering, security analysis, and test vector documentation.
 */

import { Noise } from './noise.js'
import type { NoiseInit, NoiseExtensions } from './noise.js'
import type { KeyPair } from './types.js'
import type { ComponentLogger, ConnectionEncrypter, Metrics, PeerId, PrivateKey, Upgrader } from '@libp2p/interface'

export { pureJsCrypto } from './crypto/js.js'
export { pqcKem, pqcCrypto } from './crypto/pqc.js'
export { XXhfsHandshakeState, NOISE_HFS_PROTOCOL_NAME } from './protocol-pqc.js'
export { NoiseHFS, noiseHFS } from './noise-hfs.js'
export type { HfsHandshakeStateInit } from './protocol-pqc.js'
export type { ICryptoInterface } from './crypto.js'
export type { IKem, KemKeyPair, KemEncapsulateResult } from './kem.js'
export type { NoiseHFSInit } from './noise-hfs.js'
export type { HfsHandshakeParams } from './performHandshake-hfs.js'
export type { NoiseInit, NoiseExtensions, KeyPair }

export interface NoiseComponents {
  peerId: PeerId
  privateKey: PrivateKey
  logger: ComponentLogger
  upgrader: Upgrader
  metrics?: Metrics
}

export function noise (init: NoiseInit = {}): (components: NoiseComponents) => ConnectionEncrypter<NoiseExtensions> {
  return (components: NoiseComponents) => new Noise(components, init)
}
