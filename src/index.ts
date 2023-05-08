import { Noise } from './noise.js'
import type { NoiseInit } from './noise.js'
import type { NoiseExtensions } from './proto/payload.js'
import type { ConnectionEncrypter } from '@libp2p/interface-connection-encrypter'
export * from './crypto.js'
export * from './crypto/stablelib.js'

export function noise (init: NoiseInit = {}): () => ConnectionEncrypter<NoiseExtensions> {
  return () => new Noise(init)
}
