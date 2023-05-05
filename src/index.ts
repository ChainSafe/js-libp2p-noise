import type { ConnectionEncrypter } from '@libp2p/interface-connection-encrypter'
import { Noise } from './noise.js'
import type { NoiseInit } from './noise.js'
import type { NoiseExtensions } from './proto/payload.js'
export { ICryptoInterface } from './crypto.js'
export { pureJsCrypto } from './crypto/js.js'

export function noise (init: NoiseInit = {}): () => ConnectionEncrypter<NoiseExtensions> {
  return () => new Noise(init)
}
