import { Noise } from './noise.js'
import type { NoiseInit } from './noise.js'
import type { NoiseExtensions } from './proto/payload.js'
import type { ComponentLogger, ConnectionEncrypter, Metrics, PeerId, PrivateKey } from '@libp2p/interface'
export type { ICryptoInterface } from './crypto.js'
export { pureJsCrypto } from './crypto/js.js'

export interface NoiseComponents {
  peerId: PeerId
  privateKey: PrivateKey
  logger: ComponentLogger
  metrics?: Metrics
}

export function noise (init: NoiseInit = {}): (components: NoiseComponents) => ConnectionEncrypter<NoiseExtensions> {
  return (components: NoiseComponents) => new Noise(components, init)
}
