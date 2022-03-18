import type { ConnectionEncrypter } from '@libp2p/interfaces/connection-encrypter'
import type { bytes, bytes32 } from './basic.js'

export interface KeyPair {
  publicKey: bytes32
  privateKey: bytes32
}

export interface INoiseConnection extends ConnectionEncrypter {
  remoteEarlyData?: () => bytes
}
