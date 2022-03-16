import type { bytes, bytes32 } from './basic.js'
import type { ConnectionEncrypter } from '@libp2p/interfaces/connection-encrypter'

export interface KeyPair {
  publicKey: bytes32
  privateKey: bytes32
}

export interface INoiseConnection extends ConnectionEncrypter {
  remoteEarlyData?: () => bytes
}
