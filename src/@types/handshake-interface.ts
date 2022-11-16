import type { PeerId } from '@libp2p/interface-peer-id'
import type { bytes } from './basic.js'
import type { NoiseSession } from './handshake.js'
import type { NoiseExtensions } from '../proto/payload.js'

export interface IHandshake {
  session: NoiseSession
  remotePeer: PeerId
  remoteExtensions: NoiseExtensions
  encrypt: (plaintext: bytes, session: NoiseSession) => bytes
  decrypt: (ciphertext: bytes, session: NoiseSession, dst?: Uint8Array) => { plaintext: bytes, valid: boolean }
}
