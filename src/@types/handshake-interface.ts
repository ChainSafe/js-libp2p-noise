import type { bytes } from './basic.js'
import type { NoiseSession } from './handshake.js'
import type { PeerId } from '@libp2p/interfaces/peer-id'

export interface IHandshake {
  session: NoiseSession
  remotePeer: PeerId
  remoteEarlyData: bytes
  encrypt: (plaintext: bytes, session: NoiseSession) => bytes
  decrypt: (ciphertext: bytes, session: NoiseSession) => {plaintext: bytes, valid: boolean}
}
