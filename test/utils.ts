import { keys } from '@libp2p/crypto'
import type { PrivateKey } from '@libp2p/interface-keys'
import type { PeerId } from '@libp2p/interface-peer-id'
import type { KeyPair } from '../src/@types/libp2p.js'

export async function generateEd25519Keys (): Promise<PrivateKey> {
  return await keys.generateKeyPair('Ed25519', 32)
}

export function getKeyPairFromPeerId (peerId: PeerId): KeyPair {
  if (peerId.privateKey == null || peerId.publicKey == null) {
    throw new Error('PrivateKey or PublicKey missing from PeerId')
  }

  return {
    privateKey: peerId.privateKey.subarray(0, 32),
    publicKey: peerId.publicKey
  }
}
