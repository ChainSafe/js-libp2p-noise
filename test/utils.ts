import { keys } from '@libp2p/crypto'
import type { PrivateKey } from '@libp2p/interfaces/keys'
import type { KeyPair } from '../src/@types/libp2p.js'
import type { PeerId } from '@libp2p/interfaces/peer-id'
import { Buffer } from 'buffer'

export async function generateEd25519Keys (): Promise<PrivateKey> {
  return await keys.generateKeyPair('Ed25519', 32)
}

export function getKeyPairFromPeerId (peerId: PeerId): KeyPair {
  if (peerId.privateKey == null || peerId.publicKey == null) {
    throw new Error('PrivateKey or PublicKey missing from PeerId')
  }

  return {
    privateKey: Buffer.from(peerId.privateKey.slice(0, 32)),
    publicKey: Buffer.from(peerId.publicKey)
  }
}
