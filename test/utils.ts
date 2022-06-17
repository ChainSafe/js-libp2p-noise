import { keys } from '@libp2p/crypto'
import type { PrivateKey } from '@libp2p/interface-keys'
import type { PeerId } from '@libp2p/interface-peer-id'
import { Buffer } from 'buffer'
import type { KeyPair } from '../src/@types/libp2p.js'

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
