import { keys, PrivateKey } from 'libp2p-crypto'
import { KeyPair } from '../src/@types/libp2p'
import PeerId from 'peer-id'
import { Buffer } from 'buffer'

export async function generateEd25519Keys (): Promise<PrivateKey> {
  return await keys.generateKeyPair('Ed25519', 32)
}

export function getKeyPairFromPeerId (peerId: PeerId): KeyPair {
  return {
    privateKey: Buffer.from(peerId.privKey.marshal().slice(0, 32)),
    publicKey: Buffer.from(peerId.marshalPubKey())
  }
}
