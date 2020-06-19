import { keys } from 'libp2p-crypto'
import { KeyPair } from '../src/@types/libp2p'
import PeerId from 'peer-id'

export async function generateEd25519Keys () {
  return await keys.generateKeyPair('ed25519')
}

export function getKeyPairFromPeerId (peerId: PeerId): KeyPair {
  return {
    privateKey: peerId.privKey.marshal().slice(0, 32),
    publicKey: peerId.marshalPubKey()
  }
}
