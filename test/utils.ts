import * as crypto from 'libp2p-crypto';
import {KeyPair, PeerId} from "../src/@types/libp2p";

export async function generateEd25519Keys() {
  return await crypto.keys.generateKeyPair('ed25519');
}

export function getKeyPairFromPeerId(peerId: PeerId): KeyPair {
  return {
    privateKey: peerId.privKey.marshal().slice(0, 32),
    publicKey: peerId.marshalPubKey(),
  }
}
