import * as crypto from 'libp2p-crypto';
import {KeyPair, PeerId} from "../src/@types/libp2p";
import {bytes} from "../src/@types/basic";

export async function generateEd25519Keys() {
  return await crypto.keys.generateKeyPair('ed25519');
}

export function getKeyPairFromPeerId(peerId: PeerId): KeyPair {
  return {
    privateKey: peerId.privKey.marshal().slice(0, 32),
    publicKey: peerId.marshalPubKey(),
  }
}

export function getRandomBuffer(size: number) : bytes {
  size = Math.max(1, size<<0);

    const buf = Buffer.alloc(size);
    let i = 0;
    for (; i < size; ++i) {
      buf[i] = (Math.random() * 0xFF) << 0;
    }

    return buf;
}
