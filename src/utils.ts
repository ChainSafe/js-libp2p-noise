import { x25519 } from 'bcrypto';
import * as crypto from 'libp2p-crypto';

import { KeyPair } from "./xx";
import { bytes } from "./types/basic";

export async function generateKeypair() : Promise<KeyPair> {
  const privateKey = x25519.privateKeyGenerate();
  const publicKey = x25519.publicKeyCreate(privateKey);

  return {
    publicKey,
    privateKey,
  }
}

export async function signPayload(privateKey: bytes, payload: bytes) {
  const Ed25519PrivateKey = crypto.keys.supportedKeys.ed25519.Ed25519PrivateKey;
  // const ed25519 = Ed25519PrivateKey(privateKey, "need-to-get-public-key");
  // return ed25519.sign(privateKey, payload);
}
