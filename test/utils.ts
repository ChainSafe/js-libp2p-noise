import * as crypto from 'libp2p-crypto';

export async function generateEd25519Keys() {
  return await crypto.keys.generateKeyPair('ed25519');
}
