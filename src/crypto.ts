import { Duplex } from "it-pair";
import { NoiseSession } from "./xx";
import { Handshake } from "./handshake";

interface ReturnEncryptionWrapper {
  (source: any): any;
}

// Returns generator that encrypts payload from the user
export function encryptStream(handshake: Handshake, session: NoiseSession): ReturnEncryptionWrapper {
  return async function * (source) {
    for await (const chunk of source) {
      const data = await handshake.encrypt(chunk, session);
      yield data;
    }
  }
}


// Decrypt received payload to the user
export function decryptStream(handshake: Handshake, session: NoiseSession): ReturnEncryptionWrapper {
  return async function * (source) {
    for await (const chunk of source) {
      const decrypted = await handshake.decrypt(chunk, session);
      yield decrypted
    }
  }
}
