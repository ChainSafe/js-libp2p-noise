import { Duplex } from "it-pair";
import { Handshake } from "./handshake";

interface ReturnEncryptionWrapper {
  (source: any): any;
}

// Returns generator that encrypts payload from the user
export function encryptStream(handshake: Handshake): ReturnEncryptionWrapper {
  return async function * (source) {
    for await (const chunk of source) {
      const data = await handshake.encrypt(chunk, handshake.session);
      yield data;
    }
  }
}


// Decrypt received payload to the user
export function decryptStream(handshake: Handshake): ReturnEncryptionWrapper {
  return async function * (source) {
    for await (const chunk of source) {
      const decrypted = await handshake.decrypt(chunk, handshake.session);
      yield decrypted
    }
  }
}
