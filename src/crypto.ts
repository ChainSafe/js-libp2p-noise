import { Handshake } from "./handshake";
import { Buffer } from "buffer";

interface ReturnEncryptionWrapper {
  (source: Iterable<Uint8Array>): AsyncIterableIterator<Uint8Array>;
}

// Returns generator that encrypts payload from the user
export function encryptStream(handshake: Handshake): ReturnEncryptionWrapper {
  return async function * (source) {
    for await (const chunk of source) {
      const chunkBuffer = Buffer.from(chunk);
      const data = await handshake.encrypt(chunkBuffer, handshake.session);
      yield data;
    }
  }
}


// Decrypt received payload to the user
export function decryptStream(handshake: Handshake): ReturnEncryptionWrapper {
  return async function * (source) {
    for await (const chunk of source) {
      const chunkBuffer = Buffer.from(chunk);
      const decrypted = await handshake.decrypt(chunkBuffer, handshake.session);
      yield decrypted
    }
  }
}
