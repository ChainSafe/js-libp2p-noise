import { Duplex } from "it-pair";
import { NoiseSession } from "./xx";
import { Handshake } from "./handshake";

interface IReturnEncryptionWrapper {
  (source: any): any;
}

// Returns generator that encrypts payload from the user
export function encryptStream(handshake: Handshake, session: NoiseSession) : IReturnEncryptionWrapper {
  return async function * (source) {
    for await (const chunk of source) {
      console.log("chunk: ", chunk);
      const data = await handshake.encrypt(chunk, session);
      console.log("encrypted: ", data);
      yield data;
    }
  }
}


// Decrypt received payload to the user
export function decryptStream(handshake: Handshake, session: NoiseSession) : IReturnEncryptionWrapper {
  return async function * (source) {
    for await (const chunk of source) {
      console.log("Going to decrypt chunk: ", chunk)
      const decrypted = await handshake.decrypt(chunk, session);
      console.log("Decrypted: ", decrypted)
      yield decrypted
    }
  }
}
