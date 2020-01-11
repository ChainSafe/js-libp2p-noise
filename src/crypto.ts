import { Buffer } from "buffer";
import {IHandshake} from "./@types/handshake-interface";

interface IReturnEncryptionWrapper {
  (source: Iterable<Uint8Array>): AsyncIterableIterator<Uint8Array>;
}

const maxPlaintextLength = 65519;

// Returns generator that encrypts payload from the user
export function encryptStream(handshake: IHandshake): IReturnEncryptionWrapper {
  return async function * (source) {
    for await (const chunk of source) {
      const chunkBuffer = Buffer.from(chunk.buffer, chunk.byteOffset, chunk.length);

      for (let i = 0; i < chunkBuffer.length; i += maxPlaintextLength) {
        let end = i + maxPlaintextLength;
        if (end > chunkBuffer.length) {
          end = chunkBuffer.length;
        }

        const data = handshake.encrypt(chunkBuffer.slice(i, end), handshake.session);
        yield data;
      }
    }
  }
}


// Decrypt received payload to the user
export function decryptStream(handshake: IHandshake): IReturnEncryptionWrapper {
  return async function * (source) {
    for await (const chunk of source) {
      const chunkBuffer = Buffer.from(chunk.buffer, chunk.byteOffset, chunk.length);

      for (let i = 0; i < chunkBuffer.length; i += maxPlaintextLength) {
        let end = i + maxPlaintextLength;
        if (end > chunkBuffer.length) {
          end = chunkBuffer.length;
        }

        const chunk = chunkBuffer.slice(i, end);
        const decrypted = await handshake.decrypt(chunk, handshake.session);
        yield decrypted;
      }
    }
  }
}
