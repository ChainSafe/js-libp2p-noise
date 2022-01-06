import { IHandshake } from './@types/handshake-interface'
import { NOISE_MSG_MAX_LENGTH_BYTES, NOISE_MSG_MAX_LENGTH_BYTES_WITHOUT_TAG } from './constants'

interface IReturnEncryptionWrapper {
  (source: Iterable<Uint8Array>): AsyncIterableIterator<Uint8Array>
}

// Returns generator that encrypts payload from the user
export function encryptStream (handshake: IHandshake): IReturnEncryptionWrapper {
  return async function * (source) {
    for await (const chunk of source) {
      for (let i = 0; i < chunk.length; i += NOISE_MSG_MAX_LENGTH_BYTES_WITHOUT_TAG) {
        let end = i + NOISE_MSG_MAX_LENGTH_BYTES_WITHOUT_TAG
        if (end > chunk.length) {
          end = chunk.length
        }

        const data = handshake.encrypt(chunk.slice(i, end), handshake.session)
        yield data
      }
    }
  }
}

// Decrypt received payload to the user
export function decryptStream (handshake: IHandshake): IReturnEncryptionWrapper {
  return async function * (source) {
    for await (const chunk of source) {
      for (let i = 0; i < chunk.length; i += NOISE_MSG_MAX_LENGTH_BYTES) {
        let end = i + NOISE_MSG_MAX_LENGTH_BYTES
        if (end > chunk.length) {
          end = chunk.length
        }

        const { plaintext: decrypted, valid } = await handshake.decrypt(chunk.slice(i, end), handshake.session)
        if (!valid) {
          throw new Error('Failed to validate decrypted chunk')
        }
        yield decrypted
      }
    }
  }
}
