import type { Transform } from 'it-stream-types'
import type { Uint8ArrayList } from 'uint8arraylist'
import type { IHandshake } from '../@types/handshake-interface.js'
import { NOISE_MSG_MAX_LENGTH_BYTES, NOISE_MSG_MAX_LENGTH_BYTES_WITHOUT_TAG } from '../constants.js'

// Returns generator that encrypts payload from the user
export function encryptStream (handshake: IHandshake): Transform<Uint8Array> {
  return async function * (source) {
    for await (const chunk of source) {
      for (let i = 0; i < chunk.length; i += NOISE_MSG_MAX_LENGTH_BYTES_WITHOUT_TAG) {
        let end = i + NOISE_MSG_MAX_LENGTH_BYTES_WITHOUT_TAG
        if (end > chunk.length) {
          end = chunk.length
        }

        const data = handshake.encrypt(chunk.subarray(i, end), handshake.session)
        yield data
      }
    }
  }
}

// Decrypt received payload to the user
export function decryptStream (handshake: IHandshake): Transform<Uint8ArrayList, Uint8Array> {
  return async function * (source) {
    for await (const chunk of source) {
      for (let i = 0; i < chunk.length; i += NOISE_MSG_MAX_LENGTH_BYTES) {
        let end = i + NOISE_MSG_MAX_LENGTH_BYTES
        if (end > chunk.length) {
          end = chunk.length
        }

        const { plaintext: decrypted, valid } = await handshake.decrypt(chunk.subarray(i, end), handshake.session)
        if (!valid) {
          throw new Error('Failed to validate decrypted chunk')
        }
        yield decrypted
      }
    }
  }
}
