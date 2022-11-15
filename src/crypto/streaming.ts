import type { Transform } from 'it-stream-types'
import type { Uint8ArrayList } from 'uint8arraylist'
import type { IHandshake } from '../@types/handshake-interface.js'
import type { MetricsRegistry } from '../metrics.js'
import { NOISE_MSG_MAX_LENGTH_BYTES, NOISE_MSG_MAX_LENGTH_BYTES_WITHOUT_TAG } from '../constants.js'
import { uint16BEEncode } from '../encoder.js'

// Returns generator that encrypts payload from the user
export function encryptStream (handshake: IHandshake, metrics?: MetricsRegistry): Transform<Uint8Array> {
  return async function * (source) {
    for await (const chunk of source) {
      for (let i = 0; i < chunk.length; i += NOISE_MSG_MAX_LENGTH_BYTES_WITHOUT_TAG) {
        let end = i + NOISE_MSG_MAX_LENGTH_BYTES_WITHOUT_TAG
        if (end > chunk.length) {
          end = chunk.length
        }

        const data = handshake.encrypt(chunk.subarray(i, end), handshake.session)
        metrics?.encryptedPackets.increment()

        yield uint16BEEncode(data.byteLength)
        yield data
      }
    }
  }
}

// Decrypt received payload to the user
export function decryptStream (handshake: IHandshake, metrics?: MetricsRegistry): Transform<Uint8ArrayList, Uint8Array> {
  return async function * (source) {
    for await (const chunk of source) {
      for (let i = 0; i < chunk.length; i += NOISE_MSG_MAX_LENGTH_BYTES) {
        let end = i + NOISE_MSG_MAX_LENGTH_BYTES
        if (end > chunk.length) {
          end = chunk.length
        }

        const { plaintext: decrypted, valid } = handshake.decrypt(chunk.subarray(i, end), handshake.session)
        if (!valid) {
          metrics?.decryptErrors.increment()
          throw new Error('Failed to validate decrypted chunk')
        }
        metrics?.decryptedPackets.increment()
        yield decrypted
      }
    }
  }
}
