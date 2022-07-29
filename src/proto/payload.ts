/* eslint-disable import/export */
/* eslint-disable @typescript-eslint/no-namespace */

import { encodeMessage, decodeMessage, message, bytes } from 'protons-runtime'
import type { Codec } from 'protons-runtime'
import type { Uint8ArrayList } from 'uint8arraylist'

export namespace pb {
  export interface NoiseHandshakePayload {
    identityKey: Uint8Array
    identitySig: Uint8Array
    data: Uint8Array
  }

  export namespace NoiseHandshakePayload {
    export const codec = (): Codec<NoiseHandshakePayload> => {
      return message<NoiseHandshakePayload>({
        1: { name: 'identityKey', codec: bytes },
        2: { name: 'identitySig', codec: bytes },
        3: { name: 'data', codec: bytes }
      })
    }

    export const encode = (obj: NoiseHandshakePayload): Uint8ArrayList => {
      return encodeMessage(obj, NoiseHandshakePayload.codec())
    }

    export const decode = (buf: Uint8Array | Uint8ArrayList): NoiseHandshakePayload => {
      return decodeMessage(buf, NoiseHandshakePayload.codec())
    }
  }
}
