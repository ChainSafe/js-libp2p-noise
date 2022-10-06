/* eslint-disable import/export */
/* eslint-disable @typescript-eslint/no-namespace */

import { encodeMessage, decodeMessage, message } from 'protons-runtime'
import type { Uint8ArrayList } from 'uint8arraylist'
import type { Codec } from 'protons-runtime'

export interface NoiseExtensions {
  webtransportCerthashes: Uint8Array[]
}

export namespace NoiseExtensions {
  let _codec: Codec<NoiseExtensions>

  export const codec = (): Codec<NoiseExtensions> => {
    if (_codec == null) {
      _codec = message<NoiseExtensions>((obj, writer, opts = {}) => {
        if (opts.lengthDelimited !== false) {
          writer.fork()
        }

        if (obj.webtransportCerthashes != null) {
          for (const value of obj.webtransportCerthashes) {
            writer.uint32(10)
            writer.bytes(value)
          }
        } else {
          throw new Error('Protocol error: required field "webtransportCerthashes" was not found in object')
        }

        if (opts.lengthDelimited !== false) {
          writer.ldelim()
        }
      }, (reader, length) => {
        const obj: any = {
          webtransportCerthashes: []
        }

        const end = length == null ? reader.len : reader.pos + length

        while (reader.pos < end) {
          const tag = reader.uint32()

          switch (tag >>> 3) {
            case 1:
              obj.webtransportCerthashes.push(reader.bytes())
              break
            default:
              reader.skipType(tag & 7)
              break
          }
        }

        return obj
      })
    }

    return _codec
  }

  export const encode = (obj: NoiseExtensions): Uint8Array => {
    return encodeMessage(obj, NoiseExtensions.codec())
  }

  export const decode = (buf: Uint8Array | Uint8ArrayList): NoiseExtensions => {
    return decodeMessage(buf, NoiseExtensions.codec())
  }
}

export interface NoiseHandshakePayload {
  identityKey: Uint8Array
  identitySig: Uint8Array
  extensions?: NoiseExtensions
}

export namespace NoiseHandshakePayload {
  let _codec: Codec<NoiseHandshakePayload>

  export const codec = (): Codec<NoiseHandshakePayload> => {
    if (_codec == null) {
      _codec = message<NoiseHandshakePayload>((obj, writer, opts = {}) => {
        if (opts.lengthDelimited !== false) {
          writer.fork()
        }

        if (obj.identityKey != null) {
          writer.uint32(10)
          writer.bytes(obj.identityKey)
        } else {
          throw new Error('Protocol error: required field "identityKey" was not found in object')
        }

        if (obj.identitySig != null) {
          writer.uint32(18)
          writer.bytes(obj.identitySig)
        } else {
          throw new Error('Protocol error: required field "identitySig" was not found in object')
        }

        if (obj.extensions != null) {
          writer.uint32(34)
          NoiseExtensions.codec().encode(obj.extensions, writer)
        }

        if (opts.lengthDelimited !== false) {
          writer.ldelim()
        }
      }, (reader, length) => {
        const obj: any = {
          identityKey: new Uint8Array(0),
          identitySig: new Uint8Array(0)
        }

        const end = length == null ? reader.len : reader.pos + length

        while (reader.pos < end) {
          const tag = reader.uint32()

          switch (tag >>> 3) {
            case 1:
              obj.identityKey = reader.bytes()
              break
            case 2:
              obj.identitySig = reader.bytes()
              break
            case 4:
              obj.extensions = NoiseExtensions.codec().decode(reader, reader.uint32())
              break
            default:
              reader.skipType(tag & 7)
              break
          }
        }

        if (obj.identityKey == null) {
          throw new Error('Protocol error: value for required field "identityKey" was not found in protobuf')
        }

        if (obj.identitySig == null) {
          throw new Error('Protocol error: value for required field "identitySig" was not found in protobuf')
        }

        return obj
      })
    }

    return _codec
  }

  export const encode = (obj: NoiseHandshakePayload): Uint8Array => {
    return encodeMessage(obj, NoiseHandshakePayload.codec())
  }

  export const decode = (buf: Uint8Array | Uint8ArrayList): NoiseHandshakePayload => {
    return decodeMessage(buf, NoiseHandshakePayload.codec())
  }
}
