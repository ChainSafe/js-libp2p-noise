import { concat as uint8ArrayConcat } from 'uint8arrays/concat'
import type { Uint8ArrayList } from 'uint8arraylist'
import type { bytes } from './@types/basic.js'
import type { MessageBuffer } from './@types/handshake.js'

const allocUnsafe = (len: number): Uint8Array => {
  if (globalThis.Buffer) {
    return globalThis.Buffer.allocUnsafe(len)
  }

  return new Uint8Array(len)
}

export const uint16BEEncode = (value: number, target?: Uint8Array, offset?: number): Uint8Array => {
  target = target ?? allocUnsafe(2)
  new DataView(target.buffer, target.byteOffset, target.byteLength).setUint16(offset ?? 0, value, false)
  return target
}
uint16BEEncode.bytes = 2

export const uint16BEDecode = (data: Uint8Array | Uint8ArrayList): number => {
  if (data.length < 2) throw RangeError('Could not decode int16BE')

  if (data instanceof Uint8Array) {
    return new DataView(data.buffer, data.byteOffset, data.byteLength).getUint16(0, false)
  }

  return data.getUint16(0)
}
uint16BEDecode.bytes = 2

// Note: IK and XX encoder usage is opposite (XX uses in stages encode0 where IK uses encode1)

export function encode0 (message: MessageBuffer): bytes {
  return uint8ArrayConcat([message.ne, message.ciphertext], message.ne.length + message.ciphertext.length)
}

export function encode1 (message: MessageBuffer): bytes {
  return uint8ArrayConcat([message.ne, message.ns, message.ciphertext], message.ne.length + message.ns.length + message.ciphertext.length)
}

export function encode2 (message: MessageBuffer): bytes {
  return uint8ArrayConcat([message.ns, message.ciphertext], message.ns.length + message.ciphertext.length)
}

export function decode0 (input: bytes): MessageBuffer {
  if (input.length < 32) {
    throw new Error('Cannot decode stage 0 MessageBuffer: length less than 32 bytes.')
  }

  return {
    ne: input.slice(0, 32),
    ciphertext: input.slice(32, input.length),
    ns: new Uint8Array(0)
  }
}

export function decode1 (input: bytes): MessageBuffer {
  if (input.length < 80) {
    throw new Error('Cannot decode stage 1 MessageBuffer: length less than 80 bytes.')
  }

  return {
    ne: input.slice(0, 32),
    ns: input.slice(32, 80),
    ciphertext: input.slice(80, input.length)
  }
}

export function decode2 (input: bytes): MessageBuffer {
  if (input.length < 48) {
    throw new Error('Cannot decode stage 2 MessageBuffer: length less than 48 bytes.')
  }

  return {
    ne: new Uint8Array(0),
    ns: input.slice(0, 48),
    ciphertext: input.slice(48, input.length)
  }
}
