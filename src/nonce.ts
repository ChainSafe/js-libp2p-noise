import type { bytes, uint64 } from './@types/basic'

export const MIN_NONCE = 0
// For performance reasons, the nonce is represented as a JS `number`
// JS `number` can only safely represent integers up to 2 ** 53 - 1
// This is a slight deviation from the noise spec, which describes the max nonce as 2 ** 64 - 2
// The effect is that this implementation will need a new handshake to be performed after fewer messages are exchanged than other implementations with full uint64 nonces.
// 2 ** 53 - 1 is still a large number of messages, so the practical effect of this is negligible.
export const MAX_NONCE = Number.MAX_SAFE_INTEGER

const ERR_MAX_NONCE = 'Cipherstate has reached maximum n, a new handshake must be performed'

/**
 * The nonce is an uint that's increased over time.
 * Maintaining different representations help improve performance.
 */
export class Nonce {
  private n: uint64
  private readonly bytes: bytes
  private readonly view: DataView

  constructor (n = MIN_NONCE) {
    this.n = n
    this.bytes = new Uint8Array(12)
    this.view = new DataView(this.bytes.buffer, this.bytes.byteOffset, this.bytes.byteLength)
    this.view.setUint32(4, n, true)
  }

  increment (): void {
    this.n++
    // Even though we're treating the nonce as 8 bytes, RFC7539 specifies 12 bytes for a nonce.
    this.view.setUint32(4, this.n, true)
  }

  getBytes (): bytes {
    return this.bytes
  }

  getUint64 (): uint64 {
    return this.n
  }

  assertValue (): void {
    if (this.n > MAX_NONCE) {
      throw new Error(ERR_MAX_NONCE)
    }
  }
}
