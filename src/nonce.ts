import type { bytes, uint64 } from './@types/basic'

/**
 * The nonce is an uint that's increased over time.
 * Maintaining different representations help improve performance.
 */
export class Nonce {
  private n: uint64
  private readonly bytes: bytes
  private readonly view: DataView

  constructor (n: uint64) {
    this.n = n
    this.bytes = new Uint8Array(12)
    this.view = new DataView(this.bytes.buffer, this.bytes.byteOffset, this.bytes.byteLength)
    this.view.setUint32(4, n, true)
  }

  increase (): void {
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
}
