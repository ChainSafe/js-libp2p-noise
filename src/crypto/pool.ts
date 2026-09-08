/**
 * KemKeypairPool — pre-computes KEM keypairs during idle time so the
 * keygen cost (~3 ms for ML-KEM-768 on pure-JS) does not fall on the connection
 * critical path.
 *
 * Design:
 *   - At construction the pool is synchronously filled to `minSize`.
 *   - `acquire()` pops one keypair and schedules a refill via queueMicrotask
 *     when the pool drops below `minSize`. The refill runs after the current
 *     microtask queue drains, so it doesn't block the handshake.
 *   - Works with any IKem backend (noble, WASM, future native).
 *   - Zero cryptographic tradeoff: each keypair is used exactly once.
 *
 * Usage:
 *   const pool = new KemKeypairPool(pqcKem, { minSize: 4 })
 *   // ...in the handshake initiator:
 *   const { publicKey, secretKey } = pool.acquire()
 */

import type { IKem, KemKeyPair } from '../kem.js'

interface KemKeypairPoolOptions {
  /**
   * Minimum pool depth. When the pool drops below this, a background refill
   * runs via queueMicrotask. Default: 3.
   */
  minSize?: number
}

export class KemKeypairPool {
  private readonly pool: KemKeyPair[] = []
  private readonly kem: IKem
  private readonly minSize: number
  private refillScheduled = false

  constructor (kem: IKem, { minSize = 3 }: KemKeypairPoolOptions = {}) {
    this.kem = kem
    this.minSize = minSize
    // Fill synchronously at construction — pays the keygen cost up front,
    // before any connection is established.
    this.fill()
  }

  /**
   * Acquire a pre-generated keypair from the pool. If the pool is unexpectedly
   * empty (pool was never filled or was exhausted faster than refills could run),
   * generates one synchronously as a fallback.
   */
  acquire (): KemKeyPair {
    const kp = this.pool.pop() ?? this.kem.generateKemKeyPair()
    this.scheduleRefill()
    return kp
  }

  /** Current number of ready keypairs. Exposed for monitoring/testing. */
  get size (): number {
    return this.pool.length
  }

  private fill (): void {
    while (this.pool.length < this.minSize) {
      this.pool.push(this.kem.generateKemKeyPair())
    }
  }

  private scheduleRefill (): void {
    if (this.pool.length >= this.minSize || this.refillScheduled) return
    this.refillScheduled = true
    queueMicrotask(() => {
      this.refillScheduled = false
      this.fill()
    })
  }
}
