import * as x25519 from '@stablelib/x25519'
import * as SHA256 from '@stablelib/sha256'
import { ChaCha20Poly1305 } from '@stablelib/chacha20poly1305'
import { equals as uint8ArrayEquals } from 'uint8arrays/equals'
import { concat as uint8ArrayConcat } from 'uint8arrays/concat'
import { fromString as uint8ArrayFromString } from 'uint8arrays'

import { bytes, bytes32, uint32 } from '../@types/basic'
import { CipherState, MessageBuffer, SymmetricState } from '../@types/handshake'
import { getHkdf } from '../utils'
import { logger } from '../logger'

export const MIN_NONCE = 0

export abstract class AbstractHandshake {
  public encryptWithAd (cs: CipherState, ad: Uint8Array, plaintext: Uint8Array): bytes {
    const e = this.encrypt(cs.k, cs.n, ad, plaintext)
    this.setNonce(cs, this.incrementNonce(cs.n))

    return e
  }

  public decryptWithAd (cs: CipherState, ad: Uint8Array, ciphertext: Uint8Array): {plaintext: bytes, valid: boolean} {
    const { plaintext, valid } = this.decrypt(cs.k, cs.n, ad, ciphertext)
    this.setNonce(cs, this.incrementNonce(cs.n))

    return { plaintext, valid }
  }

  // Cipher state related
  protected hasKey (cs: CipherState): boolean {
    return !this.isEmptyKey(cs.k)
  }

  protected setNonce (cs: CipherState, nonce: uint32): void {
    cs.n = nonce
  }

  protected createEmptyKey (): bytes32 {
    return new Uint8Array(32)
  }

  protected isEmptyKey (k: bytes32): boolean {
    const emptyKey = this.createEmptyKey()
    return uint8ArrayEquals(emptyKey, k)
  }

  protected incrementNonce (n: uint32): uint32 {
    return n + 1
  }

  protected nonceToBytes (n: uint32): bytes {
    const nonce = new Uint8Array(12)
    new DataView(nonce.buffer, nonce.byteOffset, nonce.byteLength).setUint32(n, 4, true)

    return nonce
  }

  protected encrypt (k: bytes32, n: uint32, ad: Uint8Array, plaintext: Uint8Array): bytes {
    const nonce = this.nonceToBytes(n)
    const ctx = new ChaCha20Poly1305(k)
    return ctx.seal(nonce, plaintext, ad)
  }

  protected encryptAndHash (ss: SymmetricState, plaintext: bytes): bytes {
    let ciphertext
    if (this.hasKey(ss.cs)) {
      ciphertext = this.encryptWithAd(ss.cs, ss.h, plaintext)
    } else {
      ciphertext = plaintext
    }

    this.mixHash(ss, ciphertext)
    return ciphertext
  }

  protected decrypt (k: bytes32, n: uint32, ad: bytes, ciphertext: bytes): {plaintext: bytes, valid: boolean} {
    const nonce = this.nonceToBytes(n)
    const ctx = new ChaCha20Poly1305(k)
    const encryptedMessage = ctx.open(
      nonce,
      ciphertext,
      ad
    )
    if (encryptedMessage) {
      return {
        plaintext: encryptedMessage,
        valid: true
      }
    } else {
      return {
        plaintext: new Uint8Array(0),
        valid: false
      }
    }
  }

  protected decryptAndHash (ss: SymmetricState, ciphertext: bytes): {plaintext: bytes, valid: boolean} {
    let plaintext: bytes; let valid = true
    if (this.hasKey(ss.cs)) {
      ({ plaintext, valid } = this.decryptWithAd(ss.cs, ss.h, ciphertext))
    } else {
      plaintext = ciphertext
    }

    this.mixHash(ss, ciphertext)
    return { plaintext, valid }
  }

  protected dh (privateKey: bytes32, publicKey: bytes32): bytes32 {
    try {
      const derivedU8 = x25519.sharedKey(privateKey, publicKey)

      if (derivedU8.length === 32) {
        return derivedU8
      }

      return derivedU8.slice(0, 32)
    } catch (e: any) {
      logger(e.message)
      return new Uint8Array(32)
    }
  }

  protected mixHash (ss: SymmetricState, data: bytes): void {
    ss.h = this.getHash(ss.h, data)
  }

  protected getHash (a: Uint8Array, b: Uint8Array): bytes32 {
    const u = SHA256.hash(uint8ArrayConcat([a, b], a.length + b.length))
    return u
  }

  protected mixKey (ss: SymmetricState, ikm: bytes32): void {
    const [ck, tempK] = getHkdf(ss.ck, ikm)
    ss.cs = this.initializeKey(tempK)
    ss.ck = ck
  }

  protected initializeKey (k: bytes32): CipherState {
    const n = MIN_NONCE
    return { k, n }
  }

  // Symmetric state related

  protected initializeSymmetric (protocolName: string): SymmetricState {
    const protocolNameBytes = uint8ArrayFromString(protocolName, 'utf-8')
    const h = this.hashProtocolName(protocolNameBytes)

    const ck = h
    const key = this.createEmptyKey()
    const cs: CipherState = this.initializeKey(key)

    return { cs, ck, h }
  }

  protected hashProtocolName (protocolName: Uint8Array): bytes32 {
    if (protocolName.length <= 32) {
      const h = new Uint8Array(32)
      h.set(protocolName)
      return h
    } else {
      return this.getHash(protocolName, new Uint8Array(0))
    }
  }

  protected split (ss: SymmetricState): {cs1: CipherState, cs2: CipherState} {
    const [tempk1, tempk2] = getHkdf(ss.ck, new Uint8Array(0))
    const cs1 = this.initializeKey(tempk1)
    const cs2 = this.initializeKey(tempk2)

    return { cs1, cs2 }
  }

  protected writeMessageRegular (cs: CipherState, payload: bytes): MessageBuffer {
    const ciphertext = this.encryptWithAd(cs, new Uint8Array(0), payload)
    const ne = this.createEmptyKey()
    const ns = new Uint8Array(0)

    return { ne, ns, ciphertext }
  }

  protected readMessageRegular (cs: CipherState, message: MessageBuffer): {plaintext: bytes, valid: boolean} {
    return this.decryptWithAd(cs, new Uint8Array(0), message.ciphertext)
  }
}
