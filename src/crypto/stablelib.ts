import { HKDF } from '@stablelib/hkdf'
import * as x25519 from '@stablelib/x25519'
import { SHA256, hash } from '@stablelib/sha256'
import { ChaCha20Poly1305 } from '@stablelib/chacha20poly1305'
import type { bytes32, bytes } from '../@types/basic.js'
import type { Hkdf } from '../@types/handshake.js'
import type { KeyPair } from '../@types/libp2p.js'
import type { ICryptoInterface } from '../crypto.js'

export const stablelib: ICryptoInterface = {
  hashSHA256 (data: Uint8Array): Uint8Array {
    return hash(data)
  },

  getHKDF (ck: bytes32, ikm: Uint8Array): Hkdf {
    const hkdf = new HKDF(SHA256, ikm, ck)
    const okmU8Array = hkdf.expand(96)
    const okm = okmU8Array

    const k1 = okm.slice(0, 32)
    const k2 = okm.slice(32, 64)
    const k3 = okm.slice(64, 96)

    return [k1, k2, k3]
  },

  generateX25519KeyPair (): KeyPair {
    const keypair = x25519.generateKeyPair()

    return {
      publicKey: keypair.publicKey,
      privateKey: keypair.secretKey
    }
  },

  generateX25519KeyPairFromSeed (seed: Uint8Array): KeyPair {
    const keypair = x25519.generateKeyPairFromSeed(seed)

    return {
      publicKey: keypair.publicKey,
      privateKey: keypair.secretKey
    }
  },

  generateX25519SharedKey (privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
    return x25519.sharedKey(privateKey, publicKey)
  },

  chaCha20Poly1305Encrypt (plaintext: Uint8Array, nonce: Uint8Array, ad: Uint8Array, k: bytes32): bytes {
    const ctx = new ChaCha20Poly1305(k)

    return ctx.seal(nonce, plaintext, ad)
  },

  chaCha20Poly1305Decrypt (ciphertext: Uint8Array, nonce: Uint8Array, ad: Uint8Array, k: bytes32): bytes | null {
    const ctx = new ChaCha20Poly1305(k)

    return ctx.open(nonce, ciphertext, ad)
  }
}
