/* eslint-disable @typescript-eslint/naming-convention */
import type { bytes, bytes32 } from '../@types/basic.js'
import type { Hkdf } from '../@types/handshake.js'
import type { KeyPair } from '../@types/libp2p.js'
import type { ICryptoInterface } from '../crypto.js'
import sodium from 'sodium-native'

import { concat as uint8ArrayConcat } from 'uint8arrays/concat'

const {
  /* @ts-expect-error */
  crypto_aead_chacha20poly1305_ietf_decrypt,
  /* @ts-expect-error */
  crypto_aead_chacha20poly1305_ietf_encrypt,
  /* @ts-expect-error */
  crypto_aead_chacha20poly1305_ietf_ABYTES,
  crypto_box_keypair,
  crypto_box_PUBLICKEYBYTES,
  crypto_box_SECRETKEYBYTES,
  crypto_box_seed_keypair,
  crypto_hash_sha256,
  crypto_scalarmult,
  crypto_scalarmult_BYTES,
  sodium_malloc,
  sodium_memzero
} = sodium

const hkdfBlockLen = 64
const hkdfHashLen = 32
const hkdfStep1 = new Uint8Array([0x01])
const hkdfStep2 = new Uint8Array([0x02])
const hkdfStep3 = new Uint8Array([0x03])
const hmacBuffer = sodium_malloc(hkdfBlockLen * 3)
const hmacKey = hmacBuffer.subarray(hkdfBlockLen * 0, hkdfBlockLen)
const hmacOuterKeyPad = hmacBuffer.subarray(hkdfBlockLen, hkdfBlockLen * 2)
const hmacInnerKeyPad = hmacBuffer.subarray(hkdfBlockLen * 2, hkdfBlockLen * 3)

/* c8 ignore start */
function hmac (out: Buffer, data: Uint8Array, key: bytes32): void {
  if (key.byteLength > hkdfBlockLen) {
    crypto_hash_sha256(hmacKey.subarray(0, hkdfHashLen), Buffer.from(key))
    sodium_memzero(hmacKey.subarray(hkdfHashLen))
  } else {
    hmacKey.set(key)
    sodium_memzero(hmacKey.subarray(key.byteLength))
  }

  for (let i = 0; i < hmacKey.byteLength; i++) {
    hmacOuterKeyPad[i] = 0x5c ^ hmacKey[i]
    hmacInnerKeyPad[i] = 0x36 ^ hmacKey[i]
  }

  crypto_hash_sha256(out, Buffer.from(uint8ArrayConcat([hmacInnerKeyPad, data])))
  sodium_memzero(hmacInnerKeyPad)
  crypto_hash_sha256(out, Buffer.from(uint8ArrayConcat([hmacOuterKeyPad, out])))
  sodium_memzero(hmacOuterKeyPad)
}

export const sodiumNative: ICryptoInterface = {
  hashSHA256 (data: Uint8Array): Uint8Array {
    const out = sodium_malloc(32)
    crypto_hash_sha256(out, Buffer.from(data))

    return out
  },
  getHKDF (ck: bytes32, ikm: Uint8Array): Hkdf {
    // Extract
    const prk = sodium_malloc(32)
    hmac(prk, ikm, ck)

    // Derive
    const out = sodium_malloc(hkdfHashLen * 3)
    const out1 = out.subarray(0, hkdfHashLen)
    const out2 = out.subarray(hkdfHashLen, hkdfHashLen * 2)
    const out3 = out.subarray(hkdfHashLen * 2, hkdfHashLen * 3)
    hmac(out1, hkdfStep1, prk)
    hmac(out2, uint8ArrayConcat([out1, hkdfStep2]), prk)
    hmac(out3, uint8ArrayConcat([out2, hkdfStep3]), prk)

    return [
      out.slice(0, hkdfHashLen),
      out.slice(hkdfHashLen, hkdfHashLen * 2),
      out.slice(hkdfHashLen * 2, hkdfHashLen * 3)
    ]
  },
  generateX25519KeyPair (): KeyPair {
    const publicKey = sodium_malloc(crypto_box_PUBLICKEYBYTES)
    const privateKey = sodium_malloc(crypto_box_SECRETKEYBYTES)

    crypto_box_keypair(publicKey, privateKey)

    return { publicKey, privateKey }
  },
  generateX25519KeyPairFromSeed (seed: Uint8Array): KeyPair {
    const publicKey = sodium_malloc(crypto_box_PUBLICKEYBYTES)
    const privateKey = sodium_malloc(crypto_box_SECRETKEYBYTES)

    crypto_box_seed_keypair(publicKey, privateKey, Buffer.from(seed))

    return { publicKey, privateKey }
  },
  generateX25519SharedKey (privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
    const shared = sodium_malloc(crypto_scalarmult_BYTES)
    crypto_scalarmult(shared, Buffer.from(privateKey), Buffer.from(publicKey))

    return shared
  },
  chaCha20Poly1305Encrypt (plaintext: Uint8Array, nonce: Uint8Array, ad: Uint8Array, k: bytes32): bytes {
    const out = sodium_malloc(plaintext.length + (crypto_aead_chacha20poly1305_ietf_ABYTES as number))

    crypto_aead_chacha20poly1305_ietf_encrypt(out, plaintext, ad, null, nonce, k)

    return out
  },
  chaCha20Poly1305Decrypt (ciphertext: Uint8Array, nonce: Uint8Array, ad: Uint8Array, k: bytes32): bytes | null {
    const out = sodium_malloc(ciphertext.length - crypto_aead_chacha20poly1305_ietf_ABYTES)

    try {
      crypto_aead_chacha20poly1305_ietf_decrypt(out, null, ciphertext, ad, nonce, k)
    } catch (error) {
      if ((error as Error).message === 'could not verify data') {
        return null
      }

      throw error
    }

    return out
  }
}
