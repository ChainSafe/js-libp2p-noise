/**
 * PQC crypto backend: classical ICryptoInterface + X-Wing KEM (IKem).
 *
 * pqcKem  — standalone IKem implementation (X-Wing via @noble/post-quantum)
 * pqcCrypto — ICryptoInterface & IKem composite for use with XXhfsHandshakeState
 *
 * X-Wing = ML-KEM-768 + X25519, combined with a SHA3-256 based combiner.
 * IETF draft: draft-connolly-cfrg-xwing-kem
 * Library:    @noble/post-quantum v0.6.0 (MIT, Paul Miller)
 *
 * Key sizes:
 *   publicKey (encapsulation key): 1216 bytes
 *   secretKey (decapsulation seed): 32 bytes (seed-based; expanded internally)
 *   cipherText:                     1120 bytes
 *   sharedSecret:                    32 bytes
 */

import { XWing } from '@noble/post-quantum/hybrid.js'
import { pureJsCrypto } from './js.js'
import type { ICryptoInterface } from '../crypto.js'
import type { IKem, KemKeyPair, KemEncapsulateResult } from '../kem.js'

/**
 * X-Wing KEM implementation of IKem.
 *
 * X-Wing is a hybrid KEM that binds an ML-KEM-768 shared secret and an X25519
 * shared secret together via a SHA3-256 based combiner, giving security as long
 * as either component is secure.
 */
// IETF X-Wing key sizes (draft-connolly-cfrg-xwing-kem, fixed by spec)
const XWING_PUBKEY_LEN = 1216 // ML-KEM-768 pubkey (1184) + X25519 pubkey (32)
const XWING_CT_LEN = 1120     // ML-KEM-768 ciphertext (1088) + X25519 ephemeral (32)
const XWING_SS_LEN = 32       // SHA3-256 output of the XWing combiner
const XWING_SK_LEN = 32       // Stored as a 32-byte seed (expanded internally)

export const pqcKem: IKem = {
  PUBKEY_LEN: XWING_PUBKEY_LEN,
  CT_LEN: XWING_CT_LEN,
  SS_LEN: XWING_SS_LEN,
  SK_LEN: XWING_SK_LEN,

  generateKemKeyPair (): KemKeyPair {
    return XWing.keygen()
  },

  encapsulate (remotePublicKey: Uint8Array): KemEncapsulateResult {
    return XWing.encapsulate(remotePublicKey)
  },

  decapsulate (cipherText: Uint8Array, secretKey: Uint8Array): Uint8Array {
    return XWing.decapsulate(cipherText, secretKey)
  }
}

/**
 * Combined PQC crypto backend: all classical ICryptoInterface operations (from
 * pureJsCrypto) plus X-Wing KEM operations (IKem).
 *
 * - Browser-compatible: no Node.js native bindings required
 * - Inherits X25519, ChaCha20-Poly1305, SHA-256, HKDF from pureJsCrypto
 * - Adds generateKemKeyPair / encapsulate / decapsulate for XXhfs
 *
 * Usage with NoiseHFS:
 *   const node = await createLibp2p({
 *     connectionEncrypters: [noiseHFS({ crypto: pqcCrypto })]
 *   })
 */
export const pqcCrypto: ICryptoInterface & IKem = {
  ...pureJsCrypto,
  ...pqcKem
}
