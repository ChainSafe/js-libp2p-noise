/**
 * PQC crypto backend: classical ICryptoInterface + ML-KEM-768 KEM (IKem).
 *
 * pqcKem  — standalone IKem implementation (raw ML-KEM-768 via @noble/post-quantum)
 * pqcCrypto — ICryptoInterface & IKem composite for use with XXhfsHandshakeState
 *
 * ML-KEM-768 is FIPS 203 (August 2024). The KEM slot in Noise XXhfs is a pure
 * KEM — no X25519 wrapper is needed because the hybrid security already comes
 * from the protocol's own DH tokens (ee, es, se).
 *
 * Key sizes:
 *   publicKey (encapsulation key): 1184 bytes
 *   secretKey (decapsulation key): 2400 bytes
 *   cipherText:                    1088 bytes
 *   sharedSecret:                    32 bytes
 */

import { ml_kem768 } from '@noble/post-quantum/ml-kem.js'
import { pureJsCrypto } from './js.js'
import type { ICryptoInterface } from '../crypto.js'
import type { IKem, KemKeyPair, KemEncapsulateResult } from '../kem.js'

// ML-KEM-768 key sizes (FIPS 203, fixed by spec)
const MLKEM768_PUBKEY_LEN = 1184
const MLKEM768_CT_LEN = 1088
const MLKEM768_SS_LEN = 32
const MLKEM768_SK_LEN = 2400

export const pqcKem: IKem = {
  PUBKEY_LEN: MLKEM768_PUBKEY_LEN,
  CT_LEN: MLKEM768_CT_LEN,
  SS_LEN: MLKEM768_SS_LEN,
  SK_LEN: MLKEM768_SK_LEN,

  generateKemKeyPair (): KemKeyPair {
    return ml_kem768.keygen()
  },

  encapsulate (remotePublicKey: Uint8Array): KemEncapsulateResult {
    return ml_kem768.encapsulate(remotePublicKey)
  },

  decapsulate (cipherText: Uint8Array, secretKey: Uint8Array): Uint8Array {
    return ml_kem768.decapsulate(cipherText, secretKey)
  }
}

export const pqcCrypto: ICryptoInterface & IKem = {
  ...pureJsCrypto,
  ...pqcKem
}
