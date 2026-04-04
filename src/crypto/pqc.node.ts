/**
 * Node.js KEM backend for Noise_XXhfs_25519+XWing_ChaChaPoly_SHA256.
 *
 * This file follows the same dual-backend pattern as PR #3432 (ML-DSA identity):
 *   src/crypto/pqc.ts      - browser / universal fallback (noble, pure JS)
 *   src/crypto/pqc.node.ts - Node.js preferred backend (this file)
 *
 * Current status:
 *   Node.js does not yet expose ML-KEM-768 or X-Wing via node:crypto.subtle.
 *   As of Node.js v22, only ECDH and RSA-OAEP are supported for key
 *   encapsulation. ML-KEM support is tracked in the Node.js issue tracker
 *   and is expected to land with native crypto.subtle support similar to
 *   how ML-DSA is being added in PR #3432.
 *
 *   Until that lands, this file re-exports the noble implementation from
 *   pqc.ts. When Node.js native support ships, replace the body of
 *   generateKemKeyPair / encapsulate / decapsulate with the native calls
 *   shown in the TODO sections below.
 *
 * How to add native support when Node.js supports ML-KEM-768:
 *
 *   // Key generation
 *   const { publicKey, privateKey } = await crypto.subtle.generateKey(
 *     { name: 'MLKEM768' },
 *     true,
 *     ['encapsulate', 'decapsulate']
 *   )
 *   const pubBytes = await crypto.subtle.exportKey('raw', publicKey)    // 1184 bytes
 *   const skBytes  = await crypto.subtle.exportKey('raw', privateKey)   // 32 bytes seed
 *
 *   // Encapsulation
 *   const pubKey = await crypto.subtle.importKey('raw', remotePublicKey, { name: 'MLKEM768' }, false, ['encapsulate'])
 *   const { ciphertext, sharedSecret } = await crypto.subtle.encapsulate(pubKey)
 *
 *   // Decapsulation
 *   const skKey = await crypto.subtle.importKey('raw', secretKey, { name: 'MLKEM768' }, false, ['decapsulate'])
 *   const sharedSecret = await crypto.subtle.decapsulate(skKey, ciphertext)
 *
 * Note on X-Wing vs raw ML-KEM-768:
 *   X-Wing (our chosen KEM) is ML-KEM-768 + X25519 with a SHA3-256 combiner
 *   (IETF draft-connolly-cfrg-xwing-kem). Even with native ML-KEM-768, the
 *   X25519 DH step and the combiner still need noble. The native path primarily
 *   helps with the ML-KEM-768 keygen/encap/decap operations, which are the
 *   most CPU intensive part of X-Wing.
 *
 * Reference: PR #3432 (feat: Post quantum identities with ML-DSA) by @dozyio
 *   shows the exact dual-backend pattern to follow:
 *   - noble implementation for browser/fallback
 *   - node:crypto.subtle for Node.js 22+ (when available)
 *   - automatic detection via typeof process !== 'undefined'
 */

// Re-export the noble implementation while native support is not yet available.
// Replace this with native crypto.subtle calls once Node.js exposes ML-KEM-768.
export { pqcKem, pqcCrypto } from './pqc.js'

// TODO: when Node.js adds native ML-KEM-768, export a pqcKemNative here:
//
// export const pqcKemNative: IKem = {
//   PUBKEY_LEN: 1216,
//   CT_LEN: 1120,
//   SS_LEN: 32,
//   SK_LEN: 32,
//   generateKemKeyPair () { /* node:crypto.subtle + X25519 combiner */ },
//   encapsulate (remotePublicKey) { /* native ML-KEM-768 + X25519 combiner */ },
//   decapsulate (cipherText, secretKey) { /* native ML-KEM-768 + X25519 combiner */ }
// }
//
// export const pqcCryptoNative: ICryptoInterface & IKem = {
//   ...pureJsCrypto,
//   ...pqcKemNative
// }
