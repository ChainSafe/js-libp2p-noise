/**
 * Node.js KEM backend for Noise_XXhfs_25519+ML-KEM-768_ChaChaPoly_SHA256.
 *
 * This file follows the same dual-backend pattern as PR #3432 (ML-DSA identity):
 *   src/crypto/pqc.ts      - browser / universal fallback (noble, pure JS)
 *   src/crypto/pqc.node.ts - Node.js preferred backend (this file)
 *
 * Current status:
 *   Node.js does not yet expose ML-KEM-768 via node:crypto.subtle.
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
 *   const skBytes  = await crypto.subtle.exportKey('raw', privateKey)   // 2400 bytes
 *
 *   // Encapsulation
 *   const pubKey = await crypto.subtle.importKey('raw', remotePublicKey, { name: 'MLKEM768' }, false, ['encapsulate'])
 *   const { ciphertext, sharedSecret } = await crypto.subtle.encapsulate(pubKey)
 *
 *   // Decapsulation
 *   const skKey = await crypto.subtle.importKey('raw', secretKey, { name: 'MLKEM768' }, false, ['decapsulate'])
 *   const sharedSecret = await crypto.subtle.decapsulate(skKey, ciphertext)
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
//   PUBKEY_LEN: 1184,
//   CT_LEN: 1088,
//   SS_LEN: 32,
//   SK_LEN: 2400,
//   generateKemKeyPair () { /* node:crypto.subtle ML-KEM-768 */ },
//   encapsulate (remotePublicKey) { /* native ML-KEM-768 encapsulate */ },
//   decapsulate (cipherText, secretKey) { /* native ML-KEM-768 decapsulate */ }
// }
//
// export const pqcCryptoNative: ICryptoInterface & IKem = {
//   ...pureJsCrypto,
//   ...pqcKemNative
// }
