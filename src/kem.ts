/**
 * Key Encapsulation Mechanism (KEM) interface for Noise HFS hybrid handshake.
 *
 * KEM is fundamentally asymmetric: encapsulate() runs at the sender, decapsulate()
 * runs at the receiver. This is why KEM cannot be expressed through the symmetric
 * ICrypto.dh(keypair, publicKey) interface — dh() works identically for both parties,
 * but encap/decap are different operations called by different parties.
 *
 * In the XXhfs pattern:
 *   - Initiator: calls generateKemKeyPair() → sends publicKey as e1 token in Message A
 *   - Responder: calls encapsulate(re1) → sends cipherText as ekem1 token in Message B
 *   - Initiator: calls decapsulate(cipherText, e1.secretKey) → recovers sharedSecret
 *   - Both:      call MixKey(sharedSecret) → quantum-safe key material enters ck
 */

export interface KemKeyPair {
  /** KEM encapsulation (public) key — 1216 bytes for X-Wing */
  publicKey: Uint8Array
  /**
   * KEM decapsulation (secret) key — stored as a 32-byte seed for X-Wing.
   * The library derives the full expanded key on demand via XWing.getPublicKey().
   * Named secretKey (not privateKey) to clearly distinguish from X25519 KeyPair.
   */
  secretKey: Uint8Array
}

export interface KemEncapsulateResult {
  /** Ciphertext to transmit to the holder of the decapsulation key (1120 bytes for X-Wing) */
  cipherText: Uint8Array
  /** Shared secret — 32 bytes, derivable only by the holder of the matching secretKey */
  sharedSecret: Uint8Array
}

/**
 * Key Encapsulation Mechanism — the PQC extension point for Noise HFS.
 *
 * Implementations: pqcKem (X-Wing = ML-KEM-768 + X25519, from @noble/post-quantum)
 */
export interface IKem {
  /** Generate a KEM ephemeral key pair for use as the e1 token */
  generateKemKeyPair(): KemKeyPair

  /**
   * Encapsulate: derive a shared secret and return it with a ciphertext.
   * Called by the party that does NOT own the key pair.
   */
  encapsulate(remotePublicKey: Uint8Array): KemEncapsulateResult

  /**
   * Decapsulate: recover the shared secret from a ciphertext using the secret key.
   * Called by the party that owns the key pair.
   * Note: ML-KEM decapsulation never throws on bad input — it returns a pseudorandom
   * value instead (implicit rejection, per FIPS 203 §6.4).
   */
  decapsulate(cipherText: Uint8Array, secretKey: Uint8Array): Uint8Array

  /** Byte length of the encapsulation (public) key */
  readonly PUBKEY_LEN: number
  /** Byte length of the ciphertext produced by encapsulate() */
  readonly CT_LEN: number
  /** Byte length of the shared secret */
  readonly SS_LEN: number
  /** Byte length of the decapsulation (secret) key */
  readonly SK_LEN: number
}
