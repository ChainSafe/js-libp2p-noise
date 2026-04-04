import { expect } from 'aegir/chai'
import { equals as uint8ArrayEquals } from 'uint8arrays/equals'
import { pqcKem, pqcCrypto } from '../src/crypto/pqc.js'

/**
 * Unit tests for the IKem interface and pqcKem (X-Wing) implementation.
 *
 * X-Wing = ML-KEM-768 + X25519, IETF draft-connolly-cfrg-xwing-kem
 * Key sizes: publicKey=1216B, secretKey=32B (seed), cipherText=1120B, sharedSecret=32B
 *
 * Note on decapsulation failure (ML-KEM implicit rejection, FIPS 203 §6.4):
 *   ML-KEM decapsulate() never throws on wrong input — it returns a pseudorandom
 *   value. Tests that check wrong-key behavior rely on statistical divergence,
 *   not an exception.
 */
describe('IKem / pqcKem (X-Wing)', () => {
  describe('constants', () => {
    it('PUBKEY_LEN is 1216 bytes (ML-KEM-768 pubkey + X25519 pubkey)', () => {
      expect(pqcKem.PUBKEY_LEN).to.equal(1216)
    })

    it('CT_LEN is 1120 bytes (ML-KEM-768 ciphertext + X25519 ephemeral)', () => {
      expect(pqcKem.CT_LEN).to.equal(1120)
    })

    it('SS_LEN is 32 bytes (SHA3-256 output of XWing combiner)', () => {
      expect(pqcKem.SS_LEN).to.equal(32)
    })

    it('SK_LEN is 32 bytes (seed-based secret key storage)', () => {
      expect(pqcKem.SK_LEN).to.equal(32)
    })
  })

  describe('generateKemKeyPair', () => {
    it('returns Uint8Array keys of correct lengths', () => {
      const kp = pqcKem.generateKemKeyPair()
      expect(kp.publicKey).to.be.instanceOf(Uint8Array)
      expect(kp.secretKey).to.be.instanceOf(Uint8Array)
      expect(kp.publicKey.byteLength).to.equal(pqcKem.PUBKEY_LEN)
      expect(kp.secretKey.byteLength).to.equal(pqcKem.SK_LEN)
    })

    it('generates different key pairs on each call', () => {
      const kp1 = pqcKem.generateKemKeyPair()
      const kp2 = pqcKem.generateKemKeyPair()
      expect(uint8ArrayEquals(kp1.publicKey, kp2.publicKey)).to.be.false
      expect(uint8ArrayEquals(kp1.secretKey, kp2.secretKey)).to.be.false
    })
  })

  describe('encapsulate', () => {
    it('returns cipherText and sharedSecret of correct lengths', () => {
      const { publicKey } = pqcKem.generateKemKeyPair()
      const result = pqcKem.encapsulate(publicKey)
      expect(result.cipherText).to.be.instanceOf(Uint8Array)
      expect(result.sharedSecret).to.be.instanceOf(Uint8Array)
      expect(result.cipherText.byteLength).to.equal(pqcKem.CT_LEN)
      expect(result.sharedSecret.byteLength).to.equal(pqcKem.SS_LEN)
    })

    it('produces different ciphertexts for same key on each call (randomised encap)', () => {
      const { publicKey } = pqcKem.generateKemKeyPair()
      const r1 = pqcKem.encapsulate(publicKey)
      const r2 = pqcKem.encapsulate(publicKey)
      // encapsulate uses random coins each time
      expect(uint8ArrayEquals(r1.cipherText, r2.cipherText)).to.be.false
    })
  })

  describe('encap + decap roundtrip', () => {
    it('decapsulate recovers the same 32-byte shared secret as encapsulate', () => {
      const kp = pqcKem.generateKemKeyPair()
      const { cipherText, sharedSecret: ss1 } = pqcKem.encapsulate(kp.publicKey)
      const ss2 = pqcKem.decapsulate(cipherText, kp.secretKey)
      expect(ss2).to.be.instanceOf(Uint8Array)
      expect(ss2.byteLength).to.equal(32)
      expect(uint8ArrayEquals(ss1, ss2)).to.be.true
    })

    it('10 independent roundtrips all succeed', () => {
      for (let i = 0; i < 10; i++) {
        const kp = pqcKem.generateKemKeyPair()
        const { cipherText, sharedSecret: ss1 } = pqcKem.encapsulate(kp.publicKey)
        const ss2 = pqcKem.decapsulate(cipherText, kp.secretKey)
        expect(uint8ArrayEquals(ss1, ss2)).to.be.true
      }
    })

    it('decapsulate with wrong secretKey produces different shared secret (implicit rejection)', () => {
      const kp1 = pqcKem.generateKemKeyPair()
      const kp2 = pqcKem.generateKemKeyPair()
      const { cipherText, sharedSecret: ss1 } = pqcKem.encapsulate(kp1.publicKey)
      // ML-KEM implicit rejection: wrong key → pseudorandom output, no throw
      const ss2 = pqcKem.decapsulate(cipherText, kp2.secretKey)
      expect(uint8ArrayEquals(ss1, ss2)).to.be.false
    })

    it('decapsulate with wrong cipherText produces different shared secret', () => {
      const kp = pqcKem.generateKemKeyPair()
      const { cipherText, sharedSecret: ss1 } = pqcKem.encapsulate(kp.publicKey)
      const tampered = cipherText.slice()
      tampered[0] ^= 0xff // flip bits in first byte
      const ss2 = pqcKem.decapsulate(tampered, kp.secretKey)
      expect(uint8ArrayEquals(ss1, ss2)).to.be.false
    })
  })

  describe('pqcCrypto composite backend', () => {
    it('KEM operations work identically to pqcKem', () => {
      const kp = pqcCrypto.generateKemKeyPair()
      expect(kp.publicKey.byteLength).to.equal(1216)
      expect(kp.secretKey.byteLength).to.equal(32)
      const { cipherText, sharedSecret: ss1 } = pqcCrypto.encapsulate(kp.publicKey)
      const ss2 = pqcCrypto.decapsulate(cipherText, kp.secretKey)
      expect(uint8ArrayEquals(ss1, ss2)).to.be.true
    })

    it('inherits X25519 key generation from pureJsCrypto', () => {
      const kp = pqcCrypto.generateX25519KeyPair()
      expect(kp.publicKey.byteLength).to.equal(32)
      expect(kp.privateKey.byteLength).to.equal(32)
    })

    it('inherits X25519 DH from pureJsCrypto', () => {
      const kpA = pqcCrypto.generateX25519KeyPair()
      const kpB = pqcCrypto.generateX25519KeyPair()
      const sharedAB = pqcCrypto.generateX25519SharedKey(kpA.privateKey, kpB.publicKey)
      const sharedBA = pqcCrypto.generateX25519SharedKey(kpB.privateKey, kpA.publicKey)
      expect(uint8ArrayEquals(sharedAB, sharedBA)).to.be.true
    })

    it('inherits hashSHA256 from pureJsCrypto', () => {
      const hash = pqcCrypto.hashSHA256(new Uint8Array(32))
      expect(hash.byteLength).to.equal(32)
    })

    it('inherits ChaCha20-Poly1305 encrypt/decrypt from pureJsCrypto', () => {
      const key = new Uint8Array(32).fill(1)
      const nonce = new Uint8Array(12).fill(2)
      const ad = new Uint8Array(0)
      const plaintext = new Uint8Array([1, 2, 3, 4, 5])
      const ciphertext = pqcCrypto.chaCha20Poly1305Encrypt(plaintext, nonce, ad, key)
      const decrypted = pqcCrypto.chaCha20Poly1305Decrypt(ciphertext, nonce, ad, key)
      expect(uint8ArrayEquals(new Uint8Array(decrypted.subarray()), plaintext)).to.be.true
    })
  })
})
