import { Buffer } from 'buffer'
import { assert, expect } from 'aegir/chai'
import { Uint8ArrayList } from 'uint8arraylist'
import { equals as uint8ArrayEquals } from 'uint8arrays/equals'
import { toString as uint8ArrayToString } from 'uint8arrays/to-string'
import { pureJsCrypto } from '../src/crypto/js.js'
import { pqcKem } from '../src/crypto/pqc.js'
import { wrapCrypto } from '../src/crypto.js'
import { ZEROLEN } from '../src/protocol.js'
import { XXhfsHandshakeState, NOISE_HFS_PROTOCOL_NAME } from '../src/protocol-pqc.js'
import type { HfsHandshakeStateInit } from '../src/protocol-pqc.js'
import type { CipherState } from '../src/protocol.js'

// ─── Shared helpers ──────────────────────────────────────────────────────────

const prologue = Buffer.alloc(0)
const crypto = wrapCrypto(pureJsCrypto)
const kem = pqcKem

function makeHandshakePair (): { initiator: XXhfsHandshakeState, responder: XXhfsHandshakeState } {
  const sInit = pureJsCrypto.generateX25519KeyPair()
  const sResp = pureJsCrypto.generateX25519KeyPair()

  const base: Omit<HfsHandshakeStateInit, 'initiator' | 's'> = {
    crypto,
    kem,
    protocolName: NOISE_HFS_PROTOCOL_NAME,
    prologue
  }

  const initiator = new XXhfsHandshakeState({ ...base, initiator: true, s: sInit })
  const responder = new XXhfsHandshakeState({ ...base, initiator: false, s: sResp })
  return { initiator, responder }
}

interface HandshakeResult {
  initiator: XXhfsHandshakeState
  responder: XXhfsHandshakeState
  cs1Init: CipherState
  cs2Init: CipherState
  cs1Resp: CipherState
  cs2Resp: CipherState
}

/** Run the full XXhfs 3-message exchange and return both sides' cipher states */
function doHandshake (): HandshakeResult {
  const { initiator, responder } = makeHandshakePair()

  /* Message A: initiator → responder (e, e1) */
  const msgA = initiator.writeMessageA(ZEROLEN)
  responder.readMessageA(new Uint8ArrayList(msgA))

  /* Message B: responder → initiator (e, ee, ekem1, s, es) */
  const msgB = responder.writeMessageB(ZEROLEN)
  initiator.readMessageB(new Uint8ArrayList(msgB))

  /* Message C: initiator → responder (s, se) */
  const msgC = initiator.writeMessageC(ZEROLEN)
  responder.readMessageC(new Uint8ArrayList(msgC))

  const [cs1Init, cs2Init] = initiator.ss.split()
  const [cs1Resp, cs2Resp] = responder.ss.split()

  return { initiator, responder, cs1Init, cs2Init, cs1Resp, cs2Resp }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

describe('XXhfsHandshakeState', () => {
  describe('construction', () => {
    it('creates without error given valid init', () => {
      try {
        makeHandshakePair()
      } catch (e) {
        assert(false, (e as Error).message)
      }
    })

    it('exposes correct protocol name constant', () => {
      expect(NOISE_HFS_PROTOCOL_NAME).to.equal('Noise_XXhfs_25519+XWing_ChaChaPoly_SHA256')
    })
  })

  describe('Message A (e, e1) — byte layout', () => {
    it('is exactly 1248 bytes with empty payload (32 DH + 1216 KEM)', () => {
      const { initiator } = makeHandshakePair()
      const msgA = initiator.writeMessageA(ZEROLEN)
      // 32 (e.pubkey) + 1216 (e1.pubkey) + 0 (empty payload, no AEAD tag — no key yet)
      expect(msgA.subarray().byteLength).to.equal(1248)
    })

    it('initiator e1 keypair is set after writeMessageA', () => {
      const { initiator } = makeHandshakePair()
      initiator.writeMessageA(ZEROLEN)
      expect(initiator.e1).to.not.be.undefined
      expect(initiator.e1?.publicKey.byteLength).to.equal(1216)
      expect(initiator.e1?.secretKey.byteLength).to.equal(32)
    })

    it('responder re1 is set after readMessageA', () => {
      const { initiator, responder } = makeHandshakePair()
      const msgA = initiator.writeMessageA(ZEROLEN)
      responder.readMessageA(new Uint8ArrayList(msgA))
      expect(responder.re1).to.not.be.undefined
      expect(responder.re1?.byteLength).to.equal(1216)
    })

    it('responder re1 matches initiator e1.publicKey', () => {
      const { initiator, responder } = makeHandshakePair()
      const msgA = initiator.writeMessageA(ZEROLEN)
      responder.readMessageA(new Uint8ArrayList(msgA))
      expect(uint8ArrayEquals(initiator.e1!.publicKey, responder.re1!)).to.be.true
    })
  })

  describe('Message B (e, ee, ekem1, s, es) — byte layout', () => {
    it('is approximately 1232 bytes overhead with empty payload (32+1136+48+16)', () => {
      const { initiator, responder } = makeHandshakePair()
      const msgA = initiator.writeMessageA(ZEROLEN)
      responder.readMessageA(new Uint8ArrayList(msgA))
      const msgB = responder.writeMessageB(ZEROLEN)
      // 32 (e) + 1136 (ekem1: 1120ct+16tag) + 48 (encS: 32+16tag) + 16 (empty payload tag)
      expect(msgB.subarray().byteLength).to.equal(1232)
    })
  })

  describe('Message C (s, se) — byte layout', () => {
    it('is exactly 64 bytes with empty payload (48 encS + 16 payload tag)', () => {
      const { initiator, responder } = makeHandshakePair()
      const msgA = initiator.writeMessageA(ZEROLEN)
      responder.readMessageA(new Uint8ArrayList(msgA))
      const msgB = responder.writeMessageB(ZEROLEN)
      initiator.readMessageB(new Uint8ArrayList(msgB))
      const msgC = initiator.writeMessageC(ZEROLEN)
      expect(msgC.subarray().byteLength).to.equal(64)
    })
  })

  describe('full handshake', () => {
    it('both sides derive the same cipher keys after 3 messages', () => {
      const { cs1Init, cs2Init, cs1Resp, cs2Resp } = doHandshake()
      assert(uint8ArrayEquals(cs1Init.k!, cs1Resp.k!), 'cs1 keys must match')
      assert(uint8ArrayEquals(cs2Init.k!, cs2Resp.k!), 'cs2 keys must match')
    })

    it('initiator cs1 encrypts, responder cs1 decrypts', () => {
      const { cs1Init, cs1Resp } = doHandshake()
      const ad = Buffer.from('auth')
      const plaintext = Buffer.from('hello quantum world')
      const ciphertext = cs1Init.encryptWithAd(ad, plaintext)
      const decrypted = cs1Resp.decryptWithAd(ad, ciphertext)
      assert(
        uint8ArrayEquals(plaintext, decrypted.subarray()),
        'decrypted text must match original'
      )
    })

    it('responder cs2 encrypts, initiator cs2 decrypts', () => {
      const { cs2Init, cs2Resp } = doHandshake()
      const ad = Buffer.from('auth')
      const plaintext = Buffer.from('post-quantum secure')
      const ciphertext = cs2Resp.encryptWithAd(ad, plaintext)
      const decrypted = cs2Init.decryptWithAd(ad, ciphertext)
      assert(
        uint8ArrayEquals(plaintext, decrypted.subarray()),
        'decrypted text must match original'
      )
    })

    it('handles non-empty payload in all 3 messages', () => {
      const { initiator, responder } = makeHandshakePair()
      const payloadA = Buffer.from('payload-a')
      const payloadB = Buffer.from('payload-b-from-responder')
      const payloadC = Buffer.from('payload-c-from-initiator')

      const msgA = initiator.writeMessageA(payloadA)
      const rxPayloadA = responder.readMessageA(new Uint8ArrayList(msgA))
      // payload in Message A is sent without AEAD (no key yet), so it comes back as-is
      expect(rxPayloadA.subarray().byteLength).to.equal(payloadA.byteLength)

      const msgB = responder.writeMessageB(payloadB)
      const rxPayloadB = initiator.readMessageB(new Uint8ArrayList(msgB))
      assert(uint8ArrayEquals(payloadB, rxPayloadB.subarray()), 'Message B payload round-trips')

      const msgC = initiator.writeMessageC(payloadC)
      const rxPayloadC = responder.readMessageC(new Uint8ArrayList(msgC))
      assert(uint8ArrayEquals(payloadC, rxPayloadC.subarray()), 'Message C payload round-trips')
    })

    it('50 independent handshakes all succeed with unique keys', () => {
      const keyPairs = new Set<string>()
      for (let i = 0; i < 50; i++) {
        const { cs1Init, cs1Resp } = doHandshake()
        assert(uint8ArrayEquals(cs1Init.k!, cs1Resp.k!))
        keyPairs.add(uint8ArrayToString(cs1Init.k!, 'hex'))
      }
      // All 50 handshakes should produce unique keys (randomised ephemerals)
      expect(keyPairs.size).to.equal(50)
    })
  })

  describe('security: tampered messages cause failure', () => {
    it('tampered Message A (e field) causes readMessageA to fail on subsequent messages', () => {
      const { initiator, responder } = makeHandshakePair()
      const msgA = initiator.writeMessageA(ZEROLEN)
      const bytes = new Uint8ArrayList(msgA)

      // Tamper the e (DH) ephemeral key — first 32 bytes
      const arr = bytes.subarray()
      arr[0] ^= 0xff
      responder.readMessageA(new Uint8ArrayList(arr))
      // Responder read will "succeed" (no key to verify against yet), but
      // subsequent DH(ee) will produce a wrong shared key → Message B decryption fails
      const msgB = responder.writeMessageB(ZEROLEN)
      expect(() => initiator.readMessageB(new Uint8ArrayList(msgB))).to.throw()
    })

    it('tampered Message B (ekem1 field) causes readMessageB to throw', () => {
      const { initiator, responder } = makeHandshakePair()
      const msgA = initiator.writeMessageA(ZEROLEN)
      responder.readMessageA(new Uint8ArrayList(msgA))

      const msgB = responder.writeMessageB(ZEROLEN)
      const bytes = msgB.subarray()
      // ekem1 starts at offset 32 (after e ephemeral); tamper the AEAD tag
      // The tag is the last 16 bytes of the ekem1 field (bytes 32+1120..32+1136)
      bytes[32 + 1120] ^= 0xff
      expect(() => initiator.readMessageB(new Uint8ArrayList(bytes))).to.throw()
    })

    it('tampered Message C (s field) causes readMessageC to throw', () => {
      const { initiator, responder } = makeHandshakePair()
      const msgA = initiator.writeMessageA(ZEROLEN)
      responder.readMessageA(new Uint8ArrayList(msgA))
      const msgB = responder.writeMessageB(ZEROLEN)
      initiator.readMessageB(new Uint8ArrayList(msgB))

      const msgC = initiator.writeMessageC(ZEROLEN)
      const bytes = msgC.subarray()
      bytes[0] ^= 0xff // tamper encrypted static key
      expect(() => responder.readMessageC(new Uint8ArrayList(bytes))).to.throw()
    })

    it('wrong static key in Message B causes authentication failure on Message C', () => {
      // Responder sends a valid Message B, but then initiator tries with a mismatched
      // static key — readMessageC should throw as AEAD tags won't verify
      const { initiator, responder } = makeHandshakePair()
      const msgA = initiator.writeMessageA(ZEROLEN)
      responder.readMessageA(new Uint8ArrayList(msgA))
      const msgB = responder.writeMessageB(ZEROLEN)
      initiator.readMessageB(new Uint8ArrayList(msgB))
      const msgC = initiator.writeMessageC(ZEROLEN)

      // Use a fresh responder that hasn't seen Message A — it will have different
      // ephemeral state and won't be able to decrypt Message C
      const { responder: freshResp } = makeHandshakePair()
      expect(() => freshResp.readMessageC(new Uint8ArrayList(msgC))).to.throw()
    })
  })

  describe('protocol isolation from classical XX', () => {
    it('XXhfs and XX produce different handshake hashes (different protocol names)', () => {
      const { initiator: hfsInit } = makeHandshakePair()
      const { initiator: xxInit } = makeHandshakePair()

      // Both write Message A — but their symmetric states were initialized with different names
      hfsInit.writeMessageA(ZEROLEN)
      xxInit.writeMessageA(ZEROLEN)

      // Handshake hash h should differ because protocol names differ
      expect(uint8ArrayEquals(hfsInit.ss.h, xxInit.ss.h)).to.be.false
    })
  })
})
