/**
 * Test vector verification for Noise_XXhfs_25519+XWing_ChaChaPoly_SHA256.
 *
 * Loads committed vectors from test/fixtures/pqc-test-vectors.json and
 * re-runs the handshake with the same seeded keys, asserting exact equality
 * of:
 *   - handshake messages A, B, C (byte-for-byte)
 *   - final handshake hash (ss.h)
 *   - transport cipher keys cs1.k and cs2.k
 *
 * If any assertion fails after a code change, either:
 *   (a) a bug was introduced — fix the code, or
 *   (b) the protocol changed intentionally — regenerate vectors with
 *       `node test/vectors/generate-pqc-vectors.js` and commit the new file.
 *
 * Note on interoperability:
 *   These vectors can be used to verify a second implementation in any
 *   language. A compatible implementation must produce identical message
 *   bytes when given the same static keys, ephemeral DH keys, KEM keypair,
 *   and encapsulation seed.
 */

import { readFileSync } from 'fs'
import { fileURLToPath } from 'url'
import { dirname, resolve } from 'path'
import { XWing } from '@noble/post-quantum/hybrid.js'
import { assert, expect } from 'aegir/chai'
import { Uint8ArrayList } from 'uint8arraylist'
import { equals as uint8ArrayEquals } from 'uint8arrays/equals'
import { pureJsCrypto } from '../src/crypto/js.js'
import { wrapCrypto } from '../src/crypto.js'
import { ZEROLEN } from '../src/protocol.js'
import { XXhfsHandshakeState, NOISE_HFS_PROTOCOL_NAME } from '../src/protocol-pqc.js'
import type { ICryptoInterface } from '../src/crypto.js'
import type { IKem, KemKeyPair } from '../src/kem.js'
import type { KeyPair } from '../src/types.js'

// ─── Fixture loading ──────────────────────────────────────────────────────────

const __dirname = dirname(fileURLToPath(import.meta.url))
// Source is at test/fixtures/; compiled output lands in dist/test/ — go up two levels.
const FIXTURE_PATH = resolve(__dirname, '../../test/fixtures/pqc-test-vectors.json')
const vectorFile = JSON.parse(readFileSync(FIXTURE_PATH, 'utf-8'))

interface TestVector {
  vector_index: number
  description: string
  static_i_public: string
  static_i_private: string
  static_r_public: string
  static_r_private: string
  ephemeral_dh_i_public: string
  ephemeral_dh_i_private: string
  ephemeral_dh_r_public: string
  ephemeral_dh_r_private: string
  ephemeral_kem_i_public: string
  ephemeral_kem_i_secret: string
  encap_seed_hex: string
  msg_a: string
  msg_b: string
  msg_c: string
  msg_a_bytes: number
  msg_b_bytes: number
  msg_c_bytes: number
  handshake_hash: string
  cs1_k: string
  cs2_k: string
}

const vectors: TestVector[] = vectorFile.vectors

// ─── Helpers ──────────────────────────────────────────────────────────────────

function fromHex (hex: string): Uint8Array {
  return Buffer.from(hex, 'hex')
}

function toHex (bytes: Uint8Array | Uint8ArrayList): string {
  const arr = (bytes as Uint8ArrayList).subarray != null
    ? (bytes as Uint8ArrayList).subarray()
    : bytes as Uint8Array
  return Buffer.from(arr).toString('hex')
}

/** Build a wrapped ICrypto where generateKeypair() returns a fixed keypair. */
function makeSeededCrypto (ephemeral: KeyPair): ReturnType<typeof wrapCrypto> {
  const seeded: ICryptoInterface = {
    ...pureJsCrypto,
    generateX25519KeyPair: () => ephemeral
  }
  return wrapCrypto(seeded)
}

/** Build an IKem with fixed KEM keypair and fixed encapsulation seed. */
function makeSeededKem (kemKp: KemKeyPair, encapSeed: Uint8Array): IKem {
  return {
    PUBKEY_LEN: 1216,
    CT_LEN: 1120,
    SS_LEN: 32,
    SK_LEN: 32,
    generateKemKeyPair: () => kemKp,
    encapsulate: (pubkey) => XWing.encapsulate(pubkey, encapSeed),
    decapsulate: (ct, sk) => XWing.decapsulate(ct, sk)
  }
}

/** Reconstruct both sides of a seeded XXhfs handshake from a test vector. */
function runVectorHandshake (v: TestVector): {
  msgA: Uint8Array | Uint8ArrayList
  msgB: Uint8Array | Uint8ArrayList
  msgC: Uint8Array | Uint8ArrayList
  handshakeHash: Uint8Array
  cs1k: Uint8Array
  cs2k: Uint8Array
} {
  const sInit: KeyPair = { publicKey: fromHex(v.static_i_public), privateKey: fromHex(v.static_i_private) }
  const sResp: KeyPair = { publicKey: fromHex(v.static_r_public), privateKey: fromHex(v.static_r_private) }
  const eInit: KeyPair = { publicKey: fromHex(v.ephemeral_dh_i_public), privateKey: fromHex(v.ephemeral_dh_i_private) }
  const eResp: KeyPair = { publicKey: fromHex(v.ephemeral_dh_r_public), privateKey: fromHex(v.ephemeral_dh_r_private) }
  const kemKp: KemKeyPair = { publicKey: fromHex(v.ephemeral_kem_i_public), secretKey: fromHex(v.ephemeral_kem_i_secret) }
  const encapSeed = fromHex(v.encap_seed_hex)

  const initiator = new XXhfsHandshakeState({
    crypto: makeSeededCrypto(eInit),
    kem: makeSeededKem(kemKp, encapSeed),
    protocolName: NOISE_HFS_PROTOCOL_NAME,
    initiator: true,
    prologue: ZEROLEN,
    s: sInit
  })

  const responder = new XXhfsHandshakeState({
    crypto: makeSeededCrypto(eResp),
    kem: makeSeededKem(kemKp, encapSeed),
    protocolName: NOISE_HFS_PROTOCOL_NAME,
    initiator: false,
    prologue: ZEROLEN,
    s: sResp
  })

  const msgA = initiator.writeMessageA(ZEROLEN)
  responder.readMessageA(new Uint8ArrayList(msgA))

  const msgB = responder.writeMessageB(ZEROLEN)
  initiator.readMessageB(new Uint8ArrayList(msgB))

  const msgC = initiator.writeMessageC(ZEROLEN)
  responder.readMessageC(new Uint8ArrayList(msgC))

  const [cs1, cs2] = initiator.ss.split()
  const handshakeHash = initiator.ss.h

  return { msgA, msgB, msgC, handshakeHash, cs1k: cs1.k!, cs2k: cs2.k! }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

describe('Noise_XXhfs test vectors', () => {
  it(`fixture file specifies protocol ${NOISE_HFS_PROTOCOL_NAME}`, () => {
    expect(vectorFile.protocol).to.equal(NOISE_HFS_PROTOCOL_NAME)
  })

  it(`fixture contains ${vectors.length} vectors`, () => {
    expect(vectors).to.have.length(5)
  })

  vectors.forEach((v) => {
    describe(`Vector ${v.vector_index}`, () => {
      let result: ReturnType<typeof runVectorHandshake>

      before(() => {
        result = runVectorHandshake(v)
      })

      it('Message A matches expected bytes', () => {
        assert(
          toHex(result.msgA) === v.msg_a,
          `Message A mismatch\n  got:      ${toHex(result.msgA).slice(0, 64)}...\n  expected: ${v.msg_a.slice(0, 64)}...`
        )
      })

      it(`Message A is ${v.msg_a_bytes} bytes`, () => {
        const len = result.msgA instanceof Uint8ArrayList
          ? result.msgA.byteLength
          : (result.msgA as Uint8Array).byteLength
        expect(len).to.equal(v.msg_a_bytes)
      })

      it('Message B matches expected bytes', () => {
        assert(
          toHex(result.msgB) === v.msg_b,
          `Message B mismatch\n  got:      ${toHex(result.msgB).slice(0, 64)}...\n  expected: ${v.msg_b.slice(0, 64)}...`
        )
      })

      it(`Message B is ${v.msg_b_bytes} bytes`, () => {
        const len = result.msgB instanceof Uint8ArrayList
          ? result.msgB.byteLength
          : (result.msgB as Uint8Array).byteLength
        expect(len).to.equal(v.msg_b_bytes)
      })

      it('Message C matches expected bytes', () => {
        assert(
          toHex(result.msgC) === v.msg_c,
          `Message C mismatch\n  got:      ${toHex(result.msgC).slice(0, 64)}...\n  expected: ${v.msg_c.slice(0, 64)}...`
        )
      })

      it(`Message C is ${v.msg_c_bytes} bytes`, () => {
        const len = result.msgC instanceof Uint8ArrayList
          ? result.msgC.byteLength
          : (result.msgC as Uint8Array).byteLength
        expect(len).to.equal(v.msg_c_bytes)
      })

      it('Final handshake hash matches', () => {
        assert(
          toHex(result.handshakeHash) === v.handshake_hash,
          'Handshake hash mismatch — chaining key or hash operation diverged'
        )
      })

      it('cs1 (initiator→responder) cipher key matches', () => {
        assert(
          uint8ArrayEquals(result.cs1k, fromHex(v.cs1_k)),
          'cs1 cipher key mismatch'
        )
      })

      it('cs2 (responder→initiator) cipher key matches', () => {
        assert(
          uint8ArrayEquals(result.cs2k, fromHex(v.cs2_k)),
          'cs2 cipher key mismatch'
        )
      })

      it('both sides converge on the same cipher keys', () => {
        // Verify responder also derives the same keys (cross-check, not just fixture)
        const sInit: KeyPair = { publicKey: fromHex(v.static_i_public), privateKey: fromHex(v.static_i_private) }
        const sResp: KeyPair = { publicKey: fromHex(v.static_r_public), privateKey: fromHex(v.static_r_private) }
        const eInit: KeyPair = { publicKey: fromHex(v.ephemeral_dh_i_public), privateKey: fromHex(v.ephemeral_dh_i_private) }
        const eResp: KeyPair = { publicKey: fromHex(v.ephemeral_dh_r_public), privateKey: fromHex(v.ephemeral_dh_r_private) }
        const kemKp: KemKeyPair = { publicKey: fromHex(v.ephemeral_kem_i_public), secretKey: fromHex(v.ephemeral_kem_i_secret) }
        const encapSeed = fromHex(v.encap_seed_hex)

        const responder = new XXhfsHandshakeState({
          crypto: makeSeededCrypto(eResp),
          kem: makeSeededKem(kemKp, encapSeed),
          protocolName: NOISE_HFS_PROTOCOL_NAME,
          initiator: false,
          prologue: ZEROLEN,
          s: sResp
        })
        const initiator = new XXhfsHandshakeState({
          crypto: makeSeededCrypto(eInit),
          kem: makeSeededKem(kemKp, encapSeed),
          protocolName: NOISE_HFS_PROTOCOL_NAME,
          initiator: true,
          prologue: ZEROLEN,
          s: sInit
        })

        const msgA = initiator.writeMessageA(ZEROLEN)
        responder.readMessageA(new Uint8ArrayList(msgA))
        const msgB = responder.writeMessageB(ZEROLEN)
        initiator.readMessageB(new Uint8ArrayList(msgB))
        const msgC = initiator.writeMessageC(ZEROLEN)
        responder.readMessageC(new Uint8ArrayList(msgC))

        const [cs1i, cs2i] = initiator.ss.split()
        const [cs1Resp, cs2Resp] = responder.ss.split()

        assert(cs1i.k != null && cs1Resp.k != null, 'cipher keys must be initialized')
        assert(uint8ArrayEquals(cs1i.k, cs1Resp.k), 'cs1 must match between sides')
        assert(cs2i.k != null && cs2Resp.k != null, 'cipher keys must be initialized')
        assert(uint8ArrayEquals(cs2i.k, cs2Resp.k), 'cs2 must match between sides')
      })
    })
  })
})
