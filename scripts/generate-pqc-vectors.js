/* eslint-disable no-console */
/**
 * Deterministic test vector generator for Noise_XXhfs_25519+ML-KEM-768_ChaChaPoly_SHA256.
 *
 * Generates NUM_VECTORS test vectors using seeded key generation so vectors
 * are reproducible across runs. Writes to test/fixtures/pqc-test-vectors.json.
 *
 * Run after build:
 *   node scripts/generate-pqc-vectors.js
 *
 * Each vector captures:
 *   - All fixed keypairs (static + ephemeral DH + KEM) as hex
 *   - The three handshake messages A, B, C as hex
 *   - The final handshake hash (ss.h) as hex
 *   - The two transport cipher keys (cs1.k, cs2.k) as hex
 *
 * Security note: seeded randomness is ONLY used here for vector generation.
 * The production code always uses cryptographically random keys.
 */

import { writeFileSync } from 'fs'
import { fileURLToPath } from 'url'
import { dirname, resolve } from 'path'
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js'
import { pureJsCrypto } from '../dist/src/crypto/js.js'
import { wrapCrypto } from '../dist/src/crypto.js'
import { XXhfsHandshakeState, NOISE_HFS_PROTOCOL_NAME } from '../dist/src/protocol-pqc.js'
import { ZEROLEN } from '../dist/src/protocol.js'
import { Uint8ArrayList } from 'uint8arraylist'

const __dirname = dirname(fileURLToPath(import.meta.url))
const OUT_PATH = resolve(__dirname, '../test/fixtures/pqc-test-vectors.json')
const NUM_VECTORS = 5

// ─── Helpers ──────────────────────────────────────────────────────────────────

function toHex (bytes) {
  if (bytes == null) return ''
  const arr = bytes.subarray ? bytes.subarray() : bytes
  return Buffer.from(arr).toString('hex')
}

function fill32 (byte) {
  return new Uint8Array(32).fill(byte)
}

function fill64 (byte) {
  return new Uint8Array(64).fill(byte)
}

/**
 * Build a seeded ICrypto (via wrapCrypto) where generateKeypair() always
 * returns the pre-generated ephemeral DH keypair.
 */
function makeSeededCrypto (ephemeralKeypair) {
  const seededInterface = {
    ...pureJsCrypto,
    generateX25519KeyPair: () => ephemeralKeypair
  }
  return wrapCrypto(seededInterface)
}

/**
 * Build a seeded IKem that uses fixed KEM keypair + fixed encapsulate seed.
 * ML-KEM-768 encapsulate() accepts a 32-byte random seed.
 */
function makeSeededKem (kemKeypair, encapSeed32) {
  return {
    PUBKEY_LEN: 1184,
    CT_LEN: 1088,
    SS_LEN: 32,
    SK_LEN: 2400,
    generateKemKeyPair: () => kemKeypair,
    encapsulate: (pubkey) => ml_kem768.encapsulate(pubkey, encapSeed32),
    decapsulate: (ct, sk) => ml_kem768.decapsulate(ct, sk)
  }
}

// ─── Vector generation ────────────────────────────────────────────────────────

function generateVector (idx) {
  // Each vector uses a distinct byte-fill so all seeds differ across vectors.
  // Seeds within a vector are spaced 0x10 apart so they never collide.
  const base = idx * 0x10

  // Static DH keypairs (seeded from 32-byte seeds)
  const sInit = pureJsCrypto.generateX25519KeyPairFromSeed(fill32(0x01 + base))
  const sResp = pureJsCrypto.generateX25519KeyPairFromSeed(fill32(0x02 + base))

  // Ephemeral DH keypairs (seeded)
  const eInit = pureJsCrypto.generateX25519KeyPairFromSeed(fill32(0x03 + base))
  const eResp = pureJsCrypto.generateX25519KeyPairFromSeed(fill32(0x04 + base))

  // KEM ephemeral keypair for initiator (seeded 64-byte ML-KEM-768 seed)
  const kemKeypair = ml_kem768.keygen(fill64(0x05 + base))

  // Encapsulation randomness (32-byte seed, used by responder)
  const encapSeed = fill32(0x06 + base)

  // ── Initiator side ──────────────────────────────────────────────────────────
  const cryptoInit = makeSeededCrypto(eInit)
  const kemInit = makeSeededKem(kemKeypair, encapSeed)  // generateKemKeyPair used, encap not used by init

  const initiator = new XXhfsHandshakeState({
    crypto: cryptoInit,
    kem: kemInit,
    protocolName: NOISE_HFS_PROTOCOL_NAME,
    initiator: true,
    prologue: ZEROLEN,
    s: sInit
  })

  // ── Responder side ──────────────────────────────────────────────────────────
  const cryptoResp = makeSeededCrypto(eResp)
  // Responder uses encapSeed for encapsulate; KEM keygen not called by responder
  const kemResp = makeSeededKem(kemKeypair /* unused by responder */, encapSeed)

  const responder = new XXhfsHandshakeState({
    crypto: cryptoResp,
    kem: kemResp,
    protocolName: NOISE_HFS_PROTOCOL_NAME,
    initiator: false,
    prologue: ZEROLEN,
    s: sResp
  })

  // ── Run the 3-message handshake ─────────────────────────────────────────────
  const msgA = initiator.writeMessageA(ZEROLEN)
  responder.readMessageA(new Uint8ArrayList(msgA))

  const msgB = responder.writeMessageB(ZEROLEN)
  initiator.readMessageB(new Uint8ArrayList(msgB))

  const msgC = initiator.writeMessageC(ZEROLEN)
  responder.readMessageC(new Uint8ArrayList(msgC))

  const [cs1Init, cs2Init] = initiator.ss.split()
  const [cs1Resp, cs2Resp] = responder.ss.split()

  // Sanity check: both sides must derive the same keys
  const cs1Match = cs1Init.k.every((b, i) => b === cs1Resp.k[i])
  const cs2Match = cs2Init.k.every((b, i) => b === cs2Resp.k[i])
  if (!cs1Match || !cs2Match) {
    throw new Error(`Vector ${idx}: cipher keys do not match! Implementation bug.`)
  }

  return {
    vector_index: idx,
    description: `Noise_XXhfs vector ${idx} — all keys seeded from base byte 0x${base.toString(16).padStart(2, '0')}`,
    // Fixed keypairs (hex)
    static_i_public: toHex(sInit.publicKey),
    static_i_private: toHex(sInit.privateKey),
    static_r_public: toHex(sResp.publicKey),
    static_r_private: toHex(sResp.privateKey),
    ephemeral_dh_i_public: toHex(eInit.publicKey),
    ephemeral_dh_i_private: toHex(eInit.privateKey),
    ephemeral_dh_r_public: toHex(eResp.publicKey),
    ephemeral_dh_r_private: toHex(eResp.privateKey),
    ephemeral_kem_i_public: toHex(kemKeypair.publicKey),
    ephemeral_kem_i_secret: toHex(kemKeypair.secretKey),
    encap_seed_hex: toHex(encapSeed),
    prologue: '',
    // Handshake messages (hex)
    msg_a: toHex(msgA),
    msg_b: toHex(msgB),
    msg_c: toHex(msgC),
    // Expected sizes (for documentation)
    msg_a_bytes: msgA.subarray ? msgA.subarray().byteLength : msgA.byteLength,
    msg_b_bytes: msgB.subarray ? msgB.subarray().byteLength : msgB.byteLength,
    msg_c_bytes: msgC.subarray ? msgC.subarray().byteLength : msgC.byteLength,
    // Final state
    handshake_hash: toHex(initiator.ss.h),
    cs1_k: toHex(cs1Init.k),
    cs2_k: toHex(cs2Init.k)
  }
}

// ─── Main ─────────────────────────────────────────────────────────────────────

const vectors = []
for (let i = 1; i <= NUM_VECTORS; i++) {
  process.stdout.write(`  Generating vector ${i}/${NUM_VECTORS}...`)
  const v = generateVector(i)
  vectors.push(v)
  console.log(` ok (A=${v.msg_a_bytes}B, B=${v.msg_b_bytes}B, C=${v.msg_c_bytes}B)`)
}

const output = {
  protocol: NOISE_HFS_PROTOCOL_NAME,
  description: 'Deterministic test vectors for Noise_XXhfs_25519+ML-KEM-768_ChaChaPoly_SHA256. All keypairs seeded for reproducibility. Do NOT use seeded keys in production.',
  generated_by: '@chainsafe/libp2p-noise (js-libp2p-noise)',
  kem: 'ML-KEM-768 (FIPS 203) via @noble/post-quantum',
  prologue: 'empty (0 bytes)',
  payload: 'empty (ZEROLEN) — no libp2p handshake payload',
  vectors
}

writeFileSync(OUT_PATH, JSON.stringify(output, null, 2))
console.log(`\n  Written ${vectors.length} vectors to ${OUT_PATH}`)
