/* eslint-disable no-console */
/**
 * Isolates two effects that the main PQC benchmark conflates.
 *
 * noise()    defaults to defaultCrypto  (Node native + AssemblyScript WASM)
 * noiseHFS() defaults to pureJsCrypto   (@noble/*, everything in JavaScript)
 *
 * So "classical vs hybrid" as measured there changes the KEM *and* the whole
 * symmetric/DH backend at the same time. This script measures classical on
 * both backends so the two effects can be separated.
 *
 *   node benchmarks/backend-isolation.mjs
 */

import { generateKeyPair } from '@libp2p/crypto/keys'
import { peerIdFromPrivateKey } from '@libp2p/peer-id'
import { defaultLogger } from '@libp2p/logger'
import { multiaddrConnectionPair } from '@libp2p/utils'
import { stubInterface } from 'sinon-ts'
import { noise } from '../dist/src/index.js'
import { noiseHFS } from '../dist/src/noise-hfs.js'
import { defaultCrypto } from '../dist/src/crypto/index.js'
import { pureJsCrypto } from '../dist/src/crypto/js.js'

const WARMUP = 5
const ITERS = 30

function makeComponents (privateKey, peerId) {
  return {
    privateKey,
    peerId,
    logger: defaultLogger(),
    upgrader: stubInterface({ getStreamMuxers: () => new Map() }),
    metrics: undefined
  }
}

async function timeHandshake (initFactory, respFactory, iPriv, iPeer, rPriv, rPeer) {
  const [outbound, inbound] = multiaddrConnectionPair()
  const init = initFactory(makeComponents(iPriv, iPeer))
  const resp = respFactory(makeComponents(rPriv, rPeer))
  const t0 = performance.now()
  await Promise.all([
    init.secureOutbound(outbound),
    resp.secureInbound(inbound)
  ])
  return performance.now() - t0
}

function median (xs) {
  const v = [...xs].sort((a, b) => a - b)
  const m = v.length >> 1
  return v.length % 2 ? v[m] : (v[m - 1] + v[m]) / 2
}

async function bench (label, initFactory, respFactory) {
  const iPriv = await generateKeyPair('Ed25519')
  const rPriv = await generateKeyPair('Ed25519')
  const iPeer = peerIdFromPrivateKey(iPriv)
  const rPeer = peerIdFromPrivateKey(rPriv)

  for (let i = 0; i < WARMUP; i++) {
    await timeHandshake(initFactory, respFactory, iPriv, iPeer, rPriv, rPeer)
  }
  const samples = []
  for (let i = 0; i < ITERS; i++) {
    samples.push(await timeHandshake(initFactory, respFactory, iPriv, iPeer, rPriv, rPeer))
  }
  const m = median(samples)
  console.log(`  ${label.padEnd(52)} ${m.toFixed(2)} ms`)
  return m
}

async function main () {
  console.log('\nIsolating KEM cost from crypto-backend cost (median of 30, 5 warm-up)\n')

  const xxNative = await bench(
    'Noise_XX        [defaultCrypto: native + WASM]',
    (c) => noise()(c), (c) => noise()(c))

  const xxPureJs = await bench(
    'Noise_XX        [pureJsCrypto]',
    (c) => noise({ crypto: pureJsCrypto })(c), (c) => noise({ crypto: pureJsCrypto })(c))

  const hfsPureJs = await bench(
    'Noise_XXhfs     [pureJsCrypto + ML-KEM-768]',
    (c) => noiseHFS()(c), (c) => noiseHFS()(c))

  const hfsNative = await bench(
    'Noise_XXhfs     [defaultCrypto + ML-KEM-768]',
    (c) => noiseHFS({ crypto: defaultCrypto })(c),
    (c) => noiseHFS({ crypto: defaultCrypto })(c))

  console.log('\n  Decomposition')
  console.log(`  backend cost alone (XX pureJs - XX native)   : ${(xxPureJs - xxNative).toFixed(2)} ms`)
  console.log(`  KEM cost alone     (XXhfs - XX, same backend): ${(hfsPureJs - xxPureJs).toFixed(2)} ms  [pureJs]`)
  console.log(`  KEM cost alone     (XXhfs - XX, same backend): ${(hfsNative - xxNative).toFixed(2)} ms  [native]`)
  console.log(`  as-reported overhead (XXhfs pureJs / XX native): ${(hfsPureJs / xxNative).toFixed(2)}x`)
  console.log(`  like-for-like overhead (pureJs / pureJs)       : ${(hfsPureJs / xxPureJs).toFixed(2)}x`)
  console.log(`  like-for-like overhead (native / native)       : ${(hfsNative / xxNative).toFixed(2)}x\n`)
}

main().catch(err => { console.error(err); process.exit(1) })
