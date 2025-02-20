import { generateKeyPair } from '@libp2p/crypto/keys'
import { defaultLogger } from '@libp2p/logger'
import { peerIdFromPrivateKey } from '@libp2p/peer-id'
import { expect } from 'aegir/chai'
import { lpStream } from 'it-length-prefixed-stream'
import { duplexPair } from 'it-pair/duplex'
import sinon from 'sinon'
import { fromString as uint8ArrayFromString } from 'uint8arrays/from-string'
import { noise } from '../src/index.js'
import { Noise } from '../src/noise.js'
import type { Metrics } from '@libp2p/interface'
import type { Uint8ArrayList } from 'uint8arraylist'

function createCounterSpy (): ReturnType<typeof sinon.spy> {
  return sinon.spy({
    increment: () => {},
    reset: () => {}
  })
}

describe('Index', () => {
  it('should expose class with tag and required functions', async () => {
    const privateKey = await generateKeyPair('Ed25519')
    const peerId = peerIdFromPrivateKey(privateKey)

    const noiseInstance = noise()({
      privateKey,
      peerId,
      logger: defaultLogger()
    })
    expect(noiseInstance.protocol).to.equal('/noise')
    expect(typeof (noiseInstance.secureInbound)).to.equal('function')
    expect(typeof (noiseInstance.secureOutbound)).to.equal('function')
  })

  it('should collect metrics', async () => {
    const metricsRegistry = new Map<string, ReturnType<typeof createCounterSpy>>()
    const metrics = {
      registerCounter: (name: string) => {
        const counter = createCounterSpy()
        metricsRegistry.set(name, counter)
        return counter
      }
    }

    const privateKeyInit = await generateKeyPair('Ed25519')
    const peerIdInit = peerIdFromPrivateKey(privateKeyInit)
    const noiseInit = new Noise({
      privateKey: privateKeyInit,
      peerId: peerIdInit,
      logger: defaultLogger(),
      metrics: metrics as any as Metrics
    })

    const privateKeyResp = await generateKeyPair('Ed25519')
    const peerIdResp = peerIdFromPrivateKey(privateKeyResp)
    const noiseResp = new Noise({
      privateKey: privateKeyResp,
      peerId: peerIdResp,
      logger: defaultLogger()
    })

    const [inboundConnection, outboundConnection] = duplexPair<Uint8Array | Uint8ArrayList>()
    const [outbound, inbound] = await Promise.all([
      noiseInit.secureOutbound(outboundConnection, {
        remotePeer: peerIdResp
      }),
      noiseResp.secureInbound(inboundConnection, {
        remotePeer: peerIdInit
      })
    ])
    const wrappedInbound = lpStream(inbound.conn)
    const wrappedOutbound = lpStream(outbound.conn)

    await wrappedOutbound.write(uint8ArrayFromString('test'))
    await wrappedInbound.read()
    expect(metricsRegistry.get('libp2p_noise_xxhandshake_successes_total')?.increment.callCount).to.equal(1)
    expect(metricsRegistry.get('libp2p_noise_xxhandshake_error_total')?.increment.callCount).to.equal(0)
    expect(metricsRegistry.get('libp2p_noise_encrypted_packets_total')?.increment.callCount).to.equal(1)
    expect(metricsRegistry.get('libp2p_noise_decrypt_errors_total')?.increment.callCount).to.equal(0)
  })
})
