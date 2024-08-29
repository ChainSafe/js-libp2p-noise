import { Buffer } from 'buffer'
import { defaultLogger } from '@libp2p/logger'
import { assert, expect } from 'aegir/chai'
import { randomBytes } from 'iso-random-stream'
import { byteStream } from 'it-byte-stream'
import { lpStream } from 'it-length-prefixed-stream'
import { duplexPair } from 'it-pair/duplex'
import sinon from 'sinon'
import { equals as uint8ArrayEquals } from 'uint8arrays/equals'
import { toString as uint8ArrayToString } from 'uint8arrays/to-string'
import { pureJsCrypto } from '../src/crypto/js.js'
import { Noise } from '../src/noise.js'
import { createPeerIdsFromFixtures } from './fixtures/peer.js'
import type { PeerId } from '@libp2p/interface'
import type { Uint8ArrayList } from 'uint8arraylist'

describe('Noise', () => {
  let remotePeer: PeerId, localPeer: PeerId
  const sandbox = sinon.createSandbox()

  before(async () => {
    [localPeer, remotePeer] = await createPeerIdsFromFixtures(2)
  })

  afterEach(function () {
    sandbox.restore()
  })

  it('should communicate through encrypted streams without noise pipes', async () => {
    try {
      const noiseInit = new Noise({
        peerId: localPeer,
        logger: defaultLogger()
      }, { staticNoiseKey: undefined, extensions: undefined })
      const noiseResp = new Noise({
        peerId: remotePeer,
        logger: defaultLogger()
      }, { staticNoiseKey: undefined, extensions: undefined })

      const [inboundConnection, outboundConnection] = duplexPair<Uint8Array | Uint8ArrayList>()
      const [outbound, inbound] = await Promise.all([
        noiseInit.secureOutbound(localPeer, outboundConnection, remotePeer),
        noiseResp.secureInbound(remotePeer, inboundConnection, localPeer)
      ])
      const wrappedInbound = lpStream(inbound.conn)
      const wrappedOutbound = lpStream(outbound.conn)

      await wrappedOutbound.write(Buffer.from('test'))
      const response = await wrappedInbound.read()
      expect(uint8ArrayToString(response.slice())).equal('test')
    } catch (e) {
      const err = e as Error
      assert(false, err.message)
    }
  })

  it('should test large payloads', async function () {
    this.timeout(10000)
    try {
      const noiseInit = new Noise({
        peerId: localPeer,
        logger: defaultLogger()
      }, { staticNoiseKey: undefined })
      const noiseResp = new Noise({
        peerId: remotePeer,
        logger: defaultLogger()
      }, { staticNoiseKey: undefined })

      const [inboundConnection, outboundConnection] = duplexPair<Uint8Array | Uint8ArrayList>()
      const [outbound, inbound] = await Promise.all([
        noiseInit.secureOutbound(localPeer, outboundConnection, remotePeer),
        noiseResp.secureInbound(remotePeer, inboundConnection, localPeer)
      ])
      const wrappedInbound = byteStream(inbound.conn)
      const wrappedOutbound = lpStream(outbound.conn)

      const largePlaintext = randomBytes(60000)
      await wrappedOutbound.write(Buffer.from(largePlaintext))
      const response = await wrappedInbound.read(60000)

      expect(response.length).equals(largePlaintext.length)
    } catch (e) {
      const err = e as Error
      assert(false, err.message)
    }
  })

  it('should working without remote peer provided in incoming connection', async () => {
    try {
      const staticKeysInitiator = pureJsCrypto.generateX25519KeyPair()
      const noiseInit = new Noise({
        peerId: localPeer,
        logger: defaultLogger()
      }, { staticNoiseKey: staticKeysInitiator.privateKey })
      const staticKeysResponder = pureJsCrypto.generateX25519KeyPair()
      const noiseResp = new Noise({
        peerId: remotePeer,
        logger: defaultLogger()
      }, { staticNoiseKey: staticKeysResponder.privateKey })

      const [inboundConnection, outboundConnection] = duplexPair<Uint8Array | Uint8ArrayList>()
      const [outbound, inbound] = await Promise.all([
        noiseInit.secureOutbound(localPeer, outboundConnection, remotePeer),
        noiseResp.secureInbound(remotePeer, inboundConnection)
      ])
      const wrappedInbound = lpStream(inbound.conn)
      const wrappedOutbound = lpStream(outbound.conn)

      await wrappedOutbound.write(Buffer.from('test v2'))
      const response = await wrappedInbound.read()
      expect(uint8ArrayToString(response.slice())).equal('test v2')

      if (inbound.remotePeer.publicKey == null || localPeer.publicKey == null ||
        outbound.remotePeer.publicKey == null || remotePeer.publicKey == null) {
        throw new Error('Public key missing from PeerId')
      }

      assert(uint8ArrayEquals(inbound.remotePeer.publicKey, localPeer.publicKey))
      assert(uint8ArrayEquals(outbound.remotePeer.publicKey, remotePeer.publicKey))
    } catch (e) {
      const err = e as Error
      assert(false, err.message)
    }
  })

  it('should accept and return Noise extension from remote peer', async () => {
    try {
      const certhashInit = Buffer.from('certhash data from init')
      const staticKeysInitiator = pureJsCrypto.generateX25519KeyPair()
      const noiseInit = new Noise({
        peerId: localPeer,
        logger: defaultLogger()
      }, { staticNoiseKey: staticKeysInitiator.privateKey, extensions: { webtransportCerthashes: [certhashInit] } })
      const staticKeysResponder = pureJsCrypto.generateX25519KeyPair()
      const certhashResp = Buffer.from('certhash data from respon')
      const noiseResp = new Noise({
        peerId: remotePeer,
        logger: defaultLogger()
      }, { staticNoiseKey: staticKeysResponder.privateKey, extensions: { webtransportCerthashes: [certhashResp] } })

      const [inboundConnection, outboundConnection] = duplexPair<Uint8Array | Uint8ArrayList>()
      const [outbound, inbound] = await Promise.all([
        noiseInit.secureOutbound(localPeer, outboundConnection, remotePeer),
        noiseResp.secureInbound(remotePeer, inboundConnection)
      ])

      assert(uint8ArrayEquals(inbound.remoteExtensions?.webtransportCerthashes[0] ?? new Uint8Array(), certhashInit))
      assert(uint8ArrayEquals(outbound.remoteExtensions?.webtransportCerthashes[0] ?? new Uint8Array(), certhashResp))
    } catch (e) {
      const err = e as Error
      assert(false, err.message)
    }
  })

  it('should accept a prologue', async () => {
    try {
      const noiseInit = new Noise({
        peerId: localPeer,
        logger: defaultLogger()
      }, { staticNoiseKey: undefined, crypto: pureJsCrypto, prologueBytes: Buffer.from('Some prologue') })
      const noiseResp = new Noise({
        peerId: remotePeer,
        logger: defaultLogger()
      }, { staticNoiseKey: undefined, crypto: pureJsCrypto, prologueBytes: Buffer.from('Some prologue') })

      const [inboundConnection, outboundConnection] = duplexPair<Uint8Array | Uint8ArrayList>()
      const [outbound, inbound] = await Promise.all([
        noiseInit.secureOutbound(localPeer, outboundConnection, remotePeer),
        noiseResp.secureInbound(remotePeer, inboundConnection, localPeer)
      ])
      const wrappedInbound = lpStream(inbound.conn)
      const wrappedOutbound = lpStream(outbound.conn)

      await wrappedOutbound.write(Buffer.from('test'))
      const response = await wrappedInbound.read()
      expect(uint8ArrayToString(response.slice())).equal('test')
    } catch (e) {
      const err = e as Error
      assert(false, err.message)
    }
  })

  it('should abort noise handshake', async () => {
    const abortController = new AbortController()
    abortController.abort()

    const noiseInit = new Noise({
      peerId: localPeer,
      logger: defaultLogger()
    }, { staticNoiseKey: undefined, extensions: undefined })
    const noiseResp = new Noise({
      peerId: remotePeer,
      logger: defaultLogger()
    }, { staticNoiseKey: undefined, extensions: undefined })

    const [inboundConnection, outboundConnection] = duplexPair<Uint8Array | Uint8ArrayList>()

    await expect(Promise.all([
      noiseInit.secureOutbound(outboundConnection, {
        remotePeer,
        signal: abortController.signal
      }),
      noiseResp.secureInbound(inboundConnection, {
        remotePeer: localPeer
      })
    ])).to.eventually.be.rejected
      .with.property('name', 'AbortError')
  })
})
