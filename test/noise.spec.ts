import { assert, expect } from 'chai'
import DuplexPair from 'it-pair/duplex'
import { createPeerIdsFromFixtures } from './fixtures/peer'
import Wrap from 'it-pb-rpc'
import sinon from 'sinon'
import BufferList from 'bl'
import { randomBytes } from 'libp2p-crypto'
import { Buffer } from 'buffer'
import uint8ArrayEquals from 'uint8arrays/equals'

import { Noise } from '../src'
import { XXHandshake } from '../src/handshake-xx'
import { createHandshakePayload, generateKeypair, getHandshakePayload, getPayload, signPayload } from '../src/utils'
import { decode0, decode2, encode1, uint16BEDecode, uint16BEEncode } from '../src/encoder'
import { XX } from '../src/handshakes/xx'
import { getKeyPairFromPeerId } from './utils'
import { KeyCache } from '../src/keycache'
import { NOISE_MSG_MAX_LENGTH_BYTES } from '../src/constants'

describe('Noise', () => {
  let remotePeer, localPeer
  const sandbox = sinon.createSandbox()

  before(async () => {
    [localPeer, remotePeer] = await createPeerIdsFromFixtures(2)
  })

  afterEach(function () {
    sandbox.restore()
  })

  it('should communicate through encrypted streams without noise pipes', async () => {
    try {
      const noiseInit = new Noise(undefined, undefined)
      const noiseResp = new Noise(undefined, undefined)

      const [inboundConnection, outboundConnection] = DuplexPair()
      const [outbound, inbound] = await Promise.all([
        noiseInit.secureOutbound(localPeer, outboundConnection, remotePeer),
        noiseResp.secureInbound(remotePeer, inboundConnection, localPeer)
      ])
      const wrappedInbound = Wrap(inbound.conn)
      const wrappedOutbound = Wrap(outbound.conn)

      wrappedOutbound.writeLP(Buffer.from('test'))
      const response = await wrappedInbound.readLP()
      expect(response.toString()).equal('test')
    } catch (e) {
      assert(false, e.message)
    }
  })

  it('should test that secureOutbound is spec compliant', async () => {
    const noiseInit = new Noise(undefined, undefined)
    const [inboundConnection, outboundConnection] = DuplexPair()

    const [outbound, { wrapped, handshake }] = await Promise.all([
      noiseInit.secureOutbound(localPeer, outboundConnection, remotePeer),
      (async () => {
        const wrapped = Wrap(
          inboundConnection,
          {
            lengthEncoder: uint16BEEncode,
            lengthDecoder: uint16BEDecode,
            maxDataLength: NOISE_MSG_MAX_LENGTH_BYTES
          }
        )
        const prologue = Buffer.alloc(0)
        const staticKeys = generateKeypair()
        const xx = new XX()

        const payload = await getPayload(remotePeer, staticKeys.publicKey)
        const handshake = new XXHandshake(false, payload, prologue, staticKeys, wrapped, localPeer, xx)

        let receivedMessageBuffer = decode0((await wrapped.readLP()).slice())
        // The first handshake message contains the initiator's ephemeral public key
        expect(receivedMessageBuffer.ne.length).equal(32)
        xx.recvMessage(handshake.session, receivedMessageBuffer)

        // Stage 1
        const { publicKey: libp2pPubKey } = getKeyPairFromPeerId(remotePeer)
        const signedPayload = await signPayload(remotePeer, getHandshakePayload(staticKeys.publicKey))
        const handshakePayload = await createHandshakePayload(libp2pPubKey, signedPayload)

        const messageBuffer = xx.sendMessage(handshake.session, handshakePayload)
        wrapped.writeLP(encode1(messageBuffer))

        // Stage 2 - finish handshake
        receivedMessageBuffer = decode2((await wrapped.readLP()).slice())
        xx.recvMessage(handshake.session, receivedMessageBuffer)
        return { wrapped, handshake }
      })()
    ])

    try {
      const wrappedOutbound = Wrap(outbound.conn)
      wrappedOutbound.write(new BufferList([Buffer.from('test')]))

      // Check that noise message is prefixed with 16-bit big-endian unsigned integer
      const receivedEncryptedPayload = (await wrapped.read()).slice()
      const dataLength = receivedEncryptedPayload.readInt16BE(0)
      const data = receivedEncryptedPayload.slice(2, dataLength + 2)
      const { plaintext: decrypted, valid } = handshake.decrypt(data, handshake.session)
      // Decrypted data should match
      assert(decrypted.equals(Buffer.from('test')))
      assert(valid)
    } catch (e) {
      assert(false, e.message)
    }
  })

  it('should test large payloads', async function () {
    this.timeout(10000)
    try {
      const noiseInit = new Noise(undefined, undefined)
      const noiseResp = new Noise(undefined, undefined)

      const [inboundConnection, outboundConnection] = DuplexPair()
      const [outbound, inbound] = await Promise.all([
        noiseInit.secureOutbound(localPeer, outboundConnection, remotePeer),
        noiseResp.secureInbound(remotePeer, inboundConnection, localPeer)
      ])
      const wrappedInbound = Wrap(inbound.conn)
      const wrappedOutbound = Wrap(outbound.conn)

      const largePlaintext = randomBytes(100000)
      wrappedOutbound.writeLP(Buffer.from(largePlaintext))
      const response = await wrappedInbound.read(100000)

      expect(response.length).equals(largePlaintext.length)
    } catch (e) {
      assert(false, e.message)
    }
  })

  it.skip('should communicate through encrypted streams with noise pipes', async () => {
    try {
      const staticKeysInitiator = generateKeypair()
      const noiseInit = new Noise(staticKeysInitiator.privateKey)
      const staticKeysResponder = generateKeypair()
      const noiseResp = new Noise(staticKeysResponder.privateKey)

      // Prepare key cache for noise pipes
      KeyCache.store(localPeer, staticKeysInitiator.publicKey)
      KeyCache.store(remotePeer, staticKeysResponder.publicKey)

      // @ts-expect-error
      const xxSpy = sandbox.spy(noiseInit, 'performXXHandshake')
      // @ts-expect-error
      const xxFallbackSpy = sandbox.spy(noiseInit, 'performXXFallbackHandshake')

      const [inboundConnection, outboundConnection] = DuplexPair()
      const [outbound, inbound] = await Promise.all([
        noiseInit.secureOutbound(localPeer, outboundConnection, remotePeer),
        noiseResp.secureInbound(remotePeer, inboundConnection, localPeer)
      ])
      const wrappedInbound = Wrap(inbound.conn)
      const wrappedOutbound = Wrap(outbound.conn)

      wrappedOutbound.writeLP(Buffer.from('test v2'))
      const response = await wrappedInbound.readLP()
      expect(response.toString()).equal('test v2')

      assert(xxSpy.notCalled)
      assert(xxFallbackSpy.notCalled)
    } catch (e) {
      assert(false, e.message)
    }
  })

  it.skip('IK -> XX fallback: initiator has invalid remote static key', async () => {
    try {
      const staticKeysInitiator = generateKeypair()
      const noiseInit = new Noise(staticKeysInitiator.privateKey)
      const noiseResp = new Noise()
      // @ts-expect-error
      const xxSpy = sandbox.spy(noiseInit, 'performXXFallbackHandshake')

      // Prepare key cache for noise pipes
      KeyCache.resetStorage()
      KeyCache.store(localPeer, staticKeysInitiator.publicKey)
      KeyCache.store(remotePeer, generateKeypair().publicKey)

      const [inboundConnection, outboundConnection] = DuplexPair()
      const [outbound, inbound] = await Promise.all([
        noiseInit.secureOutbound(localPeer, outboundConnection, remotePeer),
        noiseResp.secureInbound(remotePeer, inboundConnection, localPeer)
      ])

      const wrappedInbound = Wrap(inbound.conn)
      const wrappedOutbound = Wrap(outbound.conn)

      wrappedOutbound.writeLP(Buffer.from('test fallback'))
      const response = await wrappedInbound.readLP()
      expect(response.toString()).equal('test fallback')

      assert(xxSpy.calledOnce, 'XX Fallback method was never called.')
    } catch (e) {
      assert(false, e.message)
    }
  })

  // this didn't work before but we didn't verify decryption
  it.skip('IK -> XX fallback: responder has disabled noise pipes', async () => {
    try {
      const staticKeysInitiator = generateKeypair()
      const noiseInit = new Noise(staticKeysInitiator.privateKey)

      const staticKeysResponder = generateKeypair()
      const noiseResp = new Noise(staticKeysResponder.privateKey, undefined)
      // @ts-expect-error
      const xxSpy = sandbox.spy(noiseInit, 'performXXFallbackHandshake')

      // Prepare key cache for noise pipes
      KeyCache.store(localPeer, staticKeysInitiator.publicKey)
      KeyCache.store(remotePeer, staticKeysResponder.publicKey)

      const [inboundConnection, outboundConnection] = DuplexPair()
      const [outbound, inbound] = await Promise.all([
        noiseInit.secureOutbound(localPeer, outboundConnection, remotePeer),
        noiseResp.secureInbound(remotePeer, inboundConnection, localPeer)
      ])

      const wrappedInbound = Wrap(inbound.conn)
      const wrappedOutbound = Wrap(outbound.conn)

      wrappedOutbound.writeLP(Buffer.from('test fallback'))
      const response = await wrappedInbound.readLP()
      expect(response.toString()).equal('test fallback')

      assert(xxSpy.calledOnce, 'XX Fallback method was never called.')
    } catch (e) {
      assert(false, e.message)
    }
  })

  it.skip('Initiator starts with XX (pipes disabled), responder has enabled noise pipes', async () => {
    try {
      const staticKeysInitiator = generateKeypair()
      const noiseInit = new Noise(staticKeysInitiator.privateKey, undefined)
      const staticKeysResponder = generateKeypair()

      const noiseResp = new Noise(staticKeysResponder.privateKey)
      // @ts-expect-error
      const xxInitSpy = sandbox.spy(noiseInit, 'performXXHandshake')
      // @ts-expect-error
      const xxRespSpy = sandbox.spy(noiseResp, 'performXXFallbackHandshake')

      // Prepare key cache for noise pipes
      KeyCache.store(localPeer, staticKeysInitiator.publicKey)

      const [inboundConnection, outboundConnection] = DuplexPair()

      const [outbound, inbound] = await Promise.all([
        noiseInit.secureOutbound(localPeer, outboundConnection, remotePeer),
        noiseResp.secureInbound(remotePeer, inboundConnection, localPeer)
      ])

      const wrappedInbound = Wrap(inbound.conn)
      const wrappedOutbound = Wrap(outbound.conn)

      wrappedOutbound.writeLP(Buffer.from('test fallback'))
      const response = await wrappedInbound.readLP()
      expect(response.toString()).equal('test fallback')

      assert(xxInitSpy.calledOnce, 'XX method was never called.')
      assert(xxRespSpy.calledOnce, 'XX Fallback method was never called.')
    } catch (e) {
      assert(false, e.message)
    }
  })

  it.skip('IK: responder has no remote static key', async () => {
    try {
      const staticKeysInitiator = generateKeypair()
      const noiseInit = new Noise(staticKeysInitiator.privateKey)
      const staticKeysResponder = generateKeypair()

      const noiseResp = new Noise(staticKeysResponder.privateKey)
      // @ts-expect-error
      const ikInitSpy = sandbox.spy(noiseInit, 'performIKHandshake')
      // @ts-expect-error
      const xxFallbackInitSpy = sandbox.spy(noiseInit, 'performXXFallbackHandshake')
      // @ts-expect-error
      const ikRespSpy = sandbox.spy(noiseResp, 'performIKHandshake')

      // Prepare key cache for noise pipes
      KeyCache.resetStorage()
      KeyCache.store(remotePeer, staticKeysResponder.publicKey)

      const [inboundConnection, outboundConnection] = DuplexPair()

      const [outbound, inbound] = await Promise.all([
        noiseInit.secureOutbound(localPeer, outboundConnection, remotePeer),
        noiseResp.secureInbound(remotePeer, inboundConnection, localPeer)
      ])

      const wrappedInbound = Wrap(inbound.conn)
      const wrappedOutbound = Wrap(outbound.conn)

      wrappedOutbound.writeLP(Buffer.from('test fallback'))
      const response = await wrappedInbound.readLP()
      expect(response.toString()).equal('test fallback')

      assert(ikInitSpy.calledOnce, 'IK handshake was not called.')
      assert(ikRespSpy.calledOnce, 'IK handshake was not called.')
      assert(xxFallbackInitSpy.notCalled, 'XX Fallback method was called.')
    } catch (e) {
      assert(false, e.message)
    }
  })

  it('should working without remote peer provided in incoming connection', async () => {
    try {
      const staticKeysInitiator = generateKeypair()
      const noiseInit = new Noise(staticKeysInitiator.privateKey)
      const staticKeysResponder = generateKeypair()
      const noiseResp = new Noise(staticKeysResponder.privateKey)

      // Prepare key cache for noise pipes
      KeyCache.store(localPeer, staticKeysInitiator.publicKey)
      KeyCache.store(remotePeer, staticKeysResponder.publicKey)

      const [inboundConnection, outboundConnection] = DuplexPair()
      const [outbound, inbound] = await Promise.all([
        noiseInit.secureOutbound(localPeer, outboundConnection, remotePeer),
        noiseResp.secureInbound(remotePeer, inboundConnection)
      ])
      const wrappedInbound = Wrap(inbound.conn)
      const wrappedOutbound = Wrap(outbound.conn)

      wrappedOutbound.writeLP(Buffer.from('test v2'))
      const response = await wrappedInbound.readLP()
      expect(response.toString()).equal('test v2')

      assert(uint8ArrayEquals(inbound.remotePeer.marshalPubKey(), localPeer.marshalPubKey()))
      assert(uint8ArrayEquals(outbound.remotePeer.marshalPubKey(), remotePeer.marshalPubKey()))
    } catch (e) {
      assert(false, e.message)
    }
  })

  it('should accept and return early data from remote peer', async () => {
    try {
      const localPeerEarlyData = Buffer.from('early data')
      const staticKeysInitiator = generateKeypair()
      const noiseInit = new Noise(staticKeysInitiator.privateKey, localPeerEarlyData)
      const staticKeysResponder = generateKeypair()
      const noiseResp = new Noise(staticKeysResponder.privateKey)

      // Prepare key cache for noise pipes
      KeyCache.store(localPeer, staticKeysInitiator.publicKey)
      KeyCache.store(remotePeer, staticKeysResponder.publicKey)

      const [inboundConnection, outboundConnection] = DuplexPair()
      const [outbound, inbound] = await Promise.all([
        noiseInit.secureOutbound(localPeer, outboundConnection, remotePeer),
        noiseResp.secureInbound(remotePeer, inboundConnection)
      ])

      assert(inbound.remoteEarlyData.equals(localPeerEarlyData))
      assert(outbound.remoteEarlyData.equals(Buffer.alloc(0)))
    } catch (e) {
      assert(false, e.message)
    }
  })
})
