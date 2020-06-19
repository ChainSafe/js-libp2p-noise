import { Buffer } from 'buffer'
import { IK } from '../../src/handshakes/ik'
import { KeyPair } from '../../src/@types/libp2p'
import { createHandshakePayload, generateKeypair, getHandshakePayload } from '../../src/utils'
import { assert, expect } from 'chai'
import { generateEd25519Keys } from '../utils'

describe('IK handshake', () => {
  const prologue = Buffer.alloc(0)

  it('Test complete IK handshake', async () => {
    try {
      const ikI = new IK()
      const ikR = new IK()

      // Generate static noise keys
      const kpInitiator: KeyPair = await generateKeypair()
      const kpResponder: KeyPair = await generateKeypair()

      // Generate libp2p keys
      const libp2pInitKeys = await generateEd25519Keys()
      const libp2pRespKeys = await generateEd25519Keys()

      // Create sessions
      const initiatorSession = await ikI.initSession(true, prologue, kpInitiator, kpResponder.publicKey)
      const responderSession = await ikR.initSession(false, prologue, kpResponder, Buffer.alloc(32))

      /* Stage 0 */

      // initiator creates payload
      const initSignedPayload = await libp2pInitKeys.sign(getHandshakePayload(kpInitiator.publicKey))
      const libp2pInitPrivKey = libp2pInitKeys.marshal().slice(0, 32)
      const libp2pInitPubKey = libp2pInitKeys.marshal().slice(32, 64)
      const payloadInitEnc = await createHandshakePayload(libp2pInitPubKey, initSignedPayload)

      // initiator sends message
      const message = Buffer.concat([Buffer.alloc(0), payloadInitEnc])
      const messageBuffer = ikI.sendMessage(initiatorSession, message)

      expect(messageBuffer.ne.length).not.equal(0)

      // responder receives message
      const plaintext = ikR.recvMessage(responderSession, messageBuffer)

      /* Stage 1 */

      // responder creates payload
      const libp2pRespPrivKey = libp2pRespKeys.marshal().slice(0, 32)
      const libp2pRespPubKey = libp2pRespKeys.marshal().slice(32, 64)
      const respSignedPayload = await libp2pRespKeys.sign(getHandshakePayload(kpResponder.publicKey))
      const payloadRespEnc = await createHandshakePayload(libp2pRespPubKey, respSignedPayload)

      const message1 = Buffer.concat([message, payloadRespEnc])
      const messageBuffer2 = ikR.sendMessage(responderSession, message1)

      // initiator receives message
      const plaintext2 = ikI.recvMessage(initiatorSession, messageBuffer2)

      assert(initiatorSession.cs1.k.equals(responderSession.cs1.k))
      assert(initiatorSession.cs2.k.equals(responderSession.cs2.k))
    } catch (e) {
      console.error(e)
      return assert(false, e.message)
    }
  })
})
