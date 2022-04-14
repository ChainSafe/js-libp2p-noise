import type { PeerId } from '@libp2p/interfaces/peer-id'
import { Buffer } from 'buffer'
import { assert } from 'aegir/chai'
import { pbStream } from 'it-pb-stream'
import { duplexPair } from 'it-pair/duplex'
import { equals as uint8ArrayEquals } from 'uint8arrays/equals'
import { stablelib } from '../src/crypto/stablelib.js'
import { encode0 } from '../src/encoder.js'
import { XXFallbackHandshake } from '../src/handshake-xx-fallback.js'
import { getPayload } from '../src/utils.js'
import { createPeerIdsFromFixtures } from './fixtures/peer.js'

describe('XX Fallback Handshake', () => {
  let peerA: PeerId, peerB: PeerId

  before(async () => {
    [peerA, peerB] = await createPeerIdsFromFixtures(2)
  })

  it('should test that both parties can fallback to XX and finish handshake', async () => {
    try {
      const duplex = duplexPair<Uint8Array>()
      const connectionFrom = pbStream(duplex[0])
      const connectionTo = pbStream(duplex[1])

      const prologue = Buffer.alloc(0)
      const staticKeysInitiator = stablelib.generateX25519KeyPair()
      const staticKeysResponder = stablelib.generateX25519KeyPair()
      const ephemeralKeys = stablelib.generateX25519KeyPair()

      // Initial msg for responder is IK first message from initiator
      const handshakePayload = await getPayload(peerA, staticKeysInitiator.publicKey)
      const initialMsgR = encode0({
        ne: ephemeralKeys.publicKey,
        ns: Buffer.alloc(0),
        ciphertext: handshakePayload
      })

      const respPayload = await getPayload(peerB, staticKeysResponder.publicKey)
      const handshakeResp =
        new XXFallbackHandshake(false, respPayload, prologue, stablelib, staticKeysResponder, connectionTo, initialMsgR, peerA)

      await handshakeResp.propose()
      await handshakeResp.exchange()

      // Initial message for initiator is XX Message B from responder
      // This is the point where initiator falls back from IK
      const initialMsgI = await connectionFrom.readLP()
      const handshakeInit =
        new XXFallbackHandshake(true, handshakePayload, prologue, stablelib, staticKeysInitiator, connectionFrom, initialMsgI.slice(0), peerB, ephemeralKeys)

      await handshakeInit.propose()
      await handshakeInit.exchange()

      await handshakeInit.finish()
      await handshakeResp.finish()

      const sessionInitator = handshakeInit.session
      const sessionResponder = handshakeResp.session

      // Test shared key
      if (sessionInitator.cs1 !== undefined &&
        sessionResponder.cs1 !== undefined &&
        sessionInitator.cs2 !== undefined &&
        sessionResponder.cs2 !== undefined) {
        assert(uint8ArrayEquals(sessionInitator.cs1.k, sessionResponder.cs1.k))
        assert(uint8ArrayEquals(sessionInitator.cs2.k, sessionResponder.cs2.k))
      } else {
        assert(false)
      }
    } catch (e) {
      const err = e as Error
      assert(false, err.message)
    }
  })
})
