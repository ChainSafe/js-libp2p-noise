import Wrap from "it-pb-rpc";
import {Buffer} from "buffer";
import Duplex from 'it-pair/duplex';

import {
  generateKeypair,
  getPayload,
} from "../src/utils";
import {XXFallbackHandshake} from "../src/handshake-xx-fallback";
import {createPeerIdsFromFixtures} from "./fixtures/peer";
import {assert} from "chai";
import {decode1, encode0, encode1} from "../src/encoder";

describe("XX Fallback Handshake", () => {
  let peerA, peerB, fakePeer;

  before(async () => {
    [peerA, peerB] = await createPeerIdsFromFixtures(2);
  });

  it("should test that both parties can fallback to XX and finish handshake", async () => {
    try {
      const duplex = Duplex();
      const connectionFrom = Wrap(duplex[0]);
      const connectionTo = Wrap(duplex[1]);

      const prologue = Buffer.alloc(0);
      const staticKeysInitiator = generateKeypair();
      const staticKeysResponder = generateKeypair();
      const ephemeralKeys = generateKeypair();

      // Initial msg for responder is IK first message from initiator
      const handshakePayload = await getPayload(peerA, staticKeysInitiator.publicKey);
      const initialMsgR = encode0({
        ne: ephemeralKeys.publicKey,
        ns: Buffer.alloc(0),
        ciphertext: handshakePayload,
      });

      const respPayload = await getPayload(peerB, staticKeysResponder.publicKey);
      const handshakeResp =
        new XXFallbackHandshake(false, respPayload, prologue, staticKeysResponder, connectionTo, peerA, initialMsgR);

      await handshakeResp.propose();
      await handshakeResp.exchange();

      // Initial message for initiator is XX Message B from responder
      // This is the point where initiator falls back from IK
      const initialMsgI = await connectionFrom.readLP();
      const handshakeInit =
        new XXFallbackHandshake(true, handshakePayload, prologue, staticKeysInitiator, connectionFrom, peerB, initialMsgI, ephemeralKeys);

      await handshakeInit.propose();
      await handshakeInit.exchange();

      await handshakeInit.finish();
      await handshakeResp.finish();

      const sessionInitator = handshakeInit.session;
      const sessionResponder = handshakeResp.session;

      // Test shared key
      if (sessionInitator.cs1 && sessionResponder.cs1 && sessionInitator.cs2 && sessionResponder.cs2) {
        assert(sessionInitator.cs1.k.equals(sessionResponder.cs1.k));
        assert(sessionInitator.cs2.k.equals(sessionResponder.cs2.k));
      } else {
        assert(false);
      }
    } catch (e) {
      console.error(e);
      assert(false, e.message);
    }
  });
})
