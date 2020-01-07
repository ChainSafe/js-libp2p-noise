import Wrap from "it-pb-rpc";
import {Buffer} from "buffer";
import Duplex from 'it-pair/duplex';

import {
  createHandshakePayload,
  generateKeypair,
  getHandshakePayload,
  signPayload
} from "../src/utils";
import {generateEd25519Keys, getKeyPairFromPeerId} from "./utils";
import {Handshake} from "../src/handshake-xx-fallback";
import {createPeerIdsFromFixtures} from "./fixtures/peer";
import {assert} from "chai";
import {encode0, encode1} from "../src/encoder";

describe("XX Fallback Handshake", () => {
  let peerA, peerB, fakePeer;

  before(async () => {
    [peerA, peerB] = await createPeerIdsFromFixtures(2);
  });

  it("should make handshake with received ephemeral key (from initial IK message)", async () => {
    try {
      const duplex = Duplex();
      const connectionFrom = Wrap(duplex[0]);
      const connectionTo = Wrap(duplex[1]);

      const prologue = Buffer.from('/noise');
      const staticKeysInitiator = generateKeypair();
      const staticKeysResponder = generateKeypair();
      const ephemeralKeys = generateKeypair();

      const {privateKey: initiatorPrivKey, publicKey: initiatorPubKey} = getKeyPairFromPeerId(peerA);
      const {privateKey: responderPrivKey, publicKey: responderPubKey} = getKeyPairFromPeerId(peerB);

      const signedPayload = signPayload(initiatorPrivKey, getHandshakePayload(staticKeysInitiator.publicKey));
      const handshakePayload = await createHandshakePayload(
        initiatorPubKey,
        initiatorPrivKey,
        signedPayload,
      );
      const initialMsg = encode0({
        ne: ephemeralKeys.publicKey,
        ns: Buffer.alloc(0),
        ciphertext: handshakePayload,
      });

      const handshakeInit =
        new Handshake(true, initiatorPrivKey, initiatorPubKey, prologue, staticKeysInitiator, connectionFrom, peerB, ephemeralKeys, initialMsg);

      const handshakeResp =
        new Handshake(false, responderPrivKey, responderPubKey, prologue, staticKeysResponder, connectionTo, peerA, ephemeralKeys, initialMsg);


      await handshakeInit.propose();
      await handshakeResp.propose();

      await handshakeResp.exchange();
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
