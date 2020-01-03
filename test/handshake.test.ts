import {assert, expect} from "chai";
import Duplex from 'it-pair/duplex';
import {Buffer} from "buffer";
import Wrap from "it-pb-rpc";

import {Handshake} from "../src/handshake-xx";
import {generateKeypair} from "../src/utils";
import {createPeerIdsFromFixtures} from "./fixtures/peer";
import {getKeyPairFromPeerId} from "./utils";


describe("Handshake", () => {
  let peerA, peerB, fakePeer;

  before(async () => {
    [peerA, peerB, fakePeer] = await createPeerIdsFromFixtures(3);
  });

  it("should propose, exchange and finish handshake", async() => {
    try {
      const duplex = Duplex();
      const connectionFrom = Wrap(duplex[0]);
      const connectionTo = Wrap(duplex[1]);

      const prologue = Buffer.from('/noise');
      const staticKeysInitiator = generateKeypair();
      const staticKeysResponder = generateKeypair();

      const { privateKey: initiatorPrivKey, publicKey: initiatorPubKey } = getKeyPairFromPeerId(peerA);
      const handshakeInitator = new Handshake(true, initiatorPrivKey, initiatorPubKey, prologue, staticKeysInitiator, connectionFrom, peerB);

      const { privateKey: responderPrivKey, publicKey: responderPubKey } = getKeyPairFromPeerId(peerB);
      const handshakeResponder = new Handshake(false, responderPrivKey, responderPubKey, prologue, staticKeysResponder, connectionTo, peerA);

      await handshakeInitator.propose();
      await handshakeResponder.propose();

      await handshakeResponder.exchange();
      await handshakeInitator.exchange();

      await handshakeInitator.finish();
      await handshakeResponder.finish();

      const sessionInitator = handshakeInitator.session;
      const sessionResponder = handshakeResponder.session;

      // Test shared key
      if (sessionInitator.cs1 && sessionResponder.cs1 && sessionInitator.cs2 && sessionResponder.cs2) {
        assert(sessionInitator.cs1.k.equals(sessionResponder.cs1.k));
        assert(sessionInitator.cs2.k.equals(sessionResponder.cs2.k));
      } else {
        assert(false);
      }

      // Test encryption and decryption
      const encrypted = handshakeInitator.encrypt(Buffer.from("encryptthis"), handshakeInitator.session);
      const decrypted = handshakeResponder.decrypt(encrypted, handshakeResponder.session);
      assert(decrypted.equals(Buffer.from("encryptthis")));
    } catch (e) {
      assert(false, e.message);
    }
  });

  it("Initiator should fail to exchange handshake if given wrong public key in payload", async() => {
    try {
      const duplex = Duplex();
      const connectionFrom = Wrap(duplex[0]);
      const connectionTo = Wrap(duplex[1]);

      const prologue = Buffer.from('/noise');
      const staticKeysInitiator = generateKeypair();
      const staticKeysResponder = generateKeypair();

      const { privateKey: initiatorPrivKey, publicKey: initiatorPubKey } = getKeyPairFromPeerId(peerA);
      const handshakeInitator = new Handshake(true, initiatorPrivKey, initiatorPubKey, prologue, staticKeysInitiator, connectionFrom, fakePeer);

      const { privateKey: responderPrivKey, publicKey: responderPubKey } = getKeyPairFromPeerId(peerB);
      const handshakeResponder = new Handshake(false, responderPrivKey, responderPubKey, prologue, staticKeysResponder, connectionTo, peerA);

      await handshakeInitator.propose();
      await handshakeResponder.propose();

      await handshakeResponder.exchange();
      await handshakeInitator.exchange();

      assert(false, "Should throw exception");
    } catch (e) {
      expect(e.message).equals("Error occurred while verifying signed payload: Peer ID doesn't match libp2p public key.")
    }
  });

  it("Responder should fail to exchange handshake if given wrong public key in payload", async() => {
    try {
      const duplex = Duplex();
      const connectionFrom = Wrap(duplex[0]);
      const connectionTo = Wrap(duplex[1]);

      const prologue = Buffer.from('/noise');
      const staticKeysInitiator = generateKeypair();
      const staticKeysResponder = generateKeypair();

      const { privateKey: initiatorPrivKey, publicKey: initiatorPubKey } = getKeyPairFromPeerId(peerA);
      const handshakeInitator = new Handshake(true, initiatorPrivKey, initiatorPubKey, prologue, staticKeysInitiator, connectionFrom, peerB);

      const { privateKey: responderPrivKey, publicKey: responderPubKey } = getKeyPairFromPeerId(peerB);
      const handshakeResponder = new Handshake(false, responderPrivKey, responderPubKey, prologue, staticKeysResponder, connectionTo, fakePeer);

      await handshakeInitator.propose();
      await handshakeResponder.propose();

      await handshakeResponder.exchange();
      await handshakeInitator.exchange();

      await handshakeInitator.finish();
      await handshakeResponder.finish();

      assert(false, "Should throw exception");
    } catch (e) {
      expect(e.message).equals("Error occurred while verifying signed payload: Peer ID doesn't match libp2p public key.")
    }
  });
});
