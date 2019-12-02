import {assert} from "chai";
import Duplex from 'it-pair/duplex';
import {Buffer} from "buffer";
import Wrap from "it-pb-rpc";

import {Handshake} from "../src/handshake";
import {generateKeypair} from "../src/utils";
import {createPeerIds} from "./fixtures/peer";


describe("Handshake", () => {
  it("should propose, exchange and finish handshake", async() => {
    const duplex = Duplex();
    const connectionFrom = Wrap(duplex[0]);
    const connectionTo = Wrap(duplex[1]);

    const prologue = Buffer.from('/noise');
    const staticKeysInitiator = generateKeypair();
    const staticKeysResponder = generateKeypair();
    const [peerA, peerB] = await createPeerIds(2);

    const initiatorPrivKey = peerA.privKey.marshal().slice(0, 32);
    const initiatorPubKey = peerA.pubKey.marshal();
    const handshakeInitator = new Handshake(true, initiatorPrivKey, initiatorPubKey, prologue, staticKeysInitiator, connectionFrom);

    const responderPrivKey = peerB.privKey.marshal().slice(0, 32);
    const responderPubKey = peerB.pubKey.marshal();
    const handshakeResponder = new Handshake(false, responderPrivKey, responderPubKey, prologue, staticKeysResponder, connectionTo);

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
  });
});
