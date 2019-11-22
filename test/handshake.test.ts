import {assert} from "chai";
import Duplex from 'it-pair/duplex';
import {Buffer} from "buffer";
import Wrap from "it-pb-rpc";

import {Handshake} from "../src/handshake";
import {generateKeypair} from "../src/utils";

describe("Handshake", () => {
  it("should propose, exchange and finish handshake", async() => {
    const duplex = Duplex();
    const connectionFrom = Wrap(duplex[0]);
    const connectionTo = Wrap(duplex[1]);

    const prologue = Buffer.from('/noise');
    const staticKeysInitiator = generateKeypair();
    const staticKeysResponder = generateKeypair();

    const handshakeInitator = new Handshake('XX', staticKeysResponder.publicKey, prologue, staticKeysInitiator, connectionFrom);
    const handshakeResponder = new Handshake('XX', staticKeysInitiator.publicKey, prologue, staticKeysResponder, connectionTo);

    const sessionInitator = await handshakeInitator.propose(true);
    const sessionResponder = await handshakeResponder.propose(false);

    await handshakeResponder.exchange(false, sessionResponder);
    await handshakeInitator.exchange(true, sessionInitator);

    await handshakeInitator.finish(true, sessionInitator);
    await handshakeResponder.finish(false, sessionResponder);

    if (sessionInitator.cs1 && sessionResponder.cs1 && sessionInitator.cs2 && sessionResponder.cs2) {
      assert(sessionInitator.cs1.k.equals(sessionResponder.cs1.k));
      assert(sessionInitator.cs2.k.equals(sessionResponder.cs2.k));
    } else {
      assert(false);
    }
  });
});
