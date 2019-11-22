import { expect } from "chai";
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

    console.log("Going to start with the handshake process...")

    const sessionInitator = await handshakeInitator.propose(true);
    const sessionResponder = await handshakeResponder.propose(false);

    console.log("Propose finished")

    await handshakeInitator.exchange(true, sessionInitator);
    await handshakeResponder.exchange(false, sessionResponder);

    console.log("exchange finished")

    await handshakeInitator.finish(true, sessionInitator);
    await handshakeResponder.finish(false, sessionResponder);

    console.log("finish finished")
  })
});
