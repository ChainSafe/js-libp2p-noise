import { expect } from "chai";
import DuplexPair from 'it-pair/duplex';

import { Noise } from "../src";
import { generateEd25519Keys } from "./utils";
import {createPeerIds, createPeerIdsFromFixtures} from "./fixtures/peer";
import Wrap from "it-pb-rpc";
import {Handshake} from "../src/handshake";
import {
  createHandshakePayload,
  decodeMessageBuffer,
  encodeMessageBuffer,
  generateKeypair,
  getHandshakePayload,
  signPayload
} from "../src/utils";
import {XXHandshake} from "../src/xx";
import {Buffer} from "buffer";

describe("Noise", () => {
  let remotePeer, localPeer;

  before(async () => {
    [remotePeer, localPeer] = await createPeerIds(2);
  });

  it("should test that secureOutbound is spec compliant", async() => {
    const libp2pKeys = await generateEd25519Keys();

    const noise = new Noise(libp2pKeys._key);

    const [inboundConnection, outboundConnection] = DuplexPair();
    await Promise.all([
      noise.secureOutbound(localPeer, outboundConnection, remotePeer),
      (async () => {
        const wrapped = Wrap(inboundConnection);
        const prologue = Buffer.from('/noise');
        const staticKeys = {
          privateKey: remotePeer.privKey.bytes,
          publicKey: remotePeer.pubKey.bytes,
        };
        const handshake = new Handshake('XX', false, localPeer.pubKey.bytes, prologue, staticKeys, wrapped);

        // Finish handshake
        console.log("Starting with handshake as responder in test...");
        const sessionResponder = await handshake.propose(Buffer.alloc(0));
        await handshake.exchange(sessionResponder);
        await handshake.finish(sessionResponder);
        console.log("Finished handshake as responder in test...");

        // Create the encrypted streams
      })(),
    ]);
  })
});
