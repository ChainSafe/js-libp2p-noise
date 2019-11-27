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
    // [remotePeer, localPeer] = await createPeerIds(2);
    // TODO: Handle Peer ID received ed25519 keys

    const pair1 = generateKeypair();
    remotePeer = {
      id: "id-1",
      pubKey: { bytes: pair1.publicKey },
      privKey: { bytes: pair1.privateKey },
    }
    const pair2 = generateKeypair();
    localPeer = {
      id: "id-2",
      pubKey: { bytes: pair2.publicKey },
      privKey: { bytes: pair2.privateKey },
    }
  });

  it("should communicate through encrypted streams", async() => {
    const libp2pKeys = await generateEd25519Keys();
    const libp2pKeys2 = await generateEd25519Keys();

    const noiseInit = new Noise(libp2pKeys._key, localPeer.privKey.bytes);
    const noiseResp = new Noise(libp2pKeys2._key, remotePeer.privKey.bytes);

    const [inboundConnection, outboundConnection] = DuplexPair();
    const [outbound, inbound] = await Promise.all([
      noiseInit.secureOutbound(localPeer, outboundConnection, remotePeer),
      noiseResp.secureInbound(remotePeer, inboundConnection, localPeer),
    ]);
    const wrappedInbound = Wrap(inbound.conn);
    const wrappedOutbound = Wrap(outbound.conn);

    wrappedOutbound.writeLP(Buffer.from("test"));
    const response = await wrappedInbound.readLP();
    expect(response.toString()).equal("test");
  });

  it("should test that secureOutbound is spec compliant", async() => {
    const libp2pKeys = await generateEd25519Keys();
    const noiseInit = new Noise(libp2pKeys._key, localPeer.privKey.bytes);
    const [inboundConnection, outboundConnection] = DuplexPair();

    const [outbound] = await Promise.all([
      noiseInit.secureOutbound(localPeer, outboundConnection, remotePeer),
      (async () => {
        const wrapped = Wrap(inboundConnection);
        const prologue = Buffer.from('/noise');
        const staticKeys = {
          privateKey: remotePeer.privKey.bytes,
          publicKey: remotePeer.pubKey.bytes,
        };
        const handshake = new Handshake('XX', false, localPeer.pubKey.bytes, prologue, staticKeys, wrapped);

        // Finish handshake
        const sessionResponder = await handshake.propose(Buffer.alloc(0));
        await handshake.exchange(sessionResponder);
        await handshake.finish(sessionResponder);

        // Create the encrypted streams
        console.log(sessionResponder);
      })(),
    ]);
  })
});
