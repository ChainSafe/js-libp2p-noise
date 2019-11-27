import { expect, assert } from "chai";
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

    const [outbound, { wrapped, ns, handshake }] = await Promise.all([
      noiseInit.secureOutbound(localPeer, outboundConnection, remotePeer),
      (async () => {
        const wrapped = Wrap(inboundConnection);
        const prologue = Buffer.from('/noise');
        const staticKeys = {
          privateKey: remotePeer.privKey.bytes,
          publicKey: remotePeer.pubKey.bytes,
        };
        const xx = new XXHandshake();
        const handshake = new Handshake('XX', false, localPeer.pubKey.bytes, prologue, staticKeys, wrapped, xx);
        const ns = await xx.initSession(false, prologue, staticKeys, localPeer.pubKey.bytes);

        let receivedMessageBuffer = decodeMessageBuffer((await wrapped.readLP()).slice());
        // The first handshake message contains the initiator's ephemeral public key
        expect(receivedMessageBuffer.ne.length).equal(32);
        await xx.recvMessage(ns, receivedMessageBuffer);

        // Stage 1
        const signedPayload = signPayload(staticKeys.privateKey, getHandshakePayload(staticKeys.publicKey));
        const handshakePayload = await createHandshakePayload(localPeer.pubKey.bytes, signedPayload);

        const messageBuffer = await xx.sendMessage(ns, handshakePayload);
        wrapped.writeLP(encodeMessageBuffer(messageBuffer));

        // Stage 2 - finish handshake
        receivedMessageBuffer = decodeMessageBuffer((await wrapped.readLP()).slice());
        await xx.recvMessage(ns, receivedMessageBuffer);
        return { wrapped, ns, handshake };
      })(),
    ]);

    const wrappedOutbound = Wrap(outbound.conn);
    wrappedOutbound.write(Buffer.from("test"));

    // Check that noise message is prefixed with 16-bit big-endian unsigned integer
    const receivedEncryptedPayload = (await wrapped.read()).slice();
    const dataLength = receivedEncryptedPayload.readInt16BE(0);
    const data = receivedEncryptedPayload.slice(2, dataLength + 2);
    const decrypted = handshake.decrypt(data, ns);
    // Decrypted data should match
    assert(decrypted.equals(Buffer.from("test")));
  })
});
