import { expect, assert } from "chai";
import DuplexPair from 'it-pair/duplex';

import { Noise } from "../src";
import {createPeerIdsFromFixtures} from "./fixtures/peer";
import Wrap from "it-pb-rpc";
import {Handshake} from "../src/handshake";
import {
  createHandshakePayload,
  generateKeypair,
  getHandshakePayload,
  signPayload
} from "../src/utils";
import { decodeMessageBuffer, encodeMessageBuffer } from "../src/encoder";
import {XXHandshake} from "../src/xx";
import {Buffer} from "buffer";
import {getKeyPairFromPeerId} from "./utils";

describe("Noise", () => {
  let remotePeer, localPeer;

  before(async () => {
    [localPeer, remotePeer] = await createPeerIdsFromFixtures(2);
  });

  it("should communicate through encrypted streams", async() => {
    try {
      const { privateKey: libp2pInitPrivKey } = getKeyPairFromPeerId(localPeer);
      const { privateKey: libp2pRespPrivKey } = getKeyPairFromPeerId(remotePeer);
      const noiseInit = new Noise(libp2pInitPrivKey);
      const noiseResp = new Noise(libp2pRespPrivKey);

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
    } catch (e) {
      assert(false, e.message);
    }
  });

  it("should test that secureOutbound is spec compliant", async() => {
    const { privateKey: libp2pInitPrivKey } = getKeyPairFromPeerId(localPeer);
    const noiseInit = new Noise(libp2pInitPrivKey);
    const [inboundConnection, outboundConnection] = DuplexPair();

    const [outbound, { wrapped, handshake }] = await Promise.all([
      noiseInit.secureOutbound(localPeer, outboundConnection, remotePeer),
      (async () => {
        const wrapped = Wrap(inboundConnection);
        const prologue = Buffer.from('/noise');
        const staticKeys = generateKeypair();
        const xx = new XXHandshake();
        const { privateKey: libp2pPrivKey, publicKey: libp2pPubKey } = getKeyPairFromPeerId(remotePeer);

        const handshake = new Handshake(false, libp2pPrivKey, libp2pPubKey, prologue, staticKeys, wrapped, localPeer, xx);

        let receivedMessageBuffer = decodeMessageBuffer((await wrapped.readLP()).slice());
        // The first handshake message contains the initiator's ephemeral public key
        expect(receivedMessageBuffer.ne.length).equal(32);
        xx.recvMessage(handshake.session, receivedMessageBuffer);

        // Stage 1
        const signedPayload = signPayload(libp2pPrivKey, getHandshakePayload(staticKeys.publicKey));
        const handshakePayload = await createHandshakePayload(libp2pPubKey, libp2pPrivKey, signedPayload);

        const messageBuffer = xx.sendMessage(handshake.session, handshakePayload);
        wrapped.writeLP(encodeMessageBuffer(messageBuffer));

        // Stage 2 - finish handshake
        receivedMessageBuffer = decodeMessageBuffer((await wrapped.readLP()).slice());
        xx.recvMessage(handshake.session, receivedMessageBuffer);
        return {wrapped, handshake};
      })(),
    ]);

    try {
      const wrappedOutbound = Wrap(outbound.conn);
      wrappedOutbound.write(Buffer.from("test"));

      // Check that noise message is prefixed with 16-bit big-endian unsigned integer
      const receivedEncryptedPayload = (await wrapped.read()).slice();
      const dataLength = receivedEncryptedPayload.readInt16BE(0);
      const data = receivedEncryptedPayload.slice(2, dataLength + 2);
      const decrypted = handshake.decrypt(data, handshake.session);
      // Decrypted data should match
      assert(decrypted.equals(Buffer.from("test")));
    } catch (e) {
      assert(false, e.message);
    }
  })
});
