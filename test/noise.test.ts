import { expect, assert } from "chai";
import DuplexPair from 'it-pair/duplex';

import { Noise } from "../src";
import {createPeerIdsFromFixtures} from "./fixtures/peer";
import Wrap from "it-pb-rpc";
import { random } from "bcrypto";
import sinon from "sinon";
import {XXHandshake} from "../src/handshake-xx";
import {
  createHandshakePayload,
  generateKeypair,
  getHandshakePayload, getPayload,
  signPayload
} from "../src/utils";
import {decode0, decode1, encode1} from "../src/encoder";
import {XX} from "../src/handshakes/xx";
import {Buffer} from "buffer";
import {getKeyPairFromPeerId} from "./utils";
import {KeyCache} from "../src/keycache";
import {XXFallbackHandshake} from "../src/handshake-xx-fallback";

describe("Noise", () => {
  let remotePeer, localPeer;
  let sandbox = sinon.createSandbox();

  before(async () => {
    [localPeer, remotePeer] = await createPeerIdsFromFixtures(2);
  });

  afterEach(function() {
    sandbox.restore();
  });

  it("should communicate through encrypted streams without noise pipes", async() => {
    try {
      const noiseInit = new Noise(undefined, undefined, false);
      const noiseResp = new Noise(undefined, undefined, false);

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
    const noiseInit = new Noise(undefined, undefined, false);
    const [inboundConnection, outboundConnection] = DuplexPair();

    const [outbound, { wrapped, handshake }] = await Promise.all([
      noiseInit.secureOutbound(localPeer, outboundConnection, remotePeer),
      (async () => {
        const wrapped = Wrap(inboundConnection);
        const prologue = Buffer.alloc(0);
        const staticKeys = generateKeypair();
        const xx = new XX();

        const payload = await getPayload(remotePeer, staticKeys.publicKey);
        const handshake = new XXHandshake(false, payload, prologue, staticKeys, wrapped, localPeer, xx);

        let receivedMessageBuffer = decode0((await wrapped.readLP()).slice());
        // The first handshake message contains the initiator's ephemeral public key
        expect(receivedMessageBuffer.ne.length).equal(32);
        xx.recvMessage(handshake.session, receivedMessageBuffer);

        // Stage 1
        const { publicKey: libp2pPubKey } = getKeyPairFromPeerId(remotePeer);
        const signedPayload = await signPayload(remotePeer, getHandshakePayload(staticKeys.publicKey));
        const handshakePayload = await createHandshakePayload(libp2pPubKey, signedPayload);

        const messageBuffer = xx.sendMessage(handshake.session, handshakePayload);
        wrapped.writeLP(encode1(messageBuffer));

        // Stage 2 - finish handshake
        receivedMessageBuffer = decode1((await wrapped.readLP()).slice());
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


  it("should test large payloads", async() => {
    try {
      const noiseInit = new Noise(undefined, undefined, false);
      const noiseResp = new Noise(undefined, undefined, false);

      const [inboundConnection, outboundConnection] = DuplexPair();
      const [outbound, inbound] = await Promise.all([
        noiseInit.secureOutbound(localPeer, outboundConnection, remotePeer),
        noiseResp.secureInbound(remotePeer, inboundConnection, localPeer),
      ]);
      const wrappedInbound = Wrap(inbound.conn);
      const wrappedOutbound = Wrap(outbound.conn);

      const largePlaintext = random.randomBytes(100000);
      wrappedOutbound.writeLP(largePlaintext);
      const response = await wrappedInbound.readLP();

      expect(response.length).equals(largePlaintext.length);
    } catch (e) {
      console.error(e);
      assert(false, e.message);
    }
  });

  it("should communicate through encrypted streams with noise pipes", async() => {
    try {
      const staticKeysInitiator = generateKeypair();
      const noiseInit = new Noise(staticKeysInitiator.privateKey);
      const staticKeysResponder = generateKeypair();
      const noiseResp = new Noise(staticKeysResponder.privateKey);

      // Prepare key cache for noise pipes
      KeyCache.store(localPeer, staticKeysInitiator.publicKey);
      KeyCache.store(remotePeer, staticKeysResponder.publicKey);

      const xxSpy = sandbox.spy(noiseInit, "performXXHandshake");
      const xxFallbackSpy = sandbox.spy(noiseInit, "performXXFallbackHandshake");

      const [inboundConnection, outboundConnection] = DuplexPair();
      const [outbound, inbound] = await Promise.all([
        noiseInit.secureOutbound(localPeer, outboundConnection, remotePeer),
        noiseResp.secureInbound(remotePeer, inboundConnection, localPeer),
      ]);
      const wrappedInbound = Wrap(inbound.conn);
      const wrappedOutbound = Wrap(outbound.conn);

      wrappedOutbound.writeLP(Buffer.from("test v2"));
      const response = await wrappedInbound.readLP();
      expect(response.toString()).equal("test v2");

      assert(xxSpy.notCalled);
      assert(xxFallbackSpy.notCalled);
    } catch (e) {
      console.error(e);
      assert(false, e.message);
    }
  });

  it("IK -> XX fallback: initiator has invalid remote static key", async() => {
    try {
      const staticKeysInitiator = generateKeypair();
      const noiseInit = new Noise(staticKeysInitiator.privateKey);
      const noiseResp = new Noise();
      const xxSpy = sandbox.spy(noiseInit, "performXXFallbackHandshake");

      // Prepare key cache for noise pipes
      KeyCache.resetStorage();
      KeyCache.store(localPeer, staticKeysInitiator.publicKey);
      KeyCache.store(remotePeer, generateKeypair().publicKey);

      const [inboundConnection, outboundConnection] = DuplexPair();
      const [outbound, inbound] = await Promise.all([
        noiseInit.secureOutbound(localPeer, outboundConnection, remotePeer),
        noiseResp.secureInbound(remotePeer, inboundConnection, localPeer),
      ]);

      const wrappedInbound = Wrap(inbound.conn);
      const wrappedOutbound = Wrap(outbound.conn);

      wrappedOutbound.writeLP(Buffer.from("test fallback"));
      const response = await wrappedInbound.readLP();
      expect(response.toString()).equal("test fallback");

      assert(xxSpy.calledOnce, "XX Fallback method was never called.");
    } catch (e) {
      console.error(e);
      assert(false, e.message);
    }
  });

  it("IK -> XX fallback: responder has disabled noise pipes", async() => {
      try {
        const staticKeysInitiator = generateKeypair();
        const noiseInit = new Noise(staticKeysInitiator.privateKey);

        const staticKeysResponder = generateKeypair();
        const noiseResp = new Noise(staticKeysResponder.privateKey, undefined, false);
        const xxSpy = sandbox.spy(noiseInit, "performXXFallbackHandshake");

        // Prepare key cache for noise pipes
        KeyCache.store(localPeer, staticKeysInitiator.publicKey);
        KeyCache.store(remotePeer, staticKeysResponder.publicKey);

        const [inboundConnection, outboundConnection] = DuplexPair();
        const [outbound, inbound] = await Promise.all([
          noiseInit.secureOutbound(localPeer, outboundConnection, remotePeer),
          noiseResp.secureInbound(remotePeer, inboundConnection, localPeer),
        ]);

        const wrappedInbound = Wrap(inbound.conn);
        const wrappedOutbound = Wrap(outbound.conn);

        wrappedOutbound.writeLP(Buffer.from("test fallback"));
        const response = await wrappedInbound.readLP();
        expect(response.toString()).equal("test fallback");

        assert(xxSpy.calledOnce, "XX Fallback method was never called.");
      } catch (e) {
        console.error(e);
        assert(false, e.message);
      }
    });

  it("Initiator starts with XX (pipes disabled), responder has enabled noise pipes", async() => {
    try {
      const staticKeysInitiator = generateKeypair();
      const noiseInit = new Noise(staticKeysInitiator.privateKey, undefined, false);
      const staticKeysResponder = generateKeypair();

      const noiseResp = new Noise(staticKeysResponder.privateKey);
      const xxInitSpy = sandbox.spy(noiseInit, "performXXHandshake");
      const xxRespSpy = sandbox.spy(noiseResp, "performXXFallbackHandshake");

      // Prepare key cache for noise pipes
      KeyCache.store(localPeer, staticKeysInitiator.publicKey);

      const [inboundConnection, outboundConnection] = DuplexPair();

      const [outbound, inbound] = await Promise.all([
        noiseInit.secureOutbound(localPeer, outboundConnection, remotePeer),
        noiseResp.secureInbound(remotePeer, inboundConnection, localPeer),
      ]);

      const wrappedInbound = Wrap(inbound.conn);
      const wrappedOutbound = Wrap(outbound.conn);

      wrappedOutbound.writeLP(Buffer.from("test fallback"));
      const response = await wrappedInbound.readLP();
      expect(response.toString()).equal("test fallback");

      assert(xxInitSpy.calledOnce, "XX method was never called.");
      assert(xxRespSpy.calledOnce, "XX Fallback method was never called.");
    } catch (e) {
      console.error(e);
      assert(false, e.message);
    }
  });

  it("IK -> XX Fallback: responder has no remote static key", async() => {
    try {
      const staticKeysInitiator = generateKeypair();
      const noiseInit = new Noise(staticKeysInitiator.privateKey);
      const staticKeysResponder = generateKeypair();

      const noiseResp = new Noise(staticKeysResponder.privateKey);
      const xxFallbackInitSpy = sandbox.spy(noiseInit, "performXXFallbackHandshake");
      const xxRespSpy = sandbox.spy(noiseResp, "performXXHandshake");

      // Prepare key cache for noise pipes
      KeyCache.resetStorage();
      KeyCache.store(localPeer, staticKeysResponder.publicKey);

      const [inboundConnection, outboundConnection] = DuplexPair();

      const [outbound, inbound] = await Promise.all([
        noiseInit.secureOutbound(localPeer, outboundConnection, remotePeer),
        noiseResp.secureInbound(remotePeer, inboundConnection, localPeer),
      ]);

      const wrappedInbound = Wrap(inbound.conn);
      const wrappedOutbound = Wrap(outbound.conn);

      wrappedOutbound.writeLP(Buffer.from("test fallback"));
      const response = await wrappedInbound.readLP();
      expect(response.toString()).equal("test fallback");

      assert(xxFallbackInitSpy.calledOnce, "XX Fallback method was not called.");
      assert(xxRespSpy.calledOnce, "XX method was not called.");
    } catch (e) {
      console.error(e);
      assert(false, e.message);
    }
  });
});
