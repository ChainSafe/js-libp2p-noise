import {Buffer} from "buffer";
import {IKHandshake} from "../../src/handshakes/ik";
import {KeyPair} from "../../src/@types/libp2p";
import {createHandshakePayload, generateKeypair, getHandshakePayload} from "../../src/utils";
import {assert, expect} from "chai";
import {generateEd25519Keys} from "../utils";

describe("Index", () => {
  const prologue = Buffer.from("/noise", "utf-8");

  it("Test complete IK handshake", async () => {
    try {
      const ik = new IKHandshake();

      // Generate static noise keys
      const kpInitiator: KeyPair = await generateKeypair();
      const kpResponder: KeyPair = await generateKeypair();

      // Generate libp2p keys
      const libp2pInitKeys = await generateEd25519Keys();
      const libp2pRespKeys = await generateEd25519Keys();

      // Create sessions
      const initiatorSession = await ik.initSession(true, prologue, kpInitiator, kpResponder.publicKey);
      const responderSession = await ik.initSession(false, prologue, kpResponder, Buffer.alloc(32));

      /* Stage 0 */

      // initiator creates payload
      const initSignedPayload = await libp2pInitKeys.sign(getHandshakePayload(kpInitiator.publicKey));
      const libp2pInitPrivKey = libp2pInitKeys.marshal().slice(0, 32);
      const libp2pInitPubKey = libp2pInitKeys.marshal().slice(32, 64);
      const payloadInitEnc = await createHandshakePayload(libp2pInitPubKey, libp2pInitPrivKey, initSignedPayload);

      // initiator sends message
      const message = Buffer.concat([Buffer.alloc(0), payloadInitEnc]);
      const messageBuffer = ik.sendMessage(initiatorSession, message);

      expect(messageBuffer.ne.length).not.equal(0);

      // responder receives message
      const plaintext = ik.recvMessage(responderSession, messageBuffer);
      console.log("Stage 0 responder payload: ", plaintext);

      /* Stage 1 */

      // responder creates payload
      const libp2pRespPrivKey = libp2pRespKeys.marshal().slice(0, 32);
      const libp2pRespPubKey = libp2pRespKeys.marshal().slice(32, 64);
      const respSignedPayload = await libp2pRespKeys.sign(getHandshakePayload(kpResponder.publicKey));
      const payloadRespEnc = await createHandshakePayload(libp2pRespPubKey, libp2pRespPrivKey, respSignedPayload);

      const message1 = Buffer.concat([message, payloadRespEnc]);
      const messageBuffer2 = ik.sendMessage(responderSession, message1);

      // initator receives message
      const plaintext2 = ik.recvMessage(initiatorSession, messageBuffer2);

    } catch (e) {
      assert(false, e.message);
    }
  });
});
