import { expect, assert } from "chai";
import { Buffer } from 'buffer';
import * as crypto from 'libp2p-crypto';
import protobuf from 'protobufjs';

import { XXHandshake, KeyPair } from "../src/xx";

describe("Index", () => {
  const prologue = Buffer.from("/noise", "utf-8");

  it("Test creating new XX session", async () => {
    const xx = new XXHandshake();

    const kpInitiator: KeyPair = await xx.generateKeypair();
    const kpResponder: KeyPair = await xx.generateKeypair();


    const session = await xx.initSession(true, prologue, kpInitiator, kpResponder.publicKey);
  })

  it("Test get HKDF", async () => {
    const xx = new XXHandshake();
    const ckBytes = Buffer.from('4e6f6973655f58585f32353531395f58436861436861506f6c795f53484132353600000000000000000000000000000000000000000000000000000000000000', 'hex');
    const ikm = Buffer.from('a3eae50ea37a47e8a7aa0c7cd8e16528670536dcd538cebfd724fb68ce44f1910ad898860666227d4e8dd50d22a9a64d1c0a6f47ace092510161e9e442953da3', 'hex');
    const ck = Buffer.alloc(32);
    ckBytes.copy(ck);

    const [k1, k2, k3] = xx.getHkdf(ck, ikm);
    expect(k1.toString('hex')).to.equal('cc5659adff12714982f806e2477a8d5ddd071def4c29bb38777b7e37046f6914');
    expect(k2.toString('hex')).to.equal('a16ada915e551ab623f38be674bb4ef15d428ae9d80688899c9ef9b62ef208fa');
    expect(k3.toString('hex')).to.equal('ff67bf9727e31b06efc203907e6786667d2c7a74ac412b4d31a80ba3fd766f68');
  })

  async function generateKeypair() {
    return await crypto.keys.generateKeyPair('ed25519');;
  }

  async function doHandshake() {
    const xx = new XXHandshake();
    const kpInit = await xx.generateKeypair();
    const kpResp = await xx.generateKeypair();
    const payloadString = Buffer.from("noise-libp2p-static-key:");

    // initiator setup
    const libp2pInitKeys = await generateKeypair();
    const initSignedPayload = await libp2pInitKeys.sign(Buffer.concat([payloadString, kpInit.publicKey]));

    // responder setup
    const libp2pRespKeys = await generateKeypair();
    const respSignedPayload = await libp2pRespKeys.sign(Buffer.concat([payloadString, kpResp.publicKey]));

    // initiator: new XX noise session
    const nsInit = await xx.initSession(true, prologue, kpInit, kpResp.publicKey);
    // responder: new XX noise session
    const nsResp = await xx.initSession(false, prologue, kpResp, kpInit.publicKey);

    /* stage 0: initiator */

    // initiator creates payload
    const payloadProtoBuf = await protobuf.load("payload.proto");
    const NoiseHandshakePayload = payloadProtoBuf.lookupType("pb.NoiseHandshakePayload");
    const payloadInit = NoiseHandshakePayload.create({
      libp2pKey: libp2pInitKeys.bytes.toString('hex'),
      noiseStaticKeySignature: initSignedPayload,
    });

    const payloadInitEnc = NoiseHandshakePayload.encode(payloadInit).finish();

    // initiator sends message
    const message = Buffer.concat([Buffer.alloc(0), payloadInitEnc]);
    const messageBuffer = await xx.sendMessage(nsInit, message);

    expect(messageBuffer.ne.length).not.equal(0);
  }

  it("Test handshake", async () => {
    await doHandshake();
  })
});
