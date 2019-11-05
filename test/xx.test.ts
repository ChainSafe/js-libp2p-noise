import { expect } from "chai";
import { Buffer } from 'buffer';

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
});
