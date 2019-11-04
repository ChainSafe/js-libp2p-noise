import { expect } from "chai";
import { Buffer } from 'buffer';
import * as crypto from 'libp2p-crypto';

import { XXHandshake, KeyPair } from "../src/xx";

// TODO: Move this to some protocol related file
async function generateKeypair() : Promise<KeyPair> {
  return await crypto.keys.generateKeyPair('ed25519');
}

describe("Index", () => {
  const prologue = Buffer.from("/noise", "utf-8");

  it("Test creating new XX session", async () => {
    const kpInitiator: KeyPair = await generateKeypair();
    const kpResponder: KeyPair = await generateKeypair();

    const xx = new XXHandshake();

    const session = await xx.initSession(true, prologue, kpInitiator, kpResponder.publicKey);
    console.log(session)
  })
});
