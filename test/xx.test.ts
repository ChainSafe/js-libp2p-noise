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
    console.log(session)
  })
});
