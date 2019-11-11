import { x25519 } from 'bcrypto';

import { bytes } from "./types/basic";
import { Connection } from "./types/libp2p";
import { KeyPair, XXHandshake } from "./xx";
import { signPayload } from "../test/utils";
import {Buffer} from "buffer";

export class Noise {
  private readonly privateKey: bytes;
  private staticKeys?: KeyPair;
  private earlyData?: bytes;

  constructor(privateKey: bytes, staticNoiseKey?: bytes, earlyData?: bytes) {
    this.privateKey = privateKey;
    this.earlyData = earlyData;

    if (staticNoiseKey) {
      const publicKey = x25519.publicKeyCreate(staticNoiseKey);
      this.staticKeys = {
        privateKey: staticNoiseKey,
        publicKey,
      }
    }
  }

  public tag() {
    return '/noise';
  }

  public async encrypt(InsecureConnection: Connection, remotePublicKey: bytes) {
    const isInitiator = InsecureConnection.stats.direction === "outbound";
    const secretKey = await this.doHandshake(isInitiator, remotePublicKey);

  }

  private async doHandshake(isInitiator: boolean, remotePublicKey: bytes) : Promise<bytes> {
    const xx = new XXHandshake();
    if (!this.staticKeys) {
      this.staticKeys = await xx.generateKeypair();
    }

    let signedPayload;
    if (this.earlyData) {
      const payload = Buffer.concat([this.earlyData, this.staticKeys.publicKey])
      signedPayload = await signPayload(this.privateKey, payload);
    }

    const prologue = Buffer.from(this.tag());
    const nsInit = await xx.initSession(isInitiator, prologue, this.staticKeys, remotePublicKey);
    // TODO: Send messages, confirm handshake and return shared key
    return Buffer.alloc(0);
  }

}
