import { bytes, bytes32 } from "./@types/basic";
import { NoiseSession, XXHandshake } from "./xx";
import { KeyPair, PeerId } from "./@types/libp2p";
import {Buffer} from "buffer";

type handshakeType = "XX";

export class Handshake {
  private type: handshakeType;
  private remotePublicKey: bytes;
  private signedPayload: bytes;
  private prologue: bytes32;
  private staticKeys: KeyPair;

  constructor(
    type: handshakeType,
    remotePublicKey: bytes,
    prologue: bytes32,
    signedPayload: bytes,
    staticKeys: KeyPair,
  ) {
    this.type = type;
    this.remotePublicKey = remotePublicKey;
    this.signedPayload = signedPayload;
    this.prologue = prologue;
    this.staticKeys = staticKeys;
  }

  async propose(isInitiator: boolean) : Promise<NoiseSession> {
    const xx = new XXHandshake();

    const nsInit = await xx.initSession(isInitiator, this.prologue, this.staticKeys, this.remotePublicKey);
    if (isInitiator) {
      const message = Buffer.concat([Buffer.alloc(0), this.signedPayload]);
      const messageBuffer = await xx.sendMessage(nsInit, message);
    }
    return nsInit;
  }

  async exchange() : Promise<NoiseSession> {

  }

  async finish() : Promise<NoiseSession> {

  }
}
