import { bytes, bytes32 } from "./@types/basic";
import { NoiseSession, XXHandshake } from "./xx";
import { KeyPair, PeerId } from "./@types/libp2p";

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
    // TODO: exchange handshake messages and confirm handshake
    return nsInit;
  }

  async exchange() : Promise<NoiseSession> {

  }

  async finish() : Promise<NoiseSession> {

  }
}
