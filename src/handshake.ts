import { bytes, bytes32 } from "./types/basic";
import { NoiseSession, XXHandshake } from "./xx";
import { KeyPair } from "./types/libp2p";

export class Handshake {
  static async runXX(
    isInitiator: boolean,
    remotePublicKey: bytes,
    prologue: bytes32,
    signedPayload: bytes,
    staticKeys: KeyPair,
  ) : Promise<NoiseSession> {
    const xx = new XXHandshake();

    const nsInit = await xx.initSession(isInitiator, prologue, staticKeys, remotePublicKey);
    // TODO: exchange handshake messages and confirm handshake
    return nsInit;
  }
}
