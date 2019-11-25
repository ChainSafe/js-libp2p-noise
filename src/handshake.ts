import { bytes, bytes32 } from "./@types/basic";
import { NoiseSession, XXHandshake } from "./xx";
import { KeyPair } from "./@types/libp2p";
import { Buffer } from "buffer";
import {
  createHandshakePayload,
  decodeMessageBuffer,
  encodeMessageBuffer,
  getHandshakePayload,
  signPayload
} from "./utils";
import { WrappedConnection } from "./noise";

type handshakeType = "XX";

export class Handshake {
  private type: handshakeType;
  private remotePublicKey: bytes;
  private prologue: bytes32;
  private staticKeys: KeyPair;
  private connection: WrappedConnection;
  private xx: XXHandshake;

  constructor(
    type: handshakeType,
    remotePublicKey: bytes,
    prologue: bytes32,
    staticKeys: KeyPair,
    connection: WrappedConnection,
  ) {
    this.type = type;
    this.remotePublicKey = remotePublicKey;
    this.prologue = prologue;
    this.staticKeys = staticKeys;
    this.connection = connection;

    this.xx = new XXHandshake();
  }

  // stage 0
  async propose(isInitiator: boolean, earlyData?: bytes): Promise<NoiseSession> {
    const ns = await this.xx.initSession(isInitiator, this.prologue, this.staticKeys, this.remotePublicKey);

    if (isInitiator) {
      const signedPayload = signPayload(this.staticKeys.privateKey, getHandshakePayload(this.staticKeys.publicKey));
      const handshakePayload = await createHandshakePayload(
        this.staticKeys.publicKey,
        signedPayload,
        earlyData,
        this.staticKeys.privateKey
      );
      const message = Buffer.concat([Buffer.alloc(0), handshakePayload]);
      const messageBuffer = await this.xx.sendMessage(ns, message);
      this.connection.writeLP(encodeMessageBuffer(messageBuffer));
    } else {
      const receivedMessageBuffer = (await this.connection.readLP()).slice();
      const plaintext = await this.xx.recvMessage(ns, decodeMessageBuffer(receivedMessageBuffer));
    }

    return ns;
  }

  // stage 1
  async exchange(isInitiator: boolean, session: NoiseSession): Promise<void> {
    if (isInitiator) {
      const receivedMessageBuffer = (await this.connection.readLP()).slice();
      const plaintext = await this.xx.recvMessage(session, decodeMessageBuffer(receivedMessageBuffer));
    } else {
      // create payload as responder
      const signedPayload = signPayload(this.staticKeys.privateKey, getHandshakePayload(this.staticKeys.publicKey));
      const handshakePayload = await createHandshakePayload(this.remotePublicKey, signedPayload);

      const message = Buffer.concat([Buffer.alloc(0), handshakePayload]);
      const messageBuffer = await this.xx.sendMessage(session, message);
      this.connection.writeLP(encodeMessageBuffer(messageBuffer));
    }
  }

  // stage 2
  async finish(isInitiator: boolean, session: NoiseSession): Promise<void> {
    if (isInitiator) {
      const messageBuffer = await this.xx.sendMessage(session, Buffer.alloc(0));
      this.connection.writeLP(encodeMessageBuffer(messageBuffer));
    } else {
      const receivedMessageBuffer = (await this.connection.readLP()).slice();
      const plaintext = await this.xx.recvMessage(session, decodeMessageBuffer(receivedMessageBuffer));
    }
  }
}
