import { bytes, bytes32 } from "./@types/basic";
import { NoiseSession, XXHandshake } from "./xx";
import { KeyPair } from "./@types/libp2p";
import { Buffer } from "buffer";
import {createHandshakePayload, getHandshakePayload, signPayload} from "./utils";

type handshakeType = "XX";

export class Handshake {
  private type: handshakeType;
  private remotePublicKey: bytes;
  private prologue: bytes32;
  private staticKeys: KeyPair;
  private connection: any;
  private xx: XXHandshake;

  constructor(
    type: handshakeType,
    remotePublicKey: bytes,
    prologue: bytes32,
    staticKeys: KeyPair,
    connection,
  ) {
    this.type = type;
    this.remotePublicKey = remotePublicKey;
    this.prologue = prologue;
    this.staticKeys = staticKeys;
    this.connection = connection;

    this.xx = new XXHandshake();
  }

  // stage 0
  async propose(isInitiator: boolean, earlyData?: bytes) : Promise<NoiseSession> {
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
      this.connection.writeLP(messageBuffer);
    } else {
      const receivedMessageBuffer = (await this.connection.readLP()).slice();
      const plaintext = await this.xx.recvMessage(ns, receivedMessageBuffer);
    }

    return ns;
  }

  async exchange(isInitiator: boolean, session: NoiseSession) : Promise<void> {
    if (isInitiator) {
      const receivedMessageBuffer = (await this.connection.readLP()).slice();
      const plaintext = await this.xx.recvMessage(session, receivedMessageBuffer);
    } else {
      // create payload as responder
      const signedPayload = signPayload(this.staticKeys.privateKey, getHandshakePayload(this.staticKeys.publicKey));
      const handshakePayload = await createHandshakePayload(this.remotePublicKey, signedPayload);

      const message = Buffer.concat([Buffer.alloc(0), handshakePayload]);
      const messageBuffer = await this.xx.sendMessage(session, message);
      this.connection.writeLP(messageBuffer);
    }
  }

  async finish(isInitiator: boolean, session: NoiseSession) : Promise<void> {
    if (isInitiator) {
      const messageBuffer = await this.xx.sendMessage(session, Buffer.alloc(0));
      this.connection.writeLP(messageBuffer);
    } else {
      const receivedMessageBuffer = (await this.connection.readLP()).slice();
      const plaintext = await this.xx.recvMessage(session, receivedMessageBuffer);
    }
  }
}
