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
import {Noise, WrappedConnection} from "./noise";

type handshakeType = "XX";

export class Handshake {
  public isInitiator: boolean;

  private type: handshakeType;
  private remotePublicKey: bytes;
  private prologue: bytes32;
  private staticKeys: KeyPair;
  private connection: WrappedConnection;
  private xx: XXHandshake;

  constructor(
    type: handshakeType,
    isInitiator: boolean,
    remotePublicKey: bytes,
    prologue: bytes32,
    staticKeys: KeyPair,
    connection: WrappedConnection,
  ) {
    this.type = type;
    this.isInitiator = isInitiator;
    this.remotePublicKey = remotePublicKey;
    this.prologue = prologue;
    this.staticKeys = staticKeys;
    this.connection = connection;

    this.xx = new XXHandshake();
  }

  // stage 0
  async propose(earlyData?: bytes) : Promise<NoiseSession> {
    const ns = await this.xx.initSession(this.isInitiator, this.prologue, this.staticKeys, this.remotePublicKey);

    if (this.isInitiator) {
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
  async exchange(session: NoiseSession) : Promise<void> {
    if (this.isInitiator) {
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
  async finish(session: NoiseSession) : Promise<void> {
    if (this.isInitiator) {
      const messageBuffer = await this.xx.sendMessage(session, Buffer.alloc(0));
      this.connection.writeLP(encodeMessageBuffer(messageBuffer));
    } else {
      const receivedMessageBuffer = (await this.connection.readLP()).slice();
      const plaintext = await this.xx.recvMessage(session, decodeMessageBuffer(receivedMessageBuffer));
    }
  }

  encrypt(plaintext: bytes, session: NoiseSession): bytes {
    const cs = this.getCS(session);
    return this.xx.encryptWithAd(cs, Buffer.alloc(0), plaintext);
  }

  decrypt(ciphertext: bytes, session: NoiseSession): bytes {
    const cs = this.getCS(session, false);
    return this.xx.decryptWithAd(cs, Buffer.alloc(0), ciphertext);
  }

  private getCS(session: NoiseSession, encryption = true) {
    if (!session.cs1 || !session.cs2) {
      throw new Error("Handshake not completed properly, cipher state does not exist.");
    }

    if (this.isInitiator) {
      return encryption ? session.cs1 : session.cs2;
    } else {
      return encryption ? session.cs2 : session.cs1;
    }
  }
}
