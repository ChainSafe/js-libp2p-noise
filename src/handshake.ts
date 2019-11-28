import { Buffer } from "buffer";

import { bytes, bytes32 } from "./@types/basic";
import { NoiseSession, XXHandshake } from "./xx";
import { KeyPair } from "./@types/libp2p";
import {
  createHandshakePayload,
  decodeMessageBuffer,
  encodeMessageBuffer,
  getHandshakePayload,
  logger, signEarlyDataPayload,
  signPayload,
} from "./utils";
import { WrappedConnection } from "./noise";

export class Handshake {
  public isInitiator: boolean;
  public session: NoiseSession;

  private libp2pPrivateKey: bytes;
  private libp2pPublicKey: bytes;
  private prologue: bytes32;
  private staticKeys: KeyPair;
  private connection: WrappedConnection;
  private xx: XXHandshake;

  constructor(
    isInitiator: boolean,
    libp2pPrivateKey: bytes,
    libp2pPublicKey: bytes,
    prologue: bytes32,
    staticKeys: KeyPair,
    connection: WrappedConnection,
    handshake?: XXHandshake,
  ) {
    this.isInitiator = isInitiator;
    this.libp2pPrivateKey = libp2pPrivateKey;
    this.libp2pPublicKey = libp2pPublicKey;
    this.prologue = prologue;
    this.staticKeys = staticKeys;
    this.connection = connection;

    this.xx = handshake || new XXHandshake();
    this.session = this.xx.initSession(this.isInitiator, this.prologue, this.staticKeys);
  }

  // stage 0
  async propose(earlyData?: bytes): Promise<void> {
    if (this.isInitiator) {
      const signedPayload = signPayload(this.libp2pPrivateKey, getHandshakePayload(this.staticKeys.publicKey));
      const signedEarlyDataPayload = signEarlyDataPayload(this.libp2pPrivateKey, earlyData || Buffer.alloc(0));
      const handshakePayload = await createHandshakePayload(
        this.libp2pPublicKey,
        this.libp2pPrivateKey,
        signedPayload,
        signedEarlyDataPayload
      );
      const messageBuffer = await this.xx.sendMessage(this.session, handshakePayload);
      this.connection.writeLP(encodeMessageBuffer(messageBuffer));

      logger("Stage 0 - Initiator finished proposing, sent signed NoiseHandshake payload.");
    } else {
      const receivedMessageBuffer = decodeMessageBuffer((await this.connection.readLP()).slice());

      const plaintext = await this.xx.recvMessage(this.session, receivedMessageBuffer);
      logger("Stage 0 - Responder received proposed message and remote static public key.");
    }
  }

  // stage 1
  async exchange(): Promise<void> {
    if (this.isInitiator) {
      const receivedMessageBuffer = decodeMessageBuffer((await this.connection.readLP()).slice());
      const plaintext = await this.xx.recvMessage(this.session, receivedMessageBuffer);
      logger('Stage 1 - Initiator received the message.');
    } else {
      // create payload as responder
      const signedPayload = signPayload(this.libp2pPrivateKey, getHandshakePayload(this.staticKeys.publicKey));
      const handshakePayload = await createHandshakePayload(
        this.libp2pPublicKey,
        this.libp2pPrivateKey,
        signedPayload,
      );

      const messageBuffer = await this.xx.sendMessage(this.session, handshakePayload);
      this.connection.writeLP(encodeMessageBuffer(messageBuffer));
      logger('Stage 1 - Responder sent the message.')
    }
  }

  // stage 2
  async finish(): Promise<void> {
    if (this.isInitiator) {
      const messageBuffer = await this.xx.sendMessage(this.session, Buffer.alloc(0));
      this.connection.writeLP(encodeMessageBuffer(messageBuffer));
      logger('Stage 2 - Initiator sent message.');
    } else {
      const receivedMessageBuffer = (await this.connection.readLP()).slice();
      const plaintext = await this.xx.recvMessage(this.session, decodeMessageBuffer(receivedMessageBuffer));
      logger('Stage 2 - Responder received the message, finished handshake.')
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
