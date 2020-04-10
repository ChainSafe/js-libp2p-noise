import { Buffer } from "buffer";

import { XX } from "./handshakes/xx";
import { KeyPair } from "./@types/libp2p";
import { bytes, bytes32 } from "./@types/basic";
import { NoiseSession } from "./@types/handshake";
import {IHandshake} from "./@types/handshake-interface";
import {
  decodePayload,
  getPeerIdFromPayload,
  verifySignedPayload,
} from "./utils";
import { logger, sessionKeyLogger } from "./logger";
import {decode0, decode1, decode2, encode0, encode1, encode2} from "./encoder";
import { WrappedConnection } from "./noise";
import PeerId from "peer-id";

export class XXHandshake implements IHandshake {
  public isInitiator: boolean;
  public session: NoiseSession;
  public remotePeer!: PeerId;

  protected payload: bytes;
  protected connection: WrappedConnection;
  protected xx: XX;
  protected staticKeypair: KeyPair;

  private prologue: bytes32;

  constructor(
    isInitiator: boolean,
    payload: bytes,
    prologue: bytes32,
    staticKeypair: KeyPair,
    connection: WrappedConnection,
    remotePeer?: PeerId,
    handshake?: XX,
  ) {
    this.isInitiator = isInitiator;
    this.payload = payload;
    this.prologue = prologue;
    this.staticKeypair = staticKeypair;
    this.connection = connection;
    if(remotePeer) {
      this.remotePeer = remotePeer;
    }
    this.xx = handshake || new XX();
    this.session = this.xx.initSession(this.isInitiator, this.prologue, this.staticKeypair);
  }

  // stage 0
  public async propose(): Promise<void> {
    sessionKeyLogger(`LOCAL_STATIC_PUBLIC_KEY ${this.session.hs.s.publicKey.toString('hex')}`)
    sessionKeyLogger(`LOCAL_STATIC_PRIVATE_KEY ${this.session.hs.s.privateKey.toString('hex')}`)
    if (this.isInitiator) {
      logger("Stage 0 - Initiator starting to send first message.");
      const messageBuffer = this.xx.sendMessage(this.session, Buffer.alloc(0));
      this.connection.writeLP(encode0(messageBuffer));
      logger("Stage 0 - Initiator finished sending first message.");
      if(this.session.hs.e){
        sessionKeyLogger(`LOCAL_PUBLIC_EPHEMERAL_KEY ${this.session.hs.e.publicKey.toString('hex')}`)
        sessionKeyLogger(`LOCAL_PRIVATE_EPHEMERAL_KEY ${this.session.hs.e.privateKey.toString('hex')}`)
      }
    } else {
      logger("Stage 0 - Responder waiting to receive first message...");
      const receivedMessageBuffer = decode0((await this.connection.readLP()).slice());
      const {valid} = this.xx.recvMessage(this.session, receivedMessageBuffer);
      if(!valid) {
        throw new Error("xx handshake stage 0 validation fail");
      }
      logger("Stage 0 - Responder received first message.");
      sessionKeyLogger(`REMOTE_EPHEMEREAL_KEY ${this.session.hs.re.toString('hex')}`)
    }
  }

  // stage 1
  public async exchange(): Promise<void> {
    if (this.isInitiator) {
      logger('Stage 1 - Initiator waiting to receive first message from responder...');
      const receivedMessageBuffer = decode1((await this.connection.readLP()).slice());
      const {plaintext, valid} = this.xx.recvMessage(this.session, receivedMessageBuffer);
      if(!valid) {
        throw new Error("xx handshake stage 1 validation fail");
      }
      logger('Stage 1 - Initiator received the message.');
      sessionKeyLogger(`REMOTE_EPHEMEREAL_KEY ${this.session.hs.re.toString('hex')}`)
      sessionKeyLogger(`REMOTE_STATIC_KEY ${this.session.hs.rs.toString('hex')}`)

      logger("Initiator going to check remote's signature...");
      try {
        const decodedPayload = await decodePayload(plaintext);
        this.remotePeer = this.remotePeer || await getPeerIdFromPayload(decodedPayload);
        this.remotePeer = await verifySignedPayload(receivedMessageBuffer.ns, decodedPayload, this.remotePeer);
      } catch (e) {
        throw new Error(`Error occurred while verifying signed payload: ${e.message}`);
      }
      logger("All good with the signature!");
    } else {
      logger('Stage 1 - Responder sending out first message with signed payload and static key.');
      const messageBuffer = this.xx.sendMessage(this.session, this.payload);
      this.connection.writeLP(encode1(messageBuffer));
      logger('Stage 1 - Responder sent the second handshake message with signed payload.')
      if(this.session.hs.e){
        sessionKeyLogger(`LOCAL_PUBLIC_EPHEMERAL_KEY ${this.session.hs.e.publicKey.toString('hex')}`)
        sessionKeyLogger(`LOCAL_PRIVATE_EPHEMERAL_KEY ${this.session.hs.e.privateKey.toString('hex')}`)
      }
    }
  }

  // stage 2
  public async finish(): Promise<void> {
    if (this.isInitiator) {
      logger('Stage 2 - Initiator sending third handshake message.');
      const messageBuffer = this.xx.sendMessage(this.session, this.payload);
      this.connection.writeLP(encode2(messageBuffer));
      logger('Stage 2 - Initiator sent message with signed payload.');
    } else {
      logger('Stage 2 - Responder waiting for third handshake message...');
      const receivedMessageBuffer = decode2((await this.connection.readLP()).slice());
      const {plaintext, valid} = this.xx.recvMessage(this.session, receivedMessageBuffer);
      if(!valid) {
        throw new Error("xx handshake stage 2 validation fail");
      }
      logger('Stage 2 - Responder received the message, finished handshake.');

      try {
        const decodedPayload = await decodePayload(plaintext);
        this.remotePeer = this.remotePeer || await getPeerIdFromPayload(decodedPayload);
        await verifySignedPayload(this.session.hs.rs, decodedPayload, this.remotePeer);
      } catch (e) {
        throw new Error(`Error occurred while verifying signed payload: ${e.message}`);
      }
    }
    if(this.session.cs1 && this.session.cs2){
      sessionKeyLogger(`CIPHER_STATE_1 ${this.session.cs1.n} ${this.session.cs1.k.toString('hex')}`)
      sessionKeyLogger(`CIPHER_STATE_2 ${this.session.cs2.n} ${this.session.cs2.k.toString('hex')}`)
    }
  }

  public encrypt(plaintext: bytes, session: NoiseSession): bytes {
    const cs = this.getCS(session);

    return this.xx.encryptWithAd(cs, Buffer.alloc(0), plaintext);
  }

  public decrypt(ciphertext: bytes, session: NoiseSession): {plaintext: bytes; valid: boolean} {
    const cs = this.getCS(session, false);
    return this.xx.decryptWithAd(cs, Buffer.alloc(0), ciphertext);
  }

  public getRemoteStaticKey(): bytes {
    return this.session.hs.rs;
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
