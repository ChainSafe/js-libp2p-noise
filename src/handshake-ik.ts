import {WrappedConnection} from "./noise";
import {IK} from "./handshakes/ik";
import {NoiseSession} from "./@types/handshake";
import {bytes, bytes32} from "./@types/basic";
import {KeyPair} from "./@types/libp2p";
import {IHandshake} from "./@types/handshake-interface";
import {Buffer} from "buffer";
import {decode0, decode1, encode0, encode1} from "./encoder";
import {decodePayload, getPeerIdFromPayload, verifySignedPayload} from "./utils";
import {FailedIKError} from "./errors";
import {logger, sessionKeyLogger} from "./logger";
import PeerId from "peer-id";

export class IKHandshake implements IHandshake {
  public isInitiator: boolean;
  public session: NoiseSession;
  public remotePeer!: PeerId;

  private payload: bytes;
  private prologue: bytes32;
  private staticKeypair: KeyPair;
  private connection: WrappedConnection;
  private ik: IK;

  constructor(
    isInitiator: boolean,
    payload: bytes,
    prologue: bytes32,
    staticKeypair: KeyPair,
    connection: WrappedConnection,
    remoteStaticKey: bytes,
    remotePeer?: PeerId,
    handshake?: IK,
  ) {
    this.isInitiator = isInitiator;
    this.payload = Buffer.from(payload);
    this.prologue = prologue;
    this.staticKeypair = staticKeypair;
    this.connection = connection;
    if(remotePeer) {
      this.remotePeer = remotePeer;
    }
    this.ik = handshake || new IK();
    this.session = this.ik.initSession(this.isInitiator, this.prologue, this.staticKeypair, remoteStaticKey);
  }

  public async stage0(): Promise<void> {
    sessionKeyLogger(`LOCAL_STATIC_PUBLIC_KEY ${this.session.hs.s.publicKey.toString('hex')}`)
    sessionKeyLogger(`LOCAL_STATIC_PRIVATE_KEY ${this.session.hs.s.privateKey.toString('hex')}`)
    sessionKeyLogger(`REMOTE_STATIC_PUBLIC_KEY ${this.session.hs.rs.toString('hex')}`) 
    if (this.isInitiator) {
      logger("IK Stage 0 - Initiator sending message...");
      const messageBuffer = this.ik.sendMessage(this.session, this.payload);
      this.connection.writeLP(encode1(messageBuffer));
      logger("IK Stage 0 - Initiator sent message.");
      if(this.session.hs.e){
        sessionKeyLogger(`LOCAL_PUBLIC_EPHEMERAL_KEY ${this.session.hs.e.publicKey.toString('hex')}`)
        sessionKeyLogger(`LOCAL_PRIVATE_EPHEMERAL_KEY ${this.session.hs.e.privateKey.toString('hex')}`)
      }
    } else {
      logger("IK Stage 0 - Responder receiving message...");
      const receivedMsg = await this.connection.readLP();
      try {
        const receivedMessageBuffer = decode1(receivedMsg.slice());
        const {plaintext, valid} = this.ik.recvMessage(this.session, receivedMessageBuffer);
        if(!valid) {
          throw new Error("ik handshake stage 0 decryption validation fail");
        }
        logger("IK Stage 0 - Responder got message, going to verify payload.");
        const decodedPayload = await decodePayload(plaintext);
        this.remotePeer = this.remotePeer || await getPeerIdFromPayload(decodedPayload);
        await verifySignedPayload(this.session.hs.rs, decodedPayload, this.remotePeer);
        logger("IK Stage 0 - Responder successfully verified payload!");
        sessionKeyLogger(`REMOTE_EPHEMEREAL_KEY ${this.session.hs.re.toString('hex')}`)
      } catch (e) {
        logger("Responder breaking up with IK handshake in stage 0.");

        throw new FailedIKError(receivedMsg, `Error occurred while verifying initiator's signed payload: ${e.message}`);
      }
    }
    sessionKeyLogger(`SYMMETRIC_CIPHER_STATE ${this.session.hs.ss.cs.n} ${this.session.hs.ss.cs.k.toString('hex')}`) 
  }

  public async stage1(): Promise<void> {
    if (this.isInitiator) {
      logger("IK Stage 1 - Initiator receiving message...");
      const receivedMsg = (await this.connection.readLP()).slice();
      const receivedMessageBuffer = decode0(Buffer.from(receivedMsg));
      const {plaintext, valid} = this.ik.recvMessage(this.session, receivedMessageBuffer);
      logger("IK Stage 1 - Initiator got message, going to verify payload.");
      try {
        if(!valid) {
          throw new Error("ik stage 1 decryption validation fail");
        }
        const decodedPayload = await decodePayload(plaintext);
        this.remotePeer = this.remotePeer || await getPeerIdFromPayload(decodedPayload);
        await verifySignedPayload(receivedMessageBuffer.ns.slice(0, 32), decodedPayload, this.remotePeer);
        logger("IK Stage 1 - Initiator successfully verified payload!");
        sessionKeyLogger(`REMOTE_EPHEMERAL_KEY ${this.session.hs.re.toString('hex')}`)
      } catch (e) {
        logger("Initiator breaking up with IK handshake in stage 1.");
        throw new FailedIKError(receivedMsg, `Error occurred while verifying responder's signed payload: ${e.message}`);
      }
    } else {
      logger("IK Stage 1 - Responder sending message...");
      const messageBuffer = this.ik.sendMessage(this.session, this.payload);
      this.connection.writeLP(encode0(messageBuffer));
      logger("IK Stage 1 - Responder sent message...");
      if(this.session.hs.e){
        sessionKeyLogger(`LOCAL_PUBLIC_EPHEMERAL_KEY ${this.session.hs.e.publicKey.toString('hex')}`)
        sessionKeyLogger(`LOCAL_PRIVATE_EPHEMERAL_KEY ${this.session.hs.e.privateKey.toString('hex')}`)
      }
    }
    if(this.session.cs1 && this.session.cs2){
      sessionKeyLogger(`CIPHER_STATE_1 ${this.session.cs1.n} ${this.session.cs1.k.toString('hex')}`)
      sessionKeyLogger(`CIPHER_STATE_2 ${this.session.cs2.n} ${this.session.cs2.k.toString('hex')}`)
    }
  }

  public decrypt(ciphertext: bytes, session: NoiseSession): {plaintext: bytes; valid: boolean} {
    const cs = this.getCS(session, false);
    return this.ik.decryptWithAd(cs, Buffer.alloc(0), ciphertext);
  }

  public encrypt(plaintext: Buffer, session: NoiseSession): Buffer {
    const cs = this.getCS(session);
    return this.ik.encryptWithAd(cs, Buffer.alloc(0), plaintext);
  }

  public getLocalEphemeralKeys(): KeyPair {
    if (!this.session.hs.e) {
      throw new Error("Ephemeral keys do not exist.");
    }

    return this.session.hs.e;
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
