import {WrappedConnection} from "./noise";
import {IK} from "./handshakes/ik";
import {NoiseSession} from "./@types/handshake";
import {bytes, bytes32} from "./@types/basic";
import {KeyPair, PeerId} from "./@types/libp2p";
import {IHandshake} from "./@types/handshake-interface";
import {Buffer} from "buffer";

export class IKHandshake implements IHandshake {
  public isInitiator: boolean;
  public session: NoiseSession;

  private payload: bytes;
  private prologue: bytes32;
  private staticKeypair: KeyPair;
  private connection: WrappedConnection;
  private remotePeer: PeerId;
  private ik: IK;

  constructor(
    isInitiator: boolean,
    payload: bytes,
    prologue: bytes32,
    staticKeypair: KeyPair,
    connection: WrappedConnection,
    remotePeer: PeerId,
    handshake?: IK,
  ) {
    this.isInitiator = isInitiator;
    this.payload = payload;
    this.prologue = prologue;
    this.staticKeypair = staticKeypair;
    this.connection = connection;
    this.remotePeer = remotePeer;

    this.ik = handshake || new IK();

    // Dummy data
    // TODO: Load remote static keys if found
    const remoteStaticKeys = this.staticKeypair;
    this.session = this.ik.initSession(this.isInitiator, this.prologue, this.staticKeypair, remoteStaticKeys.publicKey);
  }

  public decrypt(ciphertext: Buffer, session: NoiseSession): Buffer {
    const cs = this.getCS(session, false);
    return this.ik.decryptWithAd(cs, Buffer.alloc(0), ciphertext);
  }

  public encrypt(plaintext: Buffer, session: NoiseSession): Buffer {
    const cs = this.getCS(session);
    return this.ik.encryptWithAd(cs, Buffer.alloc(0), plaintext);
  }

  public getRemoteEphemeralKeys(): KeyPair {
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
