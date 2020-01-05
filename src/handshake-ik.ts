import {WrappedConnection} from "./noise";
import {IKHandshake} from "./handshakes/ik";
import {NoiseSession} from "./@types/handshake";
import {bytes, bytes32} from "./@types/basic";
import {KeyPair, PeerId} from "./@types/libp2p";
import {HandshakeInterface} from "./@types/handshake-interface";
import {Buffer} from "buffer";

export class Handshake implements HandshakeInterface {
  public isInitiator: boolean;
  public session: NoiseSession;

  private libp2pPrivateKey: bytes;
  private libp2pPublicKey: bytes;
  private prologue: bytes32;
  private staticKeys: KeyPair;
  private connection: WrappedConnection;
  private remotePeer: PeerId;
  private ik: IKHandshake;

  constructor(
    isInitiator: boolean,
    libp2pPrivateKey: bytes,
    libp2pPublicKey: bytes,
    prologue: bytes32,
    staticKeys: KeyPair,
    connection: WrappedConnection,
    remotePeer: PeerId,
    handshake?: IKHandshake,
  ) {
    this.isInitiator = isInitiator;
    this.libp2pPrivateKey = libp2pPrivateKey;
    this.libp2pPublicKey = libp2pPublicKey;
    this.prologue = prologue;
    this.staticKeys = staticKeys;
    this.connection = connection;
    this.remotePeer = remotePeer;

    this.ik = handshake || new IKHandshake();

    // Dummy data
    // TODO: Load remote static keys if found
    const remoteStaticKeys = this.staticKeys;
    this.session = this.ik.initSession(this.isInitiator, this.prologue, this.staticKeys, remoteStaticKeys.publicKey);
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
