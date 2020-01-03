import {NoiseSession} from "./@types/handshake";
import {bytes, bytes32} from "./@types/basic";
import {KeyPair, PeerId} from "./@types/libp2p";
import {WrappedConnection} from "./noise";
import {IKHandshake} from "./handshakes/ik";

export class Handshake {
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
}
