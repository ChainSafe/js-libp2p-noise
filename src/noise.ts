import { x25519 } from 'bcrypto';
import { Buffer } from "buffer";
import Wrap from 'it-pb-rpc';
import DuplexPair from 'it-pair/duplex';
import ensureBuffer from 'it-buffer';
import pipe from 'it-pipe';
import lp from 'it-length-prefixed';

import { Handshake } from "./handshake";
import { generateKeypair, int16BEDecode, int16BEEncode } from "./utils";
import { decryptStream, encryptStream } from "./crypto";
import { bytes } from "./@types/basic";
import { NoiseConnection, PeerId, KeyPair, SecureOutbound } from "./@types/libp2p";
import { Duplex } from "./@types/it-pair";

export type WrappedConnection = ReturnType<typeof Wrap>;

export class Noise implements NoiseConnection {
  public protocol = "/noise";

  private readonly privateKey: bytes;
  private readonly staticKeys: KeyPair;
  private readonly earlyData?: bytes;

  constructor(privateKey: bytes, staticNoiseKey?: bytes, earlyData?: bytes) {
    this.privateKey = privateKey;
    this.earlyData = earlyData || Buffer.alloc(0);

    if (staticNoiseKey) {
      const publicKey = x25519.publicKeyCreate(staticNoiseKey); // TODO: verify this
      this.staticKeys = {
        privateKey: staticNoiseKey,
        publicKey,
      }
    } else {
      this.staticKeys = generateKeypair();
    }
  }

  /**
   * Encrypt outgoing data to the remote party (handshake as initiator)
   * @param {PeerId} localPeer - PeerId of the receiving peer
   * @param connection - streaming iterable duplex that will be encrypted
   * @param {PeerId} remotePeer - PeerId of the remote peer. Used to validate the integrity of the remote peer.
   * @returns {Promise<SecureOutbound>}
   */
  public async secureOutbound(localPeer: PeerId, connection: any, remotePeer: PeerId): Promise<SecureOutbound> {
    const wrappedConnection = Wrap(connection);
    const libp2pPublicKey = localPeer.pubKey.marshal();
    const handshake = await this.performHandshake(wrappedConnection, true, libp2pPublicKey);
    const conn = await this.createSecureConnection(wrappedConnection, handshake);

    return {
      conn,
      remotePeer,
    }
  }

  /**
   * Decrypt incoming data (handshake as responder).
   * @param {PeerId} localPeer - PeerId of the receiving peer.
   * @param connection - streaming iterable duplex that will be encryption.
   * @param {PeerId} remotePeer - optional PeerId of the initiating peer, if known. This may only exist during transport upgrades.
   * @returns {Promise<SecureOutbound>}
   */
  public async secureInbound(localPeer: PeerId, connection: any, remotePeer: PeerId): Promise<SecureOutbound> {
    const wrappedConnection = Wrap(connection);
    const libp2pPublicKey = localPeer.pubKey.marshal();
    const handshake = await this.performHandshake(wrappedConnection, false, libp2pPublicKey);
    const conn = await this.createSecureConnection(wrappedConnection, handshake);

    return {
      conn,
      remotePeer,
    };
  }

  private async performHandshake(
    connection: WrappedConnection,
    isInitiator: boolean,
    libp2pPublicKey: bytes,
  ): Promise<Handshake> {
    const prologue = Buffer.from(this.protocol);
    const handshake = new Handshake(isInitiator, this.privateKey, libp2pPublicKey, prologue, this.staticKeys, connection);

    await handshake.propose(this.earlyData);
    await handshake.exchange();
    await handshake.finish();

    return handshake;
  }

  private async createSecureConnection(
    connection: WrappedConnection,
    handshake: Handshake,
  ): Promise<Duplex> {
    // Create encryption box/unbox wrapper
    const [secure, user] = DuplexPair();
    const network = connection.unwrap();

    pipe(
      secure, // write to wrapper
      ensureBuffer, // ensure any type of data is converted to buffer
      encryptStream(handshake), // data is encrypted
      lp.encode({ lengthEncoder: int16BEEncode }), // prefix with message length
      network, // send to the remote peer
      lp.decode({ lengthDecoder: int16BEDecode }), // read message length prefix
      ensureBuffer, // ensure any type of data is converted to buffer
      decryptStream(handshake), // decrypt the incoming data
      secure // pipe to the wrapper
    );

    return user;
  }


}
