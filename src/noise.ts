import { x25519 } from 'bcrypto';
import { Buffer } from "buffer";

import { bytes } from "./@types/basic";
import {NoiseConnection, PeerId, KeyPair, SecureOutbound} from "./@types/libp2p";

import { Handshake } from "./handshake";
import { generateKeypair, signPayload } from "./utils";
import { decryptStreams, encryptStreams } from "./crypto";
import {Duplex} from "./@types/it-pair";

export class Noise implements NoiseConnection {
  public protocol = "/noise";

  private readonly privateKey: bytes;
  private staticKeys: KeyPair;
  private earlyData?: bytes;

  constructor(privateKey: bytes, staticNoiseKey?: bytes, earlyData?: bytes) {
    this.privateKey = privateKey;
    this.earlyData = earlyData;

    if (staticNoiseKey) {
      const publicKey = x25519.publicKeyCreate(staticNoiseKey);
      this.staticKeys = {
        privateKey: staticNoiseKey,
        publicKey,
      }
    } else {
      // todo: generate new static key
    }
  }

  /**
   * Encrypt outgoing data to the remote party (handshake as initiator)
   * @param {PeerId} localPeer - PeerId of the receiving peer
   * @param connection - streaming iterable duplex that will be encrypted
   * @param {PeerId} remotePeer - PeerId of the remote peer. Used to validate the integrity of the remote peer.
   * @returns {Promise<SecureOutbound>}
   */
  public async secureOutbound(localPeer: PeerId, connection: any, remotePeer: PeerId) : Promise<SecureOutbound> {
    const remotePublicKey = Buffer.from(remotePeer.pubKey);
    const session = await this.createSecureConnection(connection, remotePublicKey, true);

    return {
      conn: session,
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
  public async secureInbound(localPeer: PeerId, connection: any, remotePeer?: PeerId) : Promise<SecureOutbound> {
  }

  private async createSecureConnection(
    connection: Duplex,
    remotePublicKey: bytes,
    isInitiator: boolean,
    ) : Promise<Duplex> {
    if (!this.staticKeys) {
      this.staticKeys = await generateKeypair();
    }

    let signedPayload;
    if (this.earlyData) {
      const payload = Buffer.concat([this.earlyData, this.staticKeys.publicKey])
      signedPayload = await signPayload(this.privateKey, payload);
    }

    const prologue = Buffer.from(this.protocol);
    const handshake = new Handshake('XX', remotePublicKey, prologue, signedPayload, this.staticKeys)
    const session = await handshake.propose(isInitiator);

    return await encryptStreams(connection, session);
  }


}
