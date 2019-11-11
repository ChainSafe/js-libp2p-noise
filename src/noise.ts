import { x25519 } from 'bcrypto';
import { Buffer } from "buffer";

import { bytes } from "./types/basic";
import { InsecureConnection, NoiseConnection, PeerId, SecureConnection, KeyPair } from "./types/libp2p";

import { Handshake } from "./handshake";
import { generateKeypair, signPayload } from "./utils";

export class Noise implements NoiseConnection {
  private readonly privateKey: bytes;
  private staticKeys?: KeyPair;
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
    }
  }

  public protocol() {
    return '/noise';
  }

  // encrypt outgoing data to the remote party (handshake as initiator)
  public async secureOutbound(connection: InsecureConnection, remotePeer: PeerId) : Promise<SecureConnection> {
    try {
      const remotePublicKey = Buffer.from(remotePeer.pubKey);
      const session = await this.createSecureConnection(connection, remotePublicKey, true);
    } catch (e) {

    }
  }

  // decrypt incoming data (handshake as responder)
  public async secureInbound(connection: InsecureConnection) : Promise<SecureConnection> {
  }

  private async read(ciphertext: bytes) {

  }

  private async write(plaintext: bytes) {

  }

  private async createSecureConnection(
    connection: InsecureConnection,
    remotePublicKey: bytes,
    isInitiator: boolean,
    ) : Promise<SecureConnection> {
    if (!this.staticKeys) {
      this.staticKeys = await generateKeypair();
    }

    let signedPayload;
    if (this.earlyData) {
      const payload = Buffer.concat([this.earlyData, this.staticKeys.publicKey])
      signedPayload = await signPayload(this.privateKey, payload);
    }

    const prologue = Buffer.from(this.protocol());
    const session = await Handshake.runXX(isInitiator, remotePublicKey, prologue, signedPayload, this.staticKeys);

    return {
      insecure: connection,
      initiator: isInitiator,
      prologue,
      // localKey: get public key,
      localPeer: connection.localPeer,
      remotePeer: connection.remotePeer,
      local: {
        noiseKey: this.staticKeys.publicKey,
        // libp2pKey:
      },
      xxNoiseSession: session,
      xxComplete: true,
      noiseKeypair: this.staticKeys,
    }
  }


}
