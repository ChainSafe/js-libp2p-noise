import { bytes, bytes32 } from "./basic";
import { Duplex } from "it-pair";

export interface KeyPair {
  publicKey: bytes32,
  privateKey: bytes32,
}

export type PeerId = {
  id: string,
  privKey: string,
  pubKey: string,
};

export interface NoiseConnection {
  remoteEarlyData?(): bytes,
  secureOutbound(localPeer: PeerId, insecure: any, remotePeer: PeerId): Promise<SecureOutbound>,
  secureInbound(remotePeer: PeerId, insecure: any): Promise<SecureOutbound>,
}

export type SecureOutbound = {
  conn: Duplex,
  remotePeer: PeerId,
}
