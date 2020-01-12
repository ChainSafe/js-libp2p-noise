import { bytes, bytes32 } from "./basic";
import { Duplex } from "it-pair";

export type KeyPair = {
  publicKey: bytes32;
  privateKey: bytes32;
}

export type PeerId = {
  id: bytes;
  privKey: {
    marshal(): bytes;
  };
  pubKey: {
    marshal(): bytes;
  };
  marshalPubKey(): bytes;
  marshalPrivKey(): bytes;
};

export interface INoiseConnection {
  remoteEarlyData?(): bytes;
  secureOutbound(localPeer: PeerId, insecure: any, remotePeer: PeerId): Promise<SecureOutbound>;
  secureInbound(localPeer: PeerId, insecure: any, remotePeer: PeerId): Promise<SecureOutbound>;
}

export type SecureOutbound = {
  conn: Duplex;
  remotePeer: PeerId;
}

