import { bytes, bytes32 } from "./basic";
import { NoiseSession } from "../xx";

export interface KeyPair {
  publicKey: bytes32,
  privateKey: bytes32,
}

export type PeerId = {
  id: string,
  privKey: string,
  pubKey: string,
};

type PeerInfo = {
  noiseKey: bytes32,
  libp2pKey: bytes,
};

type ConnectionStats = {
  direction: "inbound" | "outbound",
  encryption: string,
}


// Also seen as Pair
export type Stream = {
  sink(source: Iterable<any>),
  source: Object,
}

export type Duplex = [Stream, Stream];

export interface InsecureConnection {
  localPeer: PeerId,
  remotePeer: PeerId,
  local: PeerInfo,
  remote: PeerInfo,
  stats: ConnectionStats,

  streams(): Duplex,
  addStream(muxedStream: any) : Stream,
}

export interface NoiseConnection {
  remoteEarlyData?(): bytes,
  secureOutbound(insecure: InsecureConnection, remotePeer: PeerId): Promise<SecureConnection>,
  secureInbound(insecure: InsecureConnection): Promise<SecureConnection>,
}

export interface SecureConnection {
  initiator: boolean,
  prologue: bytes32,
  localKey: bytes,

  xxNoiseSession: NoiseSession,
  xxComplete: boolean,

  noiseKeypair: KeyPair,
  msgBuffer: bytes,
}
