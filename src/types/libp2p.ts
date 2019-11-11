import { bytes } from "./basic";

type PeerId = {
  id: string,
  privKey: string,
  pubKey: string,
};

type ConnectionStats = {
  direction: "inbound" | "outbound",
  encryption: string,
}

export interface Connection {
  localPeer: PeerId,
  remotePeer: PeerId,
  stats: ConnectionStats,
}
