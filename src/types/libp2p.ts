type PeerId = {
  id: string,
  privKey: string,
  pubKey: string,
};

type ConnectionStat = {
  direction: "inbound" | "outbound",
}

export interface Connection {
  localPeer: PeerId,
  remotePeer: PeerId,
  stat: ConnectionStat,
}
