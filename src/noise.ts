import { bytes } from "./types/basic";
import { Connection } from "./types/libp2p";

export class Noise {
  constructor(privateKey: bytes, staticNoiseKey?: bytes, earlyData?: bytes) {

  }

  public tag() {
    return '/noise';
  }

  public encrypt(InsecureConnection: Connection, remotePublicKey: bytes) {

  }

}
