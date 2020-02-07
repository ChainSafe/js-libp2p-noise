import PeerId from "peer-id";

import {bytes} from "./basic";
import {NoiseSession} from "./handshake";

export interface IHandshake {
  session: NoiseSession;
  remotePeer?: PeerId;
  encrypt(plaintext: bytes, session: NoiseSession): bytes;
  decrypt(ciphertext: bytes, session: NoiseSession): bytes;
}
