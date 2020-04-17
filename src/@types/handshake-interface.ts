import {bytes} from "./basic";
import {NoiseSession} from "./handshake";
import PeerId from "peer-id";

export interface IHandshake {
  session: NoiseSession;
  remotePeer: PeerId;
  earlyData: Uint8Array;
  encrypt(plaintext: bytes, session: NoiseSession): bytes;
  decrypt(ciphertext: bytes, session: NoiseSession): {plaintext: bytes; valid: boolean};
}
