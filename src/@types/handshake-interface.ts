import {bytes} from "./basic";
import {NoiseSession} from "./handshake";

export interface IHandshake {
  session: NoiseSession;
  encrypt(plaintext: bytes, session: NoiseSession): bytes;
  decrypt(ciphertext: bytes, session: NoiseSession): bytes;
}
