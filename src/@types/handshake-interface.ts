import {bytes} from "./basic";
import {NoiseSession} from "./handshake";

export interface HandshakeInterface {
  session: NoiseSession;
  encrypt(plaintext: bytes, session: NoiseSession): bytes;
  decrypt(ciphertext: bytes, session: NoiseSession): bytes;
}
