import {Buffer} from "buffer";

import {CipherState, HandshakeState, MessageBuffer, SymmetricState} from "../@types/handshake";
import {bytes, bytes32} from "../@types/basic";
import {generateKeypair, getHkdf} from "../utils";
import {AbstractHandshake} from "./abstract-handshake";


export class IKHandshake extends AbstractHandshake {
  private writeMessageA(hs: HandshakeState, payload: bytes): MessageBuffer {
    hs.e = generateKeypair();
    const ne = hs.e.publicKey;
    this.mixHash(hs.ss, ne);
    this.mixKey(hs.ss, this.dh(hs.e.privateKey, hs.rs));
    const spk = Buffer.from(hs.s.publicKey);
    const ns = this.encryptAndHash(hs.ss, spk);

    this.mixKey(hs.ss, this.dh(hs.s.privateKey, hs.re));
    const ciphertext = this.encryptAndHash(hs.ss, payload);

    return { ne, ns, ciphertext };
  }


}
