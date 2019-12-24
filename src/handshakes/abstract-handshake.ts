import {Buffer} from "buffer";
import { AEAD, x25519, HKDF, SHA256 } from 'bcrypto';

import {bytes, bytes32, uint32} from "../@types/basic";
import {CipherState, SymmetricState} from "../@types/handshake";
import {getHkdf} from "../utils";

export class AbstractHandshake {
  protected minNonce = 0;

  protected incrementNonce(n: uint32): uint32 {
    return n + 1;
  }

  protected nonceToBytes(n: uint32): bytes {
    const nonce = Buffer.alloc(12);
    nonce.writeUInt32LE(n, 4);

    return nonce;
  }

  protected encrypt(k: bytes32, n: uint32, ad: bytes, plaintext: bytes): bytes {
    const nonce = this.nonceToBytes(n);
    const ctx = new AEAD();

    ctx.init(k, nonce);
    ctx.aad(ad);
    ctx.encrypt(plaintext);

    // Encryption is done on the sent reference
    return plaintext;
  }


  protected dh(privateKey: bytes32, publicKey: bytes32): bytes32 {
    const derived = x25519.derive(publicKey, privateKey);
    const result = Buffer.alloc(32);
    derived.copy(result);
    return result;
  }

  protected mixHash(ss: SymmetricState, data: bytes): void {
    ss.h = this.getHash(ss.h, data);
  }

  protected getHash(a: bytes, b: bytes): bytes32 {
    return SHA256.digest(Buffer.from([...a, ...b]));
  }

  protected mixKey(ss: SymmetricState, ikm: bytes32): void {
    const [ ck, tempK ] = getHkdf(ss.ck, ikm);
    ss.cs = this.initializeKey(tempK) as CipherState;
    ss.ck = ck;
  }

  protected initializeKey(k: bytes32): CipherState {
    const n = this.minNonce;
    return { k, n };
  }
}
