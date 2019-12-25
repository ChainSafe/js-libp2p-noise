import {Buffer} from "buffer";
import { AEAD, x25519, HKDF, SHA256 } from 'bcrypto';

import {bytes, bytes32, uint32} from "../@types/basic";
import {CipherState, SymmetricState} from "../@types/handshake";
import {getHkdf} from "../utils";

export class AbstractHandshake {
  protected minNonce = 0;

  public encryptWithAd(cs: CipherState, ad: bytes, plaintext: bytes): bytes {
    const e = this.encrypt(cs.k, cs.n, ad, plaintext);
    this.setNonce(cs, this.incrementNonce(cs.n));

    return e;
  }

  public decryptWithAd(cs: CipherState, ad: bytes, ciphertext: bytes): bytes {
    const plaintext = this.decrypt(cs.k, cs.n, ad, ciphertext);
    this.setNonce(cs, this.incrementNonce(cs.n));

    return plaintext;
  }


  // Cipher state related
  protected hasKey(cs: CipherState): boolean {
    return !this.isEmptyKey(cs.k);
  }

  protected setNonce(cs: CipherState, nonce: uint32): void {
    cs.n = nonce;
  }

  protected createEmptyKey(): bytes32 {
    return Buffer.alloc(32);
  }

  protected isEmptyKey(k: bytes32): boolean {
    const emptyKey = this.createEmptyKey();
    return emptyKey.equals(k);
  }

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

  protected encryptAndHash(ss: SymmetricState, plaintext: bytes): bytes {
    let ciphertext;
    if (this.hasKey(ss.cs)) {
      ciphertext = this.encryptWithAd(ss.cs, ss.h, plaintext);
    } else {
      ciphertext = plaintext;
    }

    this.mixHash(ss, ciphertext);
    return ciphertext;
  }

  protected decrypt(k: bytes32, n: uint32, ad: bytes, ciphertext: bytes): bytes {
    const nonce = this.nonceToBytes(n);
    const ctx = new AEAD();

    ctx.init(k, nonce);
    ctx.aad(ad);
    ctx.decrypt(ciphertext);

    // Decryption is done on the sent reference
    return ciphertext;
  }

  protected decryptAndHash(ss: SymmetricState, ciphertext: bytes): bytes {
    let plaintext;
    if (this.hasKey(ss.cs)) {
      plaintext = this.decryptWithAd(ss.cs, ss.h, ciphertext);
    } else {
      plaintext = ciphertext;
    }

    this.mixHash(ss, ciphertext);
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

  // Symmetric state related

  protected initializeSymmetric(protocolName: string): SymmetricState {
    const protocolNameBytes: bytes = Buffer.from(protocolName, 'utf-8');
    const h = this.hashProtocolName(protocolNameBytes);

    const ck = h;
    const key = this.createEmptyKey();
    const cs: CipherState = this.initializeKey(key);

    return { cs, ck, h };
  }

  protected hashProtocolName(protocolName: bytes): bytes32 {
    if (protocolName.length <= 32) {
      const h = Buffer.alloc(32);
      protocolName.copy(h);
      return h;
    } else {
      return this.getHash(protocolName, Buffer.alloc(0));
    }
  }

  protected split (ss: SymmetricState) {
    const [ tempk1, tempk2 ] = getHkdf(ss.ck, Buffer.alloc(0));
    const cs1 = this.initializeKey(tempk1);
    const cs2 = this.initializeKey(tempk2);

    return { cs1, cs2 };
  }
}
