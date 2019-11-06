import {bytes32, bytes16, uint32, uint64, bytes} from './types/basic'
import { Buffer } from 'buffer';
import { AEAD, x25519, HKDF, SHA256 } from 'bcrypto';
import { BN } from 'bn.js';

export interface KeyPair {
  publicKey: bytes32,
  privateKey: bytes32,
}

interface MessageBuffer {
  ne: bytes32,
  ns: bytes,
  ciphertext: bytes
}

type CipherState = {
  k: bytes32,
  n: uint32,
}

type SymmetricState = {
  cs: CipherState,
  ck: bytes32,  // chaining key
  h: bytes32, // handshake hash
}

type HandshakeState = {
  ss: SymmetricState,
  s: KeyPair,
  e?: KeyPair,
  rs: bytes32,
  re: bytes32,
  psk: bytes32,
}

type NoiseSession = {
  hs: HandshakeState,
  h?: bytes32,
  cs1?: CipherState,
  cs2?: CipherState,
  mc: uint64,
  i: boolean,
}
export type Hkdf = [bytes, bytes, bytes];

const minNonce = 0;

export class XXHandshake {
  private createEmptyKey() : bytes32 {
    return Buffer.alloc(32);
  }

  private async initializeInitiator(prologue: bytes32, s: KeyPair, rs: bytes32, psk: bytes32) : Promise<HandshakeState> {
    const name = "Noise_XX_25519_ChaChaPoly_SHA256";
    const ss = await this.initializeSymmetric(name);
    this.mixHash(ss, prologue);
    const re = Buffer.alloc(32);

    return { ss, s, rs, psk, re };
  }

  private async initializeResponder(prologue: bytes32, s: KeyPair, rs: bytes32, psk: bytes32) : Promise<HandshakeState> {
    const name = "Noise_XX_25519_ChaChaPoly_SHA256";
    const ss = await this.initializeSymmetric(name);
    this.mixHash(ss, prologue);
    const re = Buffer.alloc(32);

    return { ss, s, rs, psk, re };
  }

  private incrementNonce(n: uint32) : uint32 {
    return n + 1;
  }

  private dh(privateKey: bytes32, publicKey: bytes32) : bytes32 {
    const derived = x25519.derive(privateKey, publicKey);
    const result = Buffer.alloc(32);
    derived.copy(result);
    return result;
  }

  private convertNonce(n: uint32) : bytes {
    const nonce = Buffer.alloc(12);
    nonce.writeUInt32LE(n, 4);

    return nonce;
  }

  private encrypt(k: bytes32, n: uint32, ad: bytes, plaintext: bytes) : bytes {
    const nonce = this.convertNonce(n);
    const ctx = new AEAD();
    ctx.init(k, nonce);
    ctx.aad(ad);
    ctx.encrypt(plaintext);

    return ctx.final();
  }

  private decrypt(k: bytes32, n: uint32, ad: bytes, ciphertext: bytes) : bytes {
    const nonce = this.convertNonce(n);
    const ctx = new AEAD();

    ctx.init(k, nonce);
    ctx.aad(ad);
    ctx.decrypt(ciphertext);

    return ctx.final();
  }

  private isEmptyKey(k: bytes32) : boolean {
    const emptyKey = this.createEmptyKey();
    return emptyKey.equals(k);
  }

  // Cipher state related
  private initializeKey(k: bytes32) : CipherState {
    const n = minNonce;
    return { k, n };
  }

  private hasKey(cs: CipherState) : boolean {
    return !this.isEmptyKey(cs.k);
  }

  private setNonce(cs: CipherState, nonce: uint32) {
    cs.n = nonce;
  }

  private encryptWithAd(cs: CipherState, ad: bytes, plaintext: bytes) : bytes {
    const e = this.encrypt(cs.k, cs.n, ad, plaintext);
    this.setNonce(cs, this.incrementNonce(cs.n));
    return e;
  }

  private decryptWithAd(cs: CipherState, ad: bytes, ciphertext: bytes) : bytes {
    const plaintext = this.decrypt(cs.k, cs.n, ad, ciphertext);
    this.setNonce(cs, this.incrementNonce(cs.n));

    return plaintext;
  }

  // Symmetric state related

  private async initializeSymmetric(protocolName: string) : Promise<SymmetricState> {
    const protocolNameBytes: bytes = Buffer.from(protocolName, 'utf-8');
    const h = await this.hashProtocolName(protocolNameBytes);

    const ck = h;
    const key = this.createEmptyKey();
    const cs:CipherState = this.initializeKey(key);

    return { cs, ck, h };
  }

  private mixKey(ss: SymmetricState, ikm: bytes32) {
    const [ ck, tempK ] = this.getHkdf(ss.ck, ikm);
    ss.cs = this.initializeKey(tempK) as CipherState;
    ss.ck = ck;
  }

  private async hashProtocolName(protocolName: bytes) : Promise<bytes32> {
    if (protocolName.length <= 32) {
      let h = Buffer.alloc(32);
      protocolName.copy(h);
      return h;
    } else {
      return this.getHash(protocolName, Buffer.alloc(0));
    }
  }

  public getHkdf(ck: bytes32, ikm: bytes) : Hkdf {
    const info = Buffer.alloc(0);
    const prk = HKDF.extract(SHA256, ikm, ck);
    const okm = HKDF.expand(SHA256, prk, info, 96);

    const k1 = okm.slice(0, 32);
    const k2 = okm.slice(32, 64);
    const k3 = okm.slice(64, 96);

    return [ k1, k2, k3 ];
  }

  private mixHash(ss: SymmetricState, data: bytes) {
    ss.h = this.getHash(ss.h, data);
  }

  private getHash(a: bytes, b: bytes) : bytes32 {
    return SHA256.digest(Buffer.from([...a, ...b]));
  }

  private async encryptAndHash(ss: SymmetricState, plaintext: bytes) : Promise<bytes> {
    let ciphertext;
    if (this.hasKey(ss.cs)) {
      ciphertext = this.encryptWithAd(ss.cs, ss.h, plaintext);
    } else {
      ciphertext = plaintext;
    }

    this.mixHash(ss, ciphertext);
    return ciphertext;
  }

  private async decryptAndHash(ss: SymmetricState, ciphertext: bytes) : Promise<bytes> {
    let plaintext;
    if (this.hasKey(ss.cs)) {
      plaintext = this.decryptWithAd(ss.cs, ss.h, ciphertext);
    } else {
      plaintext = ciphertext;
    }

    this.mixHash(ss, ciphertext);
    return plaintext;
  }

  private split (ss: SymmetricState) {
    const [ tempk1, tempk2 ] = this.getHkdf(ss.ck, Buffer.alloc(0));
    const cs1 = this.initializeKey(tempk1);
    const cs2 = this.initializeKey(tempk2);

    return { cs1, cs2 };
  }

  private async writeMessageA(hs: HandshakeState, payload: bytes) : Promise<MessageBuffer> {
    let ns = Buffer.alloc(0);
    hs.e = await this.generateKeypair();
    const ne = hs.e.publicKey;

    this.mixHash(hs.ss, ne);
    const ciphertext = await this.encryptAndHash(hs.ss, payload);

    return {ne, ns, ciphertext};
  }

  private async writeMessageB(hs: HandshakeState, payload: bytes) : Promise<MessageBuffer> {
    hs.e = await this.generateKeypair();
    const ne = hs.e.publicKey;
    this.mixHash(hs.ss, ne);

    this.mixKey(hs.ss, this.dh(hs.e.privateKey, hs.re));
    const spk = Buffer.from(hs.s.publicKey);
    const ns = await this.encryptAndHash(hs.ss, spk);

    this.mixKey(hs.ss, this.dh(hs.s.privateKey, hs.re));
    const ciphertext = await this.encryptAndHash(hs.ss, payload);

    return { ne, ns, ciphertext };
  }

  private async writeMessageC(hs: HandshakeState, payload: bytes) {
    const spk = Buffer.from(hs.s.publicKey);
    const ns = await this.encryptAndHash(hs.ss, spk);
    this.mixKey(hs.ss, this.dh(hs.s.privateKey, hs.re));
    const ciphertext = await this.encryptAndHash(hs.ss, payload);
    const ne = this.createEmptyKey();
    const messageBuffer: MessageBuffer = {ne, ns, ciphertext};
    const { cs1, cs2 } = this.split(hs.ss);

    return { h: hs.ss.h, messageBuffer, cs1, cs2 };
  }

  private async writeMessageRegular(cs: CipherState, payload: bytes) : Promise<MessageBuffer> {
    const ciphertext = this.encryptWithAd(cs, Buffer.alloc(0), payload);
    const ne = this.createEmptyKey();
    const ns = Buffer.alloc(0);

    return { ne, ns, ciphertext };
  }

  private async readMessageA(hs: HandshakeState, message: MessageBuffer) : Promise<bytes> {
    // TODO: validate public key here

    this.mixHash(hs.ss, hs.re);
    return await this.decryptAndHash(hs.ss, message.ciphertext);
  }

  private async readMessageB(hs: HandshakeState, message: MessageBuffer) : Promise<bytes> {
    // TODO: validate public key here

    this.mixHash(hs.ss, hs.re);
    if (!hs.e) {
      throw new Error("Handshake state `e` param is missing.");
    }
    this.mixKey(hs.ss, this.dh(hs.e.privateKey, hs.re));
    const ns = await this.decryptAndHash(hs.ss, message.ns);
    // TODO: validate ns here as public key
    hs.rs = ns;
    this.mixKey(hs.ss, this.dh(hs.e.privateKey, hs.rs));
    return await this.decryptAndHash(hs.ss, message.ciphertext);
  }

  private async readMessageC(hs: HandshakeState, message: MessageBuffer) {
    const ns = await this.decryptAndHash(hs.ss, message.ns);
    // TODO: validate ns here as public key
    hs.rs = ns;
    if (!hs.e) {
      throw new Error("Handshake state `e` param is missing.");
    }
    this.mixKey(hs.ss, this.dh(hs.e.privateKey, hs.rs));
    const plaintext = await this.decryptAndHash(hs.ss, message.ciphertext);
    const { cs1, cs2 } = this.split(hs.ss);

    return { h: hs.ss.h, plaintext, cs1, cs2 };
  }

  private readMessageRegular(cs: CipherState, message: MessageBuffer) : bytes {
    return this.decryptWithAd(cs, Buffer.alloc(0), message.ciphertext);
  }

  public async generateKeypair() : Promise<KeyPair> {
    const privateKey = x25519.privateKeyGenerate();
    const publicKey = x25519.publicKeyCreate(privateKey);

    return {
      publicKey,
      privateKey,
    }
  }

  public async initSession(initiator: boolean, prologue: bytes32, s: KeyPair, rs: bytes32) : Promise<NoiseSession> {
    const psk = this.createEmptyKey();
    let hs;

    if (initiator) {
      hs = await this.initializeInitiator(prologue, s, rs, psk);
    } else {
      hs = await this.initializeResponder(prologue, s, rs, psk);
    }

    return {
      hs,
      i: initiator,
      mc: new BN(0),
    };
  }

  public async sendMessage(session: NoiseSession, message: bytes) : Promise<MessageBuffer> {
    let messageBuffer: MessageBuffer;
    if (session.mc.eqn(0)) {
      messageBuffer = await this.writeMessageA(session.hs, message);
    } else if (session.mc.eqn(1)) {
      messageBuffer = await this.writeMessageB(session.hs, message);
    } else if (session.mc.eqn(2)) {
      const { h, messageBuffer: resultingBuffer, cs1, cs2 } = await this.writeMessageC(session.hs, message);
      messageBuffer = resultingBuffer;
      session.h = h;
      session.cs1 = cs1;
      session.cs2 = cs2;
    } else if (session.mc.gtn(2)) {
      if (session.i) {
        if (!session.cs1) {
          throw new Error("CS1 (cipher state) is not defined")
        }

        messageBuffer = await this.writeMessageRegular(session.cs1, message);
      } else {
        if (!session.cs2) {
          throw new Error("CS2 (cipher state) is not defined")
        }

        messageBuffer = await this.writeMessageRegular(session.cs2, message);
      }
    } else {
      throw new Error("Session invalid.")
    }

    session.mc = session.mc.add(new BN(1));
    return messageBuffer;
  }

  public async RecvMessage(session: NoiseSession, message: MessageBuffer) : Promise<bytes> {
    let plaintext: bytes;
    if (session.mc.eqn(0)) {
      plaintext = await this.readMessageA(session.hs, message);
    } else if (session.mc.eqn(1)) {
      plaintext = await this.readMessageB(session.hs, message);
    } else if (session.mc.eqn(2)) {
      const { h, plaintext: resultingPlaintext, cs1, cs2 } = await this.readMessageC(session.hs, message);
      plaintext = resultingPlaintext;
      session.h = h;
      session.cs1 = cs1;
      session.cs2 = cs2;
    } else if (session.mc.gtn(2)) {
      if (session.i) {
        if (!session.cs2) {
          throw new Error("CS1 (cipher state) is not defined")
        }
        plaintext = await this.readMessageRegular(session.cs2, message);
      } else {
        if (!session.cs1) {
          throw new Error("CS1 (cipher state) is not defined")
        }
        plaintext = await this.readMessageRegular(session.cs1, message);
      }
    } else {
      throw new Error("Session invalid.");
    }

    session.mc = session.mc.add(new BN(1));
    return plaintext;
  }
}
