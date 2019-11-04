import {bytes32, bytes16, uint32, uint64, bytes} from './types/basic'
import { Buffer } from 'buffer';
import * as crypto from 'libp2p-crypto';
import AEAD from 'bcrypto/aead-browser';

interface KeyPair {
  publicKey: bytes32,
  privateKey: bytes32,
}

type CipherState = {
  k: bytes32,
  n: uint32,
}

type SymmetricState = {
  cs: CipherState,
  ck: bytes32,
  h: bytes32,
}

type HandshakeState = {
  ss: SymmetricState,
  s: KeyPair,
  e: KeyPair,
  rs: bytes32,
  re: bytes32,
  psk: bytes32,
}

type NoiseSession = {
  hs: HandshakeState,
  h: bytes32,
  cs1: CipherState,
  c2: CipherState,
  mc: uint64,
  i: boolean,
}

const minNonce = 0;

class XXHandshake {
  private createEmptyKey() : bytes32 {
    return Buffer.alloc(32);
  }

  private async initializeInitiator(prologue: bytes32, s: KeyPair, rs: bytes32, psk: bytes32) : Promise<HandshakeState> {
    let e: KeyPair;
    let re: bytes32;
    const name = "Noise_XX_25519_ChaChaPoly_SHA256";
    const ss = await this.initializeSymmetric(name);
    await this.mixHash(ss, prologue);

    return {ss, s, e, rs, re, psk};
  }

  private async initializeResponder(prologue: bytes32, s: KeyPair, rs: bytes32, psk: bytes32) : Promise<HandshakeState> {
    let e: KeyPair;
    let re: bytes32;
    const name = "Noise_XX_25519_ChaChaPoly_SHA256";
    const ss = await this.initializeSymmetric(name);
    await this.mixHash(ss, prologue);

    return {ss, s, e, rs, re, psk};
  }

  private incrementNonce(n: uint32) : uint32 {
    return n + 1;
  }

  private encrypt(k: bytes32, n: uint32, ad: bytes, plaintext: bytes) : bytes {
    const nonce = Buffer.alloc(12);
    nonce.writeUInt32LE(n, 4);
    const ctx = new AEAD();
    ctx.init(k, nonce);
    ctx.aad(ad);
    ctx.encrypt(plaintext);

    return ctx.final();
  }

  // Cipher state related
  private initializeKey(k: bytes32) : CipherState {
    const n = minNonce;
    return { k, n };
  }

  private setNonce(cs: CipherState, nonce: uint32) {
    cs.n = nonce;
  }

  private encryptWithAd(cs: CipherState, ad: bytes, plaintext: bytes) : bytes {
    const e = this.encrypt(cs.k, cs.n, ad, plaintext);
    this.setNonce(cs, this.incrementNonce(cs.n));
    return e;
  }

  // Symmetric state related

  private async initializeSymmetric(protocolName: string) : Promise<SymmetricState> {
    const protocolNameBytes: bytes = Buffer.from(protocolName, 'utf-8');
    const h = await this.hashProtocolName(protocolNameBytes);
    const ck = h;
    const key = this.createEmptyKey();
    const cs = this.initializeKey(key);

    return { cs, ck, h };
  }

  private async hashProtocolName(protocolName: bytes) : Promise<bytes32> {
    if (protocolName.length <= 32) {
      return new Promise(resolve => {
        const h = Buffer.alloc(32);
        protocolName.copy(h);
        resolve(h)
      });
    } else {
      return await this.getHash(protocolName, Buffer.from([]));
    }
  }

  private async mixHash(ss: SymmetricState, data: bytes) {
    ss.h = await this.getHash(ss.h, data);
  }

  private async getHash(a: bytes, b: bytes) : Promise<bytes32> {
    return await crypto.hmac.create('sha256', Buffer.from([...a, ...b]))
  }

  public async initSession(initiator: boolean, prologue: bytes32[], s: KeyPair, rs: bytes32) : Promise<NoiseSession> {
    let session: NoiseSession;
    const psk = this.createEmptyKey();

    if (initiator) {
      session.hs = await this.initializeInitiator(prologue, s, rs, psk);
    } else {
      session.hs = await this.initializeResponder(prologue, s, rs, psk);
    }

    session.i = initiator;
    session.mc = 0;
    return session;
  }
}
