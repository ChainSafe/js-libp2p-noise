import type { Nonce } from './nonce'
import type { NoiseExtensions } from './proto/payload'
import type { ConnectionEncrypter, PeerId } from '@libp2p/interface'
import type { Uint8ArrayList } from 'uint8arraylist'

export type bytes = Uint8Array
export type bytes32 = Uint8Array
export type bytes16 = Uint8Array

export type uint64 = number

export interface IHandshake {
  session: NoiseSession
  remotePeer: PeerId
  remoteExtensions: NoiseExtensions
  encrypt(plaintext: Uint8Array | Uint8ArrayList, session: NoiseSession): Uint8Array | Uint8ArrayList
  decrypt(ciphertext: Uint8Array | Uint8ArrayList, session: NoiseSession, dst?: Uint8Array): { plaintext: Uint8Array | Uint8ArrayList, valid: boolean }
}

export type Hkdf = [bytes, bytes, bytes]

export interface MessageBuffer {
  ne: bytes32
  ns: Uint8Array | Uint8ArrayList
  ciphertext: Uint8Array | Uint8ArrayList
}

export interface CipherState {
  k: bytes32
  // For performance reasons, the nonce is represented as a Nonce object
  // The nonce is treated as a uint64, even though the underlying `number` only has 52 safely-available bits.
  n: Nonce
}

export interface SymmetricState {
  cs: CipherState
  ck: bytes32 // chaining key
  h: bytes32 // handshake hash
}

export interface HandshakeState {
  ss: SymmetricState
  s: KeyPair
  e?: KeyPair
  rs: Uint8Array | Uint8ArrayList
  re: bytes32
  psk: bytes32
}

export interface NoiseSession {
  hs: HandshakeState
  h?: bytes32
  cs1?: CipherState
  cs2?: CipherState
  mc: uint64
  i: boolean
}

export interface INoisePayload {
  identityKey: bytes
  identitySig: bytes
  data: bytes
}

export interface KeyPair {
  publicKey: bytes32
  privateKey: bytes32
}

export interface INoiseConnection extends ConnectionEncrypter<NoiseExtensions> { }
