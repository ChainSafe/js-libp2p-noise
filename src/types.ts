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

/**
 * A CipherState object contains k and n variables, which it uses to encrypt and decrypt ciphertexts.
 * During the handshake phase each party has a single CipherState, but during the transport phase each party has two CipherState objects: one for sending, and one for receiving.
 */
export interface CipherState {
  /** A cipher key of 32 bytes (which may be empty). Empty is a special value which indicates k has not yet been initialized. */
  k: bytes32
  /**
   * An 8-byte (64-bit) unsigned integer nonce.
   *
   * For performance reasons, the nonce is represented as a Nonce object
   * The nonce is treated as a uint64, even though the underlying `number` only has 52 safely-available bits.
   */
  n: Nonce
}

/**
 * A SymmetricState object contains a CipherState plus ck and h variables. It is so-named because it encapsulates all the "symmetric crypto" used by Noise.
 * During the handshake phase each party has a single SymmetricState, which can be deleted once the handshake is finished.
 */
export interface SymmetricState {
  cs: CipherState
  /** A chaining key of 32 bytes. */
  ck: bytes32
  /** A hash output of 32 bytes. */
  h: bytes32
}

/**
 * A HandshakeState object contains a SymmetricState plus DH variables (s, e, rs, re) and a variable representing the handshake pattern.
 * During the handshake phase each party has a single HandshakeState, which can be deleted once the handshake is finished.
 */
export interface HandshakeState {
  ss: SymmetricState
  /** The local static key pair */
  s: KeyPair
  /** The local ephemeral key pair */
  e?: KeyPair
  /** The remote party's static public key */
  rs: Uint8Array | Uint8ArrayList
  /** The remote party's ephemeral public key */
  re: bytes32
}

export interface NoiseSession {
  hs: HandshakeState
  h?: bytes32
  cs1?: CipherState
  cs2?: CipherState
  mc: uint64
  i: boolean
}

/**
 * The Noise Protocol Framework caters for sending early data alongside handshake messages. We leverage this construct to transmit:
 *
 * 1. the libp2p identity key along with a signature, to authenticate each party to the other.
 * 2. extensions used by the libp2p stack.
 */
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
