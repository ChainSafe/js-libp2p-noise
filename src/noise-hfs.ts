/**
 * NoiseHFS — Post-Quantum Noise connection encrypter.
 *
 * Implements the ConnectionEncrypter interface using the XXhfs Noise pattern:
 *   Noise_XXhfs_25519+ML-KEM-768_ChaChaPoly_SHA256
 *
 * Libp2p protocol ID: /noise-mlkem768-hfs/0.1.0
 *
 * This is a drop-in replacement for the classical `noise()` factory. Swap
 * `noise()` for `noiseHFS()` in your libp2p config to get quantum-safe forward
 * secrecy via ML-KEM-768 alongside the existing identity/authentication layer
 * (Ed25519 signatures, unchanged).
 *
 * Both endpoints MUST use noiseHFS — it is not backward-compatible with the
 * classical /noise protocol because the handshake message layout differs.
 *
 * ML-DSA identity integration (PR #3432 coordination):
 *   This class currently uses Ed25519 for peer identity (the NoiseHandshakePayload
 *   signature). For a fully post-quantum handshake, the identity layer also needs
 *   to be upgraded to ML-DSA (FIPS 204) once PR #3432 lands in js-libp2p.
 *
 *   When PR #3432 merges:
 *     - Peers with KeyType.MLDSA (= 4) will sign the static key with MLDSA65
 *     - MLDSA65 signatures are 3,309 bytes vs Ed25519 at 64 bytes
 *     - The full-PQ handshake (XXhfs + MLDSA65 identity both sides) comes to
 *       roughly 9,400 bytes total wire overhead per connection
 *     - NoiseHFS.secureOutbound/secureInbound will handle this automatically
 *       because createHandshakePayload/decodeHandshakePayload delegate to
 *       privateKey.sign() which is key-type aware
 *
 *   No code changes are needed here to support ML-DSA identity once PR #3432
 *   merges — the signature is transparent to this layer.
 *
 * Node.js native KEM backend:
 *   See src/crypto/pqc.node.ts for the planned Node.js native backend that
 *   will use node:crypto.subtle once Node.js adds ML-KEM-768 support.
 */

import { publicKeyFromProtobuf } from '@libp2p/crypto/keys'
import { InvalidCryptoExchangeError, serviceCapabilities } from '@libp2p/interface'
import { peerIdFromPublicKey } from '@libp2p/peer-id'
import { lpStream } from '@libp2p/utils'
import { alloc as uint8ArrayAlloc } from 'uint8arrays/alloc'
import { NOISE_MSG_MAX_LENGTH_BYTES } from './constants.js'
import { pureJsCrypto } from './crypto/js.js'
import { pqcKem } from './crypto/pqc.js'
import { wrapCrypto } from './crypto.js'
import { uint16BEDecode, uint16BEEncode } from './encoder.js'
import { registerMetrics } from './metrics.js'
import { performHandshakeHFSInitiator, performHandshakeHFSResponder } from './performHandshake-hfs.js'
import { toMessageStream } from './utils.js'
import type { ICryptoInterface } from './crypto.js'
import type { IKem } from './kem.js'
import type { MetricsRegistry } from './metrics.js'
import type { HandshakeResult, ICrypto, INoiseConnection, INoiseExtensions, KeyPair } from './types.js'
import type { NoiseExtensions } from './noise.js'
import type { NoiseComponents } from './index.js'
import type { SecuredConnection, PrivateKey, PublicKey, StreamMuxerFactory, SecureConnectionOptions, Logger, MessageStream } from '@libp2p/interface'
import type { LengthPrefixedStream } from '@libp2p/utils'

export interface NoiseHFSInit {
  /**
   * X25519 static private key (32 bytes). Re-use across connections for
   * faster handshakes and persistent peer identity in the Noise layer.
   * If omitted, a fresh ephemeral key is generated per instance.
   */
  staticNoiseKey?: Uint8Array
  /**
   * KEM backend. Defaults to pqcKem (ML-KEM-768 via @noble/post-quantum).
   * Override for testing or to swap in a different KEM.
   */
  kemBackend?: IKem
  extensions?: Partial<NoiseExtensions>
  crypto?: ICryptoInterface
  prologueBytes?: Uint8Array
}

export class NoiseHFS implements INoiseConnection {
  public protocol = '/noise-mlkem768-hfs/0.1.0'
  public crypto: ICrypto

  private readonly prologue: Uint8Array
  private readonly staticKey: KeyPair
  private readonly kem: IKem
  private readonly extensions?: NoiseExtensions
  private readonly metrics?: MetricsRegistry
  private readonly components: NoiseComponents
  private readonly log: Logger

  constructor (components: NoiseComponents, init: NoiseHFSInit = {}) {
    const { staticNoiseKey, kemBackend, extensions, crypto, prologueBytes } = init
    const { metrics } = components

    this.components = components
    this.log = components.logger.forComponent('libp2p:noise-hfs')
    const _crypto = crypto ?? pureJsCrypto
    this.crypto = wrapCrypto(_crypto)
    this.kem = kemBackend ?? pqcKem
    this.extensions = {
      webtransportCerthashes: [],
      ...extensions
    }
    this.metrics = metrics ? registerMetrics(metrics) : undefined

    if (staticNoiseKey) {
      this.staticKey = _crypto.generateX25519KeyPairFromSeed(staticNoiseKey)
    } else {
      this.staticKey = _crypto.generateX25519KeyPair()
    }
    this.prologue = prologueBytes ?? uint8ArrayAlloc(0)
  }

  readonly [Symbol.toStringTag] = '@chainsafe/libp2p-noise-hfs'

  readonly [serviceCapabilities]: string[] = [
    '@libp2p/connection-encryption',
    '@chainsafe/libp2p-noise-hfs'
  ]

  /**
   * Encrypt outgoing data (handshake as XXhfs initiator).
   */
  async secureOutbound (connection: MessageStream, options?: SecureConnectionOptions): Promise<SecuredConnection<INoiseExtensions>> {
    const log = connection.log?.newScope('noise-hfs') ?? this.log
    const wrappedConnection = lpStream(connection, {
      lengthEncoder: uint16BEEncode,
      lengthDecoder: uint16BEDecode,
      maxDataLength: NOISE_MSG_MAX_LENGTH_BYTES
    })

    const handshake = await this.performHFSHandshakeInitiator(
      wrappedConnection,
      this.components.privateKey,
      log,
      options?.remotePeer?.publicKey,
      options
    )
    const publicKey = publicKeyFromProtobuf(handshake.payload.identityKey)

    return {
      connection: toMessageStream(wrappedConnection.unwrap(), handshake, this.metrics),
      remoteExtensions: handshake.payload.extensions,
      remotePeer: peerIdFromPublicKey(publicKey),
      streamMuxer: options?.skipStreamMuxerNegotiation === true ? undefined : this.getStreamMuxer(handshake.payload.extensions?.streamMuxers)
    }
  }

  /**
   * Decrypt incoming data (handshake as XXhfs responder).
   */
  async secureInbound (connection: MessageStream, options?: SecureConnectionOptions): Promise<SecuredConnection<INoiseExtensions>> {
    const log = connection.log?.newScope('noise-hfs') ?? this.log
    const wrappedConnection = lpStream(connection, {
      lengthEncoder: uint16BEEncode,
      lengthDecoder: uint16BEDecode,
      maxDataLength: NOISE_MSG_MAX_LENGTH_BYTES
    })

    const handshake = await this.performHFSHandshakeResponder(
      wrappedConnection,
      this.components.privateKey,
      log,
      options?.remotePeer?.publicKey,
      options
    )
    const publicKey = publicKeyFromProtobuf(handshake.payload.identityKey)

    return {
      connection: toMessageStream(wrappedConnection.unwrap(), handshake, this.metrics),
      remoteExtensions: handshake.payload.extensions,
      remotePeer: peerIdFromPublicKey(publicKey),
      streamMuxer: options?.skipStreamMuxerNegotiation === true ? undefined : this.getStreamMuxer(handshake.payload.extensions?.streamMuxers)
    }
  }

  private getStreamMuxer (protocols?: string[]): StreamMuxerFactory | undefined {
    if (protocols == null || protocols.length === 0) {
      return
    }

    const streamMuxers = this.components.upgrader.getStreamMuxers()

    if (streamMuxers != null) {
      for (const protocol of protocols) {
        const streamMuxer = streamMuxers.get(protocol)
        if (streamMuxer != null) {
          return streamMuxer
        }
      }
    }

    if (protocols.length) {
      throw new InvalidCryptoExchangeError('Early muxer negotiation was requested but the initiator and responder had no common muxers')
    }
  }

  private async performHFSHandshakeInitiator (
    connection: LengthPrefixedStream,
    privateKey: PrivateKey,
    log: Logger,
    remoteIdentityKey?: PublicKey,
    options?: SecureConnectionOptions
  ): Promise<HandshakeResult> {
    let result: HandshakeResult
    const streamMuxers = options?.skipStreamMuxerNegotiation === true ? [] : [...this.components.upgrader.getStreamMuxers().keys()]

    try {
      result = await performHandshakeHFSInitiator({
        connection,
        privateKey,
        remoteIdentityKey,
        log: log.newScope('xxhfs-handshake'),
        crypto: this.crypto,
        prologue: this.prologue,
        s: this.staticKey,
        kem: this.kem,
        extensions: {
          streamMuxers,
          webtransportCerthashes: [],
          ...this.extensions
        }
      }, options)
      this.metrics?.xxHandshakeSuccesses.increment()
    } catch (e: unknown) {
      this.metrics?.xxHandshakeErrors.increment()
      throw e
    }

    return result
  }

  private async performHFSHandshakeResponder (
    connection: LengthPrefixedStream,
    privateKey: PrivateKey,
    log: Logger,
    remoteIdentityKey?: PublicKey,
    options?: SecureConnectionOptions
  ): Promise<HandshakeResult> {
    let result: HandshakeResult
    const streamMuxers = options?.skipStreamMuxerNegotiation === true ? [] : [...this.components.upgrader.getStreamMuxers().keys()]

    try {
      result = await performHandshakeHFSResponder({
        connection,
        privateKey,
        remoteIdentityKey,
        log: log.newScope('xxhfs-handshake'),
        crypto: this.crypto,
        prologue: this.prologue,
        s: this.staticKey,
        kem: this.kem,
        extensions: {
          streamMuxers,
          webtransportCerthashes: [],
          ...this.extensions
        }
      }, options)
      this.metrics?.xxHandshakeSuccesses.increment()
    } catch (e: unknown) {
      this.metrics?.xxHandshakeErrors.increment()
      throw e
    }

    return result
  }
}

export function noiseHFS (init: NoiseHFSInit = {}): (components: NoiseComponents) => INoiseConnection {
  return (components: NoiseComponents) => new NoiseHFS(components, init)
}
