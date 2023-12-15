import { unmarshalPrivateKey } from '@libp2p/crypto/keys'
import { type MultiaddrConnection, type SecuredConnection, type PeerId, CodeError, type PrivateKey } from '@libp2p/interface'
import { peerIdFromKeys } from '@libp2p/peer-id'
import { decode } from 'it-length-prefixed'
import { lpStream, type LengthPrefixedStream } from 'it-length-prefixed-stream'
import { duplexPair } from 'it-pair/duplex'
import { pipe } from 'it-pipe'
import { alloc as uint8ArrayAlloc } from 'uint8arrays/alloc'
import { NOISE_MSG_MAX_LENGTH_BYTES } from './constants.js'
import { defaultCrypto } from './crypto/index.js'
import { wrapCrypto, type ICryptoInterface } from './crypto.js'
import { uint16BEDecode, uint16BEEncode } from './encoder.js'
import { type MetricsRegistry, registerMetrics } from './metrics.js'
import { performHandshakeInitiator, performHandshakeResponder } from './performHandshake.js'
import { decryptStream, encryptStream } from './streaming.js'
import type { NoiseComponents } from './index.js'
import type { NoiseExtensions } from './proto/payload.js'
import type { HandshakeResult, ICrypto, INoiseConnection, KeyPair } from './types.js'
import type { Duplex } from 'it-stream-types'
import type { Uint8ArrayList } from 'uint8arraylist'

export interface NoiseInit {
  /**
   * x25519 private key, reuse for faster handshakes
   */
  staticNoiseKey?: Uint8Array
  extensions?: NoiseExtensions
  crypto?: ICryptoInterface
  prologueBytes?: Uint8Array
}

export class Noise implements INoiseConnection {
  public protocol = '/noise'
  public crypto: ICrypto

  private readonly prologue: Uint8Array
  private readonly staticKey: KeyPair
  private readonly extensions?: NoiseExtensions
  private readonly metrics?: MetricsRegistry
  private readonly components: NoiseComponents

  constructor (components: NoiseComponents, init: NoiseInit = {}) {
    const { staticNoiseKey, extensions, crypto, prologueBytes } = init
    const { metrics } = components

    this.components = components
    const _crypto = crypto ?? defaultCrypto
    this.crypto = wrapCrypto(_crypto)
    this.extensions = extensions
    this.metrics = metrics ? registerMetrics(metrics) : undefined

    if (staticNoiseKey) {
      // accepts x25519 private key of length 32
      this.staticKey = _crypto.generateX25519KeyPairFromSeed(staticNoiseKey)
    } else {
      this.staticKey = _crypto.generateX25519KeyPair()
    }
    this.prologue = prologueBytes ?? uint8ArrayAlloc(0)
  }

  /**
   * Encrypt outgoing data to the remote party (handshake as initiator)
   *
   * @param localPeer - PeerId of the receiving peer
   * @param connection - streaming iterable duplex that will be encrypted
   * @param remotePeer - PeerId of the remote peer. Used to validate the integrity of the remote peer.
   */
  public async secureOutbound <Stream extends Duplex<AsyncGenerator<Uint8Array | Uint8ArrayList>> = MultiaddrConnection> (localPeer: PeerId, connection: Stream, remotePeer?: PeerId): Promise<SecuredConnection<Stream, NoiseExtensions>> {
    const wrappedConnection = lpStream(
      connection,
      {
        lengthEncoder: uint16BEEncode,
        lengthDecoder: uint16BEDecode,
        maxDataLength: NOISE_MSG_MAX_LENGTH_BYTES
      }
    )

    if (!localPeer.privateKey) {
      throw new CodeError('local peerId does not contain private key', 'ERR_NO_PRIVATE_KEY')
    }
    const privateKey = await unmarshalPrivateKey(localPeer.privateKey)

    const remoteIdentityKey = remotePeer?.publicKey

    const handshake = await this.performHandshakeInitiator(
      wrappedConnection,
      privateKey,
      remoteIdentityKey
    )
    const conn = await this.createSecureConnection(wrappedConnection, handshake)

    connection.source = conn.source
    connection.sink = conn.sink

    return {
      conn: connection,
      remoteExtensions: handshake.payload.extensions,
      remotePeer: await peerIdFromKeys(handshake.payload.identityKey)
    }
  }

  /**
   * Decrypt incoming data (handshake as responder).
   *
   * @param localPeer - PeerId of the receiving peer.
   * @param connection - streaming iterable duplex that will be encrypted.
   * @param remotePeer - optional PeerId of the initiating peer, if known. This may only exist during transport upgrades.
   */
  public async secureInbound <Stream extends Duplex<AsyncGenerator<Uint8Array | Uint8ArrayList>> = MultiaddrConnection> (localPeer: PeerId, connection: Stream, remotePeer?: PeerId): Promise<SecuredConnection<Stream, NoiseExtensions>> {
    const wrappedConnection = lpStream(
      connection,
      {
        lengthEncoder: uint16BEEncode,
        lengthDecoder: uint16BEDecode,
        maxDataLength: NOISE_MSG_MAX_LENGTH_BYTES
      }
    )

    if (!localPeer.privateKey) {
      throw new CodeError('local peerId does not contain private key', 'ERR_NO_PRIVATE_KEY')
    }
    const privateKey = await unmarshalPrivateKey(localPeer.privateKey)

    const remoteIdentityKey = remotePeer?.publicKey

    const handshake = await this.performHandshakeResponder(
      wrappedConnection,
      privateKey,
      remoteIdentityKey
    )
    const conn = await this.createSecureConnection(wrappedConnection, handshake)

    connection.source = conn.source
    connection.sink = conn.sink

    return {
      conn: connection,
      remoteExtensions: handshake.payload.extensions,
      remotePeer: await peerIdFromKeys(handshake.payload.identityKey)
    }
  }

  /**
   * Perform XX handshake as initiator.
   */
  private async performHandshakeInitiator (
    connection: LengthPrefixedStream,
    // TODO: pass private key in noise constructor via Components
    privateKey: PrivateKey,
    remoteIdentityKey?: Uint8Array | Uint8ArrayList
  ): Promise<HandshakeResult> {
    let result: HandshakeResult
    try {
      result = await performHandshakeInitiator({
        connection,
        privateKey,
        remoteIdentityKey,
        log: this.components.logger.forComponent('libp2p:noise:xxhandshake'),
        crypto: this.crypto,
        prologue: this.prologue,
        s: this.staticKey,
        extensions: this.extensions
      })
      this.metrics?.xxHandshakeSuccesses.increment()
    } catch (e: unknown) {
      this.metrics?.xxHandshakeErrors.increment()
      throw e
    }

    return result
  }

  /**
   * Perform XX handshake as responder.
   */
  private async performHandshakeResponder (
    connection: LengthPrefixedStream,
    // TODO: pass private key in noise constructor via Components
    privateKey: PrivateKey,
    remoteIdentityKey?: Uint8Array | Uint8ArrayList
  ): Promise<HandshakeResult> {
    let result: HandshakeResult
    try {
      result = await performHandshakeResponder({
        connection,
        privateKey,
        remoteIdentityKey,
        log: this.components.logger.forComponent('libp2p:noise:xxhandshake'),
        crypto: this.crypto,
        prologue: this.prologue,
        s: this.staticKey,
        extensions: this.extensions
      })
      this.metrics?.xxHandshakeSuccesses.increment()
    } catch (e: unknown) {
      this.metrics?.xxHandshakeErrors.increment()
      throw e
    }

    return result
  }

  private async createSecureConnection (
    connection: LengthPrefixedStream<Duplex<AsyncGenerator<Uint8Array | Uint8ArrayList>>>,
    handshake: HandshakeResult
  ): Promise<Duplex<AsyncGenerator<Uint8Array | Uint8ArrayList>>> {
    // Create encryption box/unbox wrapper
    const [secure, user] = duplexPair<Uint8Array | Uint8ArrayList>()
    const network = connection.unwrap()

    await pipe(
      secure, // write to wrapper
      encryptStream(handshake, this.metrics), // encrypt data + prefix with message length
      network, // send to the remote peer
      (source) => decode(source, { lengthDecoder: uint16BEDecode }), // read message length prefix
      decryptStream(handshake, this.metrics), // decrypt the incoming data
      secure // pipe to the wrapper
    )

    return user
  }
}
