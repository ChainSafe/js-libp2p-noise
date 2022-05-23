import type { PeerId } from '@libp2p/interfaces/peer-id'
import type { SecuredConnection } from '@libp2p/interfaces/connection-encrypter'
import { pbStream, ProtobufStream } from 'it-pb-stream'
import { duplexPair } from 'it-pair/duplex'
import { pipe } from 'it-pipe'
import { encode, decode } from 'it-length-prefixed'
import type { Duplex } from 'it-stream-types'
import type { bytes } from './@types/basic.js'
import type { IHandshake } from './@types/handshake-interface.js'
import type { INoiseConnection, KeyPair } from './@types/libp2p.js'
import { NOISE_MSG_MAX_LENGTH_BYTES } from './constants.js'
import type { ICryptoInterface } from './crypto.js'
import { stablelib } from './crypto/stablelib.js'
import { decryptStream, encryptStream } from './crypto/streaming.js'
import { uint16BEDecode, uint16BEEncode } from './encoder.js'
import type { FailedIKError } from './errors.js'
import { IKHandshake } from './handshake-ik.js'
import { XXHandshake } from './handshake-xx.js'
import { XXFallbackHandshake } from './handshake-xx-fallback.js'
import { KeyCache } from './keycache.js'
import { logger } from './logger.js'
import { getPayload } from './utils.js'

interface HandshakeParams {
  connection: ProtobufStream
  isInitiator: boolean
  localPeer: PeerId
  remotePeer?: PeerId
}

export class Noise implements INoiseConnection {
  public protocol = '/noise'
  public crypto: ICryptoInterface

  private readonly prologue = new Uint8Array(0)
  private readonly staticKeys: KeyPair
  private readonly earlyData?: bytes
  private readonly useNoisePipes: boolean

  /**
   * @param {bytes} staticNoiseKey - x25519 private key, reuse for faster handshakes
   * @param {bytes} earlyData
   */
  constructor (staticNoiseKey?: bytes, earlyData?: bytes, crypto: ICryptoInterface = stablelib) {
    this.earlyData = earlyData ?? new Uint8Array(0)
    // disabled until properly specked
    this.useNoisePipes = false
    this.crypto = crypto

    if (staticNoiseKey) {
      // accepts x25519 private key of length 32
      this.staticKeys = this.crypto.generateX25519KeyPairFromSeed(staticNoiseKey)
    } else {
      this.staticKeys = this.crypto.generateX25519KeyPair()
    }
  }

  /**
   * Encrypt outgoing data to the remote party (handshake as initiator)
   *
   * @param {PeerId} localPeer - PeerId of the receiving peer
   * @param {any} connection - streaming iterable duplex that will be encrypted
   * @param {PeerId} remotePeer - PeerId of the remote peer. Used to validate the integrity of the remote peer.
   * @returns {Promise<SecuredConnection>}
   */
  public async secureOutbound (localPeer: PeerId, connection: any, remotePeer: PeerId): Promise<SecuredConnection> {
    const wrappedConnection = pbStream(
      connection,
      {
        lengthEncoder: uint16BEEncode,
        lengthDecoder: uint16BEDecode,
        maxDataLength: NOISE_MSG_MAX_LENGTH_BYTES
      }
    )
    const handshake = await this.performHandshake({
      connection: wrappedConnection,
      isInitiator: true,
      localPeer,
      remotePeer
    })
    const conn = await this.createSecureConnection(wrappedConnection, handshake)

    return {
      conn,
      remoteEarlyData: handshake.remoteEarlyData,
      remotePeer: handshake.remotePeer
    }
  }

  /**
   * Decrypt incoming data (handshake as responder).
   *
   * @param {PeerId} localPeer - PeerId of the receiving peer.
   * @param {any} connection - streaming iterable duplex that will be encryption.
   * @param {PeerId} remotePeer - optional PeerId of the initiating peer, if known. This may only exist during transport upgrades.
   * @returns {Promise<SecuredConnection>}
   */
  public async secureInbound (localPeer: PeerId, connection: any, remotePeer?: PeerId): Promise<SecuredConnection> {
    const wrappedConnection = pbStream(
      connection,
      {
        lengthEncoder: uint16BEEncode,
        lengthDecoder: uint16BEDecode,
        maxDataLength: NOISE_MSG_MAX_LENGTH_BYTES
      }
    )
    const handshake = await this.performHandshake({
      connection: wrappedConnection,
      isInitiator: false,
      localPeer,
      remotePeer
    })
    const conn = await this.createSecureConnection(wrappedConnection, handshake)

    return {
      conn,
      remoteEarlyData: handshake.remoteEarlyData,
      remotePeer: handshake.remotePeer
    }
  }

  /**
   * If Noise pipes supported, tries IK handshake first with XX as fallback if it fails.
   * If noise pipes disabled or remote peer static key is unknown, use XX.
   *
   * @param {HandshakeParams} params
   */
  private async performHandshake (params: HandshakeParams): Promise<IHandshake> {
    const payload = await getPayload(params.localPeer, this.staticKeys.publicKey, this.earlyData)
    let tryIK = this.useNoisePipes
    if (params.isInitiator && KeyCache.load(params.remotePeer) === null) {
      // if we are initiator and remote static key is unknown, don't try IK
      tryIK = false
    }
    // Try IK if acting as responder or initiator that has remote's static key.
    if (tryIK) {
      // Try IK first
      const { remotePeer, connection, isInitiator } = params
      const ikHandshake = new IKHandshake(
        isInitiator,
        payload,
        this.prologue,
        this.crypto,
        this.staticKeys,
        connection,
        // safe to cast as we did checks
        KeyCache.load(params.remotePeer) ?? new Uint8Array(32),
        remotePeer as PeerId
      )

      try {
        return await this.performIKHandshake(ikHandshake)
      } catch (e) {
        const err = e as FailedIKError

        // IK failed, go to XX fallback
        let ephemeralKeys
        if (params.isInitiator) {
          ephemeralKeys = ikHandshake.getLocalEphemeralKeys()
        }
        return await this.performXXFallbackHandshake(params, payload, err.initialMsg as Uint8Array, ephemeralKeys)
      }
    } else {
      // run XX handshake
      return await this.performXXHandshake(params, payload)
    }
  }

  private async performXXFallbackHandshake (
    params: HandshakeParams,
    payload: bytes,
    initialMsg: bytes,
    ephemeralKeys?: KeyPair
  ): Promise<XXFallbackHandshake> {
    const { isInitiator, remotePeer, connection } = params
    const handshake =
      new XXFallbackHandshake(
        isInitiator,
        payload,
        this.prologue,
        this.crypto,
        this.staticKeys,
        connection,
        initialMsg,
        remotePeer,
        ephemeralKeys
      )

    try {
      await handshake.propose()
      await handshake.exchange()
      await handshake.finish()
    } catch (e) {
      const err = e as Error
      err.message = `Error occurred during XX Fallback handshake: ${err.message}`
      logger(err)
      throw err
    }

    return handshake
  }

  private async performXXHandshake (
    params: HandshakeParams,
    payload: bytes
  ): Promise<XXHandshake> {
    const { isInitiator, remotePeer, connection } = params
    const handshake = new XXHandshake(
      isInitiator,
      payload,
      this.prologue,
      this.crypto,
      this.staticKeys,
      connection,
      remotePeer
    )

    try {
      await handshake.propose()
      await handshake.exchange()
      await handshake.finish()

      if (this.useNoisePipes && handshake.remotePeer) {
        KeyCache.store(handshake.remotePeer, handshake.getRemoteStaticKey())
      }
    } catch (e: unknown) {
      if (e instanceof Error) {
        e.message = `Error occurred during XX handshake: ${e.message}`
        throw e
      }
    }

    return handshake
  }

  private async performIKHandshake (
    handshake: IKHandshake
  ): Promise<IKHandshake> {
    await handshake.stage0()
    await handshake.stage1()

    return handshake
  }

  private async createSecureConnection (
    connection: ProtobufStream,
    handshake: IHandshake
  ): Promise<Duplex<Uint8Array>> {
    // Create encryption box/unbox wrapper
    const [secure, user] = duplexPair<Uint8Array>()
    const network = connection.unwrap()

    await pipe(
      secure, // write to wrapper
      encryptStream(handshake), // data is encrypted
      encode({ lengthEncoder: uint16BEEncode }), // prefix with message length
      network, // send to the remote peer
      decode({ lengthDecoder: uint16BEDecode }), // read message length prefix
      decryptStream(handshake), // decrypt the incoming data
      secure // pipe to the wrapper
    )

    return user
  }
}
