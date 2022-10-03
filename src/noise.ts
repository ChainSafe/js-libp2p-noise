import type { PeerId } from '@libp2p/interface-peer-id'
import type { SecuredConnection } from '@libp2p/interface-connection-encrypter'
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
import { XXHandshake } from './handshake-xx.js'
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

  private readonly prologue: Uint8Array
  private readonly staticKeys: KeyPair
  private readonly earlyData?: bytes

  /**
   * @param {bytes} staticNoiseKey - x25519 private key, reuse for faster handshakes
   * @param {bytes} earlyData
   */
  constructor (staticNoiseKey?: bytes, earlyData?: bytes, crypto: ICryptoInterface = stablelib, prologueBytes?: Uint8Array) {
    this.earlyData = earlyData ?? new Uint8Array(0)
    this.crypto = crypto

    if (staticNoiseKey) {
      // accepts x25519 private key of length 32
      this.staticKeys = this.crypto.generateX25519KeyPairFromSeed(staticNoiseKey)
    } else {
      this.staticKeys = this.crypto.generateX25519KeyPair()
    }
    this.prologue = prologueBytes ?? new Uint8Array(0)
  }

  /**
   * Encrypt outgoing data to the remote party (handshake as initiator)
   *
   * @param {PeerId} localPeer - PeerId of the receiving peer
   * @param {Duplex<Uint8Array>} connection - streaming iterable duplex that will be encrypted
   * @param {PeerId} remotePeer - PeerId of the remote peer. Used to validate the integrity of the remote peer.
   * @returns {Promise<SecuredConnection>}
   */
  public async secureOutbound (localPeer: PeerId, connection: Duplex<Uint8Array>, remotePeer?: PeerId): Promise<SecuredConnection> {
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
   * @param {Duplex<Uint8Array>} connection - streaming iterable duplex that will be encryption.
   * @param {PeerId} remotePeer - optional PeerId of the initiating peer, if known. This may only exist during transport upgrades.
   * @returns {Promise<SecuredConnection>}
   */
  public async secureInbound (localPeer: PeerId, connection: Duplex<Uint8Array>, remotePeer?: PeerId): Promise<SecuredConnection> {
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

    // run XX handshake
    return await this.performXXHandshake(params, payload)
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
    } catch (e: unknown) {
      if (e instanceof Error) {
        e.message = `Error occurred during XX handshake: ${e.message}`
        throw e
      }
    }

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
