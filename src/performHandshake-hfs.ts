/**
 * XXhfs handshake orchestration — initiator and responder sides.
 *
 * Mirrors performHandshake.ts but uses XXhfsHandshakeState (which adds the
 * e1 / ekem1 KEM tokens) and NOISE_HFS_PROTOCOL_NAME. Every other step —
 * payload creation, signature verification, cipher-state split — is identical
 * to the classical XX handshake, which is intentional: only the key-exchange
 * path changes; the identity/authentication layer is preserved.
 */

import {
  logLocalStaticKeys,
  logLocalEphemeralKeys,
  logRemoteEphemeralKey,
  logRemoteStaticKey,
  logCipherState
} from './logger.js'
import { ZEROLEN } from './protocol.js'
import { XXhfsHandshakeState, NOISE_HFS_PROTOCOL_NAME } from './protocol-pqc.js'
import { createHandshakePayload, decodeHandshakePayload } from './utils.js'
import type { IKem } from './kem.js'
import type { HandshakeResult, HandshakeParams } from './types.js'
import type { AbortOptions } from '@libp2p/interface'

export interface HfsHandshakeParams extends HandshakeParams {
  /** KEM backend — provides generateKemKeyPair / encapsulate / decapsulate */
  kem: IKem
}

/**
 * Perform XXhfs handshake as the initiator (outbound connection).
 *
 * Message flow:
 *   A → responder   e, e1              (DH eph + KEM pubkey)
 *   B ← responder   e, ee, ekem1, s, es
 *   C → responder   s, se
 *
 * Cipher assignment after split():
 *   encrypt → cs1 (initiator→responder direction)
 *   decrypt → cs2 (responder→initiator direction)
 */
export async function performHandshakeHFSInitiator (init: HfsHandshakeParams, options?: AbortOptions): Promise<HandshakeResult> {
  const { log, connection, crypto, privateKey, prologue, s, remoteIdentityKey, extensions, kem } = init

  const payload = await createHandshakePayload(privateKey, s.publicKey, extensions)
  const xx = new XXhfsHandshakeState({
    crypto,
    kem,
    protocolName: NOISE_HFS_PROTOCOL_NAME,
    initiator: true,
    prologue,
    s
  })

  logLocalStaticKeys(xx.s, log)
  log.trace('HFS Stage 0 - Initiator sending first message (e, e1).')
  await connection.write(xx.writeMessageA(ZEROLEN), options)
  log.trace('HFS Stage 0 - Initiator finished sending first message.')
  logLocalEphemeralKeys(xx.e, log)

  log.trace('HFS Stage 1 - Initiator waiting for responder message (e, ee, ekem1, s, es)...')
  const plaintext = xx.readMessageB(await connection.read(options))
  log.trace('HFS Stage 1 - Initiator received the message.')
  logRemoteEphemeralKey(xx.re, log)
  logRemoteStaticKey(xx.rs, log)

  log.trace("Initiator going to check remote's signature...")
  const receivedPayload = await decodeHandshakePayload(plaintext, xx.rs, remoteIdentityKey)
  log.trace('All good with the signature!')

  log.trace('HFS Stage 2 - Initiator sending third handshake message (s, se).')
  await connection.write(xx.writeMessageC(payload), options)
  log.trace('HFS Stage 2 - Initiator sent message with signed payload.')

  const [cs1, cs2] = xx.ss.split()
  logCipherState(cs1, cs2, log)

  return {
    payload: receivedPayload,
    encrypt: (plaintext) => cs1.encryptWithAd(ZEROLEN, plaintext),
    decrypt: (ciphertext, dst) => cs2.decryptWithAd(ZEROLEN, ciphertext, dst)
  }
}

/**
 * Perform XXhfs handshake as the responder (inbound connection).
 *
 * Message flow:
 *   A ← initiator   e, e1
 *   B → initiator   e, ee, ekem1, s, es
 *   C ← initiator   s, se
 *
 * Cipher assignment after split():
 *   encrypt → cs2 (responder→initiator direction)
 *   decrypt → cs1 (initiator→responder direction)
 */
export async function performHandshakeHFSResponder (init: HfsHandshakeParams, options?: AbortOptions): Promise<HandshakeResult> {
  const { log, connection, crypto, privateKey, prologue, s, remoteIdentityKey, extensions, kem } = init

  const payload = await createHandshakePayload(privateKey, s.publicKey, extensions)
  const xx = new XXhfsHandshakeState({
    crypto,
    kem,
    protocolName: NOISE_HFS_PROTOCOL_NAME,
    initiator: false,
    prologue,
    s
  })

  logLocalStaticKeys(xx.s, log)
  log.trace('HFS Stage 0 - Responder waiting for first message (e, e1).')
  xx.readMessageA(await connection.read(options))
  log.trace('HFS Stage 0 - Responder received first message.')
  logRemoteEphemeralKey(xx.re, log)

  log.trace('HFS Stage 1 - Responder sending message (e, ee, ekem1, s, es).')
  await connection.write(xx.writeMessageB(payload), options)
  log.trace('HFS Stage 1 - Responder sent the second handshake message with signed payload.')
  logLocalEphemeralKeys(xx.e, log)

  log.trace('HFS Stage 2 - Responder waiting for third handshake message (s, se)...')
  const plaintext = xx.readMessageC(await connection.read(options))
  log.trace('HFS Stage 2 - Responder received the message, finished handshake.')
  const receivedPayload = await decodeHandshakePayload(plaintext, xx.rs, remoteIdentityKey)

  const [cs1, cs2] = xx.ss.split()
  logCipherState(cs1, cs2, log)

  return {
    payload: receivedPayload,
    encrypt: (plaintext) => cs2.encryptWithAd(ZEROLEN, plaintext),
    decrypt: (ciphertext, dst) => cs1.decryptWithAd(ZEROLEN, ciphertext, dst)
  }
}
