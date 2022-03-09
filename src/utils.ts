import { HKDF } from '@stablelib/hkdf'
import { SHA256 } from '@stablelib/sha256'
import * as x25519 from '@stablelib/x25519'
import PeerId from 'peer-id'
import { KeyPair } from './@types/libp2p'
import { bytes, bytes32 } from './@types/basic'
import { Hkdf, INoisePayload } from './@types/handshake'
import { pb } from './proto/payload'
import { equals as uint8ArrayEquals } from 'uint8arrays/equals'
import { fromString as uint8ArrayFromString } from 'uint8arrays/from-string'
import { concat as uint8ArrayConcat } from 'uint8arrays/concat'

const NoiseHandshakePayloadProto = pb.NoiseHandshakePayload

export function generateKeypair (): KeyPair {
  const keypair = x25519.generateKeyPair()

  return {
    publicKey: keypair.publicKey,
    privateKey: keypair.secretKey
  }
}

export async function getPayload (
  localPeer: PeerId,
  staticPublicKey: bytes,
  earlyData?: bytes
): Promise<bytes> {
  const signedPayload = await signPayload(localPeer, getHandshakePayload(staticPublicKey))
  const earlyDataPayload = earlyData ?? new Uint8Array(0)

  return createHandshakePayload(
    localPeer.marshalPubKey(),
    signedPayload,
    earlyDataPayload
  )
}

export function createHandshakePayload (
  libp2pPublicKey: Uint8Array,
  signedPayload: Uint8Array,
  earlyData?: Uint8Array
): bytes {
  const payloadInit = NoiseHandshakePayloadProto.create({
    identityKey: libp2pPublicKey,
    identitySig: signedPayload,
    data: earlyData ?? null
  })

  return NoiseHandshakePayloadProto.encode(payloadInit).finish()
}

export async function signPayload (peerId: PeerId, payload: bytes): Promise<bytes> {
  return await peerId.privKey.sign(payload)
}

export async function getPeerIdFromPayload (payload: pb.INoiseHandshakePayload): Promise<PeerId> {
  return await PeerId.createFromPubKey(payload.identityKey as Uint8Array)
}

export function decodePayload (payload: bytes|Uint8Array): pb.INoiseHandshakePayload {
  return NoiseHandshakePayloadProto.toObject(
    NoiseHandshakePayloadProto.decode(payload)
  ) as INoisePayload
}

export function getHandshakePayload (publicKey: bytes): bytes {
  const prefix = uint8ArrayFromString('noise-libp2p-static-key:')
  return uint8ArrayConcat([prefix, publicKey], prefix.length + publicKey.length)
}

async function isValidPeerId (peerId: Uint8Array, publicKeyProtobuf: bytes): Promise<boolean> {
  const generatedPeerId = await PeerId.createFromPubKey(publicKeyProtobuf)
  return uint8ArrayEquals(generatedPeerId.id, peerId)
}

/**
 * Verifies signed payload, throws on any irregularities.
 *
 * @param {bytes} noiseStaticKey - owner's noise static key
 * @param {bytes} payload - decoded payload
 * @param {PeerId} remotePeer - owner's libp2p peer ID
 * @returns {Promise<PeerId>} - peer ID of payload owner
 */
export async function verifySignedPayload (
  noiseStaticKey: bytes,
  payload: pb.INoiseHandshakePayload,
  remotePeer: PeerId
): Promise<PeerId> {
  const identityKey = payload.identityKey as Uint8Array
  if (!(await isValidPeerId(remotePeer.id, identityKey))) {
    throw new Error("Peer ID doesn't match libp2p public key.")
  }
  const generatedPayload = getHandshakePayload(noiseStaticKey)
  // Unmarshaling from PublicKey protobuf
  const peerId = await PeerId.createFromPubKey(identityKey)
  if (!payload.identitySig || !(await peerId.pubKey.verify(generatedPayload, payload.identitySig))) {
    throw new Error("Static key doesn't match to peer that signed payload!")
  }
  return peerId
}

export function getHkdf (ck: bytes32, ikm: Uint8Array): Hkdf {
  const hkdf = new HKDF(SHA256, ikm, ck)
  const okmU8Array = hkdf.expand(96)
  const okm = okmU8Array

  const k1 = okm.slice(0, 32)
  const k2 = okm.slice(32, 64)
  const k3 = okm.slice(64, 96)

  return [k1, k2, k3]
}

export function isValidPublicKey (pk: bytes): boolean {
  if (!(pk instanceof Uint8Array)) {
    return false
  }

  if (pk.length !== 32) {
    return false
  }

  return true
}
