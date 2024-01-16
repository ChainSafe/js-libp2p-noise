import { unmarshalPublicKey } from '@libp2p/crypto/keys'
import { type Uint8ArrayList } from 'uint8arraylist'
import { equals, toString } from 'uint8arrays'
import { concat as uint8ArrayConcat } from 'uint8arrays/concat'
import { fromString as uint8ArrayFromString } from 'uint8arrays/from-string'
import { UnexpectedPeerError } from './errors.js'
import { type NoiseExtensions, NoiseHandshakePayload } from './proto/payload.js'
import type { PrivateKey } from '@libp2p/interface'

export async function createHandshakePayload (
  privateKey: PrivateKey,
  staticPublicKey: Uint8Array | Uint8ArrayList,
  extensions?: NoiseExtensions
): Promise<Uint8Array | Uint8ArrayList> {
  const identitySig = await privateKey.sign(getSignaturePayload(staticPublicKey))

  return NoiseHandshakePayload.encode({
    identityKey: privateKey.public.bytes,
    identitySig,
    extensions
  })
}

export async function decodeHandshakePayload (
  payloadBytes: Uint8Array | Uint8ArrayList,
  remoteStaticKey?: Uint8Array | Uint8ArrayList,
  remoteIdentityKey?: Uint8Array | Uint8ArrayList
): Promise<NoiseHandshakePayload> {
  try {
    const payload = NoiseHandshakePayload.decode(payloadBytes)
    if (remoteIdentityKey) {
      const remoteIdentityKeyBytes = remoteIdentityKey.subarray()
      if (!equals(remoteIdentityKeyBytes, payload.identityKey)) {
        throw new Error(`Payload identity key ${toString(payload.identityKey, 'hex')} does not match expected remote identity key ${toString(remoteIdentityKeyBytes, 'hex')}`)
      }
    }

    if (!remoteStaticKey) {
      throw new Error('Remote static does not exist')
    }

    const signaturePayload = getSignaturePayload(remoteStaticKey)
    const publicKey = unmarshalPublicKey(payload.identityKey)

    if (!(await publicKey.verify(signaturePayload, payload.identitySig))) {
      throw new Error('Invalid payload signature')
    }

    return payload
  } catch (e) {
    throw new UnexpectedPeerError((e as Error).message)
  }
}

export function getSignaturePayload (publicKey: Uint8Array | Uint8ArrayList): Uint8Array | Uint8ArrayList {
  const prefix = uint8ArrayFromString('noise-libp2p-static-key:')

  if (publicKey instanceof Uint8Array) {
    return uint8ArrayConcat([prefix, publicKey], prefix.length + publicKey.length)
  }

  publicKey.prepend(prefix)

  return publicKey
}
