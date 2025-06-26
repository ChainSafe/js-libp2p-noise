import { publicKeyFromProtobuf, publicKeyToProtobuf } from '@libp2p/crypto/keys'
import { UnexpectedPeerError } from '@libp2p/interface'
import { concat as uint8ArrayConcat } from 'uint8arrays/concat'
import { fromString as uint8ArrayFromString } from 'uint8arrays/from-string'
import { NoiseHandshakePayload } from './proto/payload.js'
import type { NoiseExtensions } from './proto/payload.js'
import type { PrivateKey, PublicKey } from '@libp2p/interface'
import type { Uint8ArrayList } from 'uint8arraylist'

export async function createHandshakePayload (
  privateKey: PrivateKey,
  staticPublicKey: Uint8Array | Uint8ArrayList,
  extensions?: NoiseExtensions
): Promise<Uint8Array | Uint8ArrayList> {
  const identitySig = await privateKey.sign(getSignaturePayload(staticPublicKey))

  return NoiseHandshakePayload.encode({
    identityKey: publicKeyToProtobuf(privateKey.publicKey),
    identitySig,
    extensions
  })
}

export async function decodeHandshakePayload (
  payloadBytes: Uint8Array | Uint8ArrayList,
  remoteStaticKey?: Uint8Array | Uint8ArrayList,
  remoteIdentityKey?: PublicKey
): Promise<NoiseHandshakePayload> {
  try {
    const payload = NoiseHandshakePayload.decode(payloadBytes)
    const publicKey = publicKeyFromProtobuf(payload.identityKey)

    if (remoteIdentityKey?.equals(publicKey) === false) {
      throw new Error(`Payload identity key ${publicKey} does not match expected remote identity key ${remoteIdentityKey}`)
    }

    if (!remoteStaticKey) {
      throw new Error('Remote static does not exist')
    }

    const signaturePayload = getSignaturePayload(remoteStaticKey)

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
