import debug from 'debug'
import { DUMP_SESSION_KEYS } from './constants'
import { KeyPair } from './@types/libp2p'
import { NoiseSession } from './@types/handshake'
import { toString as uint8ArrayToString } from 'uint8arrays/to-string'

export const logger = debug('libp2p:noise')

let keyLogger
if (DUMP_SESSION_KEYS) {
  keyLogger = logger
} else {
  keyLogger = () => { /* do nothing */ }
}

export function logLocalStaticKeys (s: KeyPair): void {
  keyLogger(`LOCAL_STATIC_PUBLIC_KEY ${uint8ArrayToString(s.publicKey, 'hex')}`)
  keyLogger(`LOCAL_STATIC_PRIVATE_KEY ${uint8ArrayToString(s.privateKey, 'hex')}`)
}

export function logLocalEphemeralKeys (e: KeyPair|undefined): void {
  if (e) {
    keyLogger(`LOCAL_PUBLIC_EPHEMERAL_KEY ${uint8ArrayToString(e.publicKey, 'hex')}`)
    keyLogger(`LOCAL_PRIVATE_EPHEMERAL_KEY ${uint8ArrayToString(e.privateKey, 'hex')}`)
  } else {
    keyLogger('Missing local ephemeral keys.')
  }
}

export function logRemoteStaticKey (rs: Uint8Array): void {
  keyLogger(`REMOTE_STATIC_PUBLIC_KEY ${uint8ArrayToString(rs, 'hex')}`)
}

export function logRemoteEphemeralKey (re: Uint8Array): void {
  keyLogger(`REMOTE_EPHEMERAL_PUBLIC_KEY ${uint8ArrayToString(re, 'hex')}`)
}

export function logCipherState (session: NoiseSession): void {
  if (session.cs1 && session.cs2) {
    keyLogger(`CIPHER_STATE_1 ${session.cs1.n} ${uint8ArrayToString(session.cs1.k, 'hex')}`)
    keyLogger(`CIPHER_STATE_2 ${session.cs2.n} ${uint8ArrayToString(session.cs2.k, 'hex')}`)
  } else {
    keyLogger('Missing cipher state.')
  }
}
