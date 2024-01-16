import { Buffer } from 'buffer'
import { unmarshalPrivateKey } from '@libp2p/crypto/keys'
import { defaultLogger } from '@libp2p/logger'
import { assert, expect } from 'aegir/chai'
import { lpStream } from 'it-length-prefixed-stream'
import { duplexPair } from 'it-pair/duplex'
import { toString as uint8ArrayToString } from 'uint8arrays'
import { equals as uint8ArrayEquals } from 'uint8arrays/equals'
import { defaultCrypto } from '../src/crypto/index.js'
import { wrapCrypto } from '../src/crypto.js'
import { performHandshakeInitiator, performHandshakeResponder } from '../src/performHandshake.js'
import { createPeerIdsFromFixtures } from './fixtures/peer.js'
import type { PrivateKey } from '@libp2p/interface'
import type { PeerId } from '@libp2p/interface/peer-id'

describe('performHandshake', () => {
  let peerA: PeerId, peerB: PeerId, fakePeer: PeerId
  let privateKeyA: PrivateKey, privateKeyB: PrivateKey

  before(async () => {
    [peerA, peerB, fakePeer] = await createPeerIdsFromFixtures(3)
    if (!peerA.privateKey || !peerB.privateKey || !fakePeer.privateKey) throw new Error('unreachable')
    privateKeyA = await unmarshalPrivateKey(peerA.privateKey)
    privateKeyB = await unmarshalPrivateKey(peerB.privateKey)
  })

  it('should propose, exchange and finish handshake', async () => {
    const duplex = duplexPair<Uint8Array>()
    const connectionInitiator = lpStream(duplex[0])
    const connectionResponder = lpStream(duplex[1])

    const prologue = Buffer.alloc(0)
    const staticKeysInitiator = defaultCrypto.generateX25519KeyPair()
    const staticKeysResponder = defaultCrypto.generateX25519KeyPair()

    const [initiator, responder] = await Promise.all([
      performHandshakeInitiator({
        log: defaultLogger().forComponent('test'),
        connection: connectionInitiator,
        crypto: wrapCrypto(defaultCrypto),
        privateKey: privateKeyA,
        prologue,
        remoteIdentityKey: peerB.publicKey,
        s: staticKeysInitiator
      }),
      performHandshakeResponder({
        log: defaultLogger().forComponent('test'),
        connection: connectionResponder,
        crypto: wrapCrypto(defaultCrypto),
        privateKey: privateKeyB,
        prologue,
        remoteIdentityKey: peerA.publicKey,
        s: staticKeysResponder
      })
    ])

    // Test encryption and decryption
    const encrypted = initiator.encrypt(Buffer.from('encryptthis'))
    const decrypted = responder.decrypt(encrypted)
    assert(uint8ArrayEquals(decrypted.subarray(), Buffer.from('encryptthis')))
  })

  it('Initiator should fail to exchange handshake if given wrong public key in payload', async () => {
    try {
      const duplex = duplexPair<Uint8Array>()
      const connectionInitiator = lpStream(duplex[0])
      const connectionResponder = lpStream(duplex[1])

      const prologue = Buffer.alloc(0)
      const staticKeysInitiator = defaultCrypto.generateX25519KeyPair()
      const staticKeysResponder = defaultCrypto.generateX25519KeyPair()

      await Promise.all([
        performHandshakeInitiator({
          log: defaultLogger().forComponent('test'),
          connection: connectionInitiator,
          crypto: wrapCrypto(defaultCrypto),
          privateKey: privateKeyA,
          prologue,
          remoteIdentityKey: fakePeer.publicKey, // <----- look here
          s: staticKeysInitiator
        }),
        performHandshakeResponder({
          log: defaultLogger().forComponent('test'),
          connection: connectionResponder,
          crypto: wrapCrypto(defaultCrypto),
          privateKey: privateKeyB,
          prologue,
          remoteIdentityKey: peerA.publicKey,
          s: staticKeysResponder
        })
      ])

      assert(false, 'Should throw exception')
    } catch (e) {
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
      expect((e as Error).message).equals(`Payload identity key ${uint8ArrayToString(peerB.publicKey!, 'hex')} does not match expected remote identity key ${uint8ArrayToString(fakePeer.publicKey!, 'hex')}`)
    }
  })

  it('Responder should fail to exchange handshake if given wrong public key in payload', async () => {
    try {
      const duplex = duplexPair<Uint8Array>()
      const connectionInitiator = lpStream(duplex[0])
      const connectionResponder = lpStream(duplex[1])

      const prologue = Buffer.alloc(0)
      const staticKeysInitiator = defaultCrypto.generateX25519KeyPair()
      const staticKeysResponder = defaultCrypto.generateX25519KeyPair()

      await Promise.all([
        performHandshakeInitiator({
          log: defaultLogger().forComponent('test'),
          connection: connectionInitiator,
          crypto: wrapCrypto(defaultCrypto),
          privateKey: privateKeyA,
          prologue,
          remoteIdentityKey: peerB.publicKey,
          s: staticKeysInitiator
        }),
        performHandshakeResponder({
          log: defaultLogger().forComponent('test'),
          connection: connectionResponder,
          crypto: wrapCrypto(defaultCrypto),
          privateKey: privateKeyB,
          prologue,
          remoteIdentityKey: fakePeer.publicKey,
          s: staticKeysResponder
        })
      ])

      assert(false, 'Should throw exception')
    } catch (e) {
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
      expect((e as Error).message).equals(`Payload identity key ${uint8ArrayToString(peerA.publicKey!, 'hex')} does not match expected remote identity key ${uint8ArrayToString(fakePeer.publicKey!, 'hex')}`)
    }
  })
})
