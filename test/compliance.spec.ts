import { generateKeyPair } from '@libp2p/crypto/keys'
import tests from '@libp2p/interface-compliance-tests/connection-encryption'
import { defaultLogger } from '@libp2p/logger'
import { peerIdFromPrivateKey } from '@libp2p/peer-id'
import { Noise } from '../src/noise.js'

describe('spec compliance tests', function () {
  tests({
    async setup (opts) {
      const privateKey = opts?.privateKey ?? await generateKeyPair('Ed25519')
      const peerId = peerIdFromPrivateKey(privateKey)

      return new Noise({
        privateKey,
        peerId,
        logger: defaultLogger()
      })
    },
    async teardown () {}
  })
})
