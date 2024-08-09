import tests from '@libp2p/interface-compliance-tests/connection-encryption'
import { defaultLogger } from '@libp2p/logger'
import { createEd25519PeerId } from '@libp2p/peer-id-factory'
import { Noise } from '../src/noise.js'
import type { PeerId } from '@libp2p/interface'

describe('spec compliance tests', function () {
  tests({
    async setup (opts: { peerId?: PeerId }) {
      return new Noise({
        peerId: opts?.peerId ?? await createEd25519PeerId(),
        logger: defaultLogger()
      })
    },
    async teardown () {}
  })
})
