import tests from '@libp2p/interface-compliance-tests/connection-encryption'
import { defaultLogger } from '@libp2p/logger'
import { Noise } from '../src/noise.js'

describe('spec compliance tests', function () {
  tests({
    async setup () {
      return new Noise({ logger: defaultLogger() })
    },
    async teardown () {}
  })
})
