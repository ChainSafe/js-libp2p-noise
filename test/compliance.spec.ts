import tests from '@libp2p/interface-compliance-tests/connection-encrypter'
import { Noise } from '../src/index.js'

describe('spec compliance tests', function () {
  tests({
    async setup () {
      return new Noise()
    },
    async teardown () {}
  })
})
