import tests from '@libp2p/interface-connection-encrypter-compliance-tests'
import { Noise } from '../src/index.js'

describe('spec compliance tests', function () {
  tests({
    async setup () {
      return new Noise()
    },
    async teardown () {}
  })
})
