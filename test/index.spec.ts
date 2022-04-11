import { expect } from 'aegir/chai'
import { Noise } from '../src/index.js'

describe('Index', () => {
  it('should expose class with tag and required functions', () => {
    const noise = new Noise()
    expect(noise.protocol).to.equal('/noise')
    expect(typeof (noise.secureInbound)).to.equal('function')
    expect(typeof (noise.secureOutbound)).to.equal('function')
  })
})
