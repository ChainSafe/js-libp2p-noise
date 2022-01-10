import { expect } from 'chai'
import { exec } from 'child_process'
import { rm, writeFile } from 'fs/promises'
import { dirname } from 'path'
import PeerId from 'peer-id'
import { createPeer, peerIds } from '../util/createPeer'
import type Libp2p from 'libp2p'

// Test full js-libp2p stack against go-libp2p
describe('go-libp2p integration test', () => {
  let self: Libp2p
  const goController = new AbortController()
  const goIdFile = 'goId'

  after(async () => {
    // stop the go-libp2p daemon
    goController.abort()
    await rm(goIdFile, { force: true })

    // stop the js-libp2p node
    await self.stop()
  })

  it('establish a connection with a go-libp2p node', async function () {
    // start the go-libp2p daemon
    const goAddr = '/ip4/0.0.0.0/tcp/9876/ws'
    const goId = await PeerId.createFromJSON(peerIds[1])
    await writeFile(goIdFile, goId.marshalPrivKey())
    exec(`${dirname(require.resolve('go-libp2p-dep'))}/../go-libp2p/p2pd -hostAddrs ${goAddr} --id ${goIdFile}`, { signal: goController.signal }, (error, stdout, stderr) => {
      if (error) {
        console.log('error', error, stdout, stderr)
        return
      }
      console.log('stdout', stdout)
      console.log('stderr', stderr)
    })

    // start the js-libp2p node
    self = await createPeer()

    // attempt to dial the go-libp2p daemon
    try {
      await self.dial(`${goAddr}/p2p/${goId.toB58String()}`)
      // success if no error
    } catch (e) {
      // failure if there's a dial error
      expect.fail(e as string)
    }
  })
})
