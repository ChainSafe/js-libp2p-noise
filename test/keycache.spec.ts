import { assert } from 'chai'
import { KeyCache } from '../src/keycache'
import { createPeerIds, createPeerIdsFromFixtures } from './fixtures/peer'
import uint8ArrayEquals from 'uint8arrays/equals'

describe('KeyCache', () => {
  let peerA

  before(async () => {
    [peerA] = await createPeerIdsFromFixtures(2)
  })

  it('should store and load same key successfully', async () => {
    try {
      const key = Buffer.from('this is id 007')
      await KeyCache.store(peerA, key)
      const result = await KeyCache.load(peerA)
      assert(result !== null && uint8ArrayEquals(result, key), 'Stored and loaded key are not the same')
    } catch (e) {
      const err = e as Error
      assert(false, `Test failed - ${err.message}`)
    }
  })

  it('should return undefined if key not found', async () => {
    try {
      const [newPeer] = await createPeerIds(1)
      const result = await KeyCache.load(newPeer)
      assert(result === null)
    } catch (e) {
      const err = e as Error
      assert(false, `Test failed - ${err.message}`)
    }
  })
})
