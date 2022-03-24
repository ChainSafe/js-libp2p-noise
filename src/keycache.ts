import type { PeerId } from '@libp2p/interfaces/peer-id'
import { PeerMap } from '@libp2p/peer-collections'
import type { bytes32 } from './@types/basic.js'

/**
 * Storage for static keys of previously connected peers.
 */
class Keycache {
  private readonly storage = new PeerMap<bytes32>()

  public store (peerId: PeerId, key: bytes32): void {
    this.storage.set(peerId, key)
  }

  public load (peerId?: PeerId): bytes32 | null {
    if (!peerId) {
      return null
    }
    return this.storage.get(peerId) ?? null
  }

  public resetStorage (): void {
    this.storage.clear()
  }
}

const KeyCache = new Keycache()
export {
  KeyCache
}
