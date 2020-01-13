import {Mutex} from 'async-mutex';
import {PeerId} from "./@types/libp2p";
import {bytes, bytes32} from "./@types/basic";

/**
 * Storage for static keys of previously connected peers.
 */
class Keycache {
  private mutex: Mutex;
  private storage = new Map<bytes, bytes32>();

  constructor() {
    this.mutex = new Mutex();
  }

  public async store(peerId: PeerId, key: bytes32): Promise<void> {
    const release = await this.mutex.acquire();
    try {
      this.storage.set(peerId.id, key);
    } finally {
      release();
    }
  }

  public async load(peerId: PeerId): Promise<bytes32|null> {
    const release = await this.mutex.acquire();
    let key;
    try {
      key = this.storage.get(peerId.id) || null;
    } finally {
      release();
    }

    return key;
  }

  public resetStorage(): void {
    this.storage.clear();
  }

}

const KeyCache = new Keycache();
export {
  KeyCache,
}
