import {Mutex} from 'async-mutex';
import {PeerId} from "./@types/libp2p";
import {bytes, bytes32} from "./@types/basic";


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

  public async load(peerId: PeerId): Promise<bytes32> {
    const release = await this.mutex.acquire();
    let key;
    try {
      key = this.storage.get(peerId.id);
    } finally {
      release();
    }

    return key;
  }

}

const KeyCache = new Keycache();
export {
  KeyCache,
}
