import {PeerId} from "./@types/libp2p";
import {bytes, bytes32} from "./@types/basic";

/**
 * Storage for static keys of previously connected peers.
 */
class Keycache {
  private storage = new Map<bytes, bytes32>();

  public async store(peerId: PeerId, key: bytes32): Promise<void> {
    this.storage.set(peerId.id, key);
  }

  public async load(peerId: PeerId): Promise<bytes32|null> {
    return this.storage.get(peerId.id) || null;
  }

  public resetStorage(): void {
    this.storage.clear();
  }

}

const KeyCache = new Keycache();
export {
  KeyCache,
}
