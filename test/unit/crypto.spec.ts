import { assert } from 'aegir/chai'
import { stablelib } from "../../src/crypto/stablelib.js"
import { sodiumNative } from "../../src/crypto/sodium-native.js"
import { equals as uint8ArrayEquals } from 'uint8arrays/equals'
import type { ICryptoInterface } from '../../src/crypto.js'

describe('Crypto implementation', () => {
  const testCases: {id: string; encrypt: ICryptoInterface; decrypt: ICryptoInterface}[] = [
    {id: 'sodium-native should be able to decrypt from data encrypted by stablelib',  decrypt: sodiumNative, encrypt: stablelib},
    {id: 'sodium-native should be able to decrypt from data encrypted by sodium-native',  decrypt: sodiumNative, encrypt: sodiumNative},
    {id: 'stablelib should be able to decrypt from data encrypted by sodium-native',  decrypt: stablelib, encrypt: sodiumNative},
    {id: 'stablelib should be able to decrypt from data encrypted by stablelib',  decrypt: stablelib, encrypt: stablelib},
  ]
  for (const {id, encrypt, decrypt} of testCases) {
    it(id, () => {
      const data = Buffer.from('encryptthis')
      const nonce = 1000
      const nonceBytes = new Uint8Array(12)
      new DataView(nonceBytes.buffer, nonceBytes.byteOffset, nonceBytes.byteLength).setUint32(4, nonce, true)
      const key =  new Uint8Array(Array.from({length: 32}, () => 1))
      const encrypted = encrypt.chaCha20Poly1305Encrypt(data, nonceBytes, new Uint8Array(0), key)
      const decrypted = decrypt.chaCha20Poly1305Decrypt(encrypted, nonceBytes, new Uint8Array(0), key)
      assert(uint8ArrayEquals(decrypted as Uint8Array, Buffer.from('encryptthis')))
    })
  }
})
