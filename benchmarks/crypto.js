/* eslint-disable */
import {stablelib} from '../dist/src/crypto/stablelib.js'
import {sodiumNative} from '../dist/src/crypto/sodium-native.js'
import benchmark from 'benchmark'

const main = async function () {
  const data = Buffer.from('encryptthis encryptthis encryptthis encryptthis')
  const nonce = 1000
  const nonceBytes = new Uint8Array(12)
  new DataView(nonceBytes.buffer, nonceBytes.byteOffset, nonceBytes.byteLength).setUint32(4, nonce, true)
  const key =  new Uint8Array(Array.from({length: 32}, () => 1))
  const encrypted = stablelib.chaCha20Poly1305Encrypt(data, nonceBytes, new Uint8Array(0), key)

  for(const {id, crypto} of [
    {id: 'stablelib decrypt', crypto: stablelib},
    {id: 'sodium-native decrypt', crypto: sodiumNative}
  ]) {
    const bench = new benchmark(id, {
      fn: async function () {
        crypto.chaCha20Poly1305Decrypt(encrypted, nonceBytes, new Uint8Array(0), key)
      }
    })
    .on('complete', function (stats) {
      console.log(String(stats.currentTarget))
    })
    bench.run()
  }

  for(const {id, crypto} of [
    {id: 'stablelib encrypt', crypto: stablelib},
    {id: 'sodium-native encrypt', crypto: sodiumNative}
  ]) {
    const bench = new benchmark(id, {
      fn: async function () {
        crypto.chaCha20Poly1305Encrypt(data, nonceBytes, new Uint8Array(0), key)
      }
    })
    .on('complete', function (stats) {
      console.log(String(stats.currentTarget))
    })
    bench.run()
  }
}

main()