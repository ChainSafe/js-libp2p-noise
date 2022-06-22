/* eslint-disable */
import {stablelib} from '../dist/src/crypto/stablelib.js'
import {sodiumNative} from '../dist/src/crypto/sodium-native.js'
import benchmark from 'benchmark'

const main = function () {
  const nonce = 1000
  const nonceBytes = new Uint8Array(12)
  new DataView(nonceBytes.buffer, nonceBytes.byteOffset, nonceBytes.byteLength).setUint32(4, nonce, true)
  const key = new Uint8Array(Array.from({length: 32}, () => 1))

  // NOISE_MSG_MAX_LENGTH_BYTES = 65535
  for (const length of [100, 500, 5000, 20000, 65535]) {
    const data100 = Buffer.from('encryptthis encryptthis encryptthis encryptthis encryptthis encryptthis encryptthis encryptthis encr')
    const data = Buffer.concat(Array.from({length: Math.floor(length / 100)}, () => data100))

    const encrypted = stablelib.chaCha20Poly1305Encrypt(data, nonceBytes, new Uint8Array(0), key)

    for(const {id, crypto} of [
      {id: `stablelib decrypt ${length} bytes Buffer`, crypto: stablelib},
      {id: `sodium-native decrypt ${length} bytes Buffer`, crypto: sodiumNative}
    ]) {
      const bench = new benchmark(id, {
        fn: function () {
          crypto.chaCha20Poly1305Decrypt(encrypted, nonceBytes, new Uint8Array(0), key)
        }
      })
      .on('complete', function (stats) {
        console.log(String(stats.currentTarget))
      })
      bench.run()
    }

    for(const {id, crypto} of [
      {id: `stablelib encrypt ${length} bytes Buffer`, crypto: stablelib},
      {id: `sodium-native encrypt ${length} bytes Buffer`, crypto: sodiumNative}
    ]) {
      const bench = new benchmark(id, {
        fn: function () {
          crypto.chaCha20Poly1305Encrypt(data, nonceBytes, new Uint8Array(0), key)
        }
      })
      .on('complete', function (stats) {
        console.log(String(stats.currentTarget))
      })
      bench.run()
    }
  }
}

main()