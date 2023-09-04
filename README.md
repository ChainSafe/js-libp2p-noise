# js-libp2p-noise

![npm](https://img.shields.io/npm/v/@chainsafe/libp2p-noise)
[![](https://img.shields.io/github/actions/workflow/status/ChainSafe/js-libp2p-noise/js-test-and-release.yml?branch=master)](https://github.com/ChainSafe/js-libp2p-noise/actions)
[![](https://img.shields.io/badge/project-libp2p-yellow.svg?style=flat-square)](https://libp2p.io/)
![](https://img.shields.io/github/issues-raw/ChainSafe/js-libp2p-noise)
[![License Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![License MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![](https://img.shields.io/badge/npm-%3E%3D7.0.0-orange.svg?style=flat-square)
![](https://img.shields.io/badge/Node.js-%3E%3D16.0.0-orange.svg?style=flat-square)
![](https://img.shields.io/badge/browsers-last%202%20versions%2C%20not%20ie%20%3C%3D11-orange)
[![Twitter](https://img.shields.io/twitter/follow/ChainSafeth.svg?label=Twitter)](https://twitter.com/ChainSafeth)
[![Discord](https://img.shields.io/discord/593655374469660673.svg?label=Discord&logo=discord)](https://discord.gg/Q6A3YA2)

> Noise libp2p handshake for js-libp2p

This repository contains TypeScript implementation of noise protocol, an encryption protocol used in libp2p.

##### Warning: Even though this package works in browser, it will bundle around 600Kb (200Kb gzipped) of code
https://bundlephobia.com/result?p=@chainsafe/libp2p-noise@latest

## Usage

Install with `yarn add @chainsafe/libp2p-noise` or `npm i @chainsafe/libp2p-noise`.

Example of using default noise configuration and passing it to the libp2p config:

```js
import {createLibp2p} from "libp2p"
import {noise} from "@chainsafe/libp2p-noise"

//custom noise configuration, pass it instead of `noise()`
//x25519 private key
const n = noise({ staticNoiseKey });

const libp2p = await createLibp2p({
  connectionEncryption: [noise()],
  //... other options
})
```

See the [NoiseInit](https://github.com/ChainSafe/js-libp2p-noise/blob/master/src/noise.ts#L29-L38) interface for noise configuration options.

## API

This module exposes an implementation of the [ConnectionEncrypter](https://libp2p.github.io/js-libp2p/interfaces/_libp2p_interface.connection_encrypter.ConnectionEncrypter.html) interface.

## Bring your own crypto

You can provide a custom crypto implementation (instead of the default, based on [@noble](https://paulmillr.com/noble/)) by adding a `crypto` field to the init argument passed to the `Noise` factory.

The implementation must conform to the `ICryptoInterface`, defined in https://github.com/ChainSafe/js-libp2p-noise/blob/master/src/crypto.ts

## Contribute

Feel free to join in. All welcome. Open an issue!

[![](https://cdn.rawgit.com/jbenet/contribute-ipfs-gif/master/img/contribute.gif)](https://github.com/ipfs/community/blob/master/contributing.md)

## License

Licensed under either of

 * Apache 2.0, ([LICENSE-APACHE](LICENSE-APACHE) / http://www.apache.org/licenses/LICENSE-2.0)
 * MIT ([LICENSE-MIT](LICENSE-MIT) / http://opensource.org/licenses/MIT)
