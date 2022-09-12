# js-libp2p-noise

![npm](https://img.shields.io/npm/v/libp2p-noise)
[![CI](https://github.com/ChainSafe/js-libp2p-noise/actions/workflows/ci.yml/badge.svg?branch=master&event=push)](https://github.com/ChainSafe/js-libp2p-noise/actions/workflows/ci.yml)

[![](https://img.shields.io/badge/project-libp2p-yellow.svg?style=flat-square)](https://libp2p.io/)
![](https://img.shields.io/github/issues-raw/ChainSafe/js-libp2p-noise)
![](https://img.shields.io/github/license/ChainSafe/js-libp2p-noise)
![](https://img.shields.io/badge/yarn-%3E%3D1.17.0-orange.svg?style=flat-square)
![](https://img.shields.io/badge/Node.js-%3E%3D16.0.0-orange.svg?style=flat-square)
![](https://img.shields.io/badge/browsers-last%202%20versions%2C%20not%20ie%20%3C%3D11-orange)
[![Discourse posts](https://img.shields.io/discourse/https/discuss.libp2p.io/posts.svg)](https://discuss.libp2p.io)

> Noise libp2p handshake for js-libp2p

This repository contains TypeScript implementation of noise protocol, an encryption protocol used in libp2p.

##### Warning: Even though this package works in browser, it will bundle around 600Kb (200Kb gzipped) of code
https://bundlephobia.com/result?p=@chainsafe/libp2p-noise@latest

## Usage

Install with `yarn add @chainsafe/libp2p-noise` or `npm i @chainsafe/libp2p-noise`.

Example of using default noise configuration and passing it to the libp2p config:

```js
import {Noise} from "@chainsafe/libp2p-noise"

//custom noise configuration, pass it instead of `new Noise()`
const noise = new Noise(privateKey, Buffer.alloc(x));

const libp2p = new Libp2p({
   modules: {
     connEncryption: [new Noise()],
   },
});
```

Where parameters for Noise constructor are:
 - *static Noise key* - (optional) existing private Noise static key
 - *early data* - (optional) an early data payload to be sent in handshake messages



## API

This module exposes a crypto interface, as defined in the repository [js-interfaces](https://github.com/libp2p/js-libp2p-interfaces).

[» API Docs](https://github.com/libp2p/js-libp2p-interfaces/tree/master/packages/interface-connection-encrypter#api)

## Bring your own crypto

You can provide a custom crypto implementation (instead of the default, based on [stablelib](https://www.stablelib.com/)) by passing a third argument to the `Noise` constructor.

The implementation must conform to the `ICryptoInterface`, defined in https://github.com/ChainSafe/js-libp2p-noise/blob/master/src/crypto.ts

## Contribute

Feel free to join in. All welcome. Open an issue!

[![](https://cdn.rawgit.com/jbenet/contribute-ipfs-gif/master/img/contribute.gif)](https://github.com/ipfs/community/blob/master/contributing.md)

## License

Licensed under either of

 * Apache 2.0, ([LICENSE-APACHE](LICENSE-APACHE) / http://www.apache.org/licenses/LICENSE-2.0)
 * MIT ([LICENSE-MIT](LICENSE-MIT) / http://opensource.org/licenses/MIT)
