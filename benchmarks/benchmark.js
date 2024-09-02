/* eslint-disable */

import { noise } from '../dist/src/index.js'
import benchmark from 'benchmark'
import { duplexPair } from 'it-pair/duplex'
import { base64pad } from 'multiformats/bases/base64'
import { defaultLogger } from '@libp2p/logger'

const bench = async function () {
  console.log('Initializing handshake benchmark')

  const initiatorPeer = await createFromJSON({
    id: '12D3KooWH45PiqBjfnEfDfCD6TqJrpqTBJvQDwGHvjGpaWwms46D',
    privKey: 'CAESYBtKXrMwawAARmLScynQUuSwi/gGSkwqDPxi15N3dqDHa4T4iWupkMe5oYGwGH3Hyfvd/QcgSTqg71oYZJadJ6prhPiJa6mQx7mhgbAYfcfJ+939ByBJOqDvWhhklp0nqg==',
    pubKey: 'CAESIGuE+IlrqZDHuaGBsBh9x8n73f0HIEk6oO9aGGSWnSeq'
  })
  const initiatorPrivateKey = privateKeyFromProtobuf(base64pad.decode(`M${initiatorPeer.privKey}`))
  const initiator = noise()({
    privateKey: initiatorPrivateKey,
    peerId: peerIdFromPublicKey(initiatorPrivateKey.publicKey),
    logger: defaultLogger()
  })

  const responderPeer = await createFromJSON({
    id: '12D3KooWP63uzL78BRMpkQ7augMdNi1h3VBrVWZucKjyhzGVaSi1',
    privKey: 'CAESYPxO3SHyfc2578hDmfkGGBY255JjiLuVavJWy+9ivlpsxSyVKf36ipyRGL6szGzHuFs5ceEuuGVrPMg/rW2Ch1bFLJUp/fqKnJEYvqzMbMe4Wzlx4S64ZWs8yD+tbYKHVg==',
    pubKey: 'CAESIMUslSn9+oqckRi+rMxsx7hbOXHhLrhlazzIP61tgodW'
  })
  const responderPrivateKey = privateKeyFromProtobuf(base64pad.decode(`M${responderPeer.privKey}`))
  const responder = noise()({
    privateKey: responderPrivateKey,
    peerId: peerIdFromPublicKey(responderPrivateKey.publicKey),
    logger: defaultLogger()
  })

  console.log('Init complete, running benchmark')
  const bench = new benchmark('handshake', {
    defer: true,
    fn: async function (deferred) {
      const [inboundConnection, outboundConnection] = duplexPair()
      await Promise.all([
        initiator.secureOutbound(initiatorPeer, outboundConnection, responderPeer),
        responder.secureInbound(responderPeer, inboundConnection, initiatorPeer)
      ])
      deferred.resolve()
    }
  })
    .on('complete', function (stats) {
      console.log(String(stats.currentTarget))
    })
  bench.run({ async: true })
}

bench()
