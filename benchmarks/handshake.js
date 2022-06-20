/* eslint-disable */

import { Noise } from '../dist/src/index.js'
import benchmark from 'benchmark'
import { duplexPair } from 'it-pair/duplex'
import { createFromJSON } from '@libp2p/peer-id-factory'

const bench = async function () {
  console.log('Initializing handshake benchmark')
  const initiator = new Noise()
  const initiatorPeer = await createFromJSON({
    id: '12D3KooWH45PiqBjfnEfDfCD6TqJrpqTBJvQDwGHvjGpaWwms46D',
    privKey: 'CAESYBtKXrMwawAARmLScynQUuSwi/gGSkwqDPxi15N3dqDHa4T4iWupkMe5oYGwGH3Hyfvd/QcgSTqg71oYZJadJ6prhPiJa6mQx7mhgbAYfcfJ+939ByBJOqDvWhhklp0nqg==',
    pubKey: 'CAESIGuE+IlrqZDHuaGBsBh9x8n73f0HIEk6oO9aGGSWnSeq'
  })
  const responder = new Noise()
  const responderPeer = await createFromJSON({
    id: '12D3KooWP63uzL78BRMpkQ7augMdNi1h3VBrVWZucKjyhzGVaSi1',
    privKey: 'CAESYPxO3SHyfc2578hDmfkGGBY255JjiLuVavJWy+9ivlpsxSyVKf36ipyRGL6szGzHuFs5ceEuuGVrPMg/rW2Ch1bFLJUp/fqKnJEYvqzMbMe4Wzlx4S64ZWs8yD+tbYKHVg==',
    pubKey: 'CAESIMUslSn9+oqckRi+rMxsx7hbOXHhLrhlazzIP61tgodW'
  })
  console.log('Init complete, running benchmark')
  const bench = new benchmark('handshake', {
    defer: true,
    fn: async function (deffered) {
      const [inboundConnection, outboundConnection] = duplexPair()
      await Promise.all([
        initiator.secureOutbound(initiatorPeer, outboundConnection, responderPeer),
        responder.secureInbound(responderPeer, inboundConnection, initiatorPeer)
      ])
      deffered.resolve()
    }
  })
    .on('complete', function (stats) {
      console.log(String(stats.currentTarget))
    })
  bench.run({ async: true })
}

bench()
