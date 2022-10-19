import { connectInteropTests } from '@libp2p/interop'
import type { SpawnOptions, Daemon, DaemonFactory } from '@libp2p/interop'
import { createServer } from '@libp2p/daemon-server'
import { createClient } from '@libp2p/daemon-client'
import { createLibp2p, Libp2pOptions } from 'libp2p'
import { tcp } from '@libp2p/tcp'
import { multiaddr } from '@multiformats/multiaddr'
import { path as p2pd } from 'go-libp2p'
import { execa } from 'execa'
import pDefer from 'p-defer'
import { logger } from '@libp2p/logger'
import { mplex } from '@libp2p/mplex'
import fs from 'fs'
import { unmarshalPrivateKey } from '@libp2p/crypto/keys'
import type { PeerId } from '@libp2p/interface-peer-id'
import { peerIdFromKeys } from '@libp2p/peer-id'
import { noise } from '../src/index.js'

async function createGoPeer (options: SpawnOptions): Promise<Daemon> {
  const controlPort = Math.floor(Math.random() * (50000 - 10000 + 1)) + 10000
  const apiAddr = multiaddr(`/ip4/0.0.0.0/tcp/${controlPort}`)

  const log = logger(`go-libp2p:${controlPort}`)

  const opts = [
    `-listen=${apiAddr.toString()}`,
    '-hostAddrs=/ip4/0.0.0.0/tcp/0'
  ]

  if (options.noise === true) {
    opts.push('-noise=true')
  }

  if (options.key != null) {
    opts.push(`-id=${options.key}`)
  }

  const deferred = pDefer()
  const proc = execa(p2pd(), opts)

  proc.stdout?.on('data', (buf: Buffer) => {
    const str = buf.toString()
    log(str)

    // daemon has started
    if (str.includes('Control socket:')) {
      deferred.resolve()
    }
  })

  proc.stderr?.on('data', (buf) => {
    log.error(buf.toString())
  })

  await deferred.promise

  return {
    client: createClient(apiAddr),
    stop: async () => {
      await proc.kill()
    }
  }
}

async function createJsPeer (options: SpawnOptions): Promise<Daemon> {
  let peerId: PeerId | undefined

  if (options.key != null) {
    const keyFile = fs.readFileSync(options.key)
    const privateKey = await unmarshalPrivateKey(keyFile)
    peerId = await peerIdFromKeys(privateKey.public.bytes, privateKey.bytes)
  }

  const opts: Libp2pOptions = {
    peerId,
    addresses: {
      listen: ['/ip4/0.0.0.0/tcp/0']
    },
    transports: [tcp()],
    streamMuxers: [mplex()],
    connectionEncryption: [noise()]
  }

  const node = await createLibp2p(opts)
  const server = await createServer(multiaddr('/ip4/0.0.0.0/tcp/0'), node as any)
  await server.start()

  return {
    client: createClient(server.getMultiaddr()),
    stop: async () => {
      await server.stop()
      await node.stop()
    }
  }
}

async function main (): Promise<void> {
  const factory: DaemonFactory = {
    async spawn (options: SpawnOptions) {
      if (options.type === 'go') {
        return await createGoPeer(options)
      }

      return await createJsPeer(options)
    }
  }

  await connectInteropTests(factory)
}

main().catch(err => {
  console.error(err) // eslint-disable-line no-console
  process.exit(1)
})
