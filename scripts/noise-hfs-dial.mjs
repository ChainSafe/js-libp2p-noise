#!/usr/bin/env node
/**
 * Noise_XXhfs_25519+ML-KEM-768 TCP dialer (initiator).
 *
 * Dials a Noise HFS listener at localhost:<port>, runs the XXhfs handshake,
 * and prints the remote peer ID on success.
 *
 * Usage:
 *   node scripts/noise-hfs-dial.mjs [--port N]   (default port: 9999)
 *
 * The dist/ directory must exist (run `pnpm build` first).
 *
 * Protocol: Noise_XXhfs_25519+ML-KEM-768_ChaChaPoly_SHA256
 * Protocol ID: /noise-mlkem768-hfs/0.1.0
 */

import net from 'net'
import { generateKeyPair } from '@libp2p/crypto/keys'
import { defaultLogger } from '@libp2p/logger'
import { peerIdFromPrivateKey } from '@libp2p/peer-id'
import { AbstractMultiaddrConnection, ipPortToMultiaddr } from '@libp2p/utils'
import { multiaddr } from '@multiformats/multiaddr'
import { NoiseHFS } from '../dist/src/noise-hfs.js'

// ─── Parse --port N or positional arg; default 9999 ──────────────────────────

function parsePort (argv) {
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--port' && argv[i + 1] !== undefined) {
      return parseInt(argv[i + 1], 10)
    }
    if (/^\d+$/.test(argv[i])) {
      return parseInt(argv[i], 10)
    }
  }
  return 9999
}

const PORT = parsePort(process.argv.slice(2))

// ─── TCP socket → MultiaddrConnection adapter (same pattern as node-listener.mjs) ──

class TCPSocketConnection extends AbstractMultiaddrConnection {
  #socket

  constructor (init) {
    super(init)
    this.#socket = init.socket

    this.#socket.on('data', buf => this.onData(buf))
    this.#socket.on('error', err => this.abort(err))
    this.#socket.setTimeout(30_000)
    this.#socket.once('timeout', () => this.abort(new Error('TCP timeout')))
    this.#socket.once('end', () => this.onTransportClosed())
    this.#socket.once('close', hadError => {
      if (hadError) {
        this.abort(new Error('TCP transmission error'))
      } else {
        this.onTransportClosed()
      }
    })
    this.#socket.on('drain', () => this.safeDispatchEvent('drain'))
  }

  sendData (data) {
    let sentBytes = 0
    let canSendMore = true
    for (const buf of data) {
      sentBytes += buf.byteLength
      canSendMore = this.#socket.write(buf)
    }
    return { sentBytes, canSendMore }
  }

  async sendClose () {
    if (this.#socket.destroyed) return
    await new Promise((resolve) => {
      this.#socket.once('close', resolve)
      this.#socket.destroySoon()
    })
  }

  sendReset () {
    this.#socket.resetAndDestroy()
  }

  sendPause () { this.#socket.pause() }
  sendResume () { this.#socket.resume() }
}

// ─── Main ─────────────────────────────────────────────────────────────────────

async function main () {
  const privateKey = await generateKeyPair('Ed25519')
  const peerId = peerIdFromPrivateKey(privateKey)
  const log = defaultLogger().forComponent('noise-hfs:dialer')

  const components = {
    privateKey,
    peerId,
    logger: defaultLogger(),
    upgrader: { getStreamMuxers: () => new Map() }
  }

  const noiseHfs = new NoiseHFS(components)

  const socket = net.createConnection(PORT, '127.0.0.1')
  await new Promise((resolve, reject) => {
    socket.once('connect', resolve)
    socket.once('error', reject)
  })

  const remoteAddr = ipPortToMultiaddr(socket.remoteAddress, socket.remotePort)
  const localAddr = multiaddr(`/ip4/127.0.0.1/tcp/${socket.localPort}`)

  const maConn = new TCPSocketConnection({
    socket,
    remoteAddr,
    localAddr,
    direction: 'outbound',
    log: log.newScope('tcp-conn')
  })

  const { remotePeer } = await noiseHfs.secureOutbound(maConn)
  process.stdout.write(`PEER ${remotePeer.toString()}\n`)

  socket.destroySoon()
}

main().catch(err => {
  process.stderr.write(`ERROR ${err.message}\n`)
  process.exit(1)
})
