/**
 * Standalone TCP listener for Phase 5 live interop testing.
 *
 * Listens on TCP port 8000, performs a NoiseHFS (XXhfs) handshake as the
 * RESPONDER for each incoming connection, then:
 *   1. Sends "hello from JS" to the peer
 *   2. Reads back whatever the peer sends and prints it
 *
 * Usage:
 *   cd js-libp2p-noise
 *   node scripts/node-listener.mjs
 *
 * Then in another terminal:
 *   cd py-libp2p && python scripts/interop_dial.py
 */

import net from 'net'
import { generateKeyPair } from '@libp2p/crypto/keys'
import { defaultLogger } from '@libp2p/logger'
import { peerIdFromPrivateKey } from '@libp2p/peer-id'
import { AbstractMultiaddrConnection, ipPortToMultiaddr } from '@libp2p/utils'
import { multiaddr } from '@multiformats/multiaddr'
import { NoiseHFS } from '../dist/src/noise-hfs.js'

const PORT = 8000

// ─── Inline TCP socket → MultiaddrConnection adapter ────────────────────────
// @libp2p/tcp does not export socket-to-conn directly; we inline it here.
// Based on @libp2p/tcp dist/src/socket-to-conn.js
class TCPSocketConnection extends AbstractMultiaddrConnection {
  #socket

  constructor (init) {
    super(init)
    this.#socket = init.socket

    this.#socket.on('data', buf => this.onData(buf))
    this.#socket.on('error', err => this.abort(err))
    this.#socket.setTimeout(120_000)
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

  async sendClose (options) {
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

function socketToMultiaddrConn (socket, log, localAddr) {
  const remoteAddr = ipPortToMultiaddr(socket.remoteAddress, socket.remotePort)
  return new TCPSocketConnection({
    socket,
    remoteAddr,
    localAddr,
    direction: 'inbound',
    log: log.newScope('tcp-conn')
  })
}

// ─── Main ────────────────────────────────────────────────────────────────────

async function main () {
  const privateKey = await generateKeyPair('Ed25519')
  const peerId = peerIdFromPrivateKey(privateKey)
  const log = defaultLogger().forComponent('noise-hfs:listener')

  console.log(`Listener peer ID: ${peerId.toString()}`)

  const components = {
    privateKey,
    peerId,
    logger: defaultLogger(),
    upgrader: { getStreamMuxers: () => new Map() }
  }

  const noiseHfs = new NoiseHFS(components)
  console.log(`Protocol: ${noiseHfs.protocol}`)

  const localAddr = multiaddr(`/ip4/127.0.0.1/tcp/${PORT}`)

  const server = net.createServer(async (socket) => {
    console.log(`\nIncoming TCP connection from ${socket.remoteAddress}:${socket.remotePort}`)

    const maConn = socketToMultiaddrConn(socket, log, localAddr)

    try {
      console.log('Starting NoiseHFS responder handshake...')
      const { connection, remotePeer } = await noiseHfs.secureInbound(maConn)
      console.log(`Handshake complete! Remote peer: ${remotePeer.toString()}`)

      // Send greeting — connection.send() sends uint16(ct_len) || AEAD(plaintext)
      // which matches Python's NoisePacketReadWriter framing exactly.
      const greeting = new TextEncoder().encode('hello from JS\n')
      connection.send(greeting)
      console.log('Sent: "hello from JS"')

      // Read Python reply — iterate the async stream for one decrypted message
      for await (const chunk of connection) {
        const replyStr = new TextDecoder().decode(chunk instanceof Uint8Array ? chunk : chunk.slice())
        console.log(`Received: "${replyStr.trim()}"`)

        if (replyStr.trim() === 'hello from Python') {
          console.log('\n✅ INTEROP SUCCESS: Both sides exchanged messages through NoiseHFS!')
        } else {
          console.log('\n⚠️  Unexpected reply:', JSON.stringify(replyStr))
        }
        break // one message is enough
      }

      connection.close()
    } catch (err) {
      console.error('Handshake or messaging error:', err.message)
      socket.destroy()
    }
  })

  server.listen(PORT, '127.0.0.1', () => {
    console.log(`\nListening on tcp://127.0.0.1:${PORT}`)
    console.log('Waiting for Python dialer...\n')
  })

  server.on('error', err => {
    console.error('Server error:', err)
    process.exit(1)
  })
}

main().catch(err => {
  console.error(err)
  process.exit(1)
})
