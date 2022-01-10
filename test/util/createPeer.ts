import PeerId from 'peer-id'
import { Multiaddr } from 'multiaddr'
import Libp2p from 'libp2p'
import WS from 'libp2p-websockets'
import MPLEX from 'libp2p-mplex'
import { NOISE } from '../../src'

export const peerIds = [{
  id: 'QmNMMAqSxPetRS1cVMmutW5BCN1qQQyEr4u98kUvZjcfEw',
  privKey: 'CAASpQkwggShAgEAAoIBAQDPek2aeHMa0blL42RTKd6xgtkk4Zkldvq4LHxzcag5uXepiQzWANEUvoD3KcUTmMRmx14PvsxdLCNst7S2JSa0R2n5wSRs14zGy6892lx4H4tLBD1KSpQlJ6vabYM1CJhIQRG90BtzDPrJ/X1iJ2HA0PPDz0Mflam2QUMDDrU0IuV2m7gSCJ5r4EmMs3U0xnH/1gShkVx4ir0WUdoWf5KQUJOmLn1clTRHYPv4KL9A/E38+imNAXfkH3c2T7DrCcYRkZSpK+WecjMsH1dCX15hhhggNqfp3iulO1tGPxHjm7PDGTPUjpCWKpD5e50sLqsUwexac1ja6ktMfszIR+FPAgMBAAECggEAB2H2uPRoRCAKU+T3gO4QeoiJaYKNjIO7UCplE0aMEeHDnEjAKC1HQ1G0DRdzZ8sb0fxuIGlNpFMZv5iZ2ZFg2zFfV//DaAwTek9tIOpQOAYHUtgHxkj5FIlg2BjlflGb+ZY3J2XsVB+2HNHkUEXOeKn2wpTxcoJE07NmywkO8Zfr1OL5oPxOPlRN1gI4ffYH2LbfaQVtRhwONR2+fs5ISfubk5iKso6BX4moMYkxubYwZbpucvKKi/rIjUA3SK86wdCUnno1KbDfdXSgCiUlvxt/IbRFXFURQoTV6BOi3sP5crBLw8OiVubMr9/8WE6KzJ0R7hPd5+eeWvYiYnWj4QKBgQD6jRlAFo/MgPO5NZ/HRAk6LUG+fdEWexA+GGV7CwJI61W/Dpbn9ZswPDhRJKo3rquyDFVZPdd7+RlXYg1wpmp1k54z++L1srsgj72vlg4I8wkZ4YLBg0+zVgHlQ0kxnp16DvQdOgiRFvMUUMEgetsoIx1CQWTd67hTExGsW+WAZQKBgQDT/WaHWvwyq9oaZ8G7F/tfeuXvNTk3HIJdfbWGgRXB7lJ7Gf6FsX4x7PeERfL5a67JLV6JdiLLVuYC2CBhipqLqC2DB962aKMvxobQpSljBBZvZyqP1IGPoKskrSo+2mqpYkeCLbDMuJ1nujgMP7gqVjabs2zj6ACKmmpYH/oNowJ/T0ZVtvFsjkg+1VsiMupUARRQuPUWMwa9HOibM1NIZcoQV2NGXB5Z++kR6JqxQO0DZlKArrviclderUdY+UuuY4VRiSEprpPeoW7ZlbTku/Ap8QZpWNEzZorQDro7bnfBW91fX9/81ets/gCPGrfEn+58U3pdb9oleCOQc/ifpQKBgBTYGbi9bYbd9vgZs6bd2M2um+VFanbMytS+g5bSIn2LHXkVOT2UEkB+eGf9KML1n54QY/dIMmukA8HL1oNAyalpw+/aWj+9Ui5kauUhGEywHjSeBEVYM9UXizxz+m9rsoktLLLUI0o97NxCJzitG0Kub3gn0FEogsUeIc7AdinZAoGBANnM1vcteSQDs7x94TDEnvvqwSkA2UWyLidD2jXgE0PG4V6tTkK//QPBmC9eq6TIqXkzYlsErSw4XeKO91knFofmdBzzVh/ddgx/NufJV4tXF+a2iTpqYBUJiz9wpIKgf43/Ob+P1EA99GAhSdxz1ess9O2aTqf3ANzn6v6g62Pv',
  pubKey: 'CAASpgIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDPek2aeHMa0blL42RTKd6xgtkk4Zkldvq4LHxzcag5uXepiQzWANEUvoD3KcUTmMRmx14PvsxdLCNst7S2JSa0R2n5wSRs14zGy6892lx4H4tLBD1KSpQlJ6vabYM1CJhIQRG90BtzDPrJ/X1iJ2HA0PPDz0Mflam2QUMDDrU0IuV2m7gSCJ5r4EmMs3U0xnH/1gShkVx4ir0WUdoWf5KQUJOmLn1clTRHYPv4KL9A/E38+imNAXfkH3c2T7DrCcYRkZSpK+WecjMsH1dCX15hhhggNqfp3iulO1tGPxHjm7PDGTPUjpCWKpD5e50sLqsUwexac1ja6ktMfszIR+FPAgMBAAE='
}, {
  id: 'QmW8rAgaaA6sRydK1k6vonShQME47aDxaFidbtMevWs73t',
  privKey: 'CAASpwkwggSjAgEAAoIBAQCTU3gVDv3SRXLOsFln9GEf1nJ/uCEDhOG10eC0H9l9IPpVxjuPT1ep+ykFUdvefq3D3q+W3hbmiHm81o8dYv26RxZIEioToUWp7Ec5M2B/niYoE93za9/ZDwJdl7eh2hNKwAdxTmdbXUPjkIU4vLyHKRFbJIn9X8w9djldz8hoUvC1BK4L1XrT6F2l0ruJXErH2ZwI1youfSzo87TdXIoFKdrQLuW6hOtDCGKTiS+ab/DkMODc6zl8N47Oczv7vjzoWOJMUJs1Pg0ZsD1zmISY38P0y/QyEhatZn0B8BmSWxlLQuukatzOepQI6k+HtfyAAjn4UEqnMaXTP1uwLldVAgMBAAECggEAHq2f8MqpYjLiAFZKl9IUs3uFZkEiZsgx9BmbMAb91Aec+WWJG4OLHrNVTG1KWp+IcaQablEa9bBvoToQnS7y5OpOon1d066egg7Ymfmv24NEMM5KRpktCNcOSA0CySpPIB6yrg6EiUr3ixiaFUGABKkxmwgVz/Q15IqM0ZMmCUsC174PMAz1COFZxD0ZX0zgHblOJQW3dc0X3XSzhht8vU02SMoVObQHQfeXEHv3K/RiVj/Ax0bTc5JVkT8dm8xksTtsFCNOzRBqFS6MYqX6U/u0Onz3Jm5Jt7fLWb5n97gZR4SleyGrqxYNb46d9X7mP0ie7E6bzFW0DsWBIeAqVQKBgQDW0We2L1n44yOvJaMs3evpj0nps13jWidt2I3RlZXjWzWHiYQfvhWUWqps/xZBnAYgnN/38xbKzHZeRNhrqOo+VB0WK1IYl0lZVE4l6TNKCsLsUfQzsb1pePkd1eRZA+TSqsi+I/IOQlQU7HA0bMrah/5FYyUBP0jYvCOvYTlZuwKBgQCvkcVRydVlzjUgv7lY5lYvT8IHV5iYO4Qkk2q6Wjv9VUKAJZauurMdiy05PboWfs5kbETdwFybXMBcknIvZO4ihxmwL8mcoNwDVZHI4bXapIKMTCyHgUKvJ9SeTcKGC7ZuQJ8mslRmYox/HloTOXEJgQgPRxXcwa3amzvdZI+6LwKBgQCLsnQqgxKUi0m6bdR2qf7vzTH4258z6X34rjpT0F5AEyF1edVFOz0XU/q+lQhpNEi7zqjLuvbYfSyA026WXKuwSsz7jMJ/oWqev/duKgAjp2npesY/E9gkjfobD+zGgoS9BzkyhXe1FCdP0A6L2S/1+zg88WOwMvJxl6/xLl24XwKBgCm60xSajX8yIQyUpWBM9yUtpueJ2Xotgz4ST+bVNbcEAddll8gWFiaqgug9FLLuFu5lkYTHiPtgc1RNdphvO+62/9MRuLDixwh/2TPO+iNqwKDKJjda8Nei9vVddCPaOtU/xNQ0xLzFJbG9LBmvqH9izOCcu8SJwGHaTcNUeJj/AoGADCJ26cY30c13F/8awAAmFYpZWCuTP5ppTsRmjd63ixlrqgkeLGpJ7kYb5fXkcTycRGYgP0e1kssBGcmE7DuG955fx3ZJESX3GQZ+XfMHvYGONwF1EiK1f0p6+GReC2VlQ7PIkoD9o0hojM6SnWvv9EXNjCPALEbfPFFvcniKVsE=',
  pubKey: 'CAASpgIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCTU3gVDv3SRXLOsFln9GEf1nJ/uCEDhOG10eC0H9l9IPpVxjuPT1ep+ykFUdvefq3D3q+W3hbmiHm81o8dYv26RxZIEioToUWp7Ec5M2B/niYoE93za9/ZDwJdl7eh2hNKwAdxTmdbXUPjkIU4vLyHKRFbJIn9X8w9djldz8hoUvC1BK4L1XrT6F2l0ruJXErH2ZwI1youfSzo87TdXIoFKdrQLuW6hOtDCGKTiS+ab/DkMODc6zl8N47Oczv7vjzoWOJMUJs1Pg0ZsD1zmISY38P0y/QyEhatZn0B8BmSWxlLQuukatzOepQI6k+HtfyAAjn4UEqnMaXTP1uwLldVAgMBAAE='
}]

const defaultConfig = {
  modules: {
    transport: [WS],
    streamMuxer: [MPLEX],
    connEncryption: [NOISE as unknown as Libp2p.Crypto]
  },
  config: {
    pubsub: {
      enabled: false
    },
    peerDiscovery: {
      autoDial: false
    }
  }
}

function isBrowser (): boolean {
  return typeof window === 'object' || typeof self === 'object'
}

/**
 * Selectively determine the listen address based on the operating environment
 *
 * If in node, use websocket address
 * If in browser, use relay address
 */
function getListenAddress (peerId: PeerId): Multiaddr {
  return new Multiaddr('/ip4/127.0.0.1/tcp/0/ws')
  if (isBrowser()) {
    // browser
    //return new Multiaddr(`${RelayPeer.multiaddr}/p2p-circuit/p2p/${peerId.toB58String()}`)
  } else {
    // node
    return new Multiaddr('/ip4/127.0.0.1/tcp/0/ws')
  }
}

/**
 * Create libp2p node, selectively determining the listen address based on the operating environment
 * If no peerId is given, default to the first peer in the fixtures peer list
 */
export async function createPeer ({ peerId, started = true, config = {} }: { peerId?: PeerId, started?: boolean, config?: Libp2p.Libp2pConfig} = {}): Promise<Libp2p> {
  if (!peerId) {
    peerId = await PeerId.createFromJSON(peerIds[0])
  }
  const libp2p = await Libp2p.create({
    peerId: peerId,
    addresses: {
      listen: [getListenAddress(peerId).toString()]
    },
    ...defaultConfig,
    ...config
  })

  if (started) {
    await libp2p.start()
  }

  return libp2p
}
