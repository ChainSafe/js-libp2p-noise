import { Noise } from './noise.js'

export * from './crypto.js'
export * from './crypto/stablelib.js'
export * from './noise.js'

/**
 * Default configuration, it will generate new noise static key and enable noise pipes (IK handshake).
 */
export const NOISE = new Noise()
