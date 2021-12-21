declare module 'it-length-prefixed' {
  import BufferList from 'bl/BufferList'

  interface LengthDecoderFunction {
    (data: Uint8Array | BufferList): number
    bytes: number
  }

  interface LengthEncoderFunction {
    (value: number, target: Uint8Array, offset: number): number|Uint8Array
    bytes: number
  }

  interface Encoder {
    (options?: Partial<{lengthEncoder: LengthEncoderFunction}>): AsyncGenerator<BufferList, Uint8Array>
    single: (chunk: Uint8Array, options?: Partial<{lengthEncoder: LengthEncoderFunction}>) => BufferList
    MIN_POOL_SIZE: number
    DEFAULT_POOL_SIZE: number
  }

  interface DecoderOptions {
    lengthDecoder: LengthDecoderFunction
    maxLengthLength: number
    maxDataLength: number
  }

  interface Decoder {
    (options?: Partial<DecoderOptions>): AsyncGenerator<BufferList, BufferList>
    fromReader: (reader: any, options?: Partial<DecoderOptions>) => BufferList
    MAX_LENGTH_LENGTH: number
    MAX_DATA_LENGTH: number
  }

  export const encode: Encoder
  export const decode: Decoder

}
