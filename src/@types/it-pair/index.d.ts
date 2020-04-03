declare module 'it-pair' {
  export type Duplex = [Stream, Stream];

  type Stream = {
    sink(source: Iterable<any>): void;
    source: Record<string, any>;
  }
}
