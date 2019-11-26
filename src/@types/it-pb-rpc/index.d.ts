declare module "it-pb-rpc" {
  import { Buffer } from "buffer";
  import { Duplex } from "it-pair";
  type WrappedDuplex = {
    read(bytes: number): Promise<Buffer>,
    readLP(): Promise<Buffer>,
    write(input: Buffer): void,
    writeLP(input: Buffer): void,
    unwrap(): Duplex
  }

  function Wrap (duplex: any): WrappedDuplex;

  export = Wrap;
}
