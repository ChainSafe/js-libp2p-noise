declare module "it-pb-rpc" {
  import { Buffer } from "buffer";
  import { Duplex } from "it-pair";
  type WrappedDuplex = {
    read(input: Buffer): Buffer,
    write(input: Buffer): void,
    unwrap(): Duplex
  }

  function Wrap (duplex: any): WrappedDuplex;

  export = Wrap;
}
