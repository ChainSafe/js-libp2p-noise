import { expect } from "chai";
import DuplexPair from 'it-pair/duplex';

import { Noise } from "../src";
import {generateEd25519Keys} from "./utils";

describe("Noise", () => {
  it("should encrypt outgoing data using secureOutbound", async() => {
    const libp2pKeys = await generateEd25519Keys();

    const noise = new Noise(libp2pKeys._key);
    await noise.secureOutbound();
  })
});
