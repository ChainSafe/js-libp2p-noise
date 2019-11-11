import { expect } from "chai";
import { Noise } from "../src";
import {generateEd25519Keys} from "./utils";

describe("Noise", () => {
  it("should encrypt", async() => {
    const libp2pKeys = await generateEd25519Keys();

    const noise = new Noise(libp2pKeys._key);
    await noise.encrypt();
  })
});
