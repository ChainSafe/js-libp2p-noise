import { expect } from "chai";
import { Noise } from "../src";

describe("Index", () => {
  it("should expose class with tag and required functions", () => {
    const noise = new Noise(Buffer.from("privatekey"));
    expect(noise.protocol()).to.equal('/noise');
    expect(typeof(noise.secureInbound)).to.equal('function');
    expect(typeof(noise.secureOutbound)).to.equal('function');
  })
});
