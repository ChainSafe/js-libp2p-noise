import { expect } from "chai";
import { Noise } from "../src";

describe("Index", () => {
  it("should expose class with tag and encrypt functions", () => {
    const noise = new Noise(Buffer.from("privatekey"));
    expect(noise.tag()).to.equal('/noise');
    expect(typeof(noise.encrypt)).to.equal('function');
  })
});
