import { expect } from "chai";
import { tag, encrypt} from "../src";

describe("Index", () => {
  it("should expose right tag and encrypt function", () => {
    expect(tag).to.equal('/noise/1.0.0');
    expect(typeof(encrypt)).to.equal('function');
  })
});
