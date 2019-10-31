import { expect } from "chai";
import { tag, encrypt} from "../src";

describe("Index", () => {
  it("should expose right tag and encrypt function", () => {
    expect(tag).to.equal('/noise');
    expect(typeof(encrypt)).to.equal('function');
  })
});
