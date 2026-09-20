import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { getRSS } from "../src/tracker.ts";

describe("tracker before the first refresh", () => {
  it("returns an empty feed", () => {
    assert.equal(getRSS(), "");
  });
});
