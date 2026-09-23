import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { deriveHealthPath } from "../src/routes.ts";

describe("deriveHealthPath", () => {
  it("nests /health under the default RSS_PATH", () => {
    assert.equal(deriveHealthPath("/rss"), "/rss/health");
  });

  it("nests /health under a bare subpath", () => {
    assert.equal(deriveHealthPath("/blabla"), "/blabla/health");
  });

  it("nests /health under a multi-segment RSS_PATH", () => {
    assert.equal(deriveHealthPath("/blabla/rss"), "/blabla/rss/health");
  });

  it("ignores a trailing slash on RSS_PATH", () => {
    assert.equal(deriveHealthPath("/blabla/rss/"), "/blabla/rss/health");
  });
});
