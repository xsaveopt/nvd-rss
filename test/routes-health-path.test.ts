import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { deriveHealthPath } from "../src/routes.ts";

describe("deriveHealthPath", () => {
  it("keeps /health at the root for the default RSS_PATH", () => {
    assert.equal(deriveHealthPath("/rss"), "/health");
  });

  it("nests /health under a single-segment subpath", () => {
    assert.equal(deriveHealthPath("/blabla/rss"), "/blabla/health");
  });

  it("nests /health under a multi-segment subpath", () => {
    assert.equal(deriveHealthPath("/a/b/rss"), "/a/b/health");
  });

  it("ignores a trailing slash on RSS_PATH", () => {
    assert.equal(deriveHealthPath("/blabla/rss/"), "/blabla/health");
  });
});
