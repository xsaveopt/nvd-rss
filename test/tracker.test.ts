import assert from "node:assert/strict";
import { gzipSync } from "node:zlib";
import { afterEach, describe, it, mock } from "node:test";
import { getRSS, updateFeed } from "../src/tracker.ts";

const sampleFeed = {
  timestamp: "2026-07-12T00:00:00.000",
  vulnerabilities: [
    {
      cve: {
        id: "CVE-2026-0001",
        published: "2026-07-11T12:00:00.000",
        sourceIdentifier: "cve@mitre.org",
        descriptions: [{ lang: "en", value: "A critical flaw allows remote code execution." }],
        metrics: {
          cvssMetricV31: [{ cvssData: { baseScore: 9.8 } }],
        },
      },
    },
    {
      cve: {
        id: "CVE-2026-0002",
        descriptions: [{ lang: "en", value: "A low severity issue." }],
        metrics: {
          cvssMetricV31: [{ cvssData: { baseScore: 3.1 } }],
        },
      },
    },
  ],
};

function mockFeed(feed: unknown): void {
  const gz = gzipSync(Buffer.from(JSON.stringify(feed)));
  mock.method(
    globalThis,
    "fetch",
    async () =>
      ({
        ok: true,
        arrayBuffer: async () => gz.buffer.slice(gz.byteOffset, gz.byteOffset + gz.byteLength),
      }) as unknown as Response,
  );
}

describe("tracker", () => {
  afterEach(() => {
    mock.restoreAll();
  });

  it("returns an empty feed before the first refresh", () => {
    assert.equal(getRSS(), "");
  });

  it("builds an RSS feed from a mocked NVD response", async () => {
    mockFeed(sampleFeed);

    await updateFeed();

    const rss = getRSS();
    assert.match(rss, /<rss version="2\.0">/);
    assert.match(rss, /CVE-2026-0001/);
    assert.match(rss, /CVSS 9\.8/);
  });

  it("filters out CVEs below the CVSS threshold", async () => {
    mockFeed(sampleFeed);

    await updateFeed();

    const rss = getRSS();
    assert.doesNotMatch(rss, /CVE-2026-0002/);
  });
});
