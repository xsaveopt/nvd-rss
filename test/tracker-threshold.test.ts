import assert from "node:assert/strict";
import { after, before, describe, it, mock } from "node:test";
import { mockFeed, silenceConsole } from "./helpers.ts";

function cveWithScore(id: string, baseScore: number) {
  return {
    cve: {
      id,
      descriptions: [{ lang: "en", value: "A flaw." }],
      metrics: { cvssMetricV31: [{ cvssData: { baseScore } }] },
    },
  };
}

describe("CVSS_THRESHOLD", () => {
  let rss = "";

  before(async () => {
    process.env.CVSS_THRESHOLD = "5.5";
    silenceConsole();
    mockFeed({
      timestamp: "2026-07-12T00:00:00.000",
      vulnerabilities: [
        cveWithScore("CVE-2026-4001", 5.5),
        cveWithScore("CVE-2026-4002", 6.1),
        cveWithScore("CVE-2026-4003", 5.4),
      ],
    });

    const tracker = await import("../src/tracker.ts");
    await tracker.updateFeed();
    rss = tracker.getRSS();
  });

  after(() => {
    mock.restoreAll();
    delete process.env.CVSS_THRESHOLD;
  });

  it("keeps CVEs at or above the configured threshold", () => {
    assert.match(rss, /CVE-2026-4001/);
    assert.match(rss, /CVE-2026-4002/);
  });

  it("drops CVEs below the configured threshold", () => {
    assert.doesNotMatch(rss, /CVE-2026-4003/);
  });

  it("names the configured threshold in the channel", () => {
    assert.match(rss, /<title>NVD CVE Feed \(CVSS >= 5\.5\)<\/title>/);
    assert.match(rss, /<description>NVD Vulnerabilities with Score >= 5\.5<\/description>/);
  });
});
