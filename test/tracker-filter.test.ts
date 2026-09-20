import assert from "node:assert/strict";
import { after, before, describe, it, mock } from "node:test";
import { mockFeed, silenceConsole } from "./helpers.ts";

const filteredFeed = {
  timestamp: "2026-07-12T00:00:00.000",
  vulnerabilities: [
    {
      cve: {
        id: "CVE-2026-1001",
        descriptions: [{ lang: "en", value: "A WordPress plugin flaw." }],
        metrics: { cvssMetricV31: [{ cvssData: { baseScore: 9.4 } }] },
        configurations: [
          {
            nodes: [
              { cpeMatch: [{ criteria: "cpe:2.3:a:wordpress:contact_form:1.0:*:*:*:*:*:*:*" }] },
            ],
          },
        ],
      },
    },
    {
      cve: {
        id: "CVE-2026-1002",
        descriptions: [{ lang: "en", value: "A Drupal module flaw." }],
        metrics: { cvssMetricV31: [{ cvssData: { baseScore: 9.6 } }] },
        configurations: [
          { nodes: [{ cpeMatch: [{ criteria: "cpe:2.3:a:drupal:core:10.0:*:*:*:*:*:*:*" }] }] },
        ],
      },
    },
  ],
};

describe("PRODUCT_FILTER", () => {
  let rss = "";

  before(async () => {
    process.env.PRODUCT_FILTER = "wordpress";
    silenceConsole();
    mockFeed(filteredFeed);

    const tracker = await import("../src/tracker.ts");
    await tracker.updateFeed();
    rss = tracker.getRSS();
  });

  after(() => {
    mock.restoreAll();
    delete process.env.PRODUCT_FILTER;
  });

  it("keeps CVEs whose CPE criteria match the filter", () => {
    assert.match(rss, /CVE-2026-1001/);
  });

  it("drops CVEs that do not match the filter", () => {
    assert.doesNotMatch(rss, /CVE-2026-1002/);
  });

  it("names the filter in the channel description", () => {
    assert.match(rss, /\(Product: wordpress\)/);
  });
});
