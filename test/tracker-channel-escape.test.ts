import assert from "node:assert/strict";
import { after, before, describe, it, mock } from "node:test";
import { mockFeed, silenceConsole } from "./helpers.ts";

describe("channel metadata escaping", () => {
  let rss = "";

  before(async () => {
    process.env.NVD_FEED_URL = "https://feeds.example.test/nvd.json.gz?a=1&b=2";
    process.env.PRODUCT_FILTER = "acme&<co>";
    silenceConsole();
    mockFeed({
      timestamp: "2026-07-12T00:00:00.000",
      vulnerabilities: [
        {
          cve: {
            id: "CVE-2026-5001",
            descriptions: [{ lang: "en", value: "A flaw." }],
            metrics: { cvssMetricV31: [{ cvssData: { baseScore: 9.0 } }] },
            configurations: [
              { nodes: [{ cpeMatch: [{ criteria: "cpe:2.3:a:acme&<co>:widget:1.0:*:*:*" }] }] },
            ],
          },
        },
      ],
    });

    const tracker = await import("../src/tracker.ts");
    await tracker.updateFeed();
    rss = tracker.getRSS();
  });

  after(() => {
    mock.restoreAll();
    delete process.env.NVD_FEED_URL;
    delete process.env.PRODUCT_FILTER;
  });

  it("escapes the feed URL in the channel link", () => {
    assert.match(rss, /<link>https:\/\/feeds\.example\.test\/nvd\.json\.gz\?a=1&amp;b=2<\/link>/);
    assert.doesNotMatch(rss, /a=1&b=2/);
  });

  it("escapes the product filter in the channel description", () => {
    assert.match(rss, /\(Product: acme&amp;&lt;co&gt;\)<\/description>/);
    assert.doesNotMatch(rss, /acme&<co>/);
  });

  it("still includes the matching CVE", () => {
    assert.match(rss, /CVE-2026-5001/);
  });
});
