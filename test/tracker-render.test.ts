import assert from "node:assert/strict";
import { afterEach, beforeEach, describe, it, mock } from "node:test";
import { getRSS, updateFeed } from "../src/tracker.ts";
import { mockFeed, silenceConsole } from "./helpers.ts";

function feedOf(...cves: unknown[]) {
  return {
    timestamp: "2026-07-12T00:00:00.000",
    vulnerabilities: cves.map((cve) => ({ cve })),
  };
}

function itemFor(rss: string, id: string): string | undefined {
  return rss
    .split("<item>")
    .slice(1)
    .find((item) => item.includes(`<guid isPermaLink="false">${id}</guid>`));
}

function tagIn(block: string, tag: string): string | undefined {
  return block.match(new RegExp(`<${tag}>([\\s\\S]*?)</${tag}>`))?.[1];
}

async function render(...cves: unknown[]): Promise<string> {
  mockFeed(feedOf(...cves));
  await updateFeed();
  return getRSS();
}

function scored(id: string, metrics: unknown) {
  return {
    id,
    descriptions: [{ lang: "en", value: "A flaw." }],
    metrics,
  };
}

describe("CVSS scoring in the feed", () => {
  beforeEach(() => {
    silenceConsole();
  });

  afterEach(() => {
    mock.restoreAll();
  });

  it("uses a CVSS v3.0 score when no v3.1 score exists", async () => {
    const rss = await render(
      scored("CVE-2026-2001", { cvssMetricV30: [{ cvssData: { baseScore: 8.6 } }] }),
    );

    const item = itemFor(rss, "CVE-2026-2001");
    assert.ok(item);
    assert.match(tagIn(item, "title") ?? "", /\(CVSS 8\.6\)/);
  });

  it("uses a CVSS v2 score when it is the only one", async () => {
    const rss = await render(
      scored("CVE-2026-2002", { cvssMetricV2: [{ cvssData: { baseScore: 10 } }] }),
    );

    const item = itemFor(rss, "CVE-2026-2002");
    assert.ok(item);
    assert.match(tagIn(item, "title") ?? "", /\(CVSS 10\)/);
  });

  it("reports the highest score across every version and metric", async () => {
    const rss = await render(
      scored("CVE-2026-2003", {
        cvssMetricV31: [{ cvssData: { baseScore: 7.5 } }, { cvssData: { baseScore: 8.1 } }],
        cvssMetricV30: [{ cvssData: { baseScore: 9.3 } }],
        cvssMetricV2: [{ cvssData: { baseScore: 6.8 } }],
      }),
    );

    const item = itemFor(rss, "CVE-2026-2003");
    assert.ok(item);
    assert.match(tagIn(item, "title") ?? "", /\(CVSS 9\.3\)/);
    assert.match(tagIn(item, "description") ?? "", /Max CVSS Score: 9\.3$/);
  });

  it("ignores metrics that carry no base score", async () => {
    const rss = await render(
      scored("CVE-2026-2004", {
        cvssMetricV31: [{}, { cvssData: {} }, { cvssData: { baseScore: 8.2 } }],
      }),
    );

    const item = itemFor(rss, "CVE-2026-2004");
    assert.ok(item);
    assert.match(tagIn(item, "title") ?? "", /\(CVSS 8\.2\)/);
  });

  it("drops CVEs without any metrics", async () => {
    const rss = await render(
      scored("CVE-2026-2005", undefined),
      scored("CVE-2026-2006", {}),
      scored("CVE-2026-2007", { cvssMetricV31: [] }),
    );

    assert.equal(itemFor(rss, "CVE-2026-2005"), undefined);
    assert.equal(itemFor(rss, "CVE-2026-2006"), undefined);
    assert.equal(itemFor(rss, "CVE-2026-2007"), undefined);
  });

  it("keeps a score exactly on the default 8.0 threshold and drops one just below", async () => {
    const rss = await render(
      scored("CVE-2026-2008", { cvssMetricV31: [{ cvssData: { baseScore: 8.0 } }] }),
      scored("CVE-2026-2009", { cvssMetricV31: [{ cvssData: { baseScore: 7.9 } }] }),
    );

    assert.ok(itemFor(rss, "CVE-2026-2008"));
    assert.equal(itemFor(rss, "CVE-2026-2009"), undefined);
    assert.match(rss, /<title>NVD CVE Feed \(CVSS >= 8\)<\/title>/);
  });

  it("skips entries that carry no cve object", async () => {
    mockFeed({
      timestamp: "2026-07-12T00:00:00.000",
      vulnerabilities: [
        {},
        { cve: scored("CVE-2026-2010", { cvssMetricV31: [{ cvssData: { baseScore: 9.0 } }] }) },
      ],
    });
    await updateFeed();

    const rss = getRSS();
    assert.equal(rss.split("<item>").length - 1, 1);
    assert.ok(itemFor(rss, "CVE-2026-2010"));
  });
});

describe("item rendering", () => {
  beforeEach(() => {
    silenceConsole();
  });

  afterEach(() => {
    mock.restoreAll();
  });

  const high = { cvssMetricV31: [{ cvssData: { baseScore: 9.0 } }] };

  it("keeps a description of exactly fifty characters whole in the title", async () => {
    const text = "x".repeat(50);
    const rss = await render({
      id: "CVE-2026-3001",
      descriptions: [{ lang: "en", value: text }],
      metrics: high,
    });

    const item = itemFor(rss, "CVE-2026-3001");
    assert.ok(item);
    assert.equal(tagIn(item, "title"), `CVE-2026-3001 (CVSS 9) – ${text}`);
  });

  it("cuts a longer description to fifty characters and adds an ellipsis", async () => {
    const text = `${"a".repeat(50)}bcdef`;
    const rss = await render({
      id: "CVE-2026-3002",
      descriptions: [{ lang: "en", value: text }],
      metrics: high,
    });

    const item = itemFor(rss, "CVE-2026-3002");
    assert.ok(item);
    assert.equal(tagIn(item, "title"), `CVE-2026-3002 (CVSS 9) – ${"a".repeat(50)}...`);
    assert.match(tagIn(item, "description") ?? "", new RegExp(`^${text} `));
  });

  it("uses the published date as pubDate", async () => {
    const rss = await render({
      id: "CVE-2026-3003",
      published: "2026-07-11T12:00:00.000Z",
      descriptions: [{ lang: "en", value: "A flaw." }],
      metrics: high,
    });

    const item = itemFor(rss, "CVE-2026-3003");
    assert.ok(item);
    assert.equal(tagIn(item, "pubDate"), "Sat, 11 Jul 2026 12:00:00 GMT");
  });

  it("falls back to the build time when the CVE has no published date", async () => {
    const rss = await render({
      id: "CVE-2026-3004",
      descriptions: [{ lang: "en", value: "A flaw." }],
      metrics: high,
    });

    const item = itemFor(rss, "CVE-2026-3004");
    assert.ok(item);
    const lastBuildDate = tagIn(rss, "lastBuildDate");
    assert.ok(lastBuildDate);
    assert.equal(tagIn(item, "pubDate"), lastBuildDate);
  });

  it("falls back to a placeholder when there is no English description", async () => {
    const rss = await render({
      id: "CVE-2026-3005",
      descriptions: [{ lang: "es", value: "Una falla." }],
      metrics: high,
    });

    const item = itemFor(rss, "CVE-2026-3005");
    assert.ok(item);
    assert.equal(tagIn(item, "title"), "CVE-2026-3005 (CVSS 9) – No description available");
    assert.match(tagIn(item, "description") ?? "", /^No description available /);
    assert.doesNotMatch(item, /Una falla/);
  });

  it("falls back to a placeholder when the descriptions are missing", async () => {
    const rss = await render({ id: "CVE-2026-3006", metrics: high });

    const item = itemFor(rss, "CVE-2026-3006");
    assert.ok(item);
    assert.match(tagIn(item, "description") ?? "", /^No description available /);
  });

  it("puts the escaped product names in the category", async () => {
    const rss = await render({
      id: "CVE-2026-3007",
      descriptions: [{ lang: "en", value: "The Foo & Bar plugin for WordPress is vulnerable." }],
      metrics: high,
      configurations: [
        { nodes: [{ cpeMatch: [{ criteria: "cpe:2.3:a:acme:super_widget:1.0:*:*:*:*:*:*:*" }] }] },
      ],
    });

    const item = itemFor(rss, "CVE-2026-3007");
    assert.ok(item);
    assert.equal(tagIn(item, "category"), "Foo &amp; Bar, Super Widget");
  });

  it("puts Unknown in the category when no product is found", async () => {
    const rss = await render({
      id: "CVE-2026-3008",
      descriptions: [{ lang: "en", value: "A flaw." }],
      metrics: high,
    });

    const item = itemFor(rss, "CVE-2026-3008");
    assert.ok(item);
    assert.equal(tagIn(item, "category"), "Unknown");
  });
});
