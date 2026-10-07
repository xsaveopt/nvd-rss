import assert from "node:assert/strict";
import { gzipSync } from "node:zlib";
import { afterEach, beforeEach, describe, it, mock } from "node:test";
import { affectedProducts, formatAffected, resolveProducts } from "../src/cveorg.ts";
import { getRSS, updateFeed } from "../src/tracker.ts";
import { silenceConsole, toArrayBuffer } from "./helpers.ts";

function record(affected: unknown[]) {
  return { ok: true, status: 200, json: async () => ({ containers: { cna: { affected } } }) };
}

function mockRecords(records: Record<string, unknown>) {
  return mock.method(globalThis, "fetch", async (url: string) => {
    const id = String(url).split("/").pop() ?? "";
    return (records[id] ?? { ok: false, status: 404, statusText: "Not Found" }) as Response;
  });
}

describe("formatAffected", () => {
  it("joins the vendor and product", () => {
    assert.equal(formatAffected("Kiteworks", "Core"), "Kiteworks Core");
  });

  it("keeps the product alone when it already names the vendor", () => {
    assert.equal(formatAffected("MediaTek, Inc.", "MediaTek chipset"), "MediaTek chipset");
    assert.equal(
      formatAffected("Apache Software Foundation", "Apache DolphinScheduler"),
      "Apache DolphinScheduler",
    );
  });

  it("skips placeholder values", () => {
    assert.equal(formatAffected("n/a", "Widget"), "Widget");
    assert.equal(formatAffected("Acme", "n/a"), "");
    assert.equal(formatAffected(undefined, undefined), "");
  });
});

describe("resolveProducts", () => {
  beforeEach(() => {
    silenceConsole();
  });

  afterEach(() => {
    mock.restoreAll();
  });

  it("looks up each CVE once and caches the result", async () => {
    const fetchMock = mockRecords({
      "CVE-1": record([
        { vendor: "Toptech Systems", product: "TMS7" },
        { vendor: "Toptech Systems", product: "TMS7" },
        { vendor: "Toptech Systems", product: "TopHAT" },
        { vendor: "Toptech Systems", product: "Third" },
      ]),
      "CVE-2": record([{ vendor: "n/a", product: "n/a" }]),
    });

    await resolveProducts(["CVE-1", "CVE-2", "CVE-3"]);
    await resolveProducts(["CVE-1", "CVE-2", "CVE-3"]);

    assert.equal(fetchMock.mock.callCount(), 3);
    assert.equal(affectedProducts("CVE-1"), "Toptech Systems TMS7, Toptech Systems TopHAT");
    assert.equal(affectedProducts("CVE-2"), undefined);
    assert.equal(affectedProducts("CVE-3"), undefined);
  });

  it("retries a lookup that failed and drops ids that left the feed", async () => {
    const logs = silenceConsole();
    mock.method(globalThis, "fetch", async () => {
      throw new Error("network down");
    });
    await resolveProducts(["CVE-1", "CVE-4"]);
    assert.ok(logs.errorCalls() >= 1);
    mock.restoreAll();

    const fetchMock = mockRecords({ "CVE-4": record([{ vendor: "Acme", product: "Router" }]) });
    await resolveProducts(["CVE-4"]);

    assert.equal(fetchMock.mock.callCount(), 1);
    assert.equal(affectedProducts("CVE-4"), "Acme Router");
    assert.equal(affectedProducts("CVE-1"), undefined);
  });
});

describe("feed items without a product in the NVD data", () => {
  beforeEach(() => {
    silenceConsole();
  });

  afterEach(() => {
    mock.restoreAll();
  });

  it("lead with the product from the CVE.org record", async () => {
    const feed = {
      vulnerabilities: [
        {
          cve: {
            id: "CVE-2026-6001",
            descriptions: [{ lang: "en", value: "The file export endpoint leaks data." }],
            metrics: { cvssMetricV31: [{ cvssData: { baseScore: 10 } }] },
          },
        },
        {
          cve: {
            id: "CVE-2026-6002",
            descriptions: [{ lang: "en", value: "Acme Router before 2.1 allows takeover." }],
            metrics: { cvssMetricV31: [{ cvssData: { baseScore: 9 } }] },
          },
        },
      ],
    };
    const body = toArrayBuffer(gzipSync(Buffer.from(JSON.stringify(feed))));
    const lookups: string[] = [];
    mock.method(globalThis, "fetch", async (url: string) => {
      if (String(url).endsWith(".json.gz")) {
        return { ok: true, arrayBuffer: async () => body } as unknown as Response;
      }
      lookups.push(String(url));
      return record([{ vendor: "Toptech Systems", product: "TMS7" }]) as unknown as Response;
    });

    await updateFeed();

    assert.deepEqual(lookups, ["https://cveawg.mitre.org/api/cve/CVE-2026-6001"]);
    const rss = getRSS();
    assert.match(
      rss,
      /<title>\[10\] Toptech Systems TMS7: The file export endpoint leaks data\.<\/title>/,
    );
    assert.match(rss, /<category>Toptech Systems TMS7<\/category>/);
    assert.match(rss, /<title>\[9\] Acme Router: /);
  });
});
