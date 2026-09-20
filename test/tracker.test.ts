import assert from "node:assert/strict";
import { afterEach, beforeEach, describe, it, mock } from "node:test";
import { gzipSync } from "node:zlib";
import {
  escapeXml,
  getProducts,
  getRSS,
  getSource,
  matchesProductFilter,
  updateFeed,
} from "../src/tracker.ts";
import { mockBody, mockFeed, mockNotOk, sampleFeed, silenceConsole } from "./helpers.ts";

describe("escapeXml", () => {
  it("returns an empty string for missing input", () => {
    assert.equal(escapeXml(undefined), "");
    assert.equal(escapeXml(""), "");
  });

  it("escapes every XML significant character", () => {
    assert.equal(
      escapeXml(`<tag attr="a" other='b'> & more`),
      "&lt;tag attr=&quot;a&quot; other=&apos;b&apos;&gt; &amp; more",
    );
  });

  it("leaves ordinary text untouched", () => {
    assert.equal(escapeXml("plain text 1.0"), "plain text 1.0");
  });
});

describe("getSource", () => {
  it("takes the domain of an email identifier", () => {
    assert.equal(getSource({ id: "CVE-1", sourceIdentifier: "cve@mitre.org" }), "Mitre");
  });

  it("takes the first label of a bare host identifier", () => {
    assert.equal(getSource({ id: "CVE-1", sourceIdentifier: "nvd.nist.gov" }), "Nvd");
  });

  it("capitalises an identifier with no separators", () => {
    assert.equal(getSource({ id: "CVE-1", sourceIdentifier: "github" }), "Github");
  });

  it("falls back to NIST when no identifier is present", () => {
    assert.equal(getSource({ id: "CVE-1" }), "NIST");
  });
});

describe("getProducts", () => {
  it("reads the product from CPE criteria and formats it", () => {
    const cve = {
      id: "CVE-1",
      configurations: [
        {
          nodes: [
            {
              cpeMatch: [
                { criteria: "cpe:2.3:a:acme:super_widget:1.0:*:*:*:*:*:*:*" },
                { criteria: "cpe:2.3:a:acme:other_thing:2.0:*:*:*:*:*:*:*" },
              ],
            },
          ],
        },
      ],
    };

    assert.equal(getProducts(cve, ""), "Super Widget, Other Thing");
  });

  it("ignores CPE criteria with too few segments", () => {
    const cve = {
      id: "CVE-1",
      configurations: [{ nodes: [{ cpeMatch: [{ criteria: "cpe:2.3:a:acme" }] }] }],
    };

    assert.equal(getProducts(cve, ""), "Unknown");
  });

  it("deduplicates repeated CPE products and caps the list at two", () => {
    const cve = {
      id: "CVE-1",
      configurations: [
        {
          nodes: [
            {
              cpeMatch: [
                { criteria: "cpe:2.3:a:acme:alpha:1.0:*:*:*:*:*:*:*" },
                { criteria: "cpe:2.3:a:acme:alpha:2.0:*:*:*:*:*:*:*" },
                { criteria: "cpe:2.3:a:acme:beta:1.0:*:*:*:*:*:*:*" },
                { criteria: "cpe:2.3:a:acme:gamma:1.0:*:*:*:*:*:*:*" },
              ],
            },
          ],
        },
      ],
    };

    assert.equal(getProducts(cve, ""), "Alpha, Beta");
  });

  it("keeps a CPE product even when the node has no cpeMatch", () => {
    const cve = {
      id: "CVE-1",
      configurations: [
        { nodes: [{}] },
        {},
        {
          nodes: [{ cpeMatch: [{ criteria: "cpe:2.3:a:acme:lone_product:1.0:*:*:*:*:*:*:*" }] }],
        },
      ],
    };

    assert.equal(getProducts(cve, ""), "Lone Product");
  });

  it("prefers a named product from the description", () => {
    const cve = { id: "CVE-1" };
    const description = "The Contact Form plugin for WordPress is vulnerable to injection.";

    assert.equal(getProducts(cve, description), "Contact Form");
  });

  it("reads the repository name from a GitHub reference", () => {
    const cve = {
      id: "CVE-1",
      references: [{ url: "https://github.com/acme/widget-core/security/advisories/GHSA-x" }],
    };

    assert.equal(getProducts(cve, ""), "widget-core");
  });

  it("drops linux kernel when another candidate exists", () => {
    const cve = {
      id: "CVE-1",
      configurations: [
        {
          nodes: [
            {
              cpeMatch: [
                { criteria: "cpe:2.3:o:linux:linux_kernel:6.1:*:*:*:*:*:*:*" },
                { criteria: "cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*" },
              ],
            },
          ],
        },
      ],
    };

    assert.equal(getProducts(cve, ""), "Widget");
  });

  it("keeps linux kernel when it is the only candidate", () => {
    const cve = {
      id: "CVE-1",
      configurations: [
        { nodes: [{ cpeMatch: [{ criteria: "cpe:2.3:o:linux:linux_kernel:6.1:*:*:*:*:*:*:*" }] }] },
      ],
    };

    assert.equal(getProducts(cve, ""), "Linux Kernel");
  });

  it("returns Unknown when nothing identifies a product", () => {
    assert.equal(getProducts({ id: "CVE-1" }, "A flaw was found."), "Unknown");
  });
});

describe("matchesProductFilter", () => {
  const cve = {
    id: "CVE-1",
    configurations: [
      {
        nodes: [{ cpeMatch: [{ criteria: "cpe:2.3:a:wordpress:contact_form:1.0:*:*:*:*:*:*:*" }] }],
      },
    ],
  };

  it("matches case insensitively on the CPE criteria", () => {
    assert.equal(matchesProductFilter(cve, "WordPress"), true);
    assert.equal(matchesProductFilter(cve, "contact_form"), true);
  });

  it("does not match an unrelated filter", () => {
    assert.equal(matchesProductFilter(cve, "drupal"), false);
  });

  it("returns false when the CVE has no configurations", () => {
    assert.equal(matchesProductFilter({ id: "CVE-1" }, "wordpress"), false);
  });

  it("returns false when nodes or matches are missing", () => {
    assert.equal(matchesProductFilter({ id: "CVE-1", configurations: [{}] }, "wordpress"), false);
    assert.equal(
      matchesProductFilter({ id: "CVE-1", configurations: [{ nodes: [{}] }] }, "wordpress"),
      false,
    );
    assert.equal(
      matchesProductFilter(
        { id: "CVE-1", configurations: [{ nodes: [{ cpeMatch: [{}] }] }] },
        "wordpress",
      ),
      false,
    );
  });
});

describe("updateFeed", () => {
  beforeEach(() => {
    silenceConsole();
  });

  afterEach(() => {
    mock.restoreAll();
  });

  it("builds an RSS feed from a mocked NVD response", async () => {
    mockFeed(sampleFeed);

    await updateFeed();

    const rss = getRSS();
    assert.match(rss, /<rss version="2\.0">/);
    assert.match(rss, /CVE-2026-0001/);
    assert.match(rss, /CVSS 9\.8/);
    assert.match(rss, /<author>Mitre<\/author>/);
    assert.match(rss, /<link>https:\/\/nvd\.nist\.gov\/vuln\/detail\/CVE-2026-0001<\/link>/);
  });

  it("filters out CVEs below the CVSS threshold", async () => {
    mockFeed(sampleFeed);

    await updateFeed();

    assert.doesNotMatch(getRSS(), /CVE-2026-0002/);
  });

  it("escapes markup coming from the NVD description", async () => {
    mockFeed({
      timestamp: "2026-07-12T00:00:00.000",
      vulnerabilities: [
        {
          cve: {
            id: "CVE-2026-0003",
            descriptions: [{ lang: "en", value: `<script>alert("xss" & 'more')</script>` }],
            metrics: { cvssMetricV31: [{ cvssData: { baseScore: 9.1 } }] },
          },
        },
      ],
    });

    await updateFeed();

    const rss = getRSS();
    assert.doesNotMatch(rss, /<script>/);
    assert.match(rss, /&lt;script&gt;/);
    assert.match(rss, /&quot;xss&quot;/);
    assert.match(rss, /&apos;more&apos;/);
  });

  it("keeps the previous feed when the response is not ok", async () => {
    mockFeed(sampleFeed);
    await updateFeed();
    const before = getRSS();
    mock.restoreAll();

    const logs = silenceConsole();
    mockNotOk("Service Unavailable");
    await updateFeed();

    assert.equal(getRSS(), before);
    assert.ok(logs.errorCalls() >= 1);
  });

  it("keeps the previous feed when the body is not gzipped", async () => {
    mockFeed(sampleFeed);
    await updateFeed();
    const before = getRSS();
    mock.restoreAll();

    const logs = silenceConsole();
    mockBody(Buffer.from("this is not gzip"));
    await updateFeed();

    assert.equal(getRSS(), before);
    assert.ok(logs.errorCalls() >= 1);
  });

  it("keeps the previous feed when the payload is not valid JSON", async () => {
    mockFeed(sampleFeed);
    await updateFeed();
    const before = getRSS();
    mock.restoreAll();

    const logs = silenceConsole();
    mockBody(gzipSync(Buffer.from("{ not json")));
    await updateFeed();

    assert.equal(getRSS(), before);
    assert.ok(logs.errorCalls() >= 1);
  });

  it("keeps the previous feed when the payload has no vulnerabilities", async () => {
    mockFeed(sampleFeed);
    await updateFeed();
    const before = getRSS();

    mockFeed({ timestamp: "2026-07-12T00:00:00.000" });
    await updateFeed();

    assert.equal(getRSS(), before);
  });

  it("keeps the previous feed when fetch itself rejects", async () => {
    mockFeed(sampleFeed);
    await updateFeed();
    const before = getRSS();
    mock.restoreAll();

    const logs = silenceConsole();
    mock.method(globalThis, "fetch", async () => {
      throw new Error("network down");
    });
    await updateFeed();

    assert.equal(getRSS(), before);
    assert.ok(logs.errorCalls() >= 1);
  });
});
