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

  it("uses the domain when the local part is empty", () => {
    assert.equal(getSource({ id: "CVE-1", sourceIdentifier: "@mitre.org" }), "Mitre");
  });

  it("never leaks the separator when the domain part is empty", () => {
    assert.equal(getSource({ id: "CVE-1", sourceIdentifier: "cve@" }), "Cve");
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

    assert.equal(getProducts(cve, ""), "Acme Super Widget, Acme Other Thing");
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

    assert.equal(getProducts(cve, ""), "Acme Alpha, Acme Beta");
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

    assert.equal(getProducts(cve, ""), "Acme Lone Product");
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

    assert.equal(getProducts(cve, ""), "Acme Widget");
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

  it("reads the theme name from a WordPress theme description", () => {
    const description = "The Starter Blocks theme for WordPress is vulnerable to injection.";

    assert.equal(getProducts({ id: "CVE-1" }, description), "Starter Blocks");
  });

  it("reads the product that opens a developed by description", () => {
    const description = "WidgetShop developed by Acme has an authentication bypass.";

    assert.equal(getProducts({ id: "CVE-1" }, description), "WidgetShop");
  });

  it("reads the product after vulnerability in and drops a leading the", () => {
    const description = "A vulnerability in the Acme Router allows remote attackers to reboot it.";

    assert.equal(getProducts({ id: "CVE-1" }, description), "Acme Router");
  });

  it("stops the vulnerability in product at a version keyword", () => {
    const description = "A vulnerability in Widget Server version 2.1 exposes secrets.";

    assert.equal(getProducts({ id: "CVE-1" }, description), "Widget Server");
  });

  it("stops the vulnerability in product at a full stop", () => {
    const description = "There is a vulnerability in Acme Portal. Attackers can read files.";

    assert.equal(getProducts({ id: "CVE-1" }, description), "Acme Portal");
  });

  it("stops the vulnerability in product at the end of the text", () => {
    assert.equal(getProducts({ id: "CVE-1" }, "Found a vulnerability in Acme Hub"), "Acme Hub");
  });

  it("rejects a description candidate of fifty characters or more", () => {
    const name = "A".repeat(50);
    const description = `The ${name} plugin for WordPress is vulnerable.`;

    assert.equal(getProducts({ id: "CVE-1" }, description), "Unknown");
  });

  it("rejects a description candidate that mentions vulnerability", () => {
    const description = "The Vulnerability Scanner plugin for WordPress is vulnerable.";

    assert.equal(getProducts({ id: "CVE-1" }, description), "Unknown");
  });

  it("prefers vulnerable CPE products over description and GitHub guesses", () => {
    const cve = {
      id: "CVE-1",
      references: [{ url: "https://github.com/acme/widget-core/issues/1" }],
      configurations: [
        { nodes: [{ cpeMatch: [{ criteria: "cpe:2.3:a:acme:super_widget:1.0:*:*:*:*:*:*:*" }] }] },
      ],
    };
    const description = "The Contact Form plugin for WordPress is vulnerable.";

    assert.equal(getProducts(cve, description), "Acme Super Widget");
  });

  it("prefers the description over a GitHub repository", () => {
    const cve = { id: "CVE-1", references: [{ url: "https://github.com/acme/widget-core" }] };

    assert.equal(getProducts(cve, "A flaw was found in libwidget."), "libwidget");
  });

  it("skips GitHub advisory and security repositories", () => {
    const cve = {
      id: "CVE-1",
      references: [
        { url: "https://github.com/advisories/GHSA-xxxx" },
        { url: "https://github.com/acme/security-advisories/blob/main/a.md" },
        { url: "https://github.com/acme/widget-core/pull/2" },
      ],
    };

    assert.equal(getProducts(cve, ""), "widget-core");
  });

  it("uses platform CPE entries only when nothing else names a product", () => {
    const cve = {
      id: "CVE-1",
      configurations: [
        {
          nodes: [
            {
              cpeMatch: [
                { vulnerable: false, criteria: "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*" },
              ],
            },
          ],
        },
      ],
    };

    assert.equal(getProducts(cve, "Acme Agent before 2.1 allows code execution."), "Acme Agent");
    assert.equal(getProducts(cve, ""), "Microsoft Windows");
  });

  for (const [description, product] of [
    [
      "A weakness has been identified in Acme SurfBoard up to 2.0.3. The element is",
      "Acme SurfBoard",
    ],
    ["A flaw was found in libwidget. The parser reads past the end.", "libwidget"],
    ["Widgetd before 2.1.31 contains an OS command injection.", "Widgetd"],
    [
      "Acme Gateway (AG) Policy Manager, versions prior to 5.34, contains a flaw.",
      "Acme Gateway (AG) Policy Manager",
    ],
    [
      "Use after free in Aura in Acme Browser prior to 154.0.8 allowed a remote attacker.",
      "Acme Browser",
    ],
    [
      "Incorrect calculation in API in Acme Browser on on Windows prior to 155.0 allowed it.",
      "Acme Browser",
    ],
    [
      "Unauthenticated SQL Injection in Acme Members Premium <= 7.8 versions.",
      "Acme Members Premium",
    ],
    [
      "Flatstore is an open source file storage library for PHP. Prior to 3.35.3 it fails.",
      "Flatstore",
    ],
    ["simple-widget, an interface for running widgets, enables injection.", "simple-widget"],
    [
      "Use-after-free in the Widget component. This vulnerability was fixed in Acmefox ESR 153.4.",
      "Acmefox ESR",
    ],
    [
      "The Acme GPU Display Driver for Linux contains a vulnerability in the driver.",
      "Acme GPU Display Driver for Linux",
    ],
    [
      "Uncontrolled Recursion in Acmesearch can allow an authenticated user to crash it.",
      "Acmesearch",
    ],
    [
      "In the Linux kernel, the following vulnerability has been resolved: mmc: fix it.",
      "Linux kernel",
    ],
    [
      "The Acme Fusion Lite WordPress plugin before 3.48.0 does not check capabilities.",
      "Acme Fusion Lite",
    ],
    [
      "The Super Forms – Drag & Drop Form Builder plugin for WordPress is vulnerable.",
      "Super Forms",
    ],
    ["In sshd in AcmeSSH before 10.6, the restrict keyword was ignored.", "AcmeSSH"],
    ["Acmesoft has discovered a stored XSS vulnerability.", "Unknown"],
    ["Profile import crash in 4.6.0 to 4.6.8 allows denial of service.", "Unknown"],
    [
      "On affected versions of Acme Portal (on-premises) or Acme Sensor, a path traversal exists.",
      "Acme Portal",
    ],
    ["On affected devices the web server allows code execution.", "Unknown"],
    [
      "A vulnerability in the API endpoint of Acme Instant APs could allow an attacker to read files.",
      "Acme Instant APs",
    ],
    ["A vulnerability in the kernel mode layer where a user can crash it.", "Unknown"],
    ["widgetdb is a research data system developed by Acme. Prior to 2.0 it leaks.", "Unknown"],
  ]) {
    it(`reads ${product} from "${description.slice(0, 40)}..."`, () => {
      assert.equal(getProducts({ id: "CVE-1" }, description), product);
    });
  }

  it("never reads all from an in all versions phrase", () => {
    const description =
      "The Very Long Appointment Booking Plugin Name That Keeps Going Forever for WordPress plugin for WordPress is vulnerable in all versions up to 5.7.0.";

    assert.equal(getProducts({ id: "CVE-1" }, description), "Unknown");
  });

  it("ignores references that are not a GitHub repository", () => {
    const cve = {
      id: "CVE-1",
      references: [
        { url: "https://example.test/advisory" },
        { url: "https://github.com/acme" },
        {},
      ],
    };

    assert.equal(getProducts(cve, ""), "Unknown");
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
    assert.match(rss, /<rss version="2\.0" xmlns:dc="http:\/\/purl\.org\/dc\/elements\/1\.1\/">/);
    assert.match(rss, /CVE-2026-0001/);
    assert.match(rss, /Critical 9\.8/);
    assert.match(rss, /<dc:creator>Mitre<\/dc:creator>/);
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
