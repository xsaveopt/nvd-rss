import assert from "node:assert/strict";
import { after, before, describe, it, mock } from "node:test";
import express from "express";
import type { RunningServer } from "./helpers.ts";
import { updateFeed } from "../src/tracker.ts";
import { listen, mockFeed, silenceConsole } from "./helpers.ts";

const realFetch = globalThis.fetch.bind(globalThis);

function langflow(id: string, score: number, rest: string) {
  return {
    cve: {
      id,
      published: "2026-10-07T01:16:32.837",
      sourceIdentifier: "psirt@acme.test",
      descriptions: [
        { lang: "en", value: `Acme Flow 1.0.0 through 1.12.2 could allow a remote ${rest}` },
      ],
      metrics: { cvssMetricV31: [{ cvssData: { baseScore: score } }] },
      weaknesses: [{ description: [{ lang: "en", value: "CWE-94" }] }],
    },
  };
}

describe("grouped CVEs under a subpath", () => {
  let server: RunningServer;
  let rss = "";

  before(async () => {
    process.env.RSS_PATH = "/nvd/rss/";
    silenceConsole();
    mockFeed({
      vulnerabilities: [
        langflow("CVE-2026-7001", 8.1, "attacker to read <secret> files."),
        langflow("CVE-2026-7002", 9.8, "authenticated attacker to execute arbitrary code."),
        {
          cve: {
            id: "CVE-2026-7003",
            published: "2026-10-07T01:16:32.837",
            sourceIdentifier: "psirt@acme.test",
            descriptions: [{ lang: "en", value: "Other Thing before 2.0 allows takeover." }],
            metrics: { cvssMetricV31: [{ cvssData: { baseScore: 9 } }] },
          },
        },
      ],
    });
    await updateFeed();
    mock.restoreAll();

    const routes = (await import("../src/routes.ts")).default;
    const app = express();
    app.use("/", routes);
    server = await listen(app);
    rss = await (await realFetch(`${server.url}/nvd/rss/`)).text();
  });

  after(async () => {
    await server.close();
    delete process.env.RSS_PATH;
  });

  it("collapses the similar CVEs into one item", () => {
    assert.equal(rss.split("<item>").length - 1, 2);
    assert.match(rss, /<title>\[9\.8\] Acme Flow: 2 vulnerabilities<\/title>/);
    assert.match(rss, /<guid isPermaLink="false">group-2026-10-07-acme-flow-acme<\/guid>/);
    assert.match(rss, /<title>\[9\] Other Thing: /);
  });

  it("links the item to the group page under the subpath", () => {
    const link = `${server.url}/nvd/rss/group/2026-10-07-acme-flow-acme`;
    assert.match(rss, new RegExp(`<link>${link}</link>`));
    assert.ok(rss.includes(`href=&quot;${link}&quot;`));
    assert.ok(!rss.includes("\u0000"));
  });

  it("lists each CVE with its reason in the item description", () => {
    assert.match(rss, /CVE-2026-7002&lt;\/a&gt; \[9\.8\] \.\.\.authenticated attacker/);
    assert.match(rss, /\.\.\.attacker to read &amp;lt;secret&amp;gt; files\./);
  });

  it("uses the forwarded host and protocol for the link", async () => {
    const body = await (
      await realFetch(`${server.url}/nvd/rss`, {
        headers: { "X-Forwarded-Proto": "https", "X-Forwarded-Host": "feeds.example.test" },
      })
    ).text();

    assert.match(
      body,
      /<link>https:\/\/feeds\.example\.test\/nvd\/rss\/group\/2026-10-07-acme-flow-acme<\/link>/,
    );
  });

  it("serves the group page", async () => {
    const response = await realFetch(`${server.url}/nvd/rss/group/2026-10-07-acme-flow-acme`);
    const html = await response.text();

    assert.equal(response.status, 200);
    assert.match(response.headers.get("content-type") ?? "", /text\/html/);
    assert.match(html, /<h1>Acme Flow<\/h1>/);
    assert.match(html, /2 vulnerabilities published 2026-10-07 by Acme, highest 9\.8 Critical/);
    assert.match(
      html,
      /Every entry starts with: Acme Flow 1\.0\.0 through 1\.12\.2 could allow a remote \.\.\./,
    );
    assert.match(html, /href="https:\/\/nvd\.nist\.gov\/vuln\/detail\/CVE-2026-7002"/);
    assert.match(html, /\.\.\.attacker to read &lt;secret&gt; files\./);
    assert.doesNotMatch(html, /<secret>/);
    assert.ok(html.indexOf("CVE-2026-7002") < html.indexOf("CVE-2026-7001"));
  });

  it("answers 404 for a group that is not in the feed", async () => {
    const response = await realFetch(`${server.url}/nvd/rss/group/nope`);
    await response.text();

    assert.equal(response.status, 404);
  });
});
