import assert from "node:assert/strict";
import { after, describe, it, mock } from "node:test";
import { setTimeout as delay } from "node:timers/promises";
import { getRSS, startTracking } from "../src/tracker.ts";
import { mockNvd, sampleFeed, silenceConsole, waitFor } from "./helpers.ts";

describe("startTracking", () => {
  after(() => {
    mock.timers.reset();
    mock.restoreAll();
  });

  it("refreshes once immediately and then on every interval", async () => {
    silenceConsole();
    const fetchMock = mockNvd(sampleFeed, [
      { name: "MITRE", sourceIdentifiers: ["cve@mitre.org"] },
    ]);
    const calls = (kind: string) =>
      fetchMock.mock.calls.filter((call) => String(call.arguments[0]).includes(kind)).length;
    mock.timers.enable({ apis: ["setInterval"] });

    startTracking(5);

    await waitFor(() => getRSS() !== "");
    assert.equal(calls(".json.gz"), 1);
    assert.equal(calls("/source/"), 1);
    assert.match(getRSS(), /CVE-2026-0001/);
    assert.match(getRSS(), /<dc:creator>MITRE<\/dc:creator>/);

    mock.timers.tick(4 * 60 * 1000);
    await delay(20);
    assert.equal(calls(".json.gz"), 1);

    mock.timers.tick(60 * 1000);
    await waitFor(() => calls(".json.gz") === 2);

    mock.timers.tick(5 * 60 * 1000);
    await waitFor(() => calls(".json.gz") === 3);
    assert.equal(calls("/source/"), 1);
  });
});
