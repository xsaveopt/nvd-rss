import assert from "node:assert/strict";
import { after, describe, it, mock } from "node:test";
import { setTimeout as delay } from "node:timers/promises";
import { getRSS, startTracking } from "../src/tracker.ts";
import { mockFeed, sampleFeed, silenceConsole, waitFor } from "./helpers.ts";

describe("startTracking", () => {
  after(() => {
    mock.timers.reset();
    mock.restoreAll();
  });

  it("refreshes once immediately and then on every interval", async () => {
    silenceConsole();
    const fetchMock = mockFeed(sampleFeed);
    mock.timers.enable({ apis: ["setInterval"] });

    startTracking(5);

    await waitFor(() => getRSS() !== "");
    assert.equal(fetchMock.mock.callCount(), 1);
    assert.match(getRSS(), /CVE-2026-0001/);

    mock.timers.tick(4 * 60 * 1000);
    await delay(20);
    assert.equal(fetchMock.mock.callCount(), 1);

    mock.timers.tick(60 * 1000);
    await waitFor(() => fetchMock.mock.callCount() === 2);

    mock.timers.tick(5 * 60 * 1000);
    await waitFor(() => fetchMock.mock.callCount() === 3);
  });
});
