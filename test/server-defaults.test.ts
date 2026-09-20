import assert from "node:assert/strict";
import { Server } from "node:http";
import { after, before, describe, it, mock } from "node:test";
import { mockFeed, sampleFeed, silenceConsole, waitFor } from "./helpers.ts";
import { getRSS } from "../src/tracker.ts";

const realSetInterval = globalThis.setInterval;
const realListen = Server.prototype.listen;

const intervals: number[] = [];
const listenCalls: unknown[][] = [];

describe("server defaults", () => {
  before(async () => {
    delete process.env.PORT;
    delete process.env.UPDATE_INTERVAL_MINUTES;
    silenceConsole();
    mockFeed(sampleFeed);

    globalThis.setInterval = ((_handler: () => void, ms?: number) => {
      intervals.push(ms ?? 0);
      return { ref: () => {}, unref: () => {} };
    }) as unknown as typeof globalThis.setInterval;

    Server.prototype.listen = function (this: Server, ...args: unknown[]) {
      listenCalls.push(args);
      const callback = args.find((arg) => typeof arg === "function");
      if (callback) (callback as () => void)();
      return this;
    } as unknown as typeof Server.prototype.listen;

    await import("../src/server.ts");
    await waitFor(() => getRSS() !== "");
  });

  after(() => {
    globalThis.setInterval = realSetInterval;
    Server.prototype.listen = realListen;
    mock.restoreAll();
  });

  it("falls back to port 3000", () => {
    assert.equal(listenCalls.length, 1);
    assert.equal(listenCalls[0][0], 3000);
  });

  it("falls back to a thirty minute refresh interval", () => {
    assert.equal(intervals.length, 1);
    assert.equal(intervals[0], 30 * 60 * 1000);
  });

  it("starts tracking before the server is listening", () => {
    assert.match(getRSS(), /CVE-2026-0001/);
  });
});
