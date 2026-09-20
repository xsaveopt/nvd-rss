import assert from "node:assert/strict";
import { Server } from "node:http";
import { createServer } from "node:net";
import { after, before, describe, it, mock } from "node:test";
import type { AddressInfo } from "node:net";
import { getRSS } from "../src/tracker.ts";
import { mockFeed, sampleFeed, silenceConsole, waitFor } from "./helpers.ts";

const realFetch = globalThis.fetch.bind(globalThis);
const realSetInterval = globalThis.setInterval;
const realListen = Server.prototype.listen;

const intervals: number[] = [];
const listened: Server[] = [];

function freePort(): Promise<number> {
  return new Promise((resolve) => {
    const probe = createServer();
    probe.listen(0, "127.0.0.1", () => {
      const { port } = probe.address() as AddressInfo;
      probe.close(() => resolve(port));
    });
  });
}

describe("server bootstrap", () => {
  let port = 0;

  before(async () => {
    silenceConsole();
    mockFeed(sampleFeed);

    port = await freePort();
    process.env.PORT = String(port);
    process.env.UPDATE_INTERVAL_MINUTES = "7";

    globalThis.setInterval = ((_handler: () => void, ms?: number) => {
      intervals.push(ms ?? 0);
      return { ref: () => {}, unref: () => {} };
    }) as unknown as typeof globalThis.setInterval;

    Server.prototype.listen = function (this: Server, ...args: unknown[]) {
      listened.push(this);
      return (realListen as unknown as (...rest: unknown[]) => Server).apply(this, args);
    } as unknown as typeof Server.prototype.listen;

    await import("../src/server.ts");

    await waitFor(() => listened.length > 0 && listened[0].listening);
    await waitFor(() => getRSS() !== "");
  });

  after(async () => {
    globalThis.setInterval = realSetInterval;
    Server.prototype.listen = realListen;
    if (listened.length > 0) {
      await new Promise<void>((done) => {
        listened[0].close(() => done());
      });
    }
    mock.restoreAll();
    delete process.env.PORT;
    delete process.env.UPDATE_INTERVAL_MINUTES;
  });

  it("listens on the port given by PORT", () => {
    const address = listened[0].address() as AddressInfo;
    assert.equal(address.port, port);
  });

  it("schedules refreshes using UPDATE_INTERVAL_MINUTES", () => {
    assert.equal(intervals.length, 1);
    assert.equal(intervals[0], 7 * 60 * 1000);
  });

  it("serves the tracked feed through the mounted router", async () => {
    const response = await realFetch(`http://127.0.0.1:${port}/rss`);
    const body = await response.text();

    assert.equal(response.status, 200);
    assert.match(response.headers.get("content-type") ?? "", /application\/rss\+xml/);
    assert.match(body, /CVE-2026-0001/);
  });

  it("answers cross origin requests with a permissive CORS header", async () => {
    const response = await realFetch(`http://127.0.0.1:${port}/rss`, {
      headers: { Origin: "https://reader.example" },
    });
    await response.text();

    assert.equal(response.headers.get("access-control-allow-origin"), "*");
  });

  it("answers a CORS preflight before reaching the router", async () => {
    const response = await realFetch(`http://127.0.0.1:${port}/rss`, {
      method: "OPTIONS",
      headers: {
        Origin: "https://reader.example",
        "Access-Control-Request-Method": "GET",
      },
    });
    await response.text();

    assert.equal(response.status, 204);
    assert.equal(response.headers.get("access-control-allow-origin"), "*");
  });
});
