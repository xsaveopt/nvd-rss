import assert from "node:assert/strict";
import { after, before, describe, it, mock } from "node:test";
import express from "express";
import type { RunningServer } from "./helpers.ts";
import { updateFeed } from "../src/tracker.ts";
import { listen, mockFeed, sampleFeed, silenceConsole } from "./helpers.ts";

const realFetch = globalThis.fetch.bind(globalThis);

describe("RSS_PATH override", () => {
  let server: RunningServer;

  before(async () => {
    process.env.RSS_PATH = "/feed.xml";
    silenceConsole();
    mockFeed(sampleFeed);
    await updateFeed();
    mock.restoreAll();

    const routes = (await import("../src/routes.ts")).default;
    const app = express();
    app.use("/", routes);
    server = await listen(app);
  });

  after(async () => {
    await server.close();
    delete process.env.RSS_PATH;
  });

  it("serves the feed on the configured path", async () => {
    const response = await realFetch(`${server.url}/feed.xml`);
    const body = await response.text();

    assert.equal(response.status, 200);
    assert.match(response.headers.get("content-type") ?? "", /application\/rss\+xml/);
    assert.match(body, /CVE-2026-0001/);
  });

  it("no longer serves the default path", async () => {
    const response = await realFetch(`${server.url}/rss`);

    assert.equal(response.status, 404);
  });
});
