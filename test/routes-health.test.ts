import assert from "node:assert/strict";
import { describe, it, mock } from "node:test";
import express from "express";
import routes from "../src/routes.ts";
import { updateFeed } from "../src/tracker.ts";
import { listen, mockFeed, sampleFeed, silenceConsole } from "./helpers.ts";

const realFetch = globalThis.fetch.bind(globalThis);

describe("GET /health", () => {
  it("answers 503 degraded before the first feed refresh", async () => {
    const app = express();
    app.use("/", routes);
    const server = await listen(app);

    try {
      const response = await fetch(`${server.url}/health`);
      const body = await response.text();

      assert.equal(response.status, 503);
      assert.equal(body, "degraded");
      assert.match(response.headers.get("content-type") ?? "", /text\/plain/);
    } finally {
      await server.close();
    }
  });

  it("answers 200 up once the feed has been tracked", async () => {
    silenceConsole();
    mockFeed(sampleFeed);
    await updateFeed();
    mock.restoreAll();

    const app = express();
    app.use("/", routes);
    const server = await listen(app);

    try {
      const response = await realFetch(`${server.url}/health`);
      const body = await response.text();

      assert.equal(response.status, 200);
      assert.equal(body, "up");
    } finally {
      await server.close();
    }
  });
});
