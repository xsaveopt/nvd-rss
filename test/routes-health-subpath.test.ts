import assert from "node:assert/strict";
import { after, before, describe, it } from "node:test";
import express from "express";
import type { RunningServer } from "./helpers.ts";
import { listen } from "./helpers.ts";

describe("GET /health with a subpathed RSS_PATH", () => {
  let server: RunningServer;

  before(async () => {
    process.env.RSS_PATH = "/blabla/rss";

    const routes = (await import("../src/routes.ts")).default;
    const app = express();
    app.use("/", routes);
    server = await listen(app);
  });

  after(async () => {
    await server.close();
    delete process.env.RSS_PATH;
  });

  it("serves health at the derived subpath", async () => {
    const response = await fetch(`${server.url}/blabla/health`);
    const body = await response.text();

    assert.equal(response.status, 503);
    assert.equal(body, "degraded");
  });

  it("no longer serves health at the root", async () => {
    const response = await fetch(`${server.url}/health`);

    assert.equal(response.status, 404);
  });
});
