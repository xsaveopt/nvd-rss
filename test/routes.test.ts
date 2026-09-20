import assert from "node:assert/strict";
import { afterEach, describe, it, mock } from "node:test";
import express from "express";
import routes from "../src/routes.ts";
import { updateFeed } from "../src/tracker.ts";
import { listen, mockFeed, sampleFeed, silenceConsole } from "./helpers.ts";

const realFetch = globalThis.fetch.bind(globalThis);

type RouteHandler = (req: unknown, res: unknown) => void;

interface RouteLayer {
  route?: { path: string; stack: { handle: RouteHandler }[] };
}

interface StubResponse {
  status: (code: number) => StubResponse;
  set: () => StubResponse;
  send: (body: unknown) => StubResponse;
}

function routeHandler(path: string): RouteHandler {
  const layers = (routes as unknown as { stack: RouteLayer[] }).stack;
  const layer = layers.find((candidate) => candidate.route?.path === path);
  assert.ok(layer?.route, `no route registered for ${path}`);
  return layer.route.stack[0].handle;
}

describe("GET /rss", () => {
  afterEach(() => {
    mock.restoreAll();
  });

  it("serves the tracked feed as RSS", async () => {
    silenceConsole();
    mockFeed(sampleFeed);
    await updateFeed();
    mock.restoreAll();

    const app = express();
    app.use("/", routes);
    const server = await listen(app);

    try {
      const response = await realFetch(`${server.url}/rss`);
      const body = await response.text();

      assert.equal(response.status, 200);
      assert.match(response.headers.get("content-type") ?? "", /application\/rss\+xml/);
      assert.match(body, /<rss version="2\.0">/);
      assert.match(body, /CVE-2026-0001/);
    } finally {
      await server.close();
    }
  });

  it("answers 404 on a path the router does not serve", async () => {
    const app = express();
    app.use("/", routes);
    const server = await listen(app);

    try {
      const response = await realFetch(`${server.url}/nope`);
      assert.equal(response.status, 404);
    } finally {
      await server.close();
    }
  });

  it("answers 500 when writing the response throws", async () => {
    const logs = silenceConsole();
    mockFeed(sampleFeed);
    await updateFeed();

    const sent: { status: number; body: unknown } = { status: 200, body: undefined };
    const res: StubResponse = {
      status(code) {
        sent.status = code;
        return res;
      },
      set() {
        throw new Error("header write failed");
      },
      send(body) {
        sent.body = body;
        return res;
      },
    };

    routeHandler("/rss")({}, res);

    assert.equal(sent.status, 500);
    assert.equal(sent.body, "Error generating RSS feed");
    assert.ok(logs.errorCalls() >= 1);
  });
});
