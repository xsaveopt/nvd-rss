import assert from "node:assert/strict";
import { describe, it } from "node:test";
import express from "express";
import routes from "../src/routes.ts";
import { listen } from "./helpers.ts";

describe("GET /rss before the first refresh", () => {
  it("answers 503 with a retry message", async () => {
    const app = express();
    app.use("/", routes);
    const server = await listen(app);

    try {
      const response = await fetch(`${server.url}/rss`);
      const body = await response.text();

      assert.equal(response.status, 503);
      assert.equal(body, "RSS feed not ready yet. Please try again in a moment.");
    } finally {
      await server.close();
    }
  });
});
