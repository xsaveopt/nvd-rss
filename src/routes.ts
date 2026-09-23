import express from "express";
import type { Request, Response } from "express";
import { getRSS } from "./tracker.ts";

const router = express.Router();

const rssPath = process.env.RSS_PATH || "/rss";

export function deriveHealthPath(path: string): string {
  const trimmed = path.replace(/\/+$/, "") || "/";
  const lastSlash = trimmed.lastIndexOf("/");
  const dir = lastSlash <= 0 ? "" : trimmed.slice(0, lastSlash);
  return `${dir}/health`;
}

const healthPath = deriveHealthPath(rssPath);

router.get(healthPath, (_req: Request, res: Response) => {
  res.set("Content-Type", "text/plain");
  if (!getRSS()) {
    res.status(503).send("degraded");
    return;
  }
  res.send("up");
});

router.get(rssPath, (_req: Request, res: Response) => {
  try {
    const xml = getRSS();
    if (!xml) {
      res.status(503).send("RSS feed not ready yet. Please try again in a moment.");
      return;
    }
    res.set("Content-Type", "application/rss+xml");
    res.send(xml);
  } catch (error) {
    console.error("RSS Error:", error);
    res.status(500).send("Error generating RSS feed");
  }
});

export default router;
