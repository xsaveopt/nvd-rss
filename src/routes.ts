import express from "express";
import type { Request, Response } from "express";
import { renderGroupPage } from "./page.ts";
import { getGroup, getRSS } from "./tracker.ts";

const router = express.Router();

const rssPath = process.env.RSS_PATH || "/rss";

export function deriveHealthPath(path: string): string {
  return `${path.replace(/\/+$/, "")}/health`;
}

export function deriveGroupPath(path: string): string {
  return `${path.replace(/\/+$/, "")}/group/:id`;
}

const healthPath = deriveHealthPath(rssPath);
const groupPath = deriveGroupPath(rssPath);

function linkPrefix(req: Request): string {
  const proto = req.get("x-forwarded-proto")?.split(",")[0].trim() || req.protocol;
  const host = req.get("x-forwarded-host")?.split(",")[0].trim() || req.get("host") || "";
  return host ? `${proto}://${host}${rssPath.replace(/\/+$/, "")}` : rssPath.replace(/\/+$/, "");
}

router.get(healthPath, (_req: Request, res: Response) => {
  res.set("Content-Type", "text/plain");
  if (!getRSS()) {
    res.status(503).send("degraded");
    return;
  }
  res.send("up");
});

router.get(groupPath, (req: Request, res: Response) => {
  const group = getGroup(String(req.params.id));
  if (!group) {
    res.status(404).set("Content-Type", "text/plain").send("No such group in the current feed.");
    return;
  }
  res.set("Content-Type", "text/html; charset=utf-8");
  res.send(renderGroupPage(group));
});

router.get(rssPath, (req: Request, res: Response) => {
  try {
    const xml = getRSS(linkPrefix(req));
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
