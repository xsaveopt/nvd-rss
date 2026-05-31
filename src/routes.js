const express = require("express");
const router = express.Router();
const tracker = require("./tracker");

const rssPath = process.env.RSS_PATH || "/rss";

router.get(rssPath, (req, res) => {
  try {
    const xml = tracker.getRSS();
    if (!xml) {
      res
        .status(503)
        .send("RSS feed not ready yet. Please try again in a moment.");
      return;
    }
    res.set("Content-Type", "application/rss+xml");
    res.send(xml);
  } catch (error) {
    console.error("RSS Error:", error);
    res.status(500).send("Error generating RSS feed");
  }
});

module.exports = router;
