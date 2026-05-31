const express = require("express");
const cors = require("cors");
const routes = require("./routes");
const tracker = require("./tracker");

const app = express();
const port = process.env.PORT || 3000;

app.use(cors());

const interval = process.env.UPDATE_INTERVAL_MINUTES || 30;
tracker.startTracking(interval);

app.use("/", routes);

app.listen(port, () => {
  const rssPath = process.env.RSS_PATH || "/rss";
  console.log(`Server listening on port ${port}`);
  console.log(`RSS Feed available at http://localhost:${port}${rssPath}`);
  console.log(`Configuration:`);
  console.log(`- Feed URL: ${tracker.FEED_URL}`);
  console.log(`- CVSS Threshold: ${process.env.CVSS_THRESHOLD || 8.0}`);
  console.log(`- Product Filter: ${process.env.PRODUCT_FILTER || "None"}`);
});
