const zlib = require("zlib");
const { promisify } = require("util");
const gunzip = promisify(zlib.gunzip);

// Default to NVD 2.0 Recent feed
const FEED_URL =
  process.env.NVD_FEED_URL ||
  "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz";

const CVSS_THRESHOLD = parseFloat(process.env.CVSS_THRESHOLD || "8.0");
const PRODUCT_FILTER = process.env.PRODUCT_FILTER || null; // e.g., "chrome" or "windows"

let currentRSS = "";

function escapeXml(unsafe) {
  if (!unsafe) return "";
  return unsafe.replace(/[<>&'"]/g, function (c) {
    switch (c) {
      case "<":
        return "&lt;";
      case ">":
        return "&gt;";
      case "&":
        return "&amp;";
      case "'":
        return "&apos;";
      case '"':
        return "&quot;";
    }
  });
}

function getHighestCvssScore(cveItem) {
  let maxScore = 0.0;

  if (!cveItem.metrics) return 0.0;

  // Check CVSS 3.1
  if (cveItem.metrics.cvssMetricV31) {
    for (const metric of cveItem.metrics.cvssMetricV31) {
      if (metric.cvssData && metric.cvssData.baseScore > maxScore) {
        maxScore = metric.cvssData.baseScore;
      }
    }
  }

  // Check CVSS 3.0
  if (cveItem.metrics.cvssMetricV30) {
    for (const metric of cveItem.metrics.cvssMetricV30) {
      if (metric.cvssData && metric.cvssData.baseScore > maxScore) {
        maxScore = metric.cvssData.baseScore;
      }
    }
  }

  // Check CVSS 2.0
  if (cveItem.metrics.cvssMetricV2) {
    for (const metric of cveItem.metrics.cvssMetricV2) {
      if (metric.cvssData && metric.cvssData.baseScore > maxScore) {
        maxScore = metric.cvssData.baseScore;
      }
    }
  }

  return maxScore;
}

function matchesProductFilter(cveItem, filter) {
  if (!filter) return true;

  // NVD 2.0 stores configurations in 'configurations'
  // We need to look for cpeMatch strings
  if (!cveItem.configurations) return false;

  const filterLower = filter.toLowerCase();

  for (const config of cveItem.configurations) {
    if (config.nodes) {
      for (const node of config.nodes) {
        if (node.cpeMatch) {
          for (const match of node.cpeMatch) {
            if (
              match.criteria &&
              match.criteria.toLowerCase().includes(filterLower)
            ) {
              return true;
            }
          }
        }
      }
    }
  }
  return false;
}

function getProducts(cveItem, description) {
  const candidates = [];

  // 1. Description Heuristics (Highest priority for readability)
  if (description) {
    const patterns = [
      /The\s+(.+?)\s+plugin\s+for\s+WordPress/i,
      /The\s+(.+?)\s+theme\s+for\s+WordPress/i,
      /^(.+?)\s+developed\s+by/i, // "IAQS and I6 developed by JNC..."
      /\bvulnerability in\s+(?:the\s+)?(.+?)(?:\s+(?:allows|version|before|prior|is|has)|\.|$)/i, // "vulnerability in Nelio Software..."
    ];

    for (const pattern of patterns) {
      const match = description.match(pattern);
      if (match && match[1]) {
        // Clean up the match
        let p = match[1].trim();
        // Heuristic: if it's too long, it might have captured garbage
        // or if it contains certain vulnerability keywords, exclude it
        if (p.length < 50 && !p.toLowerCase().includes("vulnerability")) {
          candidates.push(p);
        }
      }
    }
  }

  // 2. GitHub References
  if (cveItem.references) {
    for (const ref of cveItem.references) {
      if (ref.url && ref.url.includes("github.com")) {
        try {
          // Basic parsing to avoid URL object issues if any
          const match = ref.url.match(/github\.com\/([^\/]+)\/([^\/]+)/);
          if (match && match[2]) {
            candidates.push(match[2]); // Repo name
          }
        } catch (e) {}
      }
    }
  }

  // 3. CPEs (Fallback)
  if (cveItem.configurations) {
    for (const config of cveItem.configurations) {
      if (config.nodes) {
        for (const node of config.nodes) {
          if (node.cpeMatch) {
            for (const match of node.cpeMatch) {
              if (match.criteria) {
                // cpe:2.3:a:vendor:product:version...
                const parts = match.criteria.split(":");
                if (parts.length >= 5) {
                  const product = parts[4];
                  // Format: "windows_10" -> "Windows 10"
                  const formatted = product
                    .replace(/_/g, " ")
                    .replace(/\b\w/g, (c) => c.toUpperCase());
                  candidates.push(formatted);
                }
              }
            }
          }
        }
      }
    }
  }

  // Deduplicate and priorize
  // We prefer the description/github matches (at the top of candidates)
  // but if we have multiple, just take the first unique non-generic ones

  const unique = [...new Set(candidates)];

  // Filter out very generic terms if we have specific ones
  const filtered = unique.filter((p) => {
    const lower = p.toLowerCase();
    return lower !== "linux kernel" && lower !== "unknown";
  });

  const final = filtered.length > 0 ? filtered : unique;

  if (final.length === 0) return "Unknown";
  return final.slice(0, 2).join(", ");
}

function getSource(cveItem) {
  if (cveItem.sourceIdentifier) {
    let src = cveItem.sourceIdentifier;
    // Remove email part if present (e.g. security@wordfence.com -> wordfence.com)
    if (src.includes("@")) {
      const parts = src.split("@");
      src = parts[1] || src;
    }
    // Remove TLD if likely generic (e.g. wordfence.com -> wordfence)
    // This is heuristic and might be too aggressive for some, but fine for typical vendors
    const parts = src.split(".");
    if (parts.length >= 2) {
      src = parts[0];
    }
    return src.charAt(0).toUpperCase() + src.slice(1);
  }
  return "NIST";
}

async function fetchAndParseFeed() {
  try {
    const response = await fetch(FEED_URL);
    if (!response.ok) {
      console.error(`Failed to fetch NVD feed: ${response.statusText}`);
      return null;
    }

    const arrayBuffer = await response.arrayBuffer();
    const buffer = Buffer.from(arrayBuffer);

    // NVD Feeds are Gzipped
    const jsonStr = await gunzip(buffer);
    const json = JSON.parse(jsonStr.toString());

    return json;
  } catch (error) {
    console.error("Error fetching/parsing feed:", error);
    return null;
  }
}

async function updateFeed() {
  console.log(`[${new Date().toISOString()}] Updating feed...`);
  const json = await fetchAndParseFeed();

  if (!json || !json.vulnerabilities) {
    console.log("No vulnerabilities found or failed to parse.");
    return;
  }

  const now = new Date().toUTCString();
  const timestamp = json.timestamp;

  const items = json.vulnerabilities
    .map((item) => {
      const cve = item.cve;
      if (!cve) return null;

      const score = getHighestCvssScore(cve);

      // Filter by CVSS Score
      if (score < CVSS_THRESHOLD) return null;

      // Filter by Product
      if (PRODUCT_FILTER && !matchesProductFilter(cve, PRODUCT_FILTER))
        return null;

      const cveId = cve.id;
      const pubDate = cve.published
        ? new Date(cve.published).toUTCString()
        : now;

      // Get description
      const descObj =
        cve.descriptions && cve.descriptions.find((d) => d.lang === "en");
      const description = descObj.value || "No description available"; // correctly access value or fallback

      const safeDescription = escapeXml(description);
      const source = getSource(cve);

      // Title: CVE (Score) – Description
      const title = `${cveId} (CVSS ${score}) – ${description.substring(0, 50)}${description.length > 50 ? "..." : ""}`;

      return `  <item>
    <title>${title}</title>
    <author>${source}</author>
    <guid isPermaLink="false">${cveId}</guid>
    <link>https://nvd.nist.gov/vuln/detail/${cveId}</link>
    <description>${safeDescription} &lt;br/&gt;&lt;br/&gt;Max CVSS Score: ${score}</description>
    <pubDate>${pubDate}</pubDate>
  </item>`;
    })
    .filter(Boolean) // Remove nulls
    .join("\n");

  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
<channel>
  <title>NVD CVE Feed (CVSS >= ${CVSS_THRESHOLD})</title>
  <link>${FEED_URL}</link>
  <description>NVD Vulnerabilities with Score >= ${CVSS_THRESHOLD}${PRODUCT_FILTER ? ` (Product: ${PRODUCT_FILTER})` : ""}</description>
  <lastBuildDate>${now}</lastBuildDate>
  <language>en-US</language>
${items}
</channel>
</rss>`;

  currentRSS = xml;
  console.log(
    `[${new Date().toISOString()}] Feed updated. Timestamp: ${timestamp}. Items: ${json.vulnerabilities.length}`,
  );
}

function startTracking(intervalMinutes) {
  updateFeed(); // Initial run
  setInterval(updateFeed, intervalMinutes * 60 * 1000);
}

function getRSS() {
  return currentRSS;
}

module.exports = {
  startTracking,
  getRSS,
  FEED_URL,
};
