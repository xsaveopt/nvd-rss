import zlib from "node:zlib";
import { promisify } from "node:util";

const gunzip = promisify(zlib.gunzip);

export const FEED_URL =
  process.env.NVD_FEED_URL || "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz";

const CVSS_THRESHOLD = Number.parseFloat(process.env.CVSS_THRESHOLD || "8.0");
const PRODUCT_FILTER = process.env.PRODUCT_FILTER || null;

interface CvssMetric {
  cvssData?: { baseScore?: number };
}

interface CpeMatch {
  criteria?: string;
}

interface ConfigNode {
  cpeMatch?: CpeMatch[];
}

interface Configuration {
  nodes?: ConfigNode[];
}

interface CveItem {
  id: string;
  published?: string;
  sourceIdentifier?: string;
  descriptions?: { lang: string; value: string }[];
  references?: { url?: string }[];
  configurations?: Configuration[];
  metrics?: {
    cvssMetricV31?: CvssMetric[];
    cvssMetricV30?: CvssMetric[];
    cvssMetricV2?: CvssMetric[];
  };
}

interface NvdFeed {
  timestamp?: string;
  vulnerabilities?: { cve?: CveItem }[];
}

let currentRSS = "";

function escapeXml(unsafe: string | undefined): string {
  if (!unsafe) return "";
  return unsafe.replace(/[<>&'"]/g, (c) => {
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
      default:
        return c;
    }
  });
}

function getHighestCvssScore(cveItem: CveItem): number {
  let maxScore = 0.0;

  if (!cveItem.metrics) return 0.0;

  const groups = [
    cveItem.metrics.cvssMetricV31,
    cveItem.metrics.cvssMetricV30,
    cveItem.metrics.cvssMetricV2,
  ];

  for (const group of groups) {
    if (!group) continue;
    for (const metric of group) {
      const score = metric.cvssData?.baseScore;
      if (score !== undefined && score > maxScore) {
        maxScore = score;
      }
    }
  }

  return maxScore;
}

function matchesProductFilter(cveItem: CveItem, filter: string): boolean {
  if (!cveItem.configurations) return false;

  const filterLower = filter.toLowerCase();

  for (const config of cveItem.configurations) {
    if (!config.nodes) continue;
    for (const node of config.nodes) {
      if (!node.cpeMatch) continue;
      for (const match of node.cpeMatch) {
        if (match.criteria && match.criteria.toLowerCase().includes(filterLower)) {
          return true;
        }
      }
    }
  }
  return false;
}

function getProducts(cveItem: CveItem, description: string): string {
  const candidates: string[] = [];

  if (description) {
    const patterns = [
      /The\s+(.+?)\s+plugin\s+for\s+WordPress/i,
      /The\s+(.+?)\s+theme\s+for\s+WordPress/i,
      /^(.+?)\s+developed\s+by/i,
      /\bvulnerability in\s+(?:the\s+)?(.+?)(?:\s+(?:allows|version|before|prior|is|has)|\.|$)/i,
    ];

    for (const pattern of patterns) {
      const match = description.match(pattern);
      if (match && match[1]) {
        const p = match[1].trim();
        if (p.length < 50 && !p.toLowerCase().includes("vulnerability")) {
          candidates.push(p);
        }
      }
    }
  }

  if (cveItem.references) {
    for (const ref of cveItem.references) {
      if (ref.url && ref.url.includes("github.com")) {
        const match = ref.url.match(/github\.com\/([^/]+)\/([^/]+)/);
        if (match && match[2]) {
          candidates.push(match[2]);
        }
      }
    }
  }

  if (cveItem.configurations) {
    for (const config of cveItem.configurations) {
      if (!config.nodes) continue;
      for (const node of config.nodes) {
        if (!node.cpeMatch) continue;
        for (const match of node.cpeMatch) {
          if (match.criteria) {
            const parts = match.criteria.split(":");
            if (parts.length >= 5) {
              const product = parts[4];
              const formatted = product.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
              candidates.push(formatted);
            }
          }
        }
      }
    }
  }

  const unique = [...new Set(candidates)];

  const filtered = unique.filter((p) => {
    const lower = p.toLowerCase();
    return lower !== "linux kernel" && lower !== "unknown";
  });

  const final = filtered.length > 0 ? filtered : unique;

  if (final.length === 0) return "Unknown";
  return final.slice(0, 2).join(", ");
}

function getSource(cveItem: CveItem): string {
  if (cveItem.sourceIdentifier) {
    let src = cveItem.sourceIdentifier;
    if (src.includes("@")) {
      const parts = src.split("@");
      src = parts[1] || src;
    }
    const parts = src.split(".");
    if (parts.length >= 2) {
      src = parts[0];
    }
    return src.charAt(0).toUpperCase() + src.slice(1);
  }
  return "NIST";
}

async function fetchAndParseFeed(): Promise<NvdFeed | null> {
  try {
    const response = await fetch(FEED_URL);
    if (!response.ok) {
      console.error(`Failed to fetch NVD feed: ${response.statusText}`);
      return null;
    }

    const arrayBuffer = await response.arrayBuffer();
    const buffer = Buffer.from(arrayBuffer);

    const jsonStr = await gunzip(buffer);
    const json = JSON.parse(jsonStr.toString()) as NvdFeed;

    return json;
  } catch (error) {
    console.error("Error fetching/parsing feed:", error);
    return null;
  }
}

export async function updateFeed(): Promise<void> {
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

      if (score < CVSS_THRESHOLD) return null;

      if (PRODUCT_FILTER && !matchesProductFilter(cve, PRODUCT_FILTER)) return null;

      const cveId = cve.id;
      const pubDate = cve.published ? new Date(cve.published).toUTCString() : now;

      const descObj = cve.descriptions?.find((d) => d.lang === "en");
      const description = descObj?.value || "No description available";

      const safeDescription = escapeXml(description);
      const source = getSource(cve);
      const products = escapeXml(getProducts(cve, description));

      const title = `${cveId} (CVSS ${score}) – ${description.substring(0, 50)}${description.length > 50 ? "..." : ""}`;

      return `  <item>
    <title>${escapeXml(title)}</title>
    <author>${escapeXml(source)}</author>
    <category>${products}</category>
    <guid isPermaLink="false">${cveId}</guid>
    <link>https://nvd.nist.gov/vuln/detail/${cveId}</link>
    <description>${safeDescription} &lt;br/&gt;&lt;br/&gt;Max CVSS Score: ${score}</description>
    <pubDate>${pubDate}</pubDate>
  </item>`;
    })
    .filter((item): item is string => item !== null)
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

export function startTracking(intervalMinutes: number): void {
  void updateFeed();
  setInterval(() => void updateFeed(), intervalMinutes * 60 * 1000);
}

export function getRSS(): string {
  return currentRSS;
}
