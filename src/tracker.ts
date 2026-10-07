import zlib from "node:zlib";
import { promisify } from "node:util";
import { affectedProducts, resolveProducts } from "./cveorg.ts";
import { buildGroups, isGroup } from "./groups.ts";
import type { Entry, Group } from "./groups.ts";
import { refreshSources, sourceName } from "./sources.ts";
import { escapeXml, summarize } from "./text.ts";

export { escapeXml, summarize };

const gunzip = promisify(zlib.gunzip);

export const FEED_URL =
  process.env.NVD_FEED_URL || "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz";

const CVSS_THRESHOLD = Number.parseFloat(process.env.CVSS_THRESHOLD || "8.0");
const PRODUCT_FILTER = process.env.PRODUCT_FILTER || null;

const MAX_REFERENCES = 3;

interface CvssMetric {
  cvssData?: { baseScore?: number };
}

interface CpeMatch {
  criteria?: string;
  vulnerable?: boolean;
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
  weaknesses?: { description?: { lang: string; value: string }[] }[];
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

interface CvssScore {
  score: number;
  version: string;
}

export const LINK_PREFIX = "\u0000prefix\u0000";

let currentRSS = "";
let currentGroups = new Map<string, Group>();

function getHighestCvss(cveItem: CveItem): CvssScore {
  const best: CvssScore = { score: 0.0, version: "" };

  if (!cveItem.metrics) return best;

  const groups: [string, CvssMetric[] | undefined][] = [
    ["3.1", cveItem.metrics.cvssMetricV31],
    ["3.0", cveItem.metrics.cvssMetricV30],
    ["2.0", cveItem.metrics.cvssMetricV2],
  ];

  for (const [version, group] of groups) {
    if (!group) continue;
    for (const metric of group) {
      const score = metric.cvssData?.baseScore;
      if (score !== undefined && score > best.score) {
        best.score = score;
        best.version = version;
      }
    }
  }

  return best;
}

export function getSeverity(score: number): string {
  if (score >= 9.0) return "Critical";
  if (score >= 7.0) return "High";
  if (score >= 4.0) return "Medium";
  if (score > 0) return "Low";
  return "None";
}

export function matchesProductFilter(cveItem: CveItem, filter: string): boolean {
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

function titleCase(value: string): string {
  return value
    .replace(/\\(.)/g, "$1")
    .replace(/_/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

export function formatCpeProduct(vendor: string, product: string): string {
  const v = titleCase(vendor);
  const p = titleCase(product);
  if (!v || v === "*" || v === "-" || p.toLowerCase().startsWith(v.toLowerCase())) return p;
  return `${v} ${p}`;
}

function cpeProducts(cveItem: CveItem, vulnerable: boolean): string[] {
  const products: string[] = [];
  for (const config of cveItem.configurations ?? []) {
    for (const node of config.nodes ?? []) {
      for (const match of node.cpeMatch ?? []) {
        if (!match.criteria || (match.vulnerable !== false) !== vulnerable) continue;
        const parts = match.criteria.split(":");
        if (parts.length >= 5) {
          products.push(formatCpeProduct(parts[3], parts[4]));
        }
      }
    }
  }
  return products;
}

const VERSION_STOP = String.raw`(?:up\s+to|before|prior\s+to|prior\s+versions?|through|versions?\s|<=?\s*v?\d|v?\d+(?:\.\d+)+)`;
const TOKEN = String.raw`[A-Z][\w\-/]*(?:\.[\w\-/]+)*`;
const NAME = String.raw`${TOKEN}(?:\s+(?:for\s+|and\s+|of\s+)?${TOKEN}){0,5}`;
const WORD = String.raw`[^\s,]*[^\s,.:;]`;

const DESCRIPTION_PATTERNS = [
  /^In the (Linux kernel)\b/,
  new RegExp(String.raw`\baffected\s+versions?\s+of\s+(?:the\s+)?(${NAME})`),
  /The\s+(.+?)\s+(?:plugin|theme|extension|module)\s+for\s+\w+/i,
  /The\s+(.+?)\s+WordPress\s+(?:plugin|theme)/i,
  /^(.+?)\s+developed\s+by/i,
  new RegExp(
    String.raw`^(?:an?\s+)?(?:[\w-]+\s+){0,3}?(?:vulnerability|flaw|weakness|issue)\s+(?:has\s+been|was|is)\s+(?:found|identified|detected|discovered|reported)\s+in\s+(?:the\s+)?(.+?)(?=\s+${VERSION_STOP}|\.(?:\s|$)|,|$)`,
    "i",
  ),
  new RegExp(String.raw`^(?:The\s+)?(${NAME})\s+is\s+an?\s`),
  /^([\w.-]+),\s+an?\s/,
  new RegExp(
    String.raw`\bin\s+(?:the\s+)?([\w][\w.\-/]*(?:\s+[A-Z][\w.\-/]*){0,4})(?:\s+(?:on|for)\s+(?:on\s+)?[A-Z]\w*)?\s+${VERSION_STOP}`,
  ),
  new RegExp(String.raw`^(?:In\s+)?(${WORD}(?:\s+${WORD}){0,6}?),?\s+${VERSION_STOP}`),
  /\bfixed\s+in\s+([A-Z][A-Za-z]+(?:\s+[A-Z][A-Za-z]+)*?)\s+\d/,
  new RegExp(
    String.raw`^(?:The\s+)?(${NAME})\s+(?:contains|allows|exposes|has(?!\s+(?:discovered|identified|found|reported))|uses|accepts|fails|does\s+not|is\s+vulnerable)\b`,
  ),
  new RegExp(String.raw`\bin\s+(${NAME})\s+(?:can|could|may|allows?)\b`),
  /\bvulnerability in\s+(?:the\s+)?(.+?)(?:\s+(?:allows|version|before|prior|is|has|could|up\s+to|through)|\.|$)/i,
];

const GENERIC_PRODUCT =
  /^(?:the|this|there|a|an|in|on|it|all|application|affected|multiple|versions?)\b|\baffected$|\b(?:where|that|which|who|whose|its|is|are|was)\b|\s(?:in|of|for|on|to|from)$/i;

function descriptionProduct(description: string): string | undefined {
  const text = description.replace(/\s+/g, " ").trim();
  for (const pattern of DESCRIPTION_PATTERNS) {
    const match = text.match(pattern);
    const p = match?.[1]
      ?.split(/\s+[–-]\s+/)[0]
      .split(/\s+in\s+/)
      .pop()
      ?.replace(/^the\s+/i, "")
      .replace(
        /^.*?\b(?:endpoint|component|interface|function|feature|service|layer)s?\s+of\s+(?:the\s+)?/i,
        "",
      )
      .trim();
    if (!p || p.length >= 50) continue;
    if (p.toLowerCase().includes("vulnerability") || GENERIC_PRODUCT.test(p)) continue;
    return p;
  }
  return undefined;
}

const NOT_A_PRODUCT_REPO = /security|advisor|cve|csaf|poc|exploit|vuln/i;

function githubProducts(cveItem: CveItem): string[] {
  const products: string[] = [];
  for (const ref of cveItem.references ?? []) {
    const match = ref.url?.match(/github\.com\/([^/]+)\/([^/#?]+)/);
    if (match && match[1] !== "advisories" && match[2] && !NOT_A_PRODUCT_REPO.test(match[2])) {
      products.push(match[2]);
    }
  }
  return products;
}

function pickProducts(candidates: string[]): string[] {
  const unique = [...new Set(candidates)];
  const filtered = unique.filter((p) => {
    const lower = p.toLowerCase();
    return lower !== "linux kernel" && lower !== "unknown";
  });
  return (filtered.length > 0 ? filtered : unique).slice(0, 2);
}

export function getProducts(cveItem: CveItem, description: string): string {
  const fromDescription = description ? descriptionProduct(description) : undefined;
  const tiers = [
    cpeProducts(cveItem, true),
    fromDescription ? [fromDescription] : [],
    githubProducts(cveItem),
    cpeProducts(cveItem, false),
  ];

  for (const tier of tiers) {
    const picked = pickProducts(tier);
    if (picked.length > 0) return picked.join(", ");
  }
  return "Unknown";
}

export function getSource(cveItem: CveItem): string {
  if (cveItem.sourceIdentifier) {
    const named = sourceName(cveItem.sourceIdentifier);
    if (named) return named;

    let src = cveItem.sourceIdentifier;
    if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(src)) {
      return "Unknown";
    }
    if (src.includes("@")) {
      const parts = src.split("@");
      src = parts[1] || parts[0];
    }
    const parts = src.split(".");
    if (parts.length >= 2) {
      src = parts[0];
    }
    return src.charAt(0).toUpperCase() + src.slice(1);
  }
  return "NIST";
}

function getWeaknesses(cveItem: CveItem): string[] {
  const ids = (cveItem.weaknesses ?? [])
    .flatMap((w) => w.description ?? [])
    .map((d) => d.value)
    .filter((v) => /^CWE-\d+$/.test(v));
  return [...new Set(ids)];
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

interface Selected {
  cve: CveItem;
  cvss: CvssScore;
  description: string;
  products: string;
}

function toEntry({ cve, cvss, description, products }: Selected): Entry {
  return {
    id: cve.id,
    score: cvss.score,
    version: cvss.version,
    severity: getSeverity(cvss.score),
    description,
    products,
    source: getSource(cve),
    weaknesses: getWeaknesses(cve),
    references: (cve.references ?? [])
      .map((r) => r.url)
      .filter((url): url is string => Boolean(url)),
    published: cve.published,
  };
}

function pubDateOf(published: string | undefined, now: string): string {
  return published ? new Date(published).toUTCString() : now;
}

function renderItem(entry: Entry, now: string): string {
  const known = entry.products !== "Unknown";
  const severity = `${entry.severity} ${entry.score}`;

  const title = known
    ? `[${entry.score}] ${entry.products}: ${summarize(entry.description)}`
    : `[${entry.score}] ${summarize(entry.description)}`;

  const facts = [
    known ? `<strong>${escapeXml(entry.products)}</strong>` : "",
    `${severity} (CVSS ${entry.version})`,
    ...entry.weaknesses,
    escapeXml(entry.source),
  ].filter(Boolean);

  const references = entry.references
    .slice(0, MAX_REFERENCES)
    .map((url) => `<a href="${escapeXml(url)}">${escapeXml(url)}</a>`);

  const html = [
    `<p>${facts.join(" · ")}</p>`,
    `<p>${escapeXml(entry.description)}</p>`,
    references.length > 0 ? `<p>${references.join("<br/>")}</p>` : "",
  ].join("");

  return `  <item>
    <title>${escapeXml(title)}</title>
    <dc:creator>${escapeXml(entry.source)}</dc:creator>
    <category>${escapeXml(entry.products)}</category>
    <guid isPermaLink="false">${entry.id}</guid>
    <link>https://nvd.nist.gov/vuln/detail/${entry.id}</link>
    <description>${escapeXml(html)}</description>
    <pubDate>${pubDateOf(entry.published, now)}</pubDate>
  </item>`;
}

function renderGroup(group: Group, now: string): string {
  const top = group.entries[0];
  const count = group.entries.length;
  const page = `${LINK_PREFIX}/group/${group.id}`;
  const latest = group.entries
    .map((e) => e.published ?? "")
    .sort()
    .at(-1);

  const facts = [
    `<strong>${escapeXml(group.products)}</strong>`,
    `${count} vulnerabilities`,
    `highest ${top.severity} ${top.score}`,
    escapeXml(group.source),
  ];

  const rows = group.entries.map(
    (e) =>
      `<li><a href="https://nvd.nist.gov/vuln/detail/${e.id}">${e.id}</a> [${e.score}] ${escapeXml(e.reason)}</li>`,
  );

  const html = [
    `<p>${facts.join(" · ")}</p>`,
    group.shared ? `<p>${escapeXml(group.shared)} ...</p>` : "",
    `<ul>${rows.join("")}</ul>`,
    `<p><a href="${page}">All ${count} on one page</a></p>`,
  ].join("");

  return `  <item>
    <title>${escapeXml(`[${top.score}] ${group.products}: ${count} vulnerabilities`)}</title>
    <dc:creator>${escapeXml(group.source)}</dc:creator>
    <category>${escapeXml(group.products)}</category>
    <guid isPermaLink="false">group-${group.id}</guid>
    <link>${page}</link>
    <description>${escapeXml(html)}</description>
    <pubDate>${pubDateOf(latest || undefined, now)}</pubDate>
  </item>`;
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

  const selected = json.vulnerabilities
    .map((item): Selected | null => {
      const cve = item.cve;
      if (!cve) return null;

      const cvss = getHighestCvss(cve);

      if (cvss.score < CVSS_THRESHOLD) return null;

      if (PRODUCT_FILTER && !matchesProductFilter(cve, PRODUCT_FILTER)) return null;

      const descObj = cve.descriptions?.find((d) => d.lang === "en");
      const description = descObj?.value || "No description available";

      return { cve, cvss, description, products: getProducts(cve, description) };
    })
    .filter((item): item is Selected => item !== null);

  await resolveProducts(selected.filter((s) => s.products === "Unknown").map((s) => s.cve.id));

  const entries = selected.map((s) =>
    toEntry(
      s.products === "Unknown" ? { ...s, products: affectedProducts(s.cve.id) ?? "Unknown" } : s,
    ),
  );
  const grouped = buildGroups(entries);
  const items = grouped.map((item) =>
    isGroup(item) ? renderGroup(item, now) : renderItem(item, now),
  );

  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:dc="http://purl.org/dc/elements/1.1/">
<channel>
  <title>NVD CVE Feed (CVSS >= ${CVSS_THRESHOLD})</title>
  <link>${escapeXml(FEED_URL)}</link>
  <description>NVD Vulnerabilities with Score >= ${CVSS_THRESHOLD}${PRODUCT_FILTER ? ` (Product: ${escapeXml(PRODUCT_FILTER)})` : ""}</description>
  <lastBuildDate>${now}</lastBuildDate>
  <language>en-US</language>
${items.join("\n")}
</channel>
</rss>`;

  currentRSS = xml;
  currentGroups = new Map(grouped.filter(isGroup).map((g) => [g.id, g]));
  console.log(
    `[${new Date().toISOString()}] Feed updated. Timestamp: ${timestamp}. Items: ${items.length} (${entries.length} CVEs) of ${json.vulnerabilities.length}`,
  );
}

async function refresh(): Promise<void> {
  await refreshSources();
  await updateFeed();
}

export function startTracking(intervalMinutes: number): void {
  void refresh();
  setInterval(() => void refresh(), intervalMinutes * 60 * 1000);
}

export function getRSS(prefix = ""): string {
  return currentRSS.replaceAll(LINK_PREFIX, prefix.replace(/[^\w.:/~%[\]-]/g, ""));
}

export function getGroup(id: string): Group | undefined {
  return currentGroups.get(id);
}
