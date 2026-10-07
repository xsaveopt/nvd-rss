import { summarize } from "./text.ts";

const MIN_SHARED_WORDS = 4;
const REASON_LENGTH = 160;

export interface Entry {
  id: string;
  score: number;
  version: string;
  severity: string;
  description: string;
  products: string;
  source: string;
  weaknesses: string[];
  references: string[];
  published?: string;
}

export interface Group {
  id: string;
  products: string;
  source: string;
  day: string;
  shared: string;
  entries: (Entry & { reason: string })[];
}

export function groupKey(entry: Entry): string | undefined {
  if (entry.products === "Unknown" || !entry.published) return undefined;
  const day = entry.published.slice(0, 10);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(day)) return undefined;
  return `${day}\n${entry.products}\n${entry.source}`;
}

function slug(value: string): string {
  return value
    .normalize("NFKD")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 60);
}

export function sharedPrefix(texts: string[]): string {
  const split = texts.map((t) => t.replace(/\s+/g, " ").trim().split(" "));
  const shortest = Math.min(...split.map((words) => words.length));
  let n = 0;
  while (n < shortest - 1 && split.every((words) => words[n] === split[0][n])) n++;
  return n >= MIN_SHARED_WORDS ? split[0].slice(0, n).join(" ") : "";
}

export function reasonFor(description: string, shared: string): string {
  const flat = description.replace(/\s+/g, " ").trim();
  const rest = shared ? flat.slice(shared.length).trim() : "";
  return rest ? `...${summarize(rest, REASON_LENGTH)}` : summarize(flat, REASON_LENGTH);
}

export function buildGroups(entries: Entry[]): (Entry | Group)[] {
  const buckets = new Map<string, Entry[]>();
  for (const entry of entries) {
    const key = groupKey(entry);
    if (!key) continue;
    const bucket = buckets.get(key) ?? [];
    bucket.push(entry);
    buckets.set(key, bucket);
  }

  const used = new Set<string>();
  const groups = new Map<string, Group>();
  for (const [key, bucket] of buckets) {
    if (bucket.length < 2) continue;
    const [day, products, source] = key.split("\n");
    const base = `${day}-${slug(products)}-${slug(source)}`;
    let id = base;
    for (let n = 2; used.has(id); n++) id = `${base}-${n}`;
    used.add(id);

    const shared = sharedPrefix(bucket.map((e) => e.description));
    const sorted = [...bucket].sort((a, b) => b.score - a.score || a.id.localeCompare(b.id));
    groups.set(key, {
      id,
      products,
      source,
      day,
      shared,
      entries: sorted.map((e) => ({ ...e, reason: reasonFor(e.description, shared) })),
    });
  }

  const out: (Entry | Group)[] = [];
  const emitted = new Set<string>();
  for (const entry of entries) {
    const key = groupKey(entry);
    const group = key ? groups.get(key) : undefined;
    if (!group) {
      out.push(entry);
    } else if (!emitted.has(group.id)) {
      emitted.add(group.id);
      out.push(group);
    }
  }
  return out;
}

export function isGroup(item: Entry | Group): item is Group {
  return "entries" in item;
}
