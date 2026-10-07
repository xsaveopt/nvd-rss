export const CVE_ORG_URL = "https://cveawg.mitre.org/api/cve";

const CONCURRENCY = 4;
const TIMEOUT_MS = 15 * 1000;
const MAX_PRODUCTS = 2;

interface CveRecord {
  containers?: {
    cna?: {
      affected?: { vendor?: string; product?: string }[];
    };
  };
}

let products = new Map<string, string | null>();

function usable(value: string | undefined): string | undefined {
  const trimmed = value?.trim();
  if (!trimmed || /^(?:n\/a|unknown|-|\*)$/i.test(trimmed)) return undefined;
  return trimmed;
}

export function formatAffected(vendor: string | undefined, product: string | undefined): string {
  const v = usable(vendor);
  const p = usable(product);
  if (!p) return "";
  if (!v) return p;
  const firstWord = v.split(/[\s,]+/)[0].toLowerCase();
  if (p.toLowerCase().includes(firstWord)) return p;
  return `${v} ${p}`;
}

async function lookup(id: string): Promise<string | null> {
  const response = await fetch(`${CVE_ORG_URL}/${encodeURIComponent(id)}`, {
    signal: AbortSignal.timeout(TIMEOUT_MS),
  });
  if (response.status === 404) return null;
  if (!response.ok) throw new Error(response.statusText);

  const record = (await response.json()) as CveRecord;
  const names = (record.containers?.cna?.affected ?? [])
    .map((a) => formatAffected(a.vendor, a.product))
    .filter(Boolean);
  const unique = [...new Set(names)].slice(0, MAX_PRODUCTS);
  return unique.length > 0 ? unique.join(", ") : null;
}

export async function resolveProducts(ids: string[]): Promise<void> {
  const wanted = new Set(ids);
  products = new Map([...products].filter(([id]) => wanted.has(id)));

  const queue = [...wanted].filter((id) => !products.has(id));
  let failed = 0;

  const worker = async () => {
    for (let id = queue.shift(); id !== undefined; id = queue.shift()) {
      try {
        products.set(id, await lookup(id));
      } catch {
        failed++;
      }
    }
  };
  await Promise.all(Array.from({ length: CONCURRENCY }, worker));

  if (failed > 0) {
    console.error(`Could not look up ${failed} of ${wanted.size} products on CVE.org.`);
  }
}

export function affectedProducts(id: string): string | undefined {
  return products.get(id) ?? undefined;
}
