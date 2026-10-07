export const SOURCES_URL = "https://services.nvd.nist.gov/rest/json/source/2.0";

const PAGE_SIZE = 1000;
const REFRESH_MS = 24 * 60 * 60 * 1000;
const TIMEOUT_MS = 30 * 1000;

interface NvdSource {
  name?: string;
  sourceIdentifiers?: string[];
}

interface SourcesPage {
  totalResults?: number;
  sources?: NvdSource[];
}

let names = new Map<string, string>();
let loadedAt = 0;

export async function refreshSources(now = Date.now()): Promise<void> {
  if (names.size > 0 && now - loadedAt < REFRESH_MS) return;

  try {
    const next = new Map<string, string>();
    let startIndex = 0;
    let total = Infinity;

    while (startIndex < total) {
      const url = `${SOURCES_URL}?resultsPerPage=${PAGE_SIZE}&startIndex=${startIndex}`;
      const response = await fetch(url, { signal: AbortSignal.timeout(TIMEOUT_MS) });
      if (!response.ok) {
        console.error(`Failed to fetch NVD sources: ${response.statusText}`);
        return;
      }

      const page = (await response.json()) as SourcesPage;
      const sources = page.sources ?? [];
      for (const source of sources) {
        if (!source.name) continue;
        for (const id of source.sourceIdentifiers ?? []) {
          next.set(id.toLowerCase(), source.name);
        }
      }

      total = page.totalResults ?? 0;
      if (sources.length === 0) break;
      startIndex += sources.length;
    }

    names = next;
    loadedAt = now;
    console.log(`[${new Date().toISOString()}] Loaded ${next.size} NVD source identifiers.`);
  } catch (error) {
    console.error("Error fetching NVD sources:", error);
  }
}

export function sourceName(identifier: string): string | undefined {
  return names.get(identifier.toLowerCase());
}
