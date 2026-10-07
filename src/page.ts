import type { Group } from "./groups.ts";
import { escapeXml } from "./text.ts";

const STYLE = `
:root {
  color-scheme: light dark;
  --bg: #f7f7f5;
  --card: #ffffff;
  --text: #1d1d1f;
  --muted: #6b6b70;
  --line: #e4e4e0;
  --link: #0b5cad;
  --critical: #b3261e;
  --high: #c25e00;
  --medium: #8a6d00;
  --low: #3b7a3b;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #161618;
    --card: #1f1f22;
    --text: #ececec;
    --muted: #9a9aa0;
    --line: #2e2e33;
    --link: #7ab4f5;
    --critical: #ff8a80;
    --high: #ffb35c;
    --medium: #e6cf5c;
    --low: #8fd18f;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--text);
  font: 16px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif;
}
main { max-width: 860px; margin: 0 auto; padding: 32px 16px 48px; }
h1 { font-size: 1.6rem; line-height: 1.25; margin: 0 0 6px; }
.meta { color: var(--muted); margin: 0 0 20px; }
.shared {
  background: var(--card);
  border: 1px solid var(--line);
  border-radius: 10px;
  padding: 12px 16px;
  margin: 0 0 24px;
}
ol { list-style: none; margin: 0; padding: 0; display: grid; gap: 10px; }
li {
  background: var(--card);
  border: 1px solid var(--line);
  border-radius: 10px;
  padding: 12px 16px;
  display: grid;
  grid-template-columns: 3.2rem 1fr;
  gap: 4px 14px;
}
.score {
  grid-row: span 2;
  font-weight: 700;
  font-size: 1.15rem;
  font-variant-numeric: tabular-nums;
}
.critical { color: var(--critical); }
.high { color: var(--high); }
.medium { color: var(--medium); }
.low { color: var(--low); }
.head { display: flex; flex-wrap: wrap; gap: 4px 12px; align-items: baseline; }
.head a { color: var(--link); font-weight: 600; text-decoration: none; }
.head a:hover { text-decoration: underline; }
.tags { color: var(--muted); font-size: 0.875rem; }
.reason { margin: 0; overflow-wrap: anywhere; }
`;

export function renderGroupPage(group: Group): string {
  const top = group.entries[0];
  const count = group.entries.length;

  const rows = group.entries
    .map((e) => {
      const tags = [e.severity, `CVSS ${e.version}`, ...e.weaknesses].join(" · ");
      return `<li>
  <span class="score ${e.severity.toLowerCase()}">${e.score}</span>
  <div class="head"><a href="https://nvd.nist.gov/vuln/detail/${escapeXml(e.id)}">${escapeXml(e.id)}</a><span class="tags">${escapeXml(tags)}</span></div>
  <p class="reason">${escapeXml(e.reason)}</p>
</li>`;
    })
    .join("\n");

  const shared = group.shared
    ? `<p class="shared">Every entry starts with: ${escapeXml(group.shared)} ...</p>`
    : "";

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeXml(group.products)} (${count} CVEs)</title>
<style>${STYLE}</style>
</head>
<body>
<main>
<h1>${escapeXml(group.products)}</h1>
<p class="meta">${count} vulnerabilities published ${escapeXml(group.day)} by ${escapeXml(group.source)}, highest ${top.score} ${escapeXml(top.severity)}</p>
${shared}
<ol>
${rows}
</ol>
</main>
</body>
</html>`;
}
