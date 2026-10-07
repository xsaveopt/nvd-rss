import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { buildGroups, isGroup, reasonFor, sharedPrefix } from "../src/groups.ts";
import type { Entry, Group } from "../src/groups.ts";

function entry(overrides: Partial<Entry>): Entry {
  return {
    id: "CVE-2026-0001",
    score: 8.8,
    version: "3.1",
    severity: "High",
    description: "Acme Widget 1.0 through 1.2 could allow a remote attacker to read files.",
    products: "Acme Widget",
    source: "Acme Corp",
    weaknesses: [],
    references: [],
    published: "2026-10-07T01:16:32.837",
    ...overrides,
  };
}

function groups(items: (Entry | Group)[]): Group[] {
  return items.filter(isGroup);
}

describe("sharedPrefix", () => {
  it("returns the words every description starts with", () => {
    assert.equal(
      sharedPrefix([
        "Acme Widget 1.0 through 1.2 could allow a remote attacker to read files.",
        "Acme Widget 1.0 through 1.2 could allow a remote authenticated attacker to run code.",
      ]),
      "Acme Widget 1.0 through 1.2 could allow a remote",
    );
  });

  it("ignores a prefix shorter than four words", () => {
    assert.equal(sharedPrefix(["Acme Widget has a flaw.", "Acme Widget leaks data."]), "");
  });

  it("always leaves at least one word for identical descriptions", () => {
    assert.equal(
      sharedPrefix(["One two three four five.", "One two three four five."]),
      "One two three four",
    );
  });
});

describe("reasonFor", () => {
  it("drops the shared prefix", () => {
    assert.equal(
      reasonFor(
        "Acme Widget 1.0 could allow a remote attacker to read files.",
        "Acme Widget 1.0 could allow",
      ),
      "...a remote attacker to read files.",
    );
  });

  it("keeps the whole description when nothing is shared", () => {
    assert.equal(reasonFor("A flaw in Acme.", ""), "A flaw in Acme.");
  });

  it("shortens a long reason", () => {
    const reason = reasonFor(`${"word ".repeat(60)}end`, "");
    assert.ok(reason.length <= 163);
    assert.ok(reason.endsWith("..."));
  });
});

describe("buildGroups", () => {
  it("groups CVEs for the same product, source and day", () => {
    const out = buildGroups([
      entry({ id: "CVE-2026-0001", score: 8.1 }),
      entry({ id: "CVE-2026-0002", score: 9.8, published: "2026-10-07T03:16:00.000" }),
      entry({ id: "CVE-2026-0003", score: 8.8 }),
    ]);

    assert.equal(out.length, 1);
    const [group] = groups(out);
    assert.equal(group.id, "2026-10-07-acme-widget-acme-corp");
    assert.deepEqual(
      group.entries.map((e) => e.id),
      ["CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0001"],
    );
    assert.equal(group.shared, "Acme Widget 1.0 through 1.2 could allow a remote attacker to read");
  });

  it("keeps a lone CVE as a plain item", () => {
    const out = buildGroups([entry({})]);

    assert.equal(out.length, 1);
    assert.equal(isGroup(out[0]), false);
  });

  it("never groups across products, sources or days", () => {
    const out = buildGroups([
      entry({ id: "CVE-1" }),
      entry({ id: "CVE-2", products: "Acme Widget Pro" }),
      entry({ id: "CVE-3", source: "VulDB" }),
      entry({ id: "CVE-4", published: "2026-10-08T00:00:00.000" }),
    ]);

    assert.equal(out.length, 4);
    assert.equal(groups(out).length, 0);
  });

  it("never groups CVEs without a known product or a published date", () => {
    const out = buildGroups([
      entry({ id: "CVE-1", products: "Unknown" }),
      entry({ id: "CVE-2", products: "Unknown" }),
      entry({ id: "CVE-3", published: undefined }),
      entry({ id: "CVE-4", published: undefined }),
    ]);

    assert.equal(groups(out).length, 0);
  });

  it("puts the group where its first CVE was and keeps the rest in order", () => {
    const out = buildGroups([
      entry({ id: "CVE-1", products: "Other" }),
      entry({ id: "CVE-2" }),
      entry({ id: "CVE-3", products: "Third" }),
      entry({ id: "CVE-4" }),
    ]);

    assert.deepEqual(
      out.map((item) => (isGroup(item) ? item.id : item.id)),
      ["CVE-1", "2026-10-07-acme-widget-acme-corp", "CVE-3"],
    );
  });

  it("gives groups whose names collide distinct ids", () => {
    const out = buildGroups([
      entry({ id: "CVE-1", products: "Acme.Widget" }),
      entry({ id: "CVE-2", products: "Acme.Widget" }),
      entry({ id: "CVE-3", products: "Acme Widget" }),
      entry({ id: "CVE-4", products: "Acme Widget" }),
    ]);

    assert.deepEqual(
      groups(out).map((g) => g.id),
      ["2026-10-07-acme-widget-acme-corp", "2026-10-07-acme-widget-acme-corp-2"],
    );
  });
});
