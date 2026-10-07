import assert from "node:assert/strict";
import { afterEach, beforeEach, describe, it, mock } from "node:test";
import { refreshSources, sourceName } from "../src/sources.ts";
import { getSource } from "../src/tracker.ts";
import { mockNotOk, silenceConsole, sourcesPage } from "./helpers.ts";

const uuid = "8254265b-2729-46b6-b9e3-3dfca2d5bfca";

describe("NVD sources", () => {
  beforeEach(() => {
    silenceConsole();
  });

  afterEach(() => {
    mock.restoreAll();
  });

  it("starts empty and falls back to parsing the identifier", () => {
    assert.equal(sourceName("cve@mitre.org"), undefined);
    assert.equal(getSource({ id: "CVE-1", sourceIdentifier: "secalert@redhat.com" }), "Redhat");
  });

  it("shows Unknown for a uuid it cannot resolve", () => {
    assert.equal(getSource({ id: "CVE-1", sourceIdentifier: uuid }), "Unknown");
  });

  it("keeps the fallback when the sources api fails", async () => {
    mockNotOk("Forbidden");
    await refreshSources(1);

    assert.equal(sourceName(uuid), undefined);
  });

  it("pages through every source and maps each identifier to its name", async () => {
    const pages = [
      sourcesPage([{ name: "MITRE", sourceIdentifiers: ["cve@mitre.org", uuid] }], 2),
      sourcesPage([{ name: "Red Hat, Inc.", sourceIdentifiers: ["secalert@redhat.com"] }], 2),
    ];
    const fetchMock = mock.method(
      globalThis,
      "fetch",
      async () => pages.shift() as unknown as Response,
    );

    await refreshSources(1);

    assert.equal(fetchMock.mock.callCount(), 2);
    assert.match(String(fetchMock.mock.calls[1].arguments[0]), /startIndex=1$/);
    assert.equal(getSource({ id: "CVE-1", sourceIdentifier: uuid.toUpperCase() }), "MITRE");
    assert.equal(getSource({ id: "CVE-1", sourceIdentifier: "cve@mitre.org" }), "MITRE");
    assert.equal(
      getSource({ id: "CVE-1", sourceIdentifier: "secalert@redhat.com" }),
      "Red Hat, Inc.",
    );
  });

  it("reuses the loaded names for a day", async () => {
    const fetchMock = mock.method(
      globalThis,
      "fetch",
      async () =>
        sourcesPage([{ name: "Other", sourceIdentifiers: [uuid] }]) as unknown as Response,
    );

    await refreshSources(1 + 60 * 1000);
    assert.equal(fetchMock.mock.callCount(), 0);
    assert.equal(sourceName(uuid), "MITRE");

    await refreshSources(1 + 24 * 60 * 60 * 1000);
    assert.equal(fetchMock.mock.callCount(), 1);
    assert.equal(sourceName(uuid), "Other");
  });

  it("keeps the previous names when a later refresh fails", async () => {
    mock.method(globalThis, "fetch", async () => {
      throw new Error("network down");
    });

    await refreshSources(3 * 24 * 60 * 60 * 1000);

    assert.equal(sourceName(uuid), "Other");
  });
});
