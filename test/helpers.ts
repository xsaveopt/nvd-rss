import { mock } from "node:test";
import { setTimeout as delay } from "node:timers/promises";
import { gzipSync } from "node:zlib";
import type { AddressInfo } from "node:net";
import type { Express } from "express";

export const sampleFeed = {
  timestamp: "2026-07-12T00:00:00.000",
  vulnerabilities: [
    {
      cve: {
        id: "CVE-2026-0001",
        published: "2026-07-11T12:00:00.000",
        sourceIdentifier: "cve@mitre.org",
        descriptions: [{ lang: "en", value: "A critical flaw allows remote code execution." }],
        metrics: {
          cvssMetricV31: [{ cvssData: { baseScore: 9.8 } }],
        },
      },
    },
    {
      cve: {
        id: "CVE-2026-0002",
        descriptions: [{ lang: "en", value: "A low severity issue." }],
        metrics: {
          cvssMetricV31: [{ cvssData: { baseScore: 3.1 } }],
        },
      },
    },
  ],
};

export function toArrayBuffer(bytes: Buffer): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

function respondWith(response: Partial<Response>) {
  return mock.method(globalThis, "fetch", async () => response as unknown as Response);
}

export function mockBody(bytes: Buffer) {
  return respondWith({ ok: true, arrayBuffer: async () => toArrayBuffer(bytes) });
}

export function mockFeed(feed: unknown) {
  return mockBody(gzipSync(Buffer.from(JSON.stringify(feed))));
}

export function mockNotOk(statusText: string) {
  return respondWith({ ok: false, statusText });
}

export function silenceConsole(): { errorCalls: () => number } {
  mock.method(console, "log", () => {});
  const error = mock.method(console, "error", () => {});
  return { errorCalls: () => error.mock.callCount() };
}

export interface RunningServer {
  url: string;
  close: () => Promise<void>;
}

export function listen(app: Express): Promise<RunningServer> {
  return new Promise((resolve) => {
    const server = app.listen(0, "127.0.0.1", () => {
      const { port } = server.address() as AddressInfo;
      resolve({
        url: `http://127.0.0.1:${port}`,
        close: () =>
          new Promise<void>((done) => {
            server.close(() => done());
          }),
      });
    });
  });
}

export async function waitFor(predicate: () => boolean, timeoutMs = 3000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() > deadline) throw new Error("timed out waiting for condition");
    await delay(5);
  }
}
