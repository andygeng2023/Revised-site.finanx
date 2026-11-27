import test from "node:test";
import assert from "node:assert/strict";
import worker from "../src/worker.js";

test("serves the Finanx single-page application", async () => {
  const response = await worker.fetch(new Request("https://finanx.test/"), {}, { waitUntil() {} });
  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type"), /text\/html/);
  const html = await response.text();
  assert.match(html, /Market intelligence/);
  assert.match(html, /PreviewIndex/);
  assert.match(html, /FullIndex/);
  assert.match(html, /Run market scan/);
  assert.match(html, /stock-chart/);
});

test("provides a health endpoint", async () => {
  const response = await worker.fetch(new Request("https://finanx.test/api/health"), {}, { waitUntil() {} });
  const body = await response.json();
  assert.equal(response.status, 200);
  assert.equal(body.ok, true);
  assert.equal(body.database, "D1");
  assert.equal(body.queue, "Cloudflare Queues");
});

test("handles browser preflight requests", async () => {
  const response = await worker.fetch(new Request("https://finanx.test/api/health", { method: "OPTIONS" }), {}, { waitUntil() {} });
  assert.equal(response.status, 204);
});

test("unknown API routes return 404", async () => {
  const response = await worker.fetch(new Request("https://finanx.test/api/not-a-route"), {}, { waitUntil() {} });
  assert.equal(response.status, 404);
});
