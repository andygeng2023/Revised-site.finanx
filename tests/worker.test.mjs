import test from "node:test";
import assert from "node:assert/strict";
import worker from "../src/worker.js";
import { getOriginalPredictions, ensemblePredictions, buildModelEvaluation, modelCandidates } from "../src/models.js";

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

test("FullIndex uses 15 original models, 10 hybrids, 3 meta-hybrids and one primary", () => {
  const closes = Array.from({ length: 420 }, (_, i) =>
    100 * Math.exp(i * 0.0004 + Math.sin(i / 13) * 0.018 + Math.cos(i / 29) * 0.009)
  );
  const volumes = closes.map((_, i) => 1_000_000 + (i % 17) * 12_000);
  const original = getOriginalPredictions(closes, volumes);
  const full = ensemblePredictions(original.predictions, {}, true);
  assert.equal(Object.keys(full).length, 29);
  const evaluation = buildModelEvaluation(closes, volumes, {}, true);
  const candidates = modelCandidates(full, evaluation.stats, {});
  assert.equal(candidates.length, 29);
  assert.equal(candidates.filter(x => x.type === "Original").length, 15);
  assert.equal(candidates.filter(x => x.type === "Hybrid").length, 10);
  assert.equal(candidates.filter(x => x.type === "Meta-hybrid").length, 3);
  assert.equal(candidates.filter(x => x.type === "Primary hybrid").length, 1);
  assert.ok(evaluation.windows > 60);
});

test("PreviewIndex keeps a smaller candidate set while retaining all hybrid layers", () => {
  const closes = Array.from({ length: 420 }, (_, i) =>
    100 * Math.exp(i * 0.0004 + Math.sin(i / 13) * 0.018 + Math.cos(i / 29) * 0.009)
  );
  const volumes = closes.map((_, i) => 1_000_000 + (i % 17) * 12_000);
  const original = getOriginalPredictions(closes, volumes);
  const preview = ensemblePredictions(original.predictions, {}, false);
  const evaluation = buildModelEvaluation(closes, volumes, {}, false);
  const candidates = modelCandidates(preview, evaluation.stats, {});
  assert.equal(candidates.length, 21);
  assert.equal(candidates.filter(x => x.type === "Original").length, 7);
  assert.equal(candidates.filter(x => x.type === "Hybrid").length, 10);
  assert.equal(candidates.filter(x => x.type === "Meta-hybrid").length, 3);
  assert.equal(candidates.filter(x => x.type === "Primary hybrid").length, 1);
});
