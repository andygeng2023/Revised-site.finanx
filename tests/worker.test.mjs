import test from "node:test";
import assert from "node:assert/strict";
import worker from "../src/worker.js";
import { getOriginalPredictions, ensemblePredictions, buildModelEvaluation, modelCandidates } from "../src/models.js";

function testEnv({ firstResult = null, failDatabase = false } = {}) {
  const calls = { sql: [], queue: 0, batches: 0 };
  const env = {
    DB: {
      prepare(sql) {
        return {
          bind(...args) {
            calls.sql.push({ sql, args });
            return {
              first: async () => {
                if (failDatabase) throw new Error("D1 unavailable");
                if (sql.includes("SELECT 1 AS ok")) return { ok: 1 };
                if (typeof firstResult === "function") {
                  const custom = firstResult(sql, args);
                  if (custom !== undefined && custom !== null) return custom;
                }
                if (sql.includes("INSERT INTO api_rate_limits")) return { attempts: 1 };
                return firstResult;
              },
              all: async () => ({ results: [] }),
              run: async () => ({ success: true, meta: { changes: 1 } })
            };
          }
        };
      },
      batch: async () => { calls.batches++; return []; }
    },
    ANALYSIS_QUEUE: { send: async () => { calls.queue++; } },
    calls
  };
  return env;
}

test("serves the Finanx application and core pages", async () => {
  const response = await worker.fetch(new Request("https://finanx.test/"), {}, { waitUntil() {} });
  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type"), /text\/html/);
  assert.equal(response.headers.get("x-content-type-options"), "nosniff");
  assert.match(response.headers.get("content-security-policy"), /frame-ancestors 'none'/);
  const html = await response.text();
  for (const marker of [
    "Market intelligence", "Market Activity", "Market Scan", "PreviewIndex",
    "FullIndex", "stock-chart", "history-chart", "market-activity",
    "password-form", "Analysis queue", "Watchlist"
  ]) assert.ok(html.includes(marker), `Missing page marker: ${marker}`);
  assert.match(html, /\.cards:not\(\.scan-rail\)\{display:grid!important/);
  assert.match(html, /\.scan-rail\{display:flex!important/);
  assert.doesNotMatch(html, /setTimeout\(\(\)=>showAuth/);
});

test("health endpoint verifies database and queue bindings", async () => {
  const env = testEnv();
  const response = await worker.fetch(new Request("https://finanx.test/api/health"), env, { waitUntil() {} });
  const body = await response.json();
  assert.equal(response.status, 200);
  assert.equal(body.ok, true);
  assert.equal(body.database, "D1");
  assert.equal(body.queue, "Cloudflare Queues");
  assert.ok(env.calls.sql.some(x => x.sql.includes("SELECT 1 AS ok")));
});

test("health endpoint reports a failed database check", async () => {
  const env = testEnv({ failDatabase: true });
  const response = await worker.fetch(new Request("https://finanx.test/api/health"), env, { waitUntil() {} });
  const body = await response.json();
  assert.equal(response.status, 503);
  assert.equal(body.ok, false);
  assert.equal(body.database, "Unavailable");
});

test("handles browser preflight requests without database access", async () => {
  const response = await worker.fetch(new Request("https://finanx.test/api/health", { method: "OPTIONS" }), {}, { waitUntil() {} });
  assert.equal(response.status, 204);
});

test("unknown API routes return 404", async () => {
  const response = await worker.fetch(new Request("https://finanx.test/api/not-a-route"), {}, { waitUntil() {} });
  assert.equal(response.status, 404);
});

test("rejects unsupported forecast horizons before querying D1", async () => {
  const env = testEnv();
  const response = await worker.fetch(new Request("https://finanx.test/api/index-availability?ticker=AAPL&horizon=0"), env, { waitUntil() {} });
  const body = await response.json();
  assert.equal(response.status, 400);
  assert.match(body.error, /whole number/);
  assert.equal(env.calls.sql.length, 0);
});

test("does not expose a user-owned analysis job to anonymous callers", async () => {
  const env = testEnv({
    firstResult: sql => sql.includes("FROM analysis_jobs")
      ? { id: "123e4567-e89b-12d3-a456-426614174000", ticker: "AAPL", status: "completed", result: "{}", user_id: "user-private" }
      : null
  });
  const response = await worker.fetch(new Request("https://finanx.test/api/analysis-status?id=123e4567-e89b-12d3-a456-426614174000"), env, { waitUntil() {} });
  assert.equal(response.status, 404);
  assert.equal(env.calls.sql.length, 1);
});

test("market scan reads existing fresh indexes without enqueuing new work", async () => {
  const env = testEnv();
  const response = await worker.fetch(new Request("https://finanx.test/api/market-scan", { method: "POST", headers: { "Content-Type": "application/json", "cf-connecting-ip": "192.0.2.10" }, body: "{}" }), env, { waitUntil() {} });
  const body = await response.json();
  assert.equal(response.status, 200);
  assert.equal(body.queued, 0);
  assert.deepEqual(body.items, []);
  assert.equal(env.calls.queue, 0);
  assert.ok(env.calls.sql.some(x => x.sql.includes("INSERT INTO api_rate_limits")));
});

test("rejects unsupported analysis horizons", async () => {
  const env = testEnv();
  const response = await worker.fetch(new Request("https://finanx.test/api/request-analysis", {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ticker: "AAPL", horizon: 1.5 })
  }), env, { waitUntil() {} });
  const body = await response.json();
  assert.equal(response.status, 400);
  assert.match(body.error, /whole number/);
});

test("hard rescan bypasses cache cooldown and is persisted for the queue consumer", async () => {
  const env = testEnv();
  const response = await worker.fetch(new Request("https://finanx.test/api/request-analysis", {
    method: "POST", headers: { "Content-Type": "application/json", "cf-connecting-ip": "192.0.2.20" },
    body: JSON.stringify({ ticker: "AAPL", hard_rescan: true })
  }), env, { waitUntil() {} });
  const body = await response.json();
  assert.equal(response.status, 202);
  assert.equal(body.status, "queued");
  assert.equal(env.calls.queue, 1);
  const insert = env.calls.sql.find(x => x.sql.includes("INSERT INTO analysis_jobs"));
  assert.ok(insert);
  assert.ok(insert.args.includes("hard_rescan"));
});

test("market feed rate limit stops excessive refresh requests", async () => {
  const env = testEnv({
    firstResult: sql => sql.includes("INSERT INTO api_rate_limits") ? { attempts: 16 } : null
  });
  const response = await worker.fetch(new Request("https://finanx.test/api/market-feed"), env, { waitUntil() {} });
  assert.equal(response.status, 429);
  assert.equal(env.calls.sql.length, 1);
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
  assert.ok(candidates.some(x => x.name === "Linear Epsilon-SVR"));
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
