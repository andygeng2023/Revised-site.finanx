import test from "node:test";
import assert from "node:assert/strict";
import vm from "node:vm";
import { readFile } from "node:fs/promises";
import worker from "../src/worker.js";
import { getOriginalPredictions, ensemblePredictions, buildModelEvaluation, modelCandidates } from "../src/models.js";

function testEnv({ firstResult = null, failDatabase = false, failUserInsert = false } = {}) {
  const calls = { sql: [], queue: 0, batches: 0, batchMessages: [] };
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
              run: async () => {
                if (failUserInsert && sql.includes("INSERT INTO users")) throw new Error("D1 daily row write limit exhausted");
                return { success: true, meta: { changes: 1 } };
              }
            };
          }
        };
      },
      batch: async () => { calls.batches++; return []; }
    },
    ANALYSIS_QUEUE: { send: async () => { calls.queue++; }, sendBatch: async messages => { calls.batchMessages.push(...messages); } },
    FULLINDEX_QUEUE: { send: async () => {}, sendBatch: async messages => { calls.batchMessages.push(...messages); } },
    PREVIEWINDEX_QUEUE: { send: async () => {}, sendBatch: async messages => { calls.batchMessages.push(...messages); } },
    AUTH_KV: (() => {
      const values = new Map();
      return {
        async get(key, type) {
          const value = values.get(key);
          if (value == null) return null;
          return type === "json" ? JSON.parse(value) : value;
        },
        async put(key, value) { values.set(key, String(value)); },
        async delete(key) { values.delete(key); }
      };
    })(),
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
    "Market intelligence", "Market pulse", "Top advancing", "Top declining", "Stocks to explore",
    "Market Scan", "PreviewIndex", "FullIndex", "stock-chart", "history-chart",
    "home-featured-cards", "discover-featured-cards", "Forecast leaders", "Recently analysed",
    "Your saved instruments", "Shared model learning", "Analysis history", "Watchlist", "settings-grid",
    "Background processing", "Validation & limitations"
  ]) assert.ok(html.includes(marker), `Missing page marker: ${marker}`);
  assert.doesNotMatch(html, /Market Activity|market-activity/);
  assert.match(html, /\.cards\{display:flex;flex-flow:row nowrap;width:100%/);
  assert.doesNotMatch(html, /\.cards:not\(\.scan-rail\)|\.scan-rail\{display:flex!important|Final horizontal-card rails/);
  assert.doesNotMatch(html, /setTimeout\(\(\)=>showAuth/);
  assert.match(html, /const API="https:\/\/revised-finanx\.stock-analyser-2026\.workers\.dev";/);
});

test("embedded browser JavaScript parses and has no duplicate HTML IDs", async () => {
  const response = await worker.fetch(new Request("https://finanx.test/"), {}, { waitUntil() {} });
  const html = await response.text();
  const script = html.split("<script>")[1]?.split("</script>")[0] || "";
  assert.ok(script, "The application script must exist");
  assert.doesNotThrow(() => new vm.Script(script), "Browser JavaScript must parse before deployment");
  const markup = html.slice(0, html.indexOf("<script>"));
  const ids = [...markup.matchAll(/id="([^"]+)"/g)].map(match => match[1]);
  assert.equal(new Set(ids).size, ids.length, "HTML IDs must be unique");
  const indexHtml = await readFile(new URL("../index.html", import.meta.url), "utf8");
  for (const marker of ["home-featured-cards", "discover-featured-cards", "home-scan-picks", "settings-grid"]) {
    assert.ok(indexHtml.includes(marker), `Static page is missing UI marker: ${marker}`);
  }
  assert.doesNotMatch(indexHtml, /Market Activity|market-activity/);
});

test("all static browser event-listener targets exist in the HTML", async () => {
  const response = await worker.fetch(new Request("https://finanx.test/"), {}, { waitUntil() {} });
  const html = await response.text();
  const body = html.slice(html.indexOf("<body>"), html.indexOf("<script>"));
  const script = html.split("<script>")[1]?.split("</script>")[0] || "";
  const ids = new Set([...body.matchAll(/id="([^"]+)"/g)].map(match => match[1]));
  const eventTargets = [...script.matchAll(/\$\("([^"]+)"\)\.addEventListener/g)].map(match => match[1]);
  const missing = [...new Set(eventTargets.filter(id => !ids.has(id)))];
  assert.deepEqual(missing, [], "Static event-listener targets must exist; generated targets should use explicit guards");
});

test("login rejects malformed email addresses before credential lookup", async () => {
  const env = testEnv();
  const response = await worker.fetch(new Request("https://finanx.test/api/auth/login", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: "not a valid email", password: "long-enough-password" })
  }), env, { waitUntil() {} });
  assert.equal(response.status, 401);
  assert.equal(env.calls.sql.some(x => x.sql.includes("FROM users")), false);
});

test("login accepts a valid email format and reaches credential lookup", async () => {
  const env = testEnv();
  const response = await worker.fetch(new Request("https://finanx.test/api/auth/login", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: "person@example.com", password: "long-enough-password" })
  }), env, { waitUntil() {} });
  assert.equal(response.status, 401);
  assert.equal(env.calls.sql.some(x => x.sql.includes("FROM users")), true);
});

test("health endpoint verifies database and queue bindings", async () => {
  const env = testEnv();
  const response = await worker.fetch(new Request("https://finanx.test/api/health"), env, { waitUntil() {} });
  const body = await response.json();
  assert.equal(response.status, 200);
  assert.equal(body.ok, true);
  assert.equal(body.database, "D1");
  assert.equal(body.queue, "Cloudflare Queues");
  assert.equal(body.full_index_queue, "Bound");
  assert.ok(env.calls.sql.some(x => x.sql.includes("SELECT 1 AS ok")));
});

test("health endpoint reports a missing FullIndex queue binding", async () => {
  const env = testEnv();
  delete env.FULLINDEX_QUEUE;
  const response = await worker.fetch(new Request("https://finanx.test/api/health"), env, { waitUntil() {} });
  const body = await response.json();
  assert.equal(response.status, 503);
  assert.equal(body.full_index_queue, "Unavailable");
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

test("PreviewIndex and FullIndex have fixed 30 and 60 day horizons", async () => {
  const source = await readFile(new URL("../src/worker.js", import.meta.url), "utf8");
  assert.match(source, /indexer==="FullIndex"\?60:30/);
  assert.match(source, /horizon:30/);
  assert.match(source, /horizon:60/);
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

test("shared index cache hit returns without queueing or writing D1", async () => {
  const env = testEnv({
    firstResult: sql => sql.includes("FROM market_index")
      ? { result: JSON.stringify({ ticker: "AAPL" }), indexed_at: new Date().toISOString(), source_job_id: "existing-job" }
      : null
  });
  const response = await worker.fetch(new Request("https://finanx.test/api/request-analysis", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ticker: "AAPL", indexer: "FullIndex" })
  }), env, { waitUntil() {} });
  const body = await response.json();
  assert.equal(response.status, 200);
  assert.equal(body.cached, true);
  assert.equal(body.ticker, "AAPL");
  assert.equal(env.calls.queue, 0);
  assert.equal(env.calls.sql.some(call => call.sql.includes("INSERT INTO analysis_jobs")), false);
});

test("market feed does not persist every quote refresh to D1", async () => {
  const source = await readFile(new URL("../src/worker.js", import.meta.url), "utf8");
  const marketFeed = source.slice(source.indexOf("async function marketFeed"), source.indexOf("async function cachedMarketFeed"));
  assert.match(marketFeed, /localMarketQuotes/);
  assert.doesNotMatch(marketFeed, /INSERT INTO market_quotes|INSERT INTO ticker_catalog|env\.DB\.batch/);
  const handler = source.slice(source.indexOf("async function cachedMarketFeed"), source.indexOf("async function watchlist"));
  assert.match(handler, /cache\.match/);
  assert.match(handler, /cache\.put/);
});

test("index discovery runs continuously, respects 30000 caps, and recovers stale queue jobs", async () => {
  const source = await readFile(new URL("../src/worker.js", import.meta.url), "utf8");
  assert.match(source, /MAX_INDEXED=30000/);
  assert.match(source, /indexedTickers\.size>=MAX_INDEXED/);
  assert.match(source, /Scheduled .*continuous discovery refresh/);
  assert.match(source, /cron==="\*\/5 \* \* \* \*"/);
  assert.match(source, /staleCutoff=new Date\(Date\.now\(\)-2\*3600000\)/);
  assert.match(source, /Recovered stale job; requeued by scheduled scan/);
  assert.match(source, /sendBatch\(batch\)/);
  assert.match(source, /job_type='scan'/);
  assert.match(source, /LIMIT 100/);
  assert.match(source, /D1_WRITE_PAUSE_KEY/);
  assert.match(source, /queue completions immediately continue the scan pipeline/);
  const status = source.slice(source.indexOf("async function queueStatus"), source.indexOf("async function searchRoute"));
  assert.match(status, /stage LIKE 'Scheduled % discovery refresh'/);
  const consumer = source.slice(source.indexOf("  async queue(batch,env){"), source.indexOf("  async scheduled(controller,env,ctx){"));
  assert.match(consumer, /completed\?\.jobType==="scan"/);
  assert.match(consumer, /refreshIndexes\(env,indexer\)/);
  assert.match(consumer, /Not enough valid historical prices were returned/);
  assert.match(consumer, /isD1DailyWriteLimitError/);
});

test("global model learning is stored in KV once per day rather than multiple D1 rows", async () => {
  const source = await readFile(new URL("../src/worker.js", import.meta.url), "utf8");
  const updater = source.slice(source.indexOf("async function updateGlobalLearning"), source.indexOf("async function updateJobProgress"));
  assert.match(updater, /AUTH_KV\.put/);
  assert.match(updater, /24\*3600000/);
  assert.doesNotMatch(updater, /env\.DB\.batch|INSERT INTO model_learning_state/);
});

test("market scan reads existing fresh indexes without enqueuing new work", async () => {
  const env = testEnv();
  const response = await worker.fetch(new Request("https://finanx.test/api/market-scan", { method: "POST", headers: { "Content-Type": "application/json", "cf-connecting-ip": "192.0.2.10" }, body: "{}" }), env, { waitUntil() {} });
  const body = await response.json();
  assert.equal(response.status, 200);
  assert.equal(body.queued, 0);
  assert.deepEqual(body.items, []);
  assert.equal(env.calls.queue, 0);
  assert.equal(env.calls.sql.some(x => x.sql.includes("api_rate_limits")), false);
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

test("auth rate limits do not write counters to D1", async () => {
  const env = testEnv();
  const request = () => worker.fetch(new Request("https://finanx.test/api/auth/signup", {
    method: "POST",
    headers: { "Content-Type": "application/json", "cf-connecting-ip": "203.0.113.240" },
    body: JSON.stringify({ email: "invalid-email", password: "not-a-valid-signup" })
  }), env, { waitUntil() {} });
  for (let i = 0; i < 5; i++) assert.equal((await request()).status, 400);
  assert.equal((await request()).status, 429);
  assert.equal(env.calls.sql.some(x => x.sql.includes("api_rate_limits")), false);
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

test("scheduled index refreshes run every five minutes for both index types", async () => {
  const env = testEnv();
  const promises = [];
  worker.scheduled({ cron: "*/5 * * * *" }, env, { waitUntil: promise => promises.push(promise) });
  assert.equal(promises.length, 2, "Both index types should be refreshed on every scan cycle");
  await Promise.all(promises);
  assert.ok(env.calls.sql.some(x => x.sql.includes("INSERT INTO analysis_jobs") && x.args[5] === "PreviewIndex"));
  assert.ok(env.calls.sql.some(x => x.sql.includes("INSERT INTO analysis_jobs") && x.args[5] === "FullIndex"));
  assert.ok(env.calls.batchMessages.length >= 2);
});


test("weekly housekeeping is separated from index refreshes", async () => {
  const env = testEnv();
  const promises = [];
  worker.scheduled({ cron: "*/5 * * * *", scheduledTime: Date.UTC(2026, 10, 29, 0, 0, 0) }, env, { waitUntil: promise => promises.push(promise) });
  await Promise.all(promises);
  assert.ok(env.calls.sql.some(call => call.sql.includes("DELETE FROM sessions")));
  assert.ok(env.calls.sql.some(call => call.sql.includes("DELETE FROM analysis_jobs")));
});

test("Worker PBKDF2 iterations stay within the WebCrypto limit", async () => {
  const source = await readFile(new URL("../src/worker.js", import.meta.url), "utf8");
  assert.match(source, /iterations:100000,hash:"SHA-256"/);
  assert.match(source, /const dailyVol=.*\n  const rawModelSignal=.*newsAdjustment=/);
});


test("signup falls back to EU KV when D1 daily writes are exhausted", async () => {
  const env = testEnv({ failUserInsert: true });
  const response = await worker.fetch(new Request("https://finanx.test/api/auth/signup", {
    method: "POST",
    headers: { "Content-Type": "application/json", "cf-connecting-ip": "192.0.2.222" },
    body: JSON.stringify({ email: "fallback@example.com", password: "secure-test-password" })
  }), env, { waitUntil() {} });
  assert.equal(response.status, 201);
  const body = await response.json();
  assert.equal(body.user.email, "fallback@example.com");
  assert.equal(body.session.token_type, "bearer");
  const me = await worker.fetch(new Request("https://finanx.test/api/auth/me", {
    headers: { Authorization: "Bearer " + body.session.access_token }
  }), env, { waitUntil() {} });
  assert.equal(me.status, 200);
  assert.equal((await me.json()).user.email, "fallback@example.com");
});


test("KV-backed accounts can add, list and remove watchlist items without D1 writes", async () => {
  const env = testEnv({ failUserInsert: true });
  const signup = await worker.fetch(new Request("https://finanx.test/api/auth/signup", {
    method: "POST", headers: { "Content-Type": "application/json", "cf-connecting-ip": "192.0.2.223" },
    body: JSON.stringify({ email: "watchlist-fallback@example.com", password: "secure-test-password" })
  }), env, { waitUntil() {} });
  assert.equal(signup.status, 201);
  const account = await signup.json();
  const headers = { Authorization: "Bearer " + account.session.access_token, "Content-Type": "application/json" };
  const add = await worker.fetch(new Request("https://finanx.test/api/watchlist", { method: "POST", headers, body: JSON.stringify({ action: "add", ticker: "AAPL" }) }), env, { waitUntil() {} });
  assert.equal(add.status, 200);
  const listed = await worker.fetch(new Request("https://finanx.test/api/watchlist", { method: "POST", headers, body: JSON.stringify({ action: "list" }) }), env, { waitUntil() {} });
  assert.deepEqual((await listed.json()).items.map(item => item.ticker), ["AAPL"]);
  const removed = await worker.fetch(new Request("https://finanx.test/api/watchlist", { method: "POST", headers, body: JSON.stringify({ action: "remove", ticker: "AAPL" }) }), env, { waitUntil() {} });
  assert.equal(removed.status, 200);
  const finalList = await worker.fetch(new Request("https://finanx.test/api/watchlist", { method: "POST", headers, body: JSON.stringify({ action: "list" }) }), env, { waitUntil() {} });
  assert.deepEqual((await finalList.json()).items, []);
});


test("signup refuses an existing D1 email before attempting KV fallback", async () => {
  const env = testEnv({
    failUserInsert: true,
    firstResult: sql => sql.includes("SELECT id FROM users WHERE email") ? { id: "existing-user-id" } : null
  });
  const response = await worker.fetch(new Request("https://finanx.test/api/auth/signup", {
    method: "POST", headers: { "Content-Type": "application/json", "cf-connecting-ip": "192.0.2.224" },
    body: JSON.stringify({ email: "existing@example.com", password: "secure-test-password" })
  }), env, { waitUntil() {} });
  assert.equal(response.status, 409);
  assert.equal(env.calls.sql.some(call => call.sql.includes("INSERT INTO users")), false);
});
