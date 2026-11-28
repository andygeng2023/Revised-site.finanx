# Revised Finanx

Finanx is a single-origin stock research application hosted on Cloudflare Workers. The Worker serves the application, provides the API, processes analysis jobs from Cloudflare Queues and schedules index refreshes. The GitHub Actions workflow runs regression tests only; it does not deploy the application or process jobs.

## Application

- Responsive market overview with a tracked-universe summary, largest daily movers and a horizontally scrolling positive-forecast scan.
- Separate stock discovery, personal watchlist, analysis queue, settings and stock-detail views.
- Keyboard-operable stock cards and market activity rows, labelled search inputs, modal focus containment and reduced-motion support.
- PreviewIndex and FullIndex selection on stock detail pages.
- Historical price chart, indexed forecast chart, forecast range, fundamentals, risk context and model diagnostics.
- Account signup/sign-in, hashed session tokens, password changes and user-scoped watchlists. Browsing and market research remain available without an account.
- No forced sign-in prompt. Guest browsing is supported.

## Data and analysis

- Yahoo Finance chart data with a secondary Yahoo host fallback, short-lived D1 quote caching and bounded upstream concurrency.
- Fresh PreviewIndex records are considered current for up to eight hours; FullIndex records for up to 24 hours.
- Market Scan reads existing fresh 30-day index records only. It filters to strictly positive expected returns and sorts by expected return; it does not enqueue analysis jobs.
- FullIndex contains 15 original estimators, 10 first-layer hybrids, 3 meta-hybrids and one primary ensemble. PreviewIndex uses seven selected original estimators with the same hybrid layers.
- Directional validation uses chronological one-trading-day holdouts. This metric is not a measure of the accuracy of a 30-day price target.
- Model-learning records aggregate model performance by index. They do not use account-specific watchlists as training data.
- The forecasting engine is a lightweight JavaScript implementation designed for Cloudflare Workers. It is not a specialist Python/scikit-learn ARIMA/SVM implementation.

## Backend safeguards

- Passwords are PBKDF2-hashed with per-account salts; bearer session tokens are SHA-256 hashed before storage.
- Public market feed, search, scan and analysis-request endpoints have per-IP rate limits.
- User-owned analysis job status is checked against the authenticated user. Anonymous jobs remain pollable by their unguessable job IDs.
- Password changes revoke all other sessions while retaining the current session.
- Market-feed calls are concurrency-limited, and quote-provider outages do not hide a fresh cached index result.
- Queue jobs are acknowledged after completion or terminal failure and retried only while retries remain.
- API health checks verify the D1 binding and queue producer binding.

## Infrastructure

- Worker: `revised-finanx`
- D1 database: `revised-finanx-db` (EU jurisdiction)
- Queue: `revised-finanx-analysis`
- Dead-letter queue: `revised-finanx-analysis-dlq`
- Bindings: `DB`, `ANALYSIS_QUEUE`
- Scheduled triggers: every six hours for PreviewIndex; daily at 02:00 UTC for FullIndex.

The D1 database is configured in `wrangler.jsonc`. The application code does not automatically apply schema changes. Apply `schema.sql` to a new D1 database before first use; do not re-run destructive migrations against a database containing data.

## Source structure

- `src/worker.js`: deployed Worker routes, auth, data access, queue handling and scheduled jobs.
- `src/page.js`: the HTML, CSS and browser application served by the Worker.
- `src/models.js`: forecasting estimators, ensemble construction and chronological evaluation.
- `index.html`: static mirror of the HTML embedded in `src/page.js`; keep these in sync.
- `schema.sql`: D1 schema.
- `tests/worker.test.mjs`: Worker, API contract, UI regression and model architecture tests.
- `wrangler.jsonc`: Worker and Cloudflare binding configuration.

The unused duplicate implementation that previously lived at `src/index.js` has been removed. Wrangler's configured entry point is `src/worker.js`.

## Local development and tests

1. Install Node.js 20 or newer.
2. Run `npm install`.
3. Configure the D1 database and Cloudflare Queues from `wrangler.jsonc`.
4. Run `npx wrangler dev`.
5. Run `npm test`.

The `.github/workflows/quality.yml` workflow runs `npm test` on pushes and pull requests. It does not require deployment secrets.

## Deploy

Deploy with Wrangler after the regression tests pass:

```sh
npm install
npm test
npx wrangler deploy
```

The existing Worker is configured with D1 binding `DB`, queue producer `ANALYSIS_QUEUE`, the queue consumer and scheduled triggers. Preserve these bindings when deploying.

## Live address

https://revised-finanx.stock-analyser-2026.workers.dev

The Worker is not currently attached to `site.finanx.is-a-fullstack.dev`. That custom hostname requires the relevant DNS zone to be managed in the same Cloudflare account.

## Limitations

Yahoo Finance endpoints are unofficial and can rate-limit, delay or change. Quote timestamps may be older than the time a page is refreshed. A 30-day forecast is an uncertain model output, not a guaranteed result or personalised investment recommendation. Market data can be delayed, incomplete or inaccurate. The application is for research and education only.
