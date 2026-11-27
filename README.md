# Revised Finanx

A self-contained stock research and analysis application delivered by Cloudflare Workers. The web interface, API, background analysis worker and scheduled refreshes are all hosted by Cloudflare. GitHub Actions are not used for deployment or job processing.

## Included

- Responsive dashboard, market watch, search/discovery, personal watchlist, analysis queue and settings.
- PreviewIndex and FullIndex with persistent two-button selection on the stock detail page.
- Default PreviewIndex analysis for a newly entered ticker, with FullIndex available as an alternative.
- Yahoo Finance chart data with short-lived quote caching and a second Yahoo host as a network fallback.
- 15 original estimator signals, 10 first-layer hybrids, 3 meta-hybrids and an adaptive primary ensemble in FullIndex; PreviewIndex runs a smaller 21-candidate set (7 + 10 + 3 + primary). Each index maintains separate global performance profiles.
- Rolling chronological one-day validation and aggregate cross-account model-learning statistics. Each index keeps a separate global profile for the models it runs.
- Historical and forecast charts, risk context, fundamentals where Yahoo returns them, and model diagnostics.
- Account signup/sign-in, 30-day sessions, and user-scoped watchlists.
- Cloudflare Queues for analysis jobs, retry handling and a dead-letter queue.
- Cron Triggers for six-hour PreviewIndex refreshes and a daily FullIndex refresh.
- D1 storage for accounts, sessions, jobs, indexes, cached quotes and model-learning state.

## Infrastructure

- Worker: `revised-finanx`
- D1 database: `revised-finanx-db` (EU jurisdiction)
- Queue: `revised-finanx-analysis`
- Dead-letter queue: `revised-finanx-analysis-dlq`
- Bindings: `DB`, `ANALYSIS_QUEUE`
- Scheduled triggers: every six hours for PreviewIndex; daily at 02:00 UTC for FullIndex.

All account, watchlist and market-index data in this deployment starts in a fresh D1 database. The database is not a copy of any existing production data.

## Local development

1. Install Node.js 20 or newer.
2. Run `npm install`.
3. Run `npx wrangler login` and make sure the correct Cloudflare account is selected.
4. Create or use the D1 database and queues described in `wrangler.jsonc`.
5. Run `npx wrangler dev`.
6. Run `npm test`.

## Deploy

The live Worker has been uploaded directly to the Cloudflare Workers API (deployment ID: `67099c95a0ec4d6a88b7cba433410192`). For repeatable future deployments, connect this repository to Cloudflare Workers Builds in the Cloudflare dashboard (Workers & Pages → Create → Workers → Connect to Git). Select this repository and the `main` branch; use `npm install` as the install command and `npx wrangler deploy` as the deploy command. Do not add a GitHub Actions workflow.

The same bindings must be present on the Worker build:
- D1: `DB` → `revised-finanx-db`
- Queue producer: `ANALYSIS_QUEUE` → `revised-finanx-analysis`
- Queue consumer: `revised-finanx-analysis`, batch size 5, 5 retries, dead-letter queue `revised-finanx-analysis-dlq`
- Cron: `0 */6 * * *` and `0 2 * * *`

## Live address

The deployed app is available at:

`https://revised-finanx.stock-analyser-2026.workers.dev`

The account's current DNS zone list does not include `is-a-fullstack.dev`, so the Worker cannot yet be attached to `site.finanx.is-a-fullstack.dev`. A custom domain can be added after that zone is managed in the same Cloudflare account (or a domain owned by you is added there).

## Notes and limitations

- Yahoo Finance endpoints are unofficial and can rate-limit, delay, or change. Quote timestamps are exposed in the API response; refreshing a page does not make upstream data real-time.
- FullIndex has the requested 29-candidate architecture (15 + 10 + 3 + primary). PreviewIndex intentionally uses a smaller selected ensemble.
- Directional accuracy is measured on chronological holdouts. It is not guaranteed to reach 70%, and results may vary substantially by instrument and market regime.
- Global learning stores aggregate model outcomes; it does not use a person's watchlist as training data.
- The forecasting engine is a lightweight JavaScript implementation intended to run inside Workers. It does not replicate a specialised Python/scikit-learn ARIMA/SVM engine.
- Financial information is for research and education only, not investment advice.
