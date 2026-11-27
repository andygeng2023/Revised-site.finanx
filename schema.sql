-- Revised Finanx D1 schema (EU jurisdiction).
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS users (
 id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, password_salt TEXT NOT NULL,
 display_name TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, last_sign_in_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
 token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL,
 FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE TABLE IF NOT EXISTS watchlist_items (
 id TEXT PRIMARY KEY, user_id TEXT NOT NULL, ticker TEXT NOT NULL, created_at TEXT NOT NULL,
 UNIQUE(user_id,ticker), FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_watchlist_user ON watchlist_items(user_id,created_at);
CREATE TABLE IF NOT EXISTS analysis_jobs (
 id TEXT PRIMARY KEY, ticker TEXT NOT NULL, period TEXT NOT NULL, horizon INTEGER NOT NULL,
 job_type TEXT NOT NULL DEFAULT 'analysis', scan_source TEXT NOT NULL DEFAULT 'both',
 save_to_indexer TEXT NOT NULL DEFAULT 'PreviewIndex', status TEXT NOT NULL,
 result TEXT, error TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
 progress INTEGER NOT NULL DEFAULT 0, stage TEXT NOT NULL DEFAULT 'Queued',
 attempts INTEGER NOT NULL DEFAULT 0, user_id TEXT, requested_by TEXT
);
CREATE INDEX IF NOT EXISTS idx_jobs_status ON analysis_jobs(status,created_at);
CREATE INDEX IF NOT EXISTS idx_jobs_ticker ON analysis_jobs(ticker,period,horizon,save_to_indexer,created_at);
CREATE TABLE IF NOT EXISTS market_index (
 ticker TEXT NOT NULL, period TEXT NOT NULL, horizon INTEGER NOT NULL, indexer TEXT NOT NULL,
 indexed_at TEXT NOT NULL, source_job_id TEXT, result TEXT NOT NULL, market_cap REAL, avg_dollar_volume REAL,
 PRIMARY KEY(ticker,period,horizon,indexer)
);
CREATE INDEX IF NOT EXISTS idx_market_index_fresh ON market_index(indexer,indexed_at);
CREATE TABLE IF NOT EXISTS api_rate_limits (
 bucket_key TEXT PRIMARY KEY, window_start INTEGER NOT NULL, attempts INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS model_learning_state (
 model_key TEXT PRIMARY KEY, observations INTEGER NOT NULL DEFAULT 0,
 correct INTEGER NOT NULL DEFAULT 0, accuracy REAL NOT NULL DEFAULT 0.5,
 weight REAL NOT NULL DEFAULT 1.0, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ticker_catalog (
 ticker TEXT PRIMARY KEY, company TEXT, currency TEXT, sector TEXT, last_indexed_at TEXT,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS app_events (
 id TEXT PRIMARY KEY, event_type TEXT NOT NULL, ticker TEXT, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS market_quotes (
 ticker TEXT PRIMARY KEY, company TEXT, currency TEXT, price REAL, change_percent REAL,
 as_of TEXT, source TEXT, updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_market_quotes_updated ON market_quotes(updated_at);
