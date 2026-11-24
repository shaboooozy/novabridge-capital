CREATE TABLE IF NOT EXISTS users (
  id BIGSERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user',
  email_verified_at TIMESTAMPTZ,
  verification_token_hash TEXT,
  reset_token_hash TEXT,
  reset_token_expires_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  flagged BOOLEAN NOT NULL DEFAULT FALSE,
  flag_reason TEXT,
  flagged_at TIMESTAMPTZ,
  flagged_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
  account_status TEXT NOT NULL DEFAULT 'active',
  admin_notes TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS portfolios (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
  cash_cents BIGINT NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS activities (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  activity TEXT NOT NULL,
  type TEXT NOT NULL,
  amount_cents BIGINT NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'Pending',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS activities_user_id_id_idx ON activities(user_id, id DESC);

CREATE TABLE IF NOT EXISTS products (
  id BIGSERIAL PRIMARY KEY,
  slug TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  category TEXT NOT NULL,
  description TEXT NOT NULL,
  risk_level TEXT NOT NULL,
  minimum_cents BIGINT NOT NULL,
  status TEXT NOT NULL DEFAULT 'draft',
  verified_at TIMESTAMPTZ,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
  action TEXT NOT NULL,
  ip_address INET,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS withdrawal_requests (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  network TEXT NOT NULL,
  wallet_address TEXT NOT NULL,
  amount_cents BIGINT NOT NULL,
  status TEXT NOT NULL DEFAULT 'Pending',
  reviewed_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
  reviewed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  review_note TEXT,
  activity_id BIGINT REFERENCES activities(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS withdrawal_requests_user_id_idx ON withdrawal_requests(user_id, id DESC);

CREATE TABLE IF NOT EXISTS funding_requests (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  network TEXT NOT NULL,
  deposit_address TEXT NOT NULL,
  amount_cents BIGINT NOT NULL,
  status TEXT NOT NULL DEFAULT 'Pending',
  activity_id BIGINT REFERENCES activities(id) ON DELETE SET NULL,
  reviewed_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
  reviewed_at TIMESTAMPTZ,
  review_note TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS funding_requests_user_id_idx ON funding_requests(user_id, id DESC);

CREATE TABLE IF NOT EXISTS deposit_wallets (
  id BIGSERIAL PRIMARY KEY,
  network TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  address TEXT NOT NULL,
  active BOOLEAN NOT NULL DEFAULT TRUE,
  updated_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS scheduled_jobs (
  id BIGSERIAL PRIMARY KEY,
  job_type TEXT NOT NULL,
  user_id BIGINT REFERENCES users(id) ON DELETE CASCADE,
  dedupe_key TEXT UNIQUE,
  payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  run_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  status TEXT NOT NULL DEFAULT 'pending',
  attempts INT NOT NULL DEFAULT 0,
  max_attempts INT NOT NULL DEFAULT 5,
  locked_by TEXT,
  locked_at TIMESTAMPTZ,
  last_error TEXT,
  completed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS scheduled_jobs_due_idx
  ON scheduled_jobs(run_at, id)
  WHERE status = 'pending';

CREATE TABLE IF NOT EXISTS wallet_listener_state (
  network TEXT PRIMARY KEY,
  address TEXT NOT NULL,
  last_seen_block BIGINT,
  last_seen_cursor TEXT,
  last_polled_at TIMESTAMPTZ,
  last_error TEXT,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS wallet_tx_events (
  id BIGSERIAL PRIMARY KEY,
  network TEXT NOT NULL,
  tx_hash TEXT NOT NULL,
  watched_address TEXT NOT NULL,
  direction TEXT NOT NULL DEFAULT 'incoming',
  asset_symbol TEXT NOT NULL,
  amount_raw TEXT NOT NULL,
  amount_cents BIGINT NOT NULL DEFAULT 0,
  confirmations INT NOT NULL DEFAULT 0,
  required_confirmations INT NOT NULL DEFAULT 1,
  status TEXT NOT NULL DEFAULT 'seen',
  user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
  activity_id BIGINT REFERENCES activities(id) ON DELETE SET NULL,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  confirmed_at TIMESTAMPTZ,
  credited_at TIMESTAMPTZ,
  UNIQUE (network, tx_hash, watched_address)
);

CREATE TABLE IF NOT EXISTS recurring_transactions (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  action_type TEXT NOT NULL,
  label TEXT NOT NULL,
  amount_cents BIGINT NOT NULL,
  network TEXT,
  wallet_address TEXT,
  interval_unit TEXT NOT NULL,
  interval_count INT NOT NULL DEFAULT 1,
  next_run_at TIMESTAMPTZ NOT NULL,
  last_run_at TIMESTAMPTZ,
  run_count INT NOT NULL DEFAULT 0,
  max_runs INT,
  status TEXT NOT NULL DEFAULT 'active',
  last_error TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS recurring_transactions_due_idx
  ON recurring_transactions(next_run_at, id)
  WHERE status = 'active';

CREATE TABLE IF NOT EXISTS remote_commands (
  id BIGSERIAL PRIMARY KEY,
  command_id TEXT NOT NULL UNIQUE,
  source TEXT NOT NULL,
  command_type TEXT NOT NULL,
  target_user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
  payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  status TEXT NOT NULL DEFAULT 'received',
  response_body JSONB NOT NULL DEFAULT '{}'::jsonb,
  error_message TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  processed_at TIMESTAMPTZ
);
