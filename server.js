require('dotenv').config();
const express = require('express');
const session = require('express-session');
const PgSession = require('connect-pg-simple')(session);
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const crypto = require('crypto');
const nodemailer = require('nodemailer');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const isProduction = process.env.NODE_ENV === 'production';
const SESSION_SECRET = process.env.SESSION_SECRET;
const DATABASE_URL = process.env.DATABASE_URL;
const APP_URL = process.env.APP_URL || `http://localhost:${PORT}`;
const onVercel = Boolean(process.env.VERCEL);

if (!onVercel) {
  if (isProduction && (!SESSION_SECRET || SESSION_SECRET.length < 32)) {
    throw new Error('SESSION_SECRET must be at least 32 characters in production.');
  }
  if (!DATABASE_URL) throw new Error('DATABASE_URL is required.');
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.DATABASE_SSL === 'false' ? false : { rejectUnauthorized: false },
  max: Number(process.env.DB_POOL_MAX || (onVercel ? 1 : 10)),
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

const q = (text, params = []) => pool.query(text, params);
const email = s => String(s || '').trim().toLowerCase();
const money = cents => Number(cents || 0) / 100;
const cents = amount => Math.round(Number(amount) * 100);
const tokenHash = token => crypto.createHash('sha256').update(token).digest('hex');
const makeToken = () => crypto.randomBytes(32).toString('hex');
const walletPatterns = {
  bitcoin: /^(bc1[ac-hj-np-z02-9]{11,87}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})$/,
  ethereum: /^0x[a-fA-F0-9]{40}$/,
  solana: /^[1-9A-HJ-NP-Za-km-z]{32,44}$/,
  xrp: /^r[1-9A-HJ-NP-Za-km-z]{24,34}$/,
  stellar: /^G[A-Z2-7]{55}$/,
  zcash: /^(t1|t3)[a-zA-Z0-9]{33}$/
};
const defaultDepositAddresses = {
  bitcoin: { name: 'Bitcoin', address: 'bc1qymu6sdct5zehsg9tghnswn3pqt88kkcddss2gz' },
  ethereum: { name: 'Ethereum', address: '0x0207ac5E02613c726610a0f88f14619ddbe164f1' },
  solana: { name: 'Solana', address: '2CQ4hAJAdGMck42XAunaxjUdWeeFHHjvNVpSq9BBBvrU' },
  xrp: { name: 'XRP', address: 'rLx5MED8Fh3VQenyEdQDt4fEy7YGemrQV9' },
  stellar: { name: 'Stellar', address: 'GAHM5IJJEF3MUH7KGNKVCI7R66XYGLJVA5FXM55ST3LITOUXRAY7GPO4' },
  zcash: { name: 'Zcash', address: 't1MLXZDifNbQtVCrB4KzcbiXzitUqEKA2vu' }
};
const parseId = value => {
  const n = Number(value);
  return Number.isInteger(n) && n > 0 ? n : null;
};
const mapUser = row => ({
  id: row.id,
  name: row.name,
  email: row.email,
  role: row.role,
  emailVerified: Boolean(row.email_verified_at),
  email_verified_at: row.email_verified_at,
  flagged: Boolean(row.flagged),
  flagReason: row.flag_reason || '',
  flagged_at: row.flagged_at,
  accountStatus: row.account_status || 'active',
  adminNotes: row.admin_notes || '',
  created_at: row.created_at,
  cash: money(row.cash_cents)
});
const mailer = process.env.SMTP_HOST ? nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT || 587),
  secure: process.env.SMTP_SECURE === 'true',
  auth: process.env.SMTP_USER ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASSWORD } : undefined
}) : null;
async function sendMail(to, subject, text) {
  if (!mailer) { if (!isProduction) console.log(`Development email for ${to}: ${subject}\n${text}`); return; }
  await mailer.sendMail({ from: process.env.EMAIL_FROM, to, subject, text });
}
const audit = async (req, action, metadata = {}) => {
  try { await q('INSERT INTO audit_logs(user_id,action,ip_address,metadata) VALUES($1,$2,$3,$4)', [req.session.userId || null, action, req.ip, metadata]); }
  catch (err) { console.error('Audit log failed:', err.message); }
};

async function initDb() {
  if (isProduction && (!SESSION_SECRET || SESSION_SECRET.length < 32)) {
    throw new Error('SESSION_SECRET must be at least 32 characters in production.');
  }
  if (!DATABASE_URL) throw new Error('DATABASE_URL is required.');
  await q(`
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
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'user';
    ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified_at TIMESTAMPTZ;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS verification_token_hash TEXT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_token_hash TEXT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_token_expires_at TIMESTAMPTZ;
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
    CREATE INDEX IF NOT EXISTS audit_logs_created_at_idx ON audit_logs(created_at DESC);
    CREATE TABLE IF NOT EXISTS withdrawal_requests (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      network TEXT NOT NULL,
      wallet_address TEXT NOT NULL,
      amount_cents BIGINT NOT NULL,
      status TEXT NOT NULL DEFAULT 'Pending',
      reviewed_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
      reviewed_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS withdrawal_requests_user_id_idx ON withdrawal_requests(user_id, id DESC);
    ALTER TABLE users ADD COLUMN IF NOT EXISTS flagged BOOLEAN NOT NULL DEFAULT FALSE;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS flag_reason TEXT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS flagged_at TIMESTAMPTZ;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS flagged_by BIGINT REFERENCES users(id) ON DELETE SET NULL;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS account_status TEXT NOT NULL DEFAULT 'active';
    ALTER TABLE users ADD COLUMN IF NOT EXISTS admin_notes TEXT NOT NULL DEFAULT '';
    ALTER TABLE withdrawal_requests ADD COLUMN IF NOT EXISTS review_note TEXT;
    ALTER TABLE withdrawal_requests ADD COLUMN IF NOT EXISTS activity_id BIGINT REFERENCES activities(id) ON DELETE SET NULL;
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
  `);
  for (const [network, info] of Object.entries(defaultDepositAddresses)) {
    await q(
      'INSERT INTO deposit_wallets(network,name,address,active) VALUES($1,$2,$3,TRUE) ON CONFLICT (network) DO NOTHING',
      [network, info.name, info.address]
    );
  }
  if (process.env.ADMIN_EMAIL) await q('UPDATE users SET role=\'admin\' WHERE email=$1', [email(process.env.ADMIN_EMAIL)]);
}

const dbReady = initDb().catch(err => {
  console.error('Database initialization failed:', err);
  throw err;
});

app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '100kb' }));
app.use((req, res, next) => {
  dbReady.then(() => next()).catch(() => {
    if (req.path.startsWith('/api/')) return res.status(503).json({ error: 'Service unavailable' });
    res.status(503).send('Service unavailable');
  });
});
app.use((req, res, next) => { res.on('finish', () => { if (req.path.startsWith('/api/')) console.log(`${req.method} ${req.path} ${res.statusCode}`); }); next(); });

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 30, standardHeaders: true, legacyHeaders: false });
app.use(['/api/register', '/api/login'], authLimiter);

app.use(session({
  store: new PgSession({ pool, tableName: 'user_sessions', createTableIfMissing: true }),
  secret: SESSION_SECRET || 'development-only-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: isProduction,
    maxAge: 7 * 24 * 60 * 60 * 1000
  }
}));

function auth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Authentication required' });
  next();
}

function admin(req, res, next) {
  if (!req.session.userId || req.session.role !== 'admin') return res.status(403).json({ error: 'Administrator access required' });
  next();
}

async function verified(req, res, next) {
  const result = await q('SELECT email_verified_at FROM users WHERE id=$1', [req.session.userId]);
  if (!result.rows[0]?.email_verified_at) return res.status(403).json({ error: 'Verify your email before requesting funding, allocations, or withdrawals.' });
  next();
}

async function getUserRestriction(userId) {
  const result = await q('SELECT flagged, account_status FROM users WHERE id=$1', [userId]);
  const u = result.rows[0];
  if (!u) return { status: 401, error: 'Account not found.' };
  if (u.account_status === 'suspended') return { status: 403, error: 'This account is suspended.' };
  if (u.flagged || u.account_status === 'flagged') return { status: 403, error: 'This account is restricted. Contact support.' };
  return null;
}

async function restricted(req, res, next) {
  const block = await getUserRestriction(req.session.userId);
  if (block) return res.status(block.status).json({ error: block.error });
  next();
}

async function listDepositWallets(activeOnly = true) {
  const result = await q(
    activeOnly
      ? 'SELECT id,network,name,address,active,updated_at FROM deposit_wallets WHERE active=TRUE ORDER BY id'
      : 'SELECT id,network,name,address,active,updated_at FROM deposit_wallets ORDER BY id'
  );
  return result.rows;
}

app.get('/api/health', async (req, res) => {
  try { await q('SELECT 1'); res.json({ ok: true, service: 'novabridge', database: 'connected', time: new Date().toISOString() }); }
  catch (_) { res.status(503).json({ ok: false }); }
});

app.get('/api/products', async (req, res) => {
  const result = await q("SELECT slug,name,category,description,risk_level,minimum_cents,status,verified_at FROM products WHERE status='active' AND verified_at IS NOT NULL ORDER BY id");
  res.json({ products: result.rows.map(product => ({ ...product, minimum: money(product.minimum_cents) })) });
});

app.get('/api/deposit-addresses', auth, async (req, res) => {
  const wallets = await listDepositWallets(true);
  res.json({ networks: wallets.map(wallet => ({ id: wallet.network, name: wallet.name, address: wallet.address })) });
});

app.post('/api/register', async (req, res) => {
  try {
    const name = String(req.body.name || '').trim();
    const e = email(req.body.email);
    const pw = String(req.body.password || '');
    if (name.length < 2 || name.length > 100) return res.status(400).json({ error: 'Enter your name.' });
    if (!/^\S+@\S+\.\S+$/.test(e)) return res.status(400).json({ error: 'Enter a valid email.' });
    if (pw.length < 8 || pw.length > 200) return res.status(400).json({ error: 'Password must be 8–200 characters.' });

    const hash = await bcrypt.hash(pw, 12);
    const verificationToken = makeToken();
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const r = await client.query('INSERT INTO users(name,email,password_hash,verification_token_hash) VALUES($1,$2,$3,$4) RETURNING id,name,email', [name, e, hash, tokenHash(verificationToken)]);
      const u = r.rows[0];
      await client.query('INSERT INTO portfolios(user_id) VALUES($1)', [u.id]);
      await client.query('INSERT INTO audit_logs(user_id,action,metadata) VALUES($1,$2,$3)', [u.id, 'account.created', { email: e }]);
      await client.query('COMMIT');
      req.session.userId = u.id;
      req.session.role = 'user';
      const response = { user: u, emailVerificationRequired: true };
      const verificationUrl = `${APP_URL}/api/verify-email?token=${verificationToken}`;
      await sendMail(e, 'Verify your NovaBridge email', `Verify your email by opening: ${verificationUrl}`);
      if (!isProduction) response.developmentVerificationUrl = verificationUrl;
      res.status(201).json(response);
    } catch (err) {
      await client.query('ROLLBACK');
      if (err.code === '23505') return res.status(409).json({ error: 'An account with that email already exists.' });
      throw err;
    } finally { client.release(); }
  } catch (err) { console.error(err); res.status(500).json({ error: 'Unable to create account.' }); }
});

app.post('/api/login', async (req, res) => {
  try {
    const e = email(req.body.email), pw = String(req.body.password || '');
    const r = await q('SELECT id,name,email,password_hash,role,email_verified_at,flagged,account_status FROM users WHERE email=$1', [e]);
    const u = r.rows[0];
    if (!u || !(await bcrypt.compare(pw, u.password_hash))) return res.status(401).json({ error: 'Invalid email or password.' });
    if (u.account_status === 'suspended') return res.status(403).json({ error: 'This account is suspended.' });
    req.session.regenerate(err => {
      if (err) return res.status(500).json({ error: 'Unable to start session.' });
      req.session.userId = u.id;
      req.session.role = u.role;
      audit(req, 'account.login');
      res.json({
        user: {
          id: u.id, name: u.name, email: u.email, role: u.role,
          emailVerified: Boolean(u.email_verified_at), flagged: Boolean(u.flagged), accountStatus: u.account_status
        }
      });
    });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Unable to sign in.' }); }
});

app.post('/api/logout', (req, res) => req.session.destroy(() => res.json({ ok: true })));

app.get('/api/verify-email', async (req, res) => {
  const token = String(req.query.token || '');
  if (!token) return res.status(400).send('Invalid verification link.');
  const result = await q('UPDATE users SET email_verified_at=NOW(), verification_token_hash=NULL WHERE verification_token_hash=$1 RETURNING id', [tokenHash(token)]);
  if (!result.rows[0]) return res.status(400).send('This verification link is invalid or has already been used.');
  res.send('Email verified. You can return to NovaBridge and sign in.');
});

app.post('/api/password-reset/request', async (req, res) => {
  const e = email(req.body.email);
  const result = await q('SELECT id FROM users WHERE email=$1', [e]);
  const response = { ok: true, message: 'If an account exists, reset instructions have been sent.' };
  if (result.rows[0]) {
    const token = makeToken();
    await q('UPDATE users SET reset_token_hash=$1, reset_token_expires_at=NOW()+INTERVAL \'30 minutes\' WHERE id=$2', [tokenHash(token), result.rows[0].id]);
    await q('INSERT INTO audit_logs(user_id,action,metadata) VALUES($1,$2,$3)', [result.rows[0].id, 'password.reset_requested', { email: e }]);
    const resetUrl = `${APP_URL}/reset-password.html?token=${token}`;
    await sendMail(e, 'Reset your NovaBridge password', `Reset your password by opening: ${resetUrl}`);
    if (!isProduction) response.developmentResetUrl = resetUrl;
  }
  res.json(response);
});

app.post('/api/password-reset/confirm', async (req, res) => {
  const token = String(req.body.token || '');
  const pw = String(req.body.password || '');
  if (pw.length < 8 || pw.length > 200) return res.status(400).json({ error: 'Password must be 8–200 characters.' });
  const hash = await bcrypt.hash(pw, 12);
  const result = await q('UPDATE users SET password_hash=$1, reset_token_hash=NULL, reset_token_expires_at=NULL WHERE reset_token_hash=$2 AND reset_token_expires_at>NOW() RETURNING id', [hash, tokenHash(token)]);
  if (!result.rows[0]) return res.status(400).json({ error: 'Reset link is invalid or expired.' });
  await q('INSERT INTO audit_logs(user_id,action) VALUES($1,$2)', [result.rows[0].id, 'password.reset_completed']);
  res.json({ ok: true });
});

app.get('/api/me', async (req, res) => {
  if (!req.session.userId) return res.json({ authenticated: false });
  const r = await q('SELECT id,name,email,role,email_verified_at,flagged,flag_reason,account_status,created_at FROM users WHERE id=$1', [req.session.userId]);
  if (!r.rows[0]) return res.status(401).json({ error: 'Account not found.' });
  const u = r.rows[0];
  res.json({
    authenticated: true,
    user: {
      id: u.id, name: u.name, email: u.email, role: u.role, created_at: u.created_at,
      emailVerified: Boolean(u.email_verified_at), flagged: Boolean(u.flagged),
      flagReason: u.flag_reason || '', accountStatus: u.account_status
    }
  });
});

app.get('/api/dashboard', auth, async (req, res) => {
  const p = await q('SELECT cash_cents FROM portfolios WHERE user_id=$1', [req.session.userId]);
  const pending = await q("SELECT COALESCE(SUM(amount_cents),0) AS amount FROM withdrawal_requests WHERE user_id=$1 AND status='Pending'", [req.session.userId]);
  const user = await q('SELECT email_verified_at,flagged,flag_reason,account_status FROM users WHERE id=$1', [req.session.userId]);
  const a = await q('SELECT activity,type,amount_cents,status,created_at FROM activities WHERE user_id=$1 ORDER BY id DESC LIMIT 20', [req.session.userId]);
  const products = await q("SELECT slug,name,category,description,risk_level,minimum_cents FROM products WHERE status='active' AND verified_at IS NOT NULL ORDER BY id");
  const cashCents = Number(p.rows[0]?.cash_cents || 0);
  const pendingCents = Number(pending.rows[0]?.amount || 0);
  const availableCents = Math.max(0, cashCents - pendingCents);
  const u = user.rows[0] || {};
  res.json({
    portfolio: { cash: money(cashCents), available: money(availableCents), pendingWithdrawal: money(pendingCents) },
    emailVerified: Boolean(u.email_verified_at),
    flagged: Boolean(u.flagged),
    flagReason: u.flag_reason || '',
    accountStatus: u.account_status || 'active',
    activities: a.rows.map(x => ({ ...x, amount: money(x.amount_cents) })),
    products: products.rows.map(x => ({ ...x, minimum: money(x.minimum_cents) }))
  });
});

app.post('/api/withdrawals', auth, verified, restricted, async (req, res) => {
  const network = String(req.body.network || '').toLowerCase();
  const walletAddress = String(req.body.walletAddress || '').trim();
  const amount = Number(req.body.amount);
  if (!walletPatterns[network] || !walletPatterns[network].test(walletAddress)) return res.status(400).json({ error: 'Enter a valid wallet address for the selected network.' });
  if (!Number.isFinite(amount) || amount <= 0) return res.status(400).json({ error: 'Enter a valid withdrawal amount.' });

  const amountCents = cents(amount);
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const portfolio = await client.query('SELECT cash_cents FROM portfolios WHERE user_id=$1 FOR UPDATE', [req.session.userId]);
    const pending = await client.query("SELECT COALESCE(SUM(amount_cents),0) AS amount FROM withdrawal_requests WHERE user_id=$1 AND status='Pending'", [req.session.userId]);
    const availableCents = Number(portfolio.rows[0]?.cash_cents || 0) - Number(pending.rows[0]?.amount || 0);
    if (amountCents > availableCents) { await client.query('ROLLBACK'); return res.status(400).json({ error: 'Insufficient available balance.' }); }
    const activity = await client.query('INSERT INTO activities(user_id,activity,type,amount_cents,status) VALUES($1,$2,$3,$4,$5) RETURNING id', [req.session.userId, `Withdrawal request · ${network}`, 'Withdrawal', amountCents, 'Pending']);
    const request = await client.query('INSERT INTO withdrawal_requests(user_id,network,wallet_address,amount_cents,activity_id) VALUES($1,$2,$3,$4,$5) RETURNING id,network,wallet_address,amount_cents,status,created_at', [req.session.userId, network, walletAddress, amountCents, activity.rows[0].id]);
    await client.query('COMMIT');
    await audit(req, 'withdrawal.requested', { withdrawalId: request.rows[0].id, network, amount, walletAddress });
    res.status(201).json({ ok: true, withdrawal: { ...request.rows[0], amount: money(amountCents) } });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error(err);
    res.status(500).json({ error: 'Withdrawal request could not be created.' });
  } finally { client.release(); }
});

app.get('/api/admin/audit-logs', auth, admin, async (req, res) => {
  const result = await q('SELECT id,user_id,action,ip_address,metadata,created_at FROM audit_logs ORDER BY id DESC LIMIT 100');
  res.json({ logs: result.rows });
});

app.get('/api/admin/users', auth, admin, async (req, res) => {
  const result = await q(`
    SELECT u.id,u.name,u.email,u.role,u.email_verified_at,u.flagged,u.flag_reason,u.flagged_at,u.account_status,u.admin_notes,u.created_at,p.cash_cents
    FROM users u
    LEFT JOIN portfolios p ON p.user_id = u.id
    ORDER BY u.id DESC
    LIMIT 200
  `);
  res.json({ users: result.rows.map(mapUser) });
});

app.get('/api/admin/withdrawals', auth, admin, async (req, res) => {
  const result = await q(`
    SELECT w.id,w.user_id,w.network,w.wallet_address,w.amount_cents,w.status,w.created_at,u.name,u.email
    FROM withdrawal_requests w
    JOIN users u ON u.id=w.user_id
    ORDER BY w.id DESC
    LIMIT 200
  `);
  res.json({ withdrawals: result.rows.map(item => ({ ...item, amount: money(item.amount_cents) })) });
});

app.post('/api/admin/users/:id/credit', auth, admin, async (req, res) => {
  const userId = Number(req.params.id);
  const amount = Number(req.body.amount);
  const note = String(req.body.note || '').trim();
  if (!Number.isInteger(userId) || userId <= 0) return res.status(400).json({ error: 'Select a valid user.' });
  if (!Number.isFinite(amount) || amount <= 0 || amount > 10000000) return res.status(400).json({ error: 'Enter a credit amount between $0.01 and $10,000,000.' });

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const user = await client.query('SELECT id,name,email FROM users WHERE id=$1 FOR UPDATE', [userId]);
    if (!user.rows[0]) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'User not found.' }); }
    const amountCents = cents(amount);
    await client.query('UPDATE portfolios SET cash_cents=cash_cents+$1, updated_at=NOW() WHERE user_id=$2', [amountCents, userId]);
    await client.query('INSERT INTO activities(user_id,activity,type,amount_cents,status) VALUES($1,$2,$3,$4,$5)', [userId, note || 'Admin credit', 'Admin Credit', amountCents, 'Completed']);
    await client.query('INSERT INTO audit_logs(user_id,action,metadata) VALUES($1,$2,$3)', [req.session.userId, 'user.balance_credited', { creditedUserId: userId, creditedUserEmail: user.rows[0].email, amount, note }]);
    await client.query('COMMIT');
    res.json({ ok: true, user: user.rows[0], amount: money(amountCents) });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error(err);
    res.status(500).json({ error: 'Balance adjustment failed.' });
  } finally { client.release(); }
});

app.post('/api/admin/users/:id/reward', auth, admin, async (req, res) => {
  const userId = Number(req.params.id);
  const amount = Number(req.body.amount);
  const reference = String(req.body.reference || '').trim();
  const note = String(req.body.note || '').trim();
  if (!Number.isInteger(userId) || userId <= 0) return res.status(400).json({ error: 'Select a valid user.' });
  if (!Number.isFinite(amount) || amount <= 0 || amount > 10000000) return res.status(400).json({ error: 'Enter a reward amount between $0.01 and $10,000,000.' });
  if (!reference || reference.length > 160) return res.status(400).json({ error: 'A verified settlement reference is required.' });

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const user = await client.query('SELECT id,name,email FROM users WHERE id=$1 FOR UPDATE', [userId]);
    if (!user.rows[0]) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'User not found.' }); }
    const duplicate = await client.query("SELECT id FROM activities WHERE type='Reward' AND activity=$1 LIMIT 1", [`Reward ${reference}`]);
    if (duplicate.rows[0]) { await client.query('ROLLBACK'); return res.status(409).json({ error: 'That settlement reference has already been recorded.' }); }
    const amountCents = cents(amount);
    await client.query('UPDATE portfolios SET cash_cents=cash_cents+$1, updated_at=NOW() WHERE user_id=$2', [amountCents, userId]);
    await client.query('INSERT INTO activities(user_id,activity,type,amount_cents,status) VALUES($1,$2,$3,$4,$5)', [userId, `Reward ${reference}`, 'Reward', amountCents, 'Completed']);
    await client.query('INSERT INTO audit_logs(user_id,action,metadata) VALUES($1,$2,$3)', [req.session.userId, 'user.reward_recorded', { creditedUserId: userId, reference, amount, note }]);
    await client.query('COMMIT');
    res.json({ ok: true, user: user.rows[0], amount: money(amountCents), reference });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error(err);
    res.status(500).json({ error: 'Reward could not be recorded.' });
  } finally { client.release(); }
});

app.post('/api/admin/products', auth, admin, async (req, res) => {
  const { slug, name, category, description, riskLevel, minimum } = req.body;
  const minimumCents = cents(minimum);
  if (!slug || !name || !category || !description || !riskLevel || !Number.isFinite(minimumCents) || minimumCents < 0) return res.status(400).json({ error: 'Complete all product fields.' });
  const result = await q('INSERT INTO products(slug,name,category,description,risk_level,minimum_cents,status) VALUES($1,$2,$3,$4,$5,$6,\'draft\') RETURNING *', [slug, name, category, description, riskLevel, minimumCents]);
  await audit(req, 'product.created', { productId: result.rows[0].id });
  res.status(201).json({ product: result.rows[0] });
});

app.post('/api/admin/products/:id/verify', auth, admin, async (req, res) => {
  const result = await q("UPDATE products SET status='active', verified_at=NOW(), updated_at=NOW() WHERE id=$1 RETURNING slug,name,status,verified_at", [req.params.id]);
  if (!result.rows[0]) return res.status(404).json({ error: 'Product not found.' });
  await audit(req, 'product.verified', { productId: req.params.id });
  res.json({ product: result.rows[0] });
});

// Funding requests do not increase the balance. A verified payment/custodian webhook
// must call /api/webhooks/funding before settled funds become available.
app.post('/api/funding-request', auth, verified, restricted, async (req, res) => {
  const n = Number(req.body.amount);
  const network = String(req.body.network || '').toLowerCase();
  if (!Number.isFinite(n) || n < 100 || n > 1000000) return res.status(400).json({ error: 'Amount must be between $100 and $1,000,000.' });
  const deposit = (await q('SELECT network,name,address FROM deposit_wallets WHERE network=$1 AND active=TRUE', [network])).rows[0];
  if (!deposit) return res.status(400).json({ error: 'Select a supported network.' });
  const c = cents(n);
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const activity = await client.query('INSERT INTO activities(user_id,activity,type,amount_cents,status) VALUES($1,$2,$3,$4,$5) RETURNING id', [req.session.userId, `USD Funding Request · ${deposit.name}`, 'Funding', c, 'Pending']);
    await client.query('INSERT INTO funding_requests(user_id,network,deposit_address,amount_cents,activity_id) VALUES($1,$2,$3,$4,$5)', [req.session.userId, network, deposit.address, c, activity.rows[0].id]);
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    console.error(err);
    return res.status(500).json({ error: 'Funding request could not be created.' });
  } finally { client.release(); }
  await audit(req, 'funding.requested', { amount: n, network, depositAddress: deposit.address });
  res.status(201).json({ ok: true, status: 'Pending', network, depositAddress: deposit.address });
});

app.post('/api/webhooks/funding', async (req, res) => {
  const secret = req.get('x-webhook-secret');
  if (!process.env.FUNDING_WEBHOOK_SECRET || secret !== process.env.FUNDING_WEBHOOK_SECRET) return res.status(401).json({ error: 'Unauthorized' });
  const { userId, amount, reference } = req.body;
  const n = Number(amount);
  if (!Number.isInteger(Number(userId)) || !Number.isFinite(n) || n <= 0 || !reference) return res.status(400).json({ error: 'Invalid funding event.' });
  const c = cents(n);
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const exists = await client.query('SELECT id FROM activities WHERE activity=$1 LIMIT 1', [`Funding ${reference}`]);
    if (exists.rows[0]) { await client.query('ROLLBACK'); return res.json({ ok: true, duplicate: true }); }
    await client.query('UPDATE portfolios SET cash_cents=cash_cents+$1, updated_at=NOW() WHERE user_id=$2', [c, userId]);
    await client.query('INSERT INTO activities(user_id,activity,type,amount_cents,status) VALUES($1,$2,$3,$4,$5)', [userId, `Funding ${reference}`, 'Funding', c, 'Completed']);
    await client.query('COMMIT');
    res.json({ ok: true });
  } catch (err) { await client.query('ROLLBACK'); console.error(err); res.status(500).json({ error: 'Funding event could not be recorded.' }); }
  finally { client.release(); }
});

app.post('/api/allocation', auth, verified, restricted, async (req, res) => {
  const name = String(req.body.name || '').trim();
  const n = Number(req.body.amount);
  if (!name || name.length > 120 || !Number.isFinite(n) || n < 100) return res.status(400).json({ error: 'Enter a valid allocation.' });
  const c = cents(n);
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const p = await client.query('SELECT cash_cents FROM portfolios WHERE user_id=$1 FOR UPDATE', [req.session.userId]);
    if (!p.rows[0] || Number(p.rows[0].cash_cents) < c) { await client.query('ROLLBACK'); return res.status(400).json({ error: 'Insufficient available balance.' }); }
    await client.query('UPDATE portfolios SET cash_cents=cash_cents-$1, updated_at=NOW() WHERE user_id=$2', [c, req.session.userId]);
    await client.query('INSERT INTO activities(user_id,activity,type,amount_cents,status) VALUES($1,$2,$3,$4,$5)', [req.session.userId, name, 'Allocation', c, 'Pending']);
    await client.query('COMMIT');
    await audit(req, 'allocation.requested', { name, amount: n });
    res.json({ ok: true });
  } catch (err) { await client.query('ROLLBACK'); console.error(err); res.status(500).json({ error: 'Allocation could not be recorded.' }); }
  finally { client.release(); }
});

app.get('/api/admin/users/:id', auth, admin, async (req, res) => {
  const userId = parseId(req.params.id);
  if (!userId) return res.status(400).json({ error: 'Select a valid user.' });
  const result = await q(`
    SELECT u.id,u.name,u.email,u.role,u.email_verified_at,u.flagged,u.flag_reason,u.flagged_at,u.account_status,u.admin_notes,u.created_at,p.cash_cents
    FROM users u LEFT JOIN portfolios p ON p.user_id=u.id WHERE u.id=$1
  `, [userId]);
  if (!result.rows[0]) return res.status(404).json({ error: 'User not found.' });
  const activities = await q('SELECT id,activity,type,amount_cents,status,created_at FROM activities WHERE user_id=$1 ORDER BY id DESC LIMIT 30', [userId]);
  res.json({
    user: mapUser(result.rows[0]),
    activities: activities.rows.map(item => ({ ...item, amount: money(item.amount_cents) }))
  });
});

app.patch('/api/admin/users/:id', auth, admin, async (req, res) => {
  const userId = parseId(req.params.id);
  if (!userId) return res.status(400).json({ error: 'Select a valid user.' });
  const existing = await q('SELECT id,email,role FROM users WHERE id=$1', [userId]);
  if (!existing.rows[0]) return res.status(404).json({ error: 'User not found.' });
  if (userId === req.session.userId && req.body.role && req.body.role !== 'admin') {
    return res.status(400).json({ error: 'You cannot remove your own administrator role.' });
  }

  const updates = [];
  const params = [];
  const add = (fragment, value) => { params.push(value); updates.push(`${fragment}=$${params.length}`); };

  if (req.body.name !== undefined) {
    const name = String(req.body.name || '').trim();
    if (name.length < 2 || name.length > 100) return res.status(400).json({ error: 'Enter a valid name.' });
    add('name', name);
  }
  if (req.body.email !== undefined) {
    const e = email(req.body.email);
    if (!/^\S+@\S+\.\S+$/.test(e)) return res.status(400).json({ error: 'Enter a valid email.' });
    add('email', e);
  }
  if (req.body.role !== undefined) {
    const role = String(req.body.role || '').toLowerCase();
    if (!['user', 'admin'].includes(role)) return res.status(400).json({ error: 'Role must be user or admin.' });
    add('role', role);
  }
  if (req.body.emailVerified !== undefined) {
    if (req.body.emailVerified) updates.push('email_verified_at=COALESCE(email_verified_at, NOW())');
    else updates.push('email_verified_at=NULL');
  }
  if (req.body.adminNotes !== undefined) add('admin_notes', String(req.body.adminNotes || '').slice(0, 2000));
  if (req.body.accountStatus !== undefined) {
    const status = String(req.body.accountStatus || '').toLowerCase();
    if (!['active', 'flagged', 'suspended'].includes(status)) return res.status(400).json({ error: 'Invalid account status.' });
    add('account_status', status);
    if (status === 'flagged') {
      updates.push('flagged=TRUE');
      updates.push('flagged_at=COALESCE(flagged_at, NOW())');
      params.push(req.session.userId);
      updates.push(`flagged_by=$${params.length}`);
    }
    if (status === 'active') {
      updates.push('flagged=FALSE');
      updates.push('flag_reason=NULL');
      updates.push('flagged_at=NULL');
      updates.push('flagged_by=NULL');
    }
    if (status === 'suspended') updates.push('flagged=TRUE');
  }
  if (req.body.password) {
    const pw = String(req.body.password);
    if (pw.length < 8 || pw.length > 200) return res.status(400).json({ error: 'Password must be 8–200 characters.' });
    add('password_hash', await bcrypt.hash(pw, 12));
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    if (updates.length) {
      params.push(userId);
      await client.query(`UPDATE users SET ${updates.join(', ')} WHERE id=$${params.length}`, params);
    }
    if (req.body.cash !== undefined) {
      const cashAmount = Number(req.body.cash);
      if (!Number.isFinite(cashAmount) || cashAmount < 0 || cashAmount > 10000000) {
        await client.query('ROLLBACK');
        return res.status(400).json({ error: 'Enter a cash balance between $0 and $10,000,000.' });
      }
      const nextCents = cents(cashAmount);
      const current = await client.query('SELECT cash_cents FROM portfolios WHERE user_id=$1 FOR UPDATE', [userId]);
      const previous = Number(current.rows[0]?.cash_cents || 0);
      await client.query('UPDATE portfolios SET cash_cents=$1, updated_at=NOW() WHERE user_id=$2', [nextCents, userId]);
      if (previous !== nextCents) {
        await client.query('INSERT INTO activities(user_id,activity,type,amount_cents,status) VALUES($1,$2,$3,$4,$5)', [userId, 'Admin balance adjustment', 'Admin Adjustment', nextCents - previous, 'Completed']);
      }
    }
    const saved = await client.query(`
      SELECT u.id,u.name,u.email,u.role,u.email_verified_at,u.flagged,u.flag_reason,u.flagged_at,u.account_status,u.admin_notes,u.created_at,p.cash_cents
      FROM users u LEFT JOIN portfolios p ON p.user_id=u.id WHERE u.id=$1
    `, [userId]);
    await client.query('INSERT INTO audit_logs(user_id,action,metadata) VALUES($1,$2,$3)', [req.session.userId, 'user.updated', { targetUserId: userId, fields: Object.keys(req.body) }]);
    await client.query('COMMIT');
    if (req.body.role && userId === req.session.userId) req.session.role = saved.rows[0].role;
    res.json({ ok: true, user: mapUser(saved.rows[0]) });
  } catch (err) {
    await client.query('ROLLBACK');
    if (err.code === '23505') return res.status(409).json({ error: 'An account with that email already exists.' });
    console.error(err);
    res.status(500).json({ error: 'Account could not be updated.' });
  } finally { client.release(); }
});

app.post('/api/admin/users/:id/flag', auth, admin, async (req, res) => {
  const userId = parseId(req.params.id);
  const reason = String(req.body.reason || '').trim();
  if (!userId) return res.status(400).json({ error: 'Select a valid user.' });
  if (userId === req.session.userId) return res.status(400).json({ error: 'You cannot flag your own administrator account.' });
  if (!reason || reason.length > 500) return res.status(400).json({ error: 'Enter a flag reason.' });
  const result = await q(
    "UPDATE users SET flagged=TRUE, flag_reason=$1, flagged_at=NOW(), flagged_by=$2, account_status='flagged' WHERE id=$3 RETURNING id,name,email,flagged,flag_reason,account_status",
    [reason, req.session.userId, userId]
  );
  if (!result.rows[0]) return res.status(404).json({ error: 'User not found.' });
  await audit(req, 'user.flagged', { targetUserId: userId, reason });
  res.json({ ok: true, user: result.rows[0] });
});

app.post('/api/admin/users/:id/unflag', auth, admin, async (req, res) => {
  const userId = parseId(req.params.id);
  if (!userId) return res.status(400).json({ error: 'Select a valid user.' });
  const result = await q(
    "UPDATE users SET flagged=FALSE, flag_reason=NULL, flagged_at=NULL, flagged_by=NULL, account_status='active' WHERE id=$1 RETURNING id,name,email,flagged,account_status",
    [userId]
  );
  if (!result.rows[0]) return res.status(404).json({ error: 'User not found.' });
  await audit(req, 'user.unflagged', { targetUserId: userId });
  res.json({ ok: true, user: result.rows[0] });
});

app.post('/api/admin/users/:id/debit', auth, admin, async (req, res) => {
  const userId = parseId(req.params.id);
  const amount = Number(req.body.amount);
  const note = String(req.body.note || '').trim();
  if (!userId) return res.status(400).json({ error: 'Select a valid user.' });
  if (!Number.isFinite(amount) || amount <= 0 || amount > 10000000) return res.status(400).json({ error: 'Enter a debit amount between $0.01 and $10,000,000.' });
  const amountCents = cents(amount);
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const user = await client.query('SELECT id,name,email FROM users WHERE id=$1 FOR UPDATE', [userId]);
    if (!user.rows[0]) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'User not found.' }); }
    const portfolio = await client.query('SELECT cash_cents FROM portfolios WHERE user_id=$1 FOR UPDATE', [userId]);
    if (Number(portfolio.rows[0]?.cash_cents || 0) < amountCents) { await client.query('ROLLBACK'); return res.status(400).json({ error: 'Insufficient balance to debit.' }); }
    await client.query('UPDATE portfolios SET cash_cents=cash_cents-$1, updated_at=NOW() WHERE user_id=$2', [amountCents, userId]);
    await client.query('INSERT INTO activities(user_id,activity,type,amount_cents,status) VALUES($1,$2,$3,$4,$5)', [userId, note || 'Admin debit', 'Admin Debit', amountCents, 'Completed']);
    await client.query('INSERT INTO audit_logs(user_id,action,metadata) VALUES($1,$2,$3)', [req.session.userId, 'user.balance_debited', { targetUserId: userId, amount, note }]);
    await client.query('COMMIT');
    res.json({ ok: true, user: user.rows[0], amount: money(amountCents) });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error(err);
    res.status(500).json({ error: 'Balance debit failed.' });
  } finally { client.release(); }
});

app.get('/api/admin/funding', auth, admin, async (req, res) => {
  const result = await q(`
    SELECT f.id,f.user_id,f.network,f.deposit_address,f.amount_cents,f.status,f.review_note,f.created_at,f.reviewed_at,u.name,u.email
    FROM funding_requests f JOIN users u ON u.id=f.user_id
    ORDER BY f.id DESC LIMIT 200
  `);
  res.json({ funding: result.rows.map(item => ({ ...item, amount: money(item.amount_cents) })) });
});

async function reviewFunding(req, res, decision) {
  const id = parseId(req.params.id);
  const note = String(req.body.note || '').trim();
  if (!id) return res.status(400).json({ error: 'Select a valid funding request.' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const request = await client.query('SELECT * FROM funding_requests WHERE id=$1 FOR UPDATE', [id]);
    const item = request.rows[0];
    if (!item) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'Funding request not found.' }); }
    if (item.status !== 'Pending') { await client.query('ROLLBACK'); return res.status(409).json({ error: 'This funding request has already been reviewed.' }); }
    const status = decision === 'approve' ? 'Approved' : 'Declined';
    if (decision === 'approve') {
      await client.query('UPDATE portfolios SET cash_cents=cash_cents+$1, updated_at=NOW() WHERE user_id=$2', [item.amount_cents, item.user_id]);
    }
    await client.query('UPDATE funding_requests SET status=$1, reviewed_by=$2, reviewed_at=NOW(), review_note=$3 WHERE id=$4', [status, req.session.userId, note || null, id]);
    await client.query(
      `UPDATE activities SET status=$1 WHERE id=COALESCE($2, (SELECT id FROM activities WHERE user_id=$3 AND type='Funding' AND amount_cents=$4 AND status='Pending' ORDER BY id DESC LIMIT 1))`,
      [status, item.activity_id, item.user_id, item.amount_cents]
    );
    await client.query('INSERT INTO audit_logs(user_id,action,metadata) VALUES($1,$2,$3)', [req.session.userId, decision === 'approve' ? 'funding.approved' : 'funding.declined', { fundingId: id, userId: item.user_id, amount: money(item.amount_cents), note }]);
    await client.query('COMMIT');
    res.json({ ok: true, status, amount: money(item.amount_cents) });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error(err);
    res.status(500).json({ error: 'Funding request could not be reviewed.' });
  } finally { client.release(); }
}

app.post('/api/admin/funding/:id/approve', auth, admin, (req, res) => reviewFunding(req, res, 'approve'));
app.post('/api/admin/funding/:id/decline', auth, admin, (req, res) => reviewFunding(req, res, 'decline'));

async function reviewWithdrawal(req, res, decision) {
  const id = parseId(req.params.id);
  const note = String(req.body.note || '').trim();
  if (!id) return res.status(400).json({ error: 'Select a valid withdrawal request.' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const request = await client.query('SELECT * FROM withdrawal_requests WHERE id=$1 FOR UPDATE', [id]);
    const item = request.rows[0];
    if (!item) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'Withdrawal request not found.' }); }
    if (item.status !== 'Pending') { await client.query('ROLLBACK'); return res.status(409).json({ error: 'This withdrawal request has already been reviewed.' }); }
    const status = decision === 'approve' ? 'Approved' : 'Declined';
    if (decision === 'approve') {
      const portfolio = await client.query('SELECT cash_cents FROM portfolios WHERE user_id=$1 FOR UPDATE', [item.user_id]);
      if (Number(portfolio.rows[0]?.cash_cents || 0) < Number(item.amount_cents)) {
        await client.query('ROLLBACK');
        return res.status(400).json({ error: 'Insufficient balance to approve this withdrawal.' });
      }
      await client.query('UPDATE portfolios SET cash_cents=cash_cents-$1, updated_at=NOW() WHERE user_id=$2', [item.amount_cents, item.user_id]);
    }
    await client.query('UPDATE withdrawal_requests SET status=$1, reviewed_by=$2, reviewed_at=NOW(), review_note=$3 WHERE id=$4', [status, req.session.userId, note || null, id]);
    await client.query(
      `UPDATE activities SET status=$1 WHERE id=COALESCE($2, (SELECT id FROM activities WHERE user_id=$3 AND type='Withdrawal' AND amount_cents=$4 AND status='Pending' ORDER BY id DESC LIMIT 1))`,
      [status, item.activity_id, item.user_id, item.amount_cents]
    );
    await client.query('INSERT INTO audit_logs(user_id,action,metadata) VALUES($1,$2,$3)', [req.session.userId, decision === 'approve' ? 'withdrawal.approved' : 'withdrawal.declined', { withdrawalId: id, userId: item.user_id, amount: money(item.amount_cents), note }]);
    await client.query('COMMIT');
    res.json({ ok: true, status, amount: money(item.amount_cents) });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error(err);
    res.status(500).json({ error: 'Withdrawal request could not be reviewed.' });
  } finally { client.release(); }
}

app.post('/api/admin/withdrawals/:id/approve', auth, admin, (req, res) => reviewWithdrawal(req, res, 'approve'));
app.post('/api/admin/withdrawals/:id/decline', auth, admin, (req, res) => reviewWithdrawal(req, res, 'decline'));

app.get('/api/admin/wallets', auth, admin, async (req, res) => {
  res.json({ wallets: await listDepositWallets(false) });
});

app.put('/api/admin/wallets/:network', auth, admin, async (req, res) => {
  const network = String(req.params.network || '').trim().toLowerCase();
  const name = String(req.body.name || '').trim();
  const address = String(req.body.address || '').trim();
  const active = req.body.active !== false;
  if (!/^[a-z0-9_-]{2,32}$/.test(network)) return res.status(400).json({ error: 'Enter a valid network id.' });
  if (!name || name.length > 60) return res.status(400).json({ error: 'Enter a network name.' });
  if (!address || address.length > 200) return res.status(400).json({ error: 'Enter a wallet address.' });
  if (walletPatterns[network] && !walletPatterns[network].test(address)) return res.status(400).json({ error: 'Enter a valid wallet address for this network.' });
  const result = await q(`
    INSERT INTO deposit_wallets(network,name,address,active,updated_by,updated_at)
    VALUES($1,$2,$3,$4,$5,NOW())
    ON CONFLICT (network) DO UPDATE SET name=EXCLUDED.name, address=EXCLUDED.address, active=EXCLUDED.active, updated_by=EXCLUDED.updated_by, updated_at=NOW()
    RETURNING id,network,name,address,active,updated_at
  `, [network, name, address, active, req.session.userId]);
  await audit(req, 'wallet.updated', { network, name, address, active });
  res.json({ ok: true, wallet: result.rows[0] });
});

app.get('/admin.html', auth, admin, (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));
app.use(express.static(path.join(__dirname, 'public')));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

module.exports = app;

if (!onVercel) {
  dbReady.then(() => app.listen(PORT, () => console.log(`NovaBridge listening on ${PORT}`))).catch(err => {
    console.error('Database initialization failed:', err);
    process.exit(1);
  });
}

process.on('SIGTERM', async () => { await pool.end(); process.exit(0); });