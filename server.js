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

if (isProduction && (!SESSION_SECRET || SESSION_SECRET.length < 32)) {
  throw new Error('SESSION_SECRET must be at least 32 characters in production.');
}
if (!DATABASE_URL) throw new Error('DATABASE_URL is required.');

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.DATABASE_SSL === 'false' ? false : { rejectUnauthorized: false },
  max: Number(process.env.DB_POOL_MAX || 10),
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

const q = (text, params = []) => pool.query(text, params);
const email = s => String(s || '').trim().toLowerCase();
const money = cents => Number(cents || 0) / 100;
const cents = amount => Math.round(Number(amount) * 100);
const tokenHash = token => crypto.createHash('sha256').update(token).digest('hex');
const makeToken = () => crypto.randomBytes(32).toString('hex');
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
  `);
  if (process.env.ADMIN_EMAIL) await q('UPDATE users SET role=\'admin\' WHERE email=$1', [email(process.env.ADMIN_EMAIL)]);
}

app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '100kb' }));
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
  if (!result.rows[0]?.email_verified_at) return res.status(403).json({ error: 'Verify your email before requesting funding or allocations.' });
  next();
}

app.get('/api/health', async (req, res) => {
  try { await q('SELECT 1'); res.json({ ok: true, service: 'novabridge', database: 'connected', time: new Date().toISOString() }); }
  catch (_) { res.status(503).json({ ok: false }); }
});

app.get('/api/products', async (req, res) => {
  const result = await q("SELECT slug,name,category,description,risk_level,minimum_cents,status,verified_at FROM products WHERE status='active' AND verified_at IS NOT NULL ORDER BY id");
  res.json({ products: result.rows.map(product => ({ ...product, minimum: money(product.minimum_cents) })) });
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
    const r = await q('SELECT id,name,email,password_hash,role FROM users WHERE email=$1', [e]);
    const u = r.rows[0];
    if (!u || !(await bcrypt.compare(pw, u.password_hash))) return res.status(401).json({ error: 'Invalid email or password.' });
    req.session.regenerate(err => {
      if (err) return res.status(500).json({ error: 'Unable to start session.' });
      req.session.userId = u.id;
      req.session.role = u.role;
      audit(req, 'account.login');
      res.json({ user: { id: u.id, name: u.name, email: u.email } });
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
  const r = await q('SELECT id,name,email,created_at FROM users WHERE id=$1', [req.session.userId]);
  if (!r.rows[0]) return res.status(401).json({ error: 'Account not found.' });
  res.json({ authenticated: true, user: r.rows[0] });
});

app.get('/api/dashboard', auth, async (req, res) => {
  const p = await q('SELECT cash_cents FROM portfolios WHERE user_id=$1', [req.session.userId]);
  const a = await q('SELECT activity,type,amount_cents,status,created_at FROM activities WHERE user_id=$1 ORDER BY id DESC LIMIT 20', [req.session.userId]);
  const products = await q("SELECT slug,name,category,description,risk_level,minimum_cents FROM products WHERE status='active' AND verified_at IS NOT NULL ORDER BY id");
  res.json({
    portfolio: { cash: money(p.rows[0]?.cash_cents) },
    activities: a.rows.map(x => ({ ...x, amount: money(x.amount_cents) })),
    products: products.rows.map(x => ({ ...x, minimum: money(x.minimum_cents) }))
  });
});

app.get('/api/admin/audit-logs', auth, admin, async (req, res) => {
  const result = await q('SELECT id,user_id,action,ip_address,metadata,created_at FROM audit_logs ORDER BY id DESC LIMIT 100');
  res.json({ logs: result.rows });
});

app.get('/api/admin/users', auth, admin, async (req, res) => {
  const result = await q('SELECT id,name,email,role,email_verified_at,created_at FROM users ORDER BY id DESC LIMIT 100');
  res.json({ users: result.rows });
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
app.post('/api/funding-request', auth, verified, async (req, res) => {
  const n = Number(req.body.amount);
  if (!Number.isFinite(n) || n < 100 || n > 1000000) return res.status(400).json({ error: 'Amount must be between $100 and $1,000,000.' });
  const c = cents(n);
  await q('INSERT INTO activities(user_id,activity,type,amount_cents,status) VALUES($1,$2,$3,$4,$5)', [req.session.userId, 'USD Funding Request', 'Funding', c, 'Pending']);
  await audit(req, 'funding.requested', { amount: n });
  res.status(201).json({ ok: true, status: 'Pending' });
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

app.post('/api/allocation', auth, verified, async (req, res) => {
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

app.use(express.static(path.join(__dirname, 'public')));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

initDb().then(() => app.listen(PORT, () => console.log(`NovaBridge listening on ${PORT}`))).catch(err => {
  console.error('Database initialization failed:', err);
  process.exit(1);
});

process.on('SIGTERM', async () => { await pool.end(); process.exit(0); });