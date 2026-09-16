# NovaBridge Capital

Production-oriented Node.js/Express application with PostgreSQL persistence, secure password hashing, PostgreSQL-backed sessions, rate limiting, security headers, account dashboards, funding requests and allocation records.

## What changed from the original ZIP

- Removed SQLite and `better-sqlite3`.
- Added PostgreSQL via `pg`.
- Added PostgreSQL-backed sessions via `connect-pg-simple`.
- Added automatic PostgreSQL schema initialization.
- Added `helmet` security headers.
- Added authentication rate limiting.
- Added production session configuration.
- Added a health endpoint at `/api/health`.
- Removed prototype/demo wording and fake dashboard activity from the interface.
- Replaced demo funding with a funding-request flow.
- Added a server-to-server funding webhook so only verified settlement events can increase a user's balance.
- Added `render.yaml` for deployment.

## Important financial integration boundary

This repository contains the account, authentication, portfolio ledger and API infrastructure. It does **not** pretend that an investment, crypto purchase, mining position, custody transfer or payment has occurred when no external financial rail has confirmed it.

`POST /api/funding-request` creates a pending funding request. It does not credit the user's available balance.

A payment processor, bank transfer service, custodian or other authorized settlement system should call:

`POST /api/webhooks/funding`

with:

- header: `x-webhook-secret: <FUNDING_WEBHOOK_SECRET>`
- JSON body: `{ "userId": 123, "amount": 5000, "reference": "provider-transaction-id" }`

Only that verified event credits the account ledger. Before production launch, replace the shared-secret webhook with the payment provider's official signature verification/idempotency mechanism.

The allocation endpoint records an allocation against available account balance. Connecting those records to an actual broker, custodian, exchange, mining operator or lending book requires the corresponding provider integration and legal/compliance controls.

## Environment variables

Copy `.env.example` to `.env` locally:

```env
PORT=3000
NODE_ENV=development
DATABASE_URL=postgresql://USER:PASSWORD@HOST:5432/DATABASE
DATABASE_SSL=true
SESSION_SECRET=use-a-long-random-secret
FUNDING_WEBHOOK_SECRET=use-a-separate-long-secret
APP_URL=http://localhost:3000
ADMIN_EMAIL=admin@example.com
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=...
SMTP_PASSWORD=...
EMAIL_FROM=NovaBridge <no-reply@example.com>
DB_POOL_MAX=10
```

`SMTP_*` and `EMAIL_FROM` are required for real email delivery. In development, verification and reset URLs are returned in API responses for local testing. Set `ADMIN_EMAIL` to an existing account email to bootstrap that account as an administrator on startup.

## Product publishing

Products are private by default. The public API returns only records with `status='active'` and a non-null `verified_at`. An administrator must create and verify product records after the mandate, disclosures, fees, liquidity terms, and operational controls have been approved. This repository intentionally does not seed performance claims, assets-under-management figures, investor counts, or testimonials.

## Public launch requirements

Before accepting public users or customer funds, obtain jurisdiction-specific legal review of the linked Terms, Privacy, Risk Disclosures, Fees, and Withdrawals templates. Complete KYC/AML, identity verification, sanctions screening, custody/payment integrations, signed webhook verification, withdrawal controls, admin separation of duties, incident response, backups, monitoring, and an independent security review.

## Local development

```bash
npm install
npm start
```

Open `http://localhost:3000`.

## Deployment

Public hosting uses **Vercel** (the website) and **Neon** (PostgreSQL). Both have free plans that sign up with GitHub and do not require a credit card.

1. Create a free Neon project at [neon.tech](https://neon.tech) and copy the pooled connection string (`DATABASE_URL`).
2. Import this GitHub repository at [vercel.com/new](https://vercel.com/new).
3. In the Vercel project, set:

```env
NODE_ENV=production
DATABASE_URL=postgresql://...neon.tech/neondb?sslmode=require
DATABASE_SSL=true
SESSION_SECRET=use-a-long-random-secret
FUNDING_WEBHOOK_SECRET=use-a-separate-long-secret
APP_URL=https://your-app.vercel.app
ADMIN_EMAIL=you@example.com
```

4. Deploy. The public URL is `https://your-app.vercel.app`.

A `render.yaml` is still included if you prefer Render, but Render may ask for a card.

## Security before real-money launch

At minimum, complete:

1. Payment/bank/custody integration with signed webhooks and idempotency.
2. KYC/AML and sanctions controls appropriate to the products and jurisdiction.
3. Authorization and admin roles for operational actions.
4. Immutable financial ledger and reconciliation.
5. Audit logging.
6. CSRF protection appropriate to the chosen authentication architecture.
7. Password reset and email verification.
8. Backup/restore and monitoring.
9. Independent security review.
10. Legal/regulatory review for every investment, lending, crypto and mining product offered.
