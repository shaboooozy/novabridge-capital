const crypto = require('crypto');

const ALLOWED_UNITS = new Set(['minute', 'hour', 'day', 'week', 'month']);

function advanceNextRun(fromDate, unit, count) {
  const d = new Date(fromDate);
  const n = Math.max(1, Number(count) || 1);
  if (unit === 'minute') d.setUTCMinutes(d.getUTCMinutes() + n);
  else if (unit === 'hour') d.setUTCHours(d.getUTCHours() + n);
  else if (unit === 'day') d.setUTCDate(d.getUTCDate() + n);
  else if (unit === 'week') d.setUTCDate(d.getUTCDate() + n * 7);
  else if (unit === 'month') d.setUTCMonth(d.getUTCMonth() + n);
  else d.setUTCDate(d.getUTCDate() + n);
  return d;
}

function createTransactionEngine({ pool, q, cents, money, ethRpc, fetchJson, usdPrices }) {
  const workerId = `${process.pid}-${crypto.randomBytes(4).toString('hex')}`;
  let loopTimer = null;
  let ticking = false;

  async function ensureSchedulerTables() {
    await q(`
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
    `);
  }

  async function enqueueJob({ jobType, userId = null, dedupeKey = null, payload = {}, runAt = new Date() }) {
    const res = await q(
      `INSERT INTO scheduled_jobs(job_type, user_id, dedupe_key, payload, run_at, status)
       VALUES($1, $2, $3, $4::jsonb, $5, 'pending')
       ON CONFLICT (dedupe_key) DO NOTHING
       RETURNING *`,
      [jobType, userId, dedupeKey, JSON.stringify(payload), runAt]
    );
    return res.rows[0] || null;
  }

  // 1. Server-triggered wallet listener (checks BTC/ETH deposit wallets + collateral tx hashes)
  async function runWalletListenerTick() {
    const walletsRes = await q('SELECT network, address FROM deposit_wallets WHERE active=TRUE ORDER BY id');
    const prices = await usdPrices().catch(() => ({}));

    for (const w of walletsRes.rows) {
      try {
        if (w.network === 'bitcoin') {
          const txs = await fetchJson(`https://blockstream.info/api/address/${encodeURIComponent(w.address)}/txs`).catch(() => []);
          const tipHeight = Number(await fetchJson('https://blockstream.info/api/blocks/tip/height').catch(() => 0));
          for (const tx of (Array.isArray(txs) ? txs.slice(0, 15) : [])) {
            let receivedSats = 0;
            for (const vout of (tx.vout || [])) {
              if (vout.scriptpubkey_address === w.address) receivedSats += Number(vout.value || 0);
            }
            if (receivedSats <= 0) continue;
            const confs = tx.status?.confirmed && tipHeight && tx.status?.block_height
              ? Math.max(1, tipHeight - Number(tx.status.block_height) + 1)
              : 0;
            const btcAmt = receivedSats / 1e8;
            const usdCents = Math.round(btcAmt * (prices.bitcoin || 0) * 100);
            await q(
              `INSERT INTO wallet_tx_events(
                 network, tx_hash, watched_address, direction, asset_symbol,
                 amount_raw, amount_cents, confirmations, required_confirmations, status, metadata
               )
               VALUES('bitcoin', $1, $2, 'incoming', 'BTC', $3, $4, $5, 3, $6, $7::jsonb)
               ON CONFLICT (network, tx_hash, watched_address)
               DO UPDATE SET confirmations = GREATEST(wallet_tx_events.confirmations, EXCLUDED.confirmations),
                             status = CASE WHEN wallet_tx_events.status = 'credited' THEN 'credited'
                                           WHEN EXCLUDED.confirmations >= wallet_tx_events.required_confirmations THEN 'confirmed'
                                           ELSE wallet_tx_events.status END,
                             confirmed_at = COALESCE(wallet_tx_events.confirmed_at, CASE WHEN EXCLUDED.confirmations >= wallet_tx_events.required_confirmations THEN NOW() ELSE NULL END)`,
              [
                tx.txid,
                w.address,
                String(receivedSats),
                usdCents,
                confs,
                confs >= 3 ? 'confirmed' : 'seen',
                JSON.stringify({ btcAmount: btcAmt })
              ]
            );
          }
          await q(
            `INSERT INTO wallet_listener_state(network, address, last_seen_block, last_polled_at, last_error, updated_at)
             VALUES('bitcoin', $1, $2, NOW(), NULL, NOW())
             ON CONFLICT (network) DO UPDATE SET address=EXCLUDED.address, last_seen_block=EXCLUDED.last_seen_block, last_polled_at=NOW(), last_error=NULL, updated_at=NOW()`,
            [w.address, tipHeight || null]
          );
        } else if (w.network === 'ethereum') {
          const latestHex = await ethRpc('eth_blockNumber', []).catch(() => null);
          const latestBlock = latestHex ? parseInt(latestHex, 16) : null;
          await q(
            `INSERT INTO wallet_listener_state(network, address, last_seen_block, last_polled_at, last_error, updated_at)
             VALUES('ethereum', $1, $2, NOW(), NULL, NOW())
             ON CONFLICT (network) DO UPDATE SET address=EXCLUDED.address, last_seen_block=COALESCE(EXCLUDED.last_seen_block, wallet_listener_state.last_seen_block), last_polled_at=NOW(), last_error=NULL, updated_at=NOW()`,
            [w.address, latestBlock]
          );
        }
      } catch (err) {
        await q(
          `INSERT INTO wallet_listener_state(network, address, last_polled_at, last_error, updated_at)
           VALUES($1, $2, NOW(), $3, NOW())
           ON CONFLICT (network) DO UPDATE SET last_polled_at=NOW(), last_error=$3, updated_at=NOW()`,
          [w.network, w.address, String(err.message || err).slice(0, 300)]
        ).catch(() => {});
      }
    }

    // Reconcile pending ETH collateral transactions
    const pendingApps = await q(
      `SELECT id, collateral_tx, wallet_address, collateral_address, collateral_amount
       FROM credit_applications
       WHERE status='Pending' AND collateral_status='Sent' AND network='ethereum' AND collateral_symbol='ETH' AND collateral_tx <> ''
       LIMIT 25`
    );
    for (const appRow of pendingApps.rows) {
      if (!/^0x[a-fA-F0-9]{64}$/.test(appRow.collateral_tx)) continue;
      try {
        const receipt = await ethRpc('eth_getTransactionReceipt', [appRow.collateral_tx]);
        if (receipt && receipt.status === '0x1') {
          await q("UPDATE credit_applications SET collateral_status='Received' WHERE id=$1 AND status='Pending'", [appRow.id]);
        }
      } catch (_) {}
    }
  }

  // 2. Automatic recurring transaction processor
  async function processDueRecurringTransactions() {
    const dueRes = await q(
      `SELECT id FROM recurring_transactions
       WHERE status='active' AND next_run_at <= NOW()
       ORDER BY next_run_at ASC, id ASC
       LIMIT 25`
    );

    for (const row of dueRes.rows) {
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        const recRes = await client.query(
          `SELECT * FROM recurring_transactions
           WHERE id=$1 AND status='active' AND next_run_at <= NOW()
           FOR UPDATE SKIP LOCKED`,
          [row.id]
        );
        const rec = recRes.rows[0];
        if (!rec) {
          await client.query('ROLLBACK');
          continue;
        }

        const uRes = await client.query('SELECT flagged, account_status FROM users WHERE id=$1', [rec.user_id]);
        const u = uRes.rows[0];
        if (!u || u.account_status === 'suspended' || u.flagged || u.account_status === 'flagged') {
          await client.query(
            `UPDATE recurring_transactions
             SET status='paused', last_error='Account restricted or suspended', updated_at=NOW()
             WHERE id=$1`,
            [rec.id]
          );
          await client.query('COMMIT');
          continue;
        }

        const pRes = await client.query('SELECT cash_cents FROM portfolios WHERE user_id=$1 FOR UPDATE', [rec.user_id]);
        const pendingRes = await client.query(
          "SELECT COALESCE(SUM(amount_cents),0) AS amount FROM withdrawal_requests WHERE user_id=$1 AND status='Pending'",
          [rec.user_id]
        );
        const cashCents = Number(pRes.rows[0]?.cash_cents || 0);
        const pendingCents = Number(pendingRes.rows[0]?.amount || 0);
        const availableCents = cashCents - pendingCents;

        if (availableCents < Number(rec.amount_cents)) {
          const retryAt = advanceNextRun(new Date(), rec.interval_unit, rec.interval_count);
          await client.query(
            `UPDATE recurring_transactions
             SET next_run_at=$1, last_error='Insufficient available balance', updated_at=NOW()
             WHERE id=$2`,
            [retryAt, rec.id]
          );
          await client.query('COMMIT');
          continue;
        }

        if (rec.action_type === 'allocation') {
          await client.query(
            'UPDATE portfolios SET cash_cents=cash_cents-$1, updated_at=NOW() WHERE user_id=$2',
            [rec.amount_cents, rec.user_id]
          );
          await client.query(
            `INSERT INTO activities(user_id, activity, type, amount_cents, status)
             VALUES($1, $2, 'Recurring Allocation', $3, 'Completed')`,
            [rec.user_id, rec.label, rec.amount_cents]
          );
        } else if (rec.action_type === 'withdrawal') {
          const act = await client.query(
            `INSERT INTO activities(user_id, activity, type, amount_cents, status)
             VALUES($1, $2, 'Recurring Withdrawal', $3, 'Pending')
             RETURNING id`,
            [rec.user_id, rec.label || `Recurring withdrawal · ${rec.network || 'wallet'}`, rec.amount_cents]
          );
          await client.query(
            `INSERT INTO withdrawal_requests(user_id, network, wallet_address, amount_cents, status, activity_id)
             VALUES($1, $2, $3, $4, 'Pending', $5)`,
            [rec.user_id, rec.network || 'ethereum', rec.wallet_address || '', rec.amount_cents, act.rows[0].id]
          );
        }

        const nextRunCount = Number(rec.run_count || 0) + 1;
        const reachedMax = rec.max_runs && nextRunCount >= Number(rec.max_runs);
        const nextRunAt = advanceNextRun(rec.next_run_at, rec.interval_unit, rec.interval_count);

        await client.query(
          `UPDATE recurring_transactions
           SET run_count=$1,
               last_run_at=NOW(),
               next_run_at=$2,
               status=$3,
               last_error=NULL,
               updated_at=NOW()
           WHERE id=$4`,
          [nextRunCount, nextRunAt, reachedMax ? 'completed' : 'active', rec.id]
        );
        await client.query(
          `INSERT INTO audit_logs(user_id, action, metadata)
           VALUES($1, 'recurring.executed', $2::jsonb)`,
          [rec.user_id, JSON.stringify({ recurringId: rec.id, actionType: rec.action_type, amount: money(rec.amount_cents), runCount: nextRunCount })]
        );
        await client.query('COMMIT');
      } catch (err) {
        await client.query('ROLLBACK').catch(() => {});
        await q(
          'UPDATE recurring_transactions SET last_error=$1, updated_at=NOW() WHERE id=$2',
          [String(err.message || err).slice(0, 300), row.id]
        ).catch(() => {});
      } finally {
        client.release();
      }
    }
  }

  // 3. Remote transaction command handler (idempotent by commandId)
  async function executeRemoteCommand({ commandId, source = 'remote', commandType, targetUserId = null, payload = {} }) {
    const existing = await q('SELECT * FROM remote_commands WHERE command_id=$1', [commandId]);
    if (existing.rows[0] && existing.rows[0].status === 'applied') {
      return { idempotentReplay: true, command: existing.rows[0] };
    }

    await q(
      `INSERT INTO remote_commands(command_id, source, command_type, target_user_id, payload, status)
       VALUES($1, $2, $3, $4, $5::jsonb, 'processing')
       ON CONFLICT (command_id) DO UPDATE SET status='processing'`,
      [commandId, source, commandType, targetUserId, JSON.stringify(payload)]
    );

    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      let responseBody = { ok: true, commandId, commandType };

      if (commandType === 'credit_user') {
        const uid = Number(targetUserId || payload.userId);
        const amtCents = cents(payload.amount);
        if (!uid || !Number.isFinite(amtCents) || amtCents <= 0) throw new Error('Invalid credit_user payload');
        await client.query('UPDATE portfolios SET cash_cents=cash_cents+$1, updated_at=NOW() WHERE user_id=$2', [amtCents, uid]);
        await client.query(
          `INSERT INTO activities(user_id, activity, type, amount_cents, status)
           VALUES($1, $2, 'Remote Credit', $3, 'Completed')`,
          [uid, String(payload.note || `Remote command ${commandId}`).slice(0, 140), amtCents]
        );
        responseBody.userId = uid;
        responseBody.amount = money(amtCents);
      } else if (commandType === 'debit_user') {
        const uid = Number(targetUserId || payload.userId);
        const amtCents = cents(payload.amount);
        if (!uid || !Number.isFinite(amtCents) || amtCents <= 0) throw new Error('Invalid debit_user payload');
        const p = await client.query('SELECT cash_cents FROM portfolios WHERE user_id=$1 FOR UPDATE', [uid]);
        if (Number(p.rows[0]?.cash_cents || 0) < amtCents) throw new Error('Insufficient balance for debit_user');
        await client.query('UPDATE portfolios SET cash_cents=cash_cents-$1, updated_at=NOW() WHERE user_id=$2', [amtCents, uid]);
        await client.query(
          `INSERT INTO activities(user_id, activity, type, amount_cents, status)
           VALUES($1, $2, 'Remote Debit', $3, 'Completed')`,
          [uid, String(payload.note || `Remote command ${commandId}`).slice(0, 140), amtCents]
        );
        responseBody.userId = uid;
        responseBody.amount = money(amtCents);
      } else if (commandType === 'pause_recurring' || commandType === 'resume_recurring') {
        const recId = Number(payload.recurringId);
        const nextStatus = commandType === 'pause_recurring' ? 'paused' : 'active';
        const upd = await client.query(
          "UPDATE recurring_transactions SET status=$1, updated_at=NOW() WHERE id=$2 AND status <> 'cancelled' RETURNING id, status",
          [nextStatus, recId]
        );
        if (!upd.rows[0]) throw new Error('Recurring transaction not found or cancelled');
        responseBody.recurring = upd.rows[0];
      } else if (commandType === 'trigger_wallet_poll') {
        responseBody.polled = true;
      } else {
        throw new Error(`Unsupported command_type: ${commandType}`);
      }

      await client.query(
        `INSERT INTO audit_logs(user_id, action, metadata)
         VALUES($1, 'remote.command_applied', $2::jsonb)`,
        [targetUserId || null, JSON.stringify({ commandId, source, commandType, payload })]
      );

      const saved = await client.query(
        `UPDATE remote_commands
         SET status='applied', response_body=$1::jsonb, error_message=NULL, processed_at=NOW()
         WHERE command_id=$2
         RETURNING *`,
        [JSON.stringify(responseBody), commandId]
      );
      await client.query('COMMIT');
      return { idempotentReplay: false, command: saved.rows[0] };
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {});
      await q(
        `UPDATE remote_commands
         SET status='failed', error_message=$1, processed_at=NOW()
         WHERE command_id=$2`,
        [String(err.message || err).slice(0, 400), commandId]
      ).catch(() => {});
      throw err;
    } finally {
      client.release();
    }
  }

  // 4. Background job queue runner (FOR UPDATE SKIP LOCKED)
  async function claimAndRunJobs(limit = 10) {
    for (let i = 0; i < limit; i++) {
      const client = await pool.connect();
      let job = null;
      try {
        await client.query('BEGIN');
        const picked = await client.query(
          `SELECT * FROM scheduled_jobs
           WHERE status='pending' AND run_at <= NOW()
           ORDER BY run_at ASC, id ASC
           FOR UPDATE SKIP LOCKED
           LIMIT 1`
        );
        job = picked.rows[0];
        if (!job) {
          await client.query('ROLLBACK');
          client.release();
          break;
        }
        await client.query(
          `UPDATE scheduled_jobs
           SET status='processing', attempts=attempts+1, locked_by=$1, locked_at=NOW(), updated_at=NOW()
           WHERE id=$2`,
          [workerId, job.id]
        );
        await client.query('COMMIT');
      } catch (err) {
        await client.query('ROLLBACK').catch(() => {});
        client.release();
        throw err;
      }
      client.release();

      try {
        if (job.job_type === 'wallet_listener_tick') {
          await runWalletListenerTick();
        } else if (job.job_type === 'recurring_transaction') {
          await processDueRecurringTransactions();
        } else if (job.job_type === 'remote_command') {
          await executeRemoteCommand(job.payload || {});
        }
        await q(
          `UPDATE scheduled_jobs
           SET status='completed', completed_at=NOW(), locked_by=NULL, locked_at=NULL, updated_at=NOW()
           WHERE id=$1`,
          [job.id]
        );
      } catch (err) {
        const attempts = Number(job.attempts || 0) + 1;
        const maxAttempts = Number(job.max_attempts || 5);
        const failed = attempts >= maxAttempts;
        const backoffSec = Math.min(300, 15 * 2 ** Math.min(5, attempts));
        await q(
          `UPDATE scheduled_jobs
           SET status=$1,
               run_at=NOW() + ($2 || ' seconds')::interval,
               last_error=$3,
               locked_by=NULL,
               locked_at=NULL,
               updated_at=NOW()
           WHERE id=$4`,
          [failed ? 'failed' : 'pending', String(backoffSec), String(err.message || err).slice(0, 400), job.id]
        );
      }
    }
  }

  async function runSchedulerTick() {
    if (ticking) return { skipped: true };
    ticking = true;
    try {
      await ensureSchedulerTables();
      await enqueueJob({
        jobType: 'wallet_listener_tick',
        dedupeKey: `wallet_tick:${Math.floor(Date.now() / 60000)}`,
        payload: {}
      });
      await enqueueJob({
        jobType: 'recurring_transaction',
        dedupeKey: `recurring_tick:${Math.floor(Date.now() / 30000)}`,
        payload: {}
      });
      await processDueRecurringTransactions();
      await claimAndRunJobs(10);
      return { ok: true };
    } finally {
      ticking = false;
    }
  }

  function startBackgroundLoop(intervalMs = 30000) {
    if (loopTimer) return;
    setTimeout(() => { runSchedulerTick().catch(err => console.error('Scheduler tick error:', err)); }, 3000);
    loopTimer = setInterval(() => {
      runSchedulerTick().catch(err => console.error('Scheduler loop error:', err));
    }, intervalMs);
    if (loopTimer.unref) loopTimer.unref();
  }

  function stopBackgroundLoop() {
    if (loopTimer) {
      clearInterval(loopTimer);
      loopTimer = null;
    }
  }

  return {
    ALLOWED_UNITS,
    ensureSchedulerTables,
    enqueueJob,
    runWalletListenerTick,
    processDueRecurringTransactions,
    executeRemoteCommand,
    runSchedulerTick,
    startBackgroundLoop,
    stopBackgroundLoop
  };
}

module.exports = { createTransactionEngine };
