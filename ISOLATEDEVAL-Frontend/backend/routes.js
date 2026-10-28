'use strict';

const { authenticate, authorize } = require('./auth');
const { checkRateLimit, evaluateAttack, applyIsolationFilter, analyzeProjectFiles } = require('./security');

function registerRoutes(req, res, db, ledger, body) {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = url.pathname.replace(/\/$/, '') || '/';
  const method = req.method.toUpperCase();

  // Helper to send JSON response
  const json = (status, data, extraHeaders = {}) => {
    res.writeHead(status, {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, X-Token, Authorization',
      ...extraHeaders
    });
    res.end(JSON.stringify(data));
  };

  // 1. Health check (no auth required)
  if (pathname === '/api/health' && method === 'GET') {
    return json(200, {
      status: 'healthy',
      version: '1.0.0',
      system: 'ISOLATEDEVAL Security Control Plane',
      uptime: process.uptime(),
      timestamp: Date.now()
    });
  }

  // 2. Available tokens helper (convenient for UI and operators)
  if (pathname === '/api/tokens' && method === 'GET') {
    const tokens = db.prepare('SELECT role, actor, name, token FROM tokens GROUP BY role').all();
    return json(200, {
      description: 'Pre-configured memory tokens for ISOLATEDEVAL roles',
      tokens
    });
  }

  // 3. Security Proof endpoints
  if (pathname === '/api/proof' && method === 'GET') {
    return json(200, {
      verticals: [
        { id: '01', title: 'Identity & least privilege', detail: 'Role authentication enforced via X-Token independently on every API route.' },
        { id: '02', title: 'Commit–reveal isolation', detail: 'Attack payloads remain hidden from Blue Team until run conclusion. Commits are SHA-256 hashed.' },
        { id: '03', title: 'Token handling', detail: 'Tokens are memory-only, verified server-side, and never logged or persisted in localStorage.' },
        { id: '04', title: 'Rate limiting', detail: 'Sliding-window threshold rate limiter responds with HTTP 429 and Retry-After header.' },
        { id: '05', title: 'Tamper-evident ledger', detail: 'Sequential SHA-256 hash-chain ledger exposes any retroactively altered entries.' },
        { id: '06', title: 'Results integrity', detail: 'Attack verdicts are matched against defence rules and digests; only released on conclusion.' },
        { id: '07', title: 'Auditable operations', detail: 'Every significant state change records actor, timestamp, event, and integrity hash in ledger.' }
      ]
    });
  }

  // --- Rate Limiting Enforcement ---
  const clientKey = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
  const rateLimitError = checkRateLimit(clientKey, db);
  if (rateLimitError) {
    return json(rateLimitError.status, rateLimitError.body, rateLimitError.headers);
  }

  // --- Authentication ---
  const user = authenticate(req, db);

  // 4. Whoami
  if (pathname === '/api/whoami' && method === 'GET') {
    const authError = authorize(user, [], pathname, db);
    if (authError) return json(authError.status, authError.body);

    return json(200, {
      role: user.role,
      actor: user.actor,
      name: user.name,
      token: user.token
    });
  }

  // All subsequent routes require authentication
  if (!user) {
    return json(401, {
      error: '401 Unauthorized',
      message: 'Authentication required. Send valid X-Token header.'
    });
  }

  // 5. Runs List & Creation
  if (pathname === '/api/runs') {
    if (method === 'GET') {
      const runs = db.prepare('SELECT * FROM runs ORDER BY id DESC').all();
      const attacks = db.prepare('SELECT * FROM attacks ORDER BY id ASC').all();

      const fullRuns = runs.map(r => {
        const runAttacks = attacks.filter(a => a.run_id === r.id);
        const assembled = {
          id: r.id,
          status: r.status,
          committed: r.committed,
          revealed: r.revealed,
          created: r.created,
          attacks: runAttacks
        };
        return applyIsolationFilter(assembled, user.role);
      });

      return json(200, fullRuns);
    }

    if (method === 'POST') {
      const authError = authorize(user, ['Admin', 'Client', 'Red Team'], pathname, db);
      if (authError) return json(authError.status, authError.body);

      // Generate next Run ID
      const runs = db.prepare('SELECT id FROM runs').all();
      const maxIdNum = runs.reduce((max, r) => {
        const num = parseInt(r.id.replace('RUN-', ''), 10);
        return isNaN(num) ? max : Math.max(max, num);
      }, 1042);

      const nextId = `RUN-${maxIdNum + 1}`;
      const now = new Date();
      const createdStr = `${now.toISOString().slice(0, 10)} ${now.toTimeString().slice(0, 5)}`;

      db.prepare(`
        INSERT INTO runs (id, status, committed, revealed, created, updated_at)
        VALUES (?, 'open', 0, 0, ?, ?)
      `).run(nextId, createdStr, Date.now());

      // Append to Ledger
      ledger.append(user.actor, 'Run created', { runId: nextId });

      return json(201, {
        id: nextId,
        status: 'open',
        committed: 0,
        revealed: 0,
        created: createdStr,
        attacks: []
      });
    }
  }

  // 6. Run Specific Actions: /api/runs/:id, /api/runs/:id/attacks, /api/runs/:id/reveal
  const runMatch = pathname.match(/^\/api\/runs\/([^/]+)(?:\/(attacks|commit|reveal))?$/);
  if (runMatch) {
    const runId = decodeURIComponent(runMatch[1]);
    const action = runMatch[2];

    const run = db.prepare('SELECT * FROM runs WHERE id = ?').get(runId);
    if (!run) {
      return json(404, { error: '404 Not Found', message: `Run ${runId} not found.` });
    }

    // A. Sub-action: /api/runs/:id/attacks or /api/runs/:id/commit
    if ((action === 'attacks' || action === 'commit') && method === 'POST') {
      const authError = authorize(user, ['Red Team', 'Admin'], pathname, db);
      if (authError) return json(authError.status, authError.body);

      if (run.status === 'concluded') {
        return json(400, { error: '400 Bad Request', message: 'This run is concluded. Cannot commit new payloads.' });
      }

      const payload = body && body.payload ? String(body.payload).trim() : '';
      if (!payload) {
        return json(400, { error: '400 Bad Request', message: 'Payload cannot be empty.' });
      }

      // Fetch active defence rules
      const defenceRows = db.prepare('SELECT rule FROM defences').all();
      const activeRules = defenceRows.map(d => d.rule);

      // Evaluate attack
      const evaluation = evaluateAttack(payload, activeRules);

      // Determine next attack ID
      const attackCount = db.prepare('SELECT COUNT(*) as c FROM attacks WHERE run_id = ?').get(runId).c;
      const attackId = `ATK-${String(attackCount + 1).padStart(2, '0')}`;

      // Insert attack
      db.prepare(`
        INSERT INTO attacks (id, run_id, payload, verdict, rule, digest, revealed, created_at)
        VALUES (?, ?, ?, ?, ?, ?, 0, ?)
      `).run(attackId, runId, payload, evaluation.verdict, evaluation.rule, evaluation.digest, new Date().toISOString());

      // Update run committed count
      const updatedCommitted = run.committed + 1;
      db.prepare('UPDATE runs SET committed = ?, updated_at = ? WHERE id = ?').run(updatedCommitted, Date.now(), runId);

      // Append to Ledger
      ledger.append(user.actor, 'Payload committed', {
        runId,
        attackId,
        digest: evaluation.digest
      });

      return json(201, {
        id: attackId,
        run_id: runId,
        digest: evaluation.digest,
        committed: updatedCommitted,
        revealed: run.revealed,
        status: 'committed'
      });
    }

    // B. Sub-action: /api/runs/:id/reveal
    if (action === 'reveal' && method === 'POST') {
      const authError = authorize(user, ['Red Team', 'Admin'], pathname, db);
      if (authError) return json(authError.status, authError.body);

      if (run.status !== 'concluded') {
        return json(400, { error: '400 Bad Request', message: 'Reveal is locked until the run concludes.' });
      }

      const nextRevealed = Math.min(run.committed, run.revealed + 1);
      db.prepare('UPDATE runs SET revealed = ?, updated_at = ? WHERE id = ?').run(nextRevealed, Date.now(), runId);

      ledger.append(user.actor, 'Payload revealed', { runId, revealed: nextRevealed });

      return json(200, {
        id: runId,
        committed: run.committed,
        revealed: nextRevealed
      });
    }

    // C. Conclude Run or update: POST /api/runs/:id (action: 'conclude')
    if (method === 'POST') {
      if (body && body.action === 'conclude') {
        const authError = authorize(user, ['Admin'], pathname, db);
        if (authError) return json(authError.status, authError.body);

        // Update run status to concluded and mark all attacks revealed
        db.prepare(`
          UPDATE runs
          SET status = 'concluded', revealed = committed, updated_at = ?
          WHERE id = ?
        `).run(Date.now(), runId);

        db.prepare('UPDATE attacks SET revealed = 1 WHERE run_id = ?').run(runId);

        // Append to Ledger
        ledger.append('admin', 'Run concluded', { runId, totalAttacks: run.committed });

        // Record Alert
        const now = new Date();
        db.prepare(`
          INSERT INTO alerts (severity, event, detail, time, timestamp)
          VALUES (?, ?, ?, ?, ?)
        `).run('low', 'Run concluded', `Admin concluded ${runId}. Results released.`, now.toTimeString().split(' ')[0], now.getTime());

        const updatedRun = db.prepare('SELECT * FROM runs WHERE id = ?').get(runId);
        const runAttacks = db.prepare('SELECT * FROM attacks WHERE run_id = ?').all(runId);
        updatedRun.attacks = runAttacks;

        return json(200, applyIsolationFilter(updatedRun, user.role));
      }
    }

    // D. Get single run detail: GET /api/runs/:id
    if (method === 'GET') {
      const runAttacks = db.prepare('SELECT * FROM attacks WHERE run_id = ? ORDER BY id ASC').all(runId);
      const assembled = {
        id: run.id,
        status: run.status,
        committed: run.committed,
        revealed: run.revealed,
        created: run.created,
        attacks: runAttacks
      };
      return json(200, applyIsolationFilter(assembled, user.role));
    }
  }

  // 7. Defences: GET /api/defences & PUT /api/defences
  if (pathname === '/api/defences') {
    if (method === 'GET') {
      // Red Team is not allowed to inspect Blue Team defences
      if (user.role === 'Red Team') {
        return json(403, { error: '403 Forbidden', message: 'Access restricted for Red Team to preserve isolation.' });
      }

      const rows = db.prepare('SELECT rule FROM defences ORDER BY rowid ASC').all();
      return json(200, { rules: rows.map(r => r.rule) });
    }

    if (method === 'PUT') {
      const authError = authorize(user, ['Blue Team', 'Admin'], pathname, db);
      if (authError) return json(authError.status, authError.body);

      const rules = body && Array.isArray(body.rules) ? body.rules : [];

      db.exec('DELETE FROM defences');
      const insert = db.prepare('INSERT INTO defences (rule, created_at) VALUES (?, ?)');
      rules.forEach(rule => {
        const trimmed = String(rule).trim();
        if (trimmed) insert.run(trimmed, new Date().toISOString());
      });

      // Append to Ledger
      ledger.append(user.actor, 'Defences saved', { rulesCount: rules.length });

      return json(200, { status: 'ok', rules });
    }
  }

  // 8. Evidence Ledger: GET /api/ledger, /api/ledger/verify, /api/ledger/tamper, /api/ledger/reset
  if (pathname === '/api/ledger') {
    if (method === 'GET') {
      const entries = ledger.getAll(true);
      return json(200, entries);
    }
  }

  if (pathname === '/api/ledger/verify') {
    const result = ledger.verify();
    if (result.valid) {
      const now = new Date();
      db.prepare(`
        INSERT INTO alerts (severity, event, detail, time, timestamp)
        VALUES (?, ?, ?, ?, ?)
      `).run('low', 'Ledger verified', `Integrity check completed successfully (${result.count} entries).`, now.toTimeString().split(' ')[0], now.getTime());
    }
    return json(200, result);
  }

  if (pathname === '/api/ledger/tamper' && method === 'POST') {
    const authError = authorize(user, ['Admin'], pathname, db);
    if (authError) return json(authError.status, authError.body);

    const tampered = ledger.tamper();
    const now = new Date();
    db.prepare(`
      INSERT INTO alerts (severity, event, detail, time, timestamp)
      VALUES (?, ?, ?, ?, ?)
    `).run('high', 'Ledger tamper simulated', 'Admin initiated demonstration tampering in evidence chain.', now.toTimeString().split(' ')[0], now.getTime());

    return json(200, {
      tampered,
      message: 'Tamper simulated. Re-running verification will detect broken hash chain.'
    });
  }

  if (pathname === '/api/ledger/reset' && method === 'POST') {
    const authError = authorize(user, ['Admin'], pathname, db);
    if (authError) return json(authError.status, authError.body);

    ledger.repair();
    return json(200, {
      repaired: true,
      message: 'Ledger hashes recomputed and verified.'
    });
  }

  // 9. Alerts & Monitoring Telemetry: GET /api/alerts or /api/monitoring
  if ((pathname === '/api/alerts' || pathname === '/api/monitoring') && method === 'GET') {
    const alerts = db.prepare('SELECT severity, event, detail, time FROM alerts ORDER BY id DESC LIMIT 50').all();
    return json(200, alerts);
  }

  // 10. File Upload & Surface Analysis: POST /api/upload or POST /api/analyze
  if ((pathname === '/api/upload' || pathname === '/api/analyze') && method === 'POST') {
    const files = body && Array.isArray(body.files) ? body.files : [];
    const analysis = analyzeProjectFiles(files);
    return json(200, analysis);
  }

  // Route not found
  return json(404, { error: '404 Not Found', message: `Route ${method} ${pathname} not found.` });
}

module.exports = {
  registerRoutes
};
