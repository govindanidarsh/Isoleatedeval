'use strict';

const crypto = require('node:crypto');

// In-memory sliding window rate limiter
const rateLimits = new Map(); // key -> [timestamps]
const WINDOW_MS = 60 * 1000;  // 1 minute window
const MAX_REQUESTS = 120;     // 120 requests per minute

/**
 * Checks and records rate limits.
 * Returns null if allowed, or rate limit response if exceeded.
 */
function checkRateLimit(clientKey, db) {
  const now = Date.now();
  const timestamps = (rateLimits.get(clientKey) || []).filter(ts => now - ts < WINDOW_MS);

  if (timestamps.length >= MAX_REQUESTS) {
    try {
      if (db) {
        const timeStr = new Date().toTimeString().split(' ')[0];
        db.prepare(`
          INSERT INTO alerts (severity, event, detail, time, timestamp)
          VALUES (?, ?, ?, ?, ?)
        `).run(
          'medium',
          'Rate-limit warning',
          `Client exceeded rate limit (${timestamps.length} reqs / min)`,
          timeStr,
          now
        );
      }
    } catch (_) {}

    return {
      status: 429,
      headers: {
        'Retry-After': '5',
        'X-RateLimit-Limit': String(MAX_REQUESTS),
        'X-RateLimit-Remaining': '0'
      },
      body: {
        error: '429 Rate limited',
        message: 'Slow down — rate limit reached.'
      }
    };
  }

  timestamps.push(now);
  rateLimits.set(clientKey, timestamps);
  return null;
}

/**
 * Evaluates an attack payload against active defence rules and policy heuristics.
 */
function evaluateAttack(payload, activeRules = []) {
  const normalized = String(payload || '').trim();
  const lower = normalized.toLowerCase();

  // Create cryptographic SHA-256 commitment digest
  const fullHash = crypto.createHash('sha256').update(normalized).digest('hex');
  const digest = `sha256:${fullHash.slice(0, 16)}…${fullHash.slice(-6)}`;

  // 1. Check Blue Team active keyword rules
  const matchedRule = activeRules.find(rule => lower.includes(rule.toLowerCase()));
  if (matchedRule) {
    return {
      verdict: 'blocked',
      rule: matchedRule,
      digest
    };
  }

  // 2. Check general safety policy refusal
  const refusalKeywords = ['harm', 'malware', 'exploit', 'bypass safeguards', 'illegal'];
  if (refusalKeywords.some(kw => lower.includes(kw))) {
    return {
      verdict: 'refused',
      rule: 'safety policy',
      digest
    };
  }

  // 3. Check for successful jailbreak / prompt leak indicators that bypassed defence rules
  const jailbreakIndicators = ['dan mode', 'override all policy', 'print secrets', 'root access', 'developer mode', 'jailbreak'];
  if (jailbreakIndicators.some(kw => lower.includes(kw))) {
    return {
      verdict: 'compromised',
      rule: 'none',
      digest
    };
  }

  // 4. Benign query / safe payload
  return {
    verdict: 'safe',
    rule: 'none',
    digest
  };
}

/**
 * Enforces role-based commit-reveal isolation on runs and attacks data.
 */
function applyIsolationFilter(run, userRole) {
  if (!run) return null;

  const clone = { ...run };
  const isOpen = clone.status === 'open';

  if (!clone.attacks) {
    clone.attacks = [];
  }

  if (isOpen) {
    if (userRole === 'Blue Team') {
      // Blue Team MUST NOT see attack payloads or attack text during active runs
      clone.attacks = clone.attacks.map(atk => ({
        id: atk.id,
        payload: '[REDACTED - COMMIT-REVEAL ISOLATION ACTIVE]',
        verdict: 'sealed',
        rule: 'sealed',
        digest: atk.digest
      }));
    } else if (userRole === 'Red Team') {
      // Red Team can inspect their own payload & digest, but verdicts are sealed until run conclusion
      clone.attacks = clone.attacks.map(atk => ({
        id: atk.id,
        payload: atk.payload,
        verdict: 'sealed',
        rule: 'sealed',
        digest: atk.digest
      }));
    } else if (userRole === 'Auditor') {
      // Auditor in open runs sees metadata and digests only
      clone.attacks = clone.attacks.map(atk => ({
        id: atk.id,
        payload: '[SEALED - AWAITING CONCLUSION]',
        verdict: 'sealed',
        rule: 'sealed',
        digest: atk.digest
      }));
    }
  }

  return clone;
}

/**
 * Static metadata security surface analysis for client project uploads.
 */
function analyzeProjectFiles(files = []) {
  const sensitivePatterns = [/env/i, /secret/i, /key/i, /token/i, /cert/i, /password/i, /config/i, /\.pem$/i, /\.id_rsa$/i];
  
  let sensitiveCount = 0;
  const categorized = files.map(f => {
    const isSensitive = sensitivePatterns.some(p => p.test(f.name));
    if (isSensitive) sensitiveCount++;
    return {
      name: f.name,
      size: f.size || 0,
      type: f.type || 'Unknown',
      surfaceSignal: isSensitive ? 'REVIEW NAME' : 'INVENTORIED',
      sensitive: isSensitive
    };
  });

  return {
    totalFiles: files.length,
    sensitiveAssetsIdentified: sensitiveCount,
    status: 'INVENTORY READY',
    summary: `${files.length} assets analyzed. ${sensitiveCount} sensitive patterns flagged for inspection.`,
    assets: categorized
  };
}

module.exports = {
  checkRateLimit,
  evaluateAttack,
  applyIsolationFilter,
  analyzeProjectFiles
};
