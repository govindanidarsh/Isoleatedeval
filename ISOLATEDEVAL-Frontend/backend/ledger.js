'use strict';

const crypto = require('node:crypto');

const GENESIS_PREV_HASH = '0x0000000000000000000000000000000000000000000000000000000000000000';

/**
 * Computes a deterministic SHA-256 hash for a ledger entry.
 */
function computeHash(seq, time, actor, event, details, prevHash) {
  const payload = [
    seq,
    time,
    actor,
    event,
    typeof details === 'string' ? details : JSON.stringify(details || {}),
    prevHash
  ].join('|');

  return '0x' + crypto.createHash('sha256').update(payload).digest('hex');
}

/**
 * Creates an in-memory or database-backed Ledger Manager.
 */
class LedgerManager {
  constructor(db) {
    this.db = db;
  }

  /**
   * Initializes the ledger table and seeds default genesis entries if empty.
   */
  init() {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS ledger (
        seq TEXT PRIMARY KEY,
        time TEXT NOT NULL,
        timestamp INTEGER NOT NULL,
        actor TEXT NOT NULL,
        event TEXT NOT NULL,
        details TEXT NOT NULL,
        prev_hash TEXT NOT NULL,
        hash TEXT NOT NULL
      );
    `);

    const count = this.db.prepare('SELECT COUNT(*) as count FROM ledger').get().count;
    if (count === 0) {
      this.seedInitialEntries();
    }
  }

  seedInitialEntries() {
    const seedEvents = [
      { actor: 'admin', event: 'Run created', details: JSON.stringify({ runId: 'RUN-1040' }), time: '14:11:44', ts: Date.now() - 300000 },
      { actor: 'red-team', event: 'Payload committed', details: JSON.stringify({ runId: 'RUN-1041', digest: 'sha256:cc81a4b10' }), time: '14:12:01', ts: Date.now() - 200000 },
      { actor: 'blue-team', event: 'Defences saved', details: JSON.stringify({ rulesCount: 4 }), time: '14:12:08', ts: Date.now() - 100000 }
    ];

    let prevHash = GENESIS_PREV_HASH;
    const stmt = this.db.prepare(`
      INSERT INTO ledger (seq, time, timestamp, actor, event, details, prev_hash, hash)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);

    seedEvents.forEach((item, index) => {
      const seq = String(index + 1).padStart(4, '0');
      const hash = computeHash(seq, item.time, item.actor, item.event, item.details, prevHash);
      stmt.run(seq, item.time, item.ts, item.actor, item.event, item.details, prevHash, hash);
      prevHash = hash;
    });
  }

  /**
   * Retrieves the current HEAD entry of the ledger.
   */
  getHead() {
    return this.db.prepare('SELECT * FROM ledger ORDER BY seq DESC LIMIT 1').get();
  }

  /**
   * Appends a new immutable entry to the ledger chain.
   */
  append(actor, event, details = {}) {
    const head = this.getHead();
    const prevHash = head ? head.hash : GENESIS_PREV_HASH;
    const nextSeqNum = head ? parseInt(head.seq, 10) + 1 : 1;
    const seq = String(nextSeqNum).padStart(4, '0');

    const now = new Date();
    const time = now.toTimeString().split(' ')[0];
    const timestamp = now.getTime();
    const detailsStr = typeof details === 'string' ? details : JSON.stringify(details);

    const hash = computeHash(seq, time, actor, event, detailsStr, prevHash);

    const stmt = this.db.prepare(`
      INSERT INTO ledger (seq, time, timestamp, actor, event, details, prev_hash, hash)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(seq, time, timestamp, actor, event, detailsStr, prevHash, hash);

    return {
      seq,
      time,
      timestamp,
      actor,
      event,
      details,
      prev_hash: prevHash,
      hash
    };
  }

  /**
   * Retrieves all entries in reverse chronological order (newest first, for UI) or chronological.
   */
  getAll(descending = true) {
    const order = descending ? 'DESC' : 'ASC';
    return this.db.prepare(`SELECT * FROM ledger ORDER BY seq ${order}`).all();
  }

  /**
   * Verifies the cryptographic integrity of the entire chain from genesis to head.
   */
  verify() {
    const entries = this.db.prepare('SELECT * FROM ledger ORDER BY seq ASC').all();
    if (entries.length === 0) {
      return { valid: true, count: 0, head: GENESIS_PREV_HASH };
    }

    let prevHash = GENESIS_PREV_HASH;
    for (let i = 0; i < entries.length; i++) {
      const entry = entries[i];

      // Check linkage with previous hash
      if (entry.prev_hash !== prevHash) {
        return {
          valid: false,
          broken_seq: entry.seq,
          reason: `Broken chain link at sequence ${entry.seq}: expected prev_hash ${prevHash}, got ${entry.prev_hash}`,
          entry
        };
      }

      // Check hash calculation
      const expectedHash = computeHash(
        entry.seq,
        entry.time,
        entry.actor,
        entry.event,
        entry.details,
        entry.prev_hash
      );

      if (entry.hash !== expectedHash) {
        return {
          valid: false,
          broken_seq: entry.seq,
          reason: `Hash mismatch at sequence ${entry.seq}: expected ${expectedHash}, got ${entry.hash}`,
          entry
        };
      }

      prevHash = entry.hash;
    }

    return {
      valid: true,
      count: entries.length,
      head: entries[entries.length - 1].hash
    };
  }

  /**
   * Simulates tampering by corrupting an entry's hash or content.
   */
  tamper(targetSeq) {
    const entries = this.getAll(false);
    if (entries.length === 0) return false;

    const seqToTamper = targetSeq || entries[entries.length - 1].seq;
    const stmt = this.db.prepare(`
      UPDATE ledger
      SET hash = '0xBAD0' || substr(hash, 7)
      WHERE seq = ?
    `);
    stmt.run(seqToTamper);
    return true;
  }

  /**
   * Restores valid hashes across the chain.
   */
  repair() {
    const entries = this.getAll(false);
    let prevHash = GENESIS_PREV_HASH;

    const stmt = this.db.prepare(`
      UPDATE ledger
      SET prev_hash = ?, hash = ?
      WHERE seq = ?
    `);

    for (const entry of entries) {
      const hash = computeHash(
        entry.seq,
        entry.time,
        entry.actor,
        entry.event,
        entry.details,
        prevHash
      );
      stmt.run(prevHash, hash, entry.seq);
      prevHash = hash;
    }
  }
}

module.exports = {
  computeHash,
  LedgerManager,
  GENESIS_PREV_HASH
};
