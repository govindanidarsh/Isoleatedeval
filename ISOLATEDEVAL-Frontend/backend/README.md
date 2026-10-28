# ISOLATEDEVAL Backend

A cryptographically verified, role-isolated backend for the **ISOLATEDEVAL** AI red-teaming and evaluation platform.

Built with native Node.js (v22+), zero external dependencies, native SQLite (`node:sqlite`), and standard Web Crypto / `node:crypto`.

---

## Key Features

1. **Strict Role-Based Access Control (RBAC)**:
   - **Client**: Upload and inspect surface metadata, view public runs and results.
   - **Red Team**: Commit attack payloads (prompt injections, jailbreaks, policy overrides), receive SHA-256 digests. Red Team is strictly forbidden from viewing Blue Team defence rules.
   - **Blue Team**: Define keyword and pattern defence rules. Blue Team is strictly isolated from viewing active attack payloads before a run concludes.
   - **Admin**: Create and conclude evaluation runs, view telemetry alerts, verify and simulate tamper detection in the evidence ledger.
   - **Auditor**: Read-only verification of runs, evidence chains, and security receipts.

2. **Commit–Reveal Isolation (Vertical 02)**:
   - During open runs, attack payloads are hashed with SHA-256 commitments immediately.
   - Payloads and attack text are completely hidden and redacted from the Blue Team (`[REDACTED - COMMIT-REVEAL ISOLATION ACTIVE]`) until conclusion.
   - Concluding a run computes verdicts (`safe`, `blocked`, `refused`, `compromised`) against defence rules and releases results.

3. **Tamper-Evident Ledger (Vertical 05)**:
   - Hash-linked blockchain sequence:
     $$\text{Hash}_i = \text{SHA-256}(\text{Seq}_i \parallel \text{Time}_i \parallel \text{Actor}_i \parallel \text{Event}_i \parallel \text{Details}_i \parallel \text{PrevHash}_i)$$
   - Full chain verification from genesis to HEAD via `/api/ledger/verify`.
   - Simulated tamper detection via `/api/ledger/tamper` immediately pinpoints the broken block sequence.

4. **Rate Limiting & Telemetry (Vertical 04 & 07)**:
   - Sliding-window threshold limiter returning HTTP `429 Rate limited` with `Retry-After`.
   - Security alerts logged for unauthorized access attempts (`403`), rate limit threshold crossings, and tamper simulations.

5. **Integrated Static Web Server**:
   - Automatically serves `index.html` at `http://localhost:8000` with CORS preflight handling.

---

## Quick Start

### 1. Start Server
```bash
# Using npm
npm start

# Or directly with node
node backend/server.js

# Or with the root launcher
./run.sh
```

The server starts at `http://localhost:8000`.

### 2. Run Test Suite
```bash
node backend/test.js
```
Executes 17 automated tests covering health checks, RBAC authorization, commit-reveal data redaction, defence isolation, SHA-256 attack commits, run conclusion, ledger verification, and tamper detection.

---

## Pre-configured Role Tokens

Tokens are passed in the `X-Token` header:

| Role | Pre-configured Token | Short Alias | Permissions Summary |
|---|---|---|---|
| **Client** | `client-token-123` | `client` | Upload project files, inspect runs & released results |
| **Red Team** | `redteam-token-456` | `red-team` | Commit attack payloads, get SHA-256 commitments (defence rules hidden) |
| **Blue Team** | `blueteam-token-789` | `blue-team` | Manage defence rules (open attack payloads hidden) |
| **Admin** | `admin-token-999` | `admin` | Full control: create/conclude runs, tamper/verify ledger |
| **Auditor** | `auditor-token-321` | `auditor` | Read-only audit of runs, evidence ledger, telemetry |

---

## API Reference

### Identity & Access
- `GET /api/health` — Service health and uptime.
- `GET /api/tokens` — List available role tokens and aliases.
- `GET /api/whoami` — Authenticate `X-Token` and return role and actor metadata.

### Runs & Attack Commit/Reveal
- `GET /api/runs` — List runs (attacks filtered and redacted based on requester's role).
- `POST /api/runs` — Create a new evaluation run (`RUN-1043`, `RUN-1044`...).
- `GET /api/runs/:id` — Get run details with role-appropriate redaction.
- `POST /api/runs/:id` — Conclude run (`{ "action": "conclude" }`). Evaluates attacks and releases results.
- `POST /api/runs/:id/attacks` — Red Team commits payload. Returns SHA-256 digest commitment.
- `POST /api/runs/:id/reveal` — Reveal attack payload (locked until run concludes).

### Blue Team Defences
- `GET /api/defences` — Get active defence rules (returns `403` to Red Team).
- `PUT /api/defences` — Update active defence keyword rules (`{ "rules": [...] }`).

### Evidence Ledger
- `GET /api/ledger` — Retrieve all ledger blocks in chronological or reverse order.
- `GET /api/ledger/verify` — Recompute and cryptographically verify the entire hash chain.
- `POST /api/ledger/tamper` — (Admin only) Corrupt a ledger block to demonstrate tamper detection.
- `POST /api/ledger/reset` — (Admin only) Repair and restore valid hash chain.

### Telemetry & File Analysis
- `GET /api/alerts` — Recent security alerts and audit telemetry.
- `POST /api/upload` — Analyze client project files and flag sensitive credentials/configs.
- `GET /api/proof` — 7 security verticals checklist.
