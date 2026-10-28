<div align="center">

# 🛡️ ISOLATEDEVAL
### Cryptographically Verified, Role-Isolated AI Red-Teaming & Safety Evaluation OS

[![Node.js](https://img.shields.io/badge/Node.js-v22+-339933?style=flat&logo=nodedotjs&logoColor=white)](https://nodejs.org/)
[![Database](https://img.shields.io/badge/Database-SQLite%20(Native%20WAL)-003B57?style=flat&logo=sqlite&logoColor=white)](https://nodejs.org/api/sqlite.html)
[![Cryptography](https://img.shields.io/badge/Cryptography-SHA--256%20Hash%20Chain-blue?style=flat&logo=gnupg&logoColor=white)](https://nodejs.org/api/crypto.html)
[![Tests](https://img.shields.io/badge/Tests-17%2F17%20Passing-brightgreen?style=flat)](backend/test.js)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-Zero%20External-orange?style=flat)](package.json)
[![Compliance](https://img.shields.io/badge/Compliance-EU%20AI%20Act%20%7C%20NIST%20AI%20RMF-purple?style=flat)](https://artificialintelligenceact.eu/)

<p align="center">
  <b>Don't just test AI security. Prove it.</b><br>
  A zero-dependency control plane that decouples attack submission, blind defense tuning, and verifiable result release using cryptographic commit–reveal isolation.
</p>

[Live Prototype](http://localhost:8000) • [Interactive 9-Slide Pitch Deck](pitch-deck.html) • [API Documentation](backend/README.md) • [Security Verticals](#-seven-security-verticals)

</div>

---

## ⚡ The Problem: Why Current AI Red-Teaming Fails

1. **The "Cheating Defender" Dilemma (Collusion)**: When Blue Teams (defenders) see attack prompts in advance, they write narrow keyword filters just to pass the evaluation. Models look safe in testing, but fail immediately against real-world jailbreaks.
2. **"Security by Trust Me"**: Evaluations live in mutable spreadsheets, Discord chats, and standard database logs that can be edited, deleted, or fabricated retroactively.
3. **Regulatory Exposure**: Under the **EU AI Act (Articles 9 & 15)** and **NIST AI RMF**, enterprises face statutory penalties (up to €35M / 7% turnover) without verifiable, mathematically reproducible adversarial testing records.

---

## 🚀 The Solution: Cryptographic Commit–Reveal Isolation

ISOLATEDEVAL enforces mathematical trust between attackers, defenders, and compliance auditors:

```
┌──────────────┐         ┌────────────────────────┐         ┌──────────────┐
│   RED TEAM   │ ──────> │   ISOLATION GATEWAY    │ <────── │  BLUE TEAM   │
│ (Attacker)   │         │ (Commit-Reveal Chamber)│         │  (Defender)  │
└──────────────┘         └────────────────────────┘         └──────────────┘
       │                              │                            │
Submits Jailbreak              Generates SHA-256             Defends BLIND
Prompt Payload                 Commitment Hash               (Attack Text REDACTED)
                                      │
                                      ▼
                        ┌───────────────────────────┐
                        │   TAMPER-EVIDENT LEDGER   │
                        │  H_i = SHA-256(Block_i)   │
                        └───────────────────────────┘
                                      │
                               Run Concluded
                                      ▼
                        ┌───────────────────────────┐
                        │   REPRODUCIBLE RECEIPTS   │
                        │ SAFE | BLOCKED | REFUSED  │
                        └───────────────────────────┘
```

---

## ✨ Key Features

- **🔐 Commit–Reveal Isolation**: Red Team commits attack payloads; an irreversible SHA-256 digest is generated instantly. Attack text is strictly **redacted** (`[REDACTED - ISOLATION ACTIVE]`) from the Blue Team until run conclusion.
- **⌬ Tamper-Evident Ledger**: Cryptographic hash chain linking every run, commit, defence update, and verdict:
  $$\text{Hash}_i = \text{SHA-256}(\text{Seq}_i \parallel \text{Time}_i \parallel \text{Actor}_i \parallel \text{Event}_i \parallel \text{Details}_i \parallel \text{PrevHash}_i)$$
  Any retroactive alteration immediately breaks the chain and flags the exact corrupted block sequence.
- **👥 5 Role-Scoped Vantage Points**: Scoped least-privilege workspaces for **Client**, **Red Team**, **Blue Team**, **Admin**, and **Auditor**.
- **🚦 Native Sliding-Window Rate Limiting**: Anti-DDoS and rate-limiting returning HTTP `429 Rate limited` with `Retry-After`.
- **📦 Zero External Dependencies**: 100% built on modern native Node.js (v22+), built-in `node:sqlite` (WAL mode), `node:crypto`, and `node:http`. Runs air-gapped out of the box with **zero `npm install`**.

---

## 🏁 Quick Start

### 1. Launch Server & App (One Command)
```bash
./run.sh
```
Or directly with Node:
```bash
node backend/server.js
```
The server starts at `http://localhost:8000` and serves both the REST API and the interactive frontend.

### 2. Run Test Suite
```bash
node backend/test.js
```
Executes all **17 automated tests** verifying RBAC, commit-reveal data redaction, defence isolation, SHA-256 attack commitments, run conclusion, and ledger tamper detection.

### 3. Interactive Pitch Deck
Open `http://localhost:8000/pitch-deck.html` or double-click `pitch-deck.html` in your browser for the interactive 9-slide presentation.

---

## 🔑 Pre-Configured Access Tokens

Authenticate via memory-only `X-Token` headers (never stored in `localStorage`):

| Role | Pre-configured Token | Alias | Permissions & Vantage Point |
|---|---|---|---|
| ◈ **Client** | `client-token-123` | `client` | Project asset upload, surface risk analysis, public runs & results |
| ⌁ **Red Team** | `redteam-token-456` | `red-team` | Commit attack payloads, receive SHA-256 digests. Defence rules hidden. |
| ⛨ **Blue Team** | `blueteam-token-789` | `blue-team` | Manage defence keyword rules. Attack text strictly hidden until conclusion. |
| ⚙ **Admin** | `admin-token-999` | `admin` | Full control: create runs, conclude runs, tamper & verify evidence ledger. |
| ⌕ **Auditor** | `auditor-token-321` | `auditor` | Read-only audit of runs, cryptographic evidence ledger, and telemetry. |

---

## 📜 Seven Security Verticals

1. **Identity & Least Privilege (Vertical 01)**: Independent role authorization enforced on every API route via `X-Token`.
2. **Commit–Reveal Isolation (Vertical 02)**: Real-time SHA-256 commitment hashing; attack text sealed from defenders during testing.
3. **Token Handling (Vertical 03)**: In-memory session authentication; zero persistence in browser storage prevents token theft.
4. **Rate Limiting (Vertical 04)**: Sliding-window token-bucket limiter responding with HTTP 429 and `Retry-After`.
5. **Tamper-Evident Ledger (Vertical 05)**: Sequential SHA-256 hash-chain ledger that detects retroactive data manipulation.
6. **Results Integrity (Vertical 06)**: Automated evaluation of attacks against defence rules producing `safe`, `blocked`, `refused`, or `compromised` verdicts.
7. **Auditable Operations (Vertical 07)**: Immutable audit blocks logged for every significant system event with cryptographic receipts.

---

## 🏛️ Regulatory Compliance Mapping

| Standard | Requirement | ISOLATEDEVAL Implementation |
|---|---|---|
| **EU AI Act — Art. 9** | Risk management throughout lifecycle | Append-only ledger recording all evaluation sessions and model responses. |
| **EU AI Act — Art. 15** | Cyber resilience & adversarial testing | Commit-reveal red-teaming against prompt injections and data leaks. |
| **NIST AI RMF — Measure 2.3** | Systematic adversarial testing | Role-isolated evaluation runs with reproducible cryptographic receipts. |
| **ISO/IEC 42001** | AI management system traceability | Non-repudiable audit trails signed with SHA-256 block hashes. |

---

## 📁 Repository Structure

```
ISOLATEDEVAL-Frontend/
├── backend/
│   ├── server.js        # Native HTTP server & static file host (Node 22+)
│   ├── db.js            # SQLite database manager using native node:sqlite
│   ├── auth.js          # Memory-safe X-Token validator & RBAC policy enforcer
│   ├── ledger.js        # Cryptographic SHA-256 hash-chain engine
│   ├── security.js      # Rate limiter, attack evaluator & commit-reveal isolator
│   ├── routes.js        # REST API route controllers
│   ├── test.js          # In-memory automated test suite (17/17 tests passing)
│   ├── package.json     # Node.js package metadata
│   └── README.md        # Comprehensive backend API documentation
├── index.html           # Interactive frontend UI (CRT landing, story, access gate, control plane)
├── pitch-deck.html      # Interactive 9-slide presentation with live prototype tabs
├── run.sh               # Executable startup bash script
├── run.command          # Double-clickable macOS launcher
└── README.md            # Main documentation
```

---

## 📄 License

This project is licensed under the Apache-2.0 License.
