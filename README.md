# Extending PR-RABE for Risk-Adaptive and Secure Cross-Organizational CTI Sharing

**B.Tech Project (BTP) — Phase I**
Department of CSE — Cyber Security, Indian Institute of Information Technology Kottayam

| Team | Roll Number |
|------|-------------|
| Manasa Manoj | 2023BCY0041 |
| Manish Anand | 2023BCY0053 |
| Jadhav Sai | 2023BCY0064 |
| Bhaskar Naik | 2023BCY0031 |

**Guide:** Dr. A Balu

---

## Overview

A full-stack web platform for **privacy-preserving cyber threat intelligence (CTI) sharing** that extends the PR-RABE (Privacy-preserving Revocable Registered Attribute-Based Encryption) scheme with a **risk-adaptive layer**.

The core contribution is an event-driven risk/trust engine that **automatically drives PR-RABE's AGK (Attribute Group Key) revocation** — unlike the base scheme where revocation is manual. Organizations' decryption eligibility changes dynamically as their behavioral trust evolves, without re-encrypting existing ciphertexts.

### Key Features

- **PR-RABE Encryption Pipeline** — KEM-DEM hybrid: AES-256-GCM authenticated encryption with HKDF-SHA256 key derivation, LSSS policy strings auto-generated from record sensitivity
- **Dynamic Trust Scoring** — Five-component weighted trust function (sharing contribution, policy compliance, data reliability, engagement, security posture) computed at decryption time
- **Risk-Adaptive Policies** — FIPS 199 high-water mark classification with Bell-LaPadula clearance model
- **Targeted Revocation** — AGK rotation revokes one organization without touching any other member's keys
- **STIX 2.1 Intelligence** — Structured threat bundles (indicators, malware, attack-patterns, identities, observed-data)
- **CTI Correlation** — Cross-organizational indicator linking for campaign reconstruction
- **Knowledge Graph** — Interactive force-directed visualization of threat relationships
- **MITRE ATT&CK Mapping** — Technique heatmap with collaborative filtering predictions

---

## Architecture

The platform implements an **8-stage pipeline** with a continuous feedback loop:

```
CTI Sources (Organizations + OSINT)
        │
   1. CTI Collection ──── Ingest raw threat data (hashes, IPs, domains, TTPs)
        │
   2. Normalization ───── Convert to STIX 2.1 format
        │
   3. CTI Correlation ─── Link related indicators across organizations
        │
   4. Risk Analysis ───── Assess severity (CVSS, EPSS, sector impact)
        │
   5. Trust Profile ───── Compute org trust from behavioral signals ◄──┐
        │                                                                │
   6. Access Decision ─── Map sensitivity × trust → attribute policy    │
        │                                                                │
   7. PR-RABE Encrypt ─── LSSS policy with hidden attributes (AGK)     │
        │                                                                │
   8. Distribution ────── Ciphertext + header to authorized consumers   │
                                                                         │
   Feedback Loop: submissions, violations, behavior ─────────────────────┘
```

---

## Project Structure

```
CTI-BTP/
├── backend/
│   ├── app.py                    # Flask API routes and middleware
│   ├── crypto_engine.py          # AES-256-GCM + HKDF encryption pipeline
│   ├── prrabe_interface.py       # PR-RABE operations and AGK management
│   ├── policy_engine.py          # Risk-adaptive LSSS policy generation
│   ├── trust_engine.py           # Dynamic trust scoring (5 components)
│   ├── advanced_cti.py           # CTI record management + STIX bundles
│   ├── advanced_cti_processor.py # CTI processing and normalization
│   ├── correlation.py            # Cross-org indicator correlation
│   ├── risk_analysis.py          # CVSS/EPSS threat risk assessment
│   ├── authentication.py         # JWT auth with bcrypt
│   ├── organizations.py          # Organization CRUD + trust tracking
│   ├── database.py               # SQLite connection and schema
│   ├── ai_predictor.py           # ML severity prediction
│   ├── temporal_engine.py        # Dynamic risk decay
│   ├── knowledge_graph.py        # Graph data builder
│   ├── graph_analytics.py        # PageRank centrality
│   ├── pdf_cti_extractor.py      # PDF threat report ingestion
│   ├── crypto/                   # PR-RABE_P cryptographic implementation
│   │   ├── prrabe/               # Core scheme (setup, encrypt, decrypt, AGK)
│   │   ├── demo_simple.py        # Standalone ABE demo
│   │   └── demo_slide19.py       # Proposal slide 19 walkthrough
│   ├── policy_simulation.py      # Synthetic policy engine workload
│   └── tests/                    # Test suite
├── frontend/
│   └── src/
│       ├── App.jsx               # Navigation and app shell
│       ├── CryptoSharing.jsx     # PR-RABE encrypt/decrypt interface
│       ├── DashboardOverview.jsx  # Platform statistics dashboard
│       ├── CTISubmissionForm.jsx  # CTI submission with STIX generation
│       ├── KnowledgeGraph.jsx     # Threat relationship graph
│       ├── ATTACKNavigator.jsx    # MITRE ATT&CK heatmap
│       ├── TemporalIntelligence.jsx # Threat timeline analysis
│       ├── PDFIntelligence.jsx    # PDF extraction interface
│       ├── AccessControl.jsx      # Organization/user management
│       ├── LandingPage.jsx        # Public landing page
│       ├── LoginPage.jsx          # Authentication UI
│       └── api.js                 # API client with token management
├── scripts/
│   └── seed_demo.py              # Database seeding (orgs, users, CTI records)
├── docs/
│   └── crypto/DEVIATIONS.md      # PR-RABE implementation notes
├── requirements.txt              # Python dependencies
├── requirements-crypto.txt       # Optional: charm-crypto (Linux only)
└── README.md
```

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Backend | Flask 3.x (Python 3.11) |
| Frontend | React 18 + Vite |
| Database | SQLite (WAL mode) |
| Encryption | PyCryptodome (AES-256-GCM), HKDF-SHA256 |
| Authentication | JWT + bcrypt |
| CTI Format | STIX 2.1 |
| Visualization | react-force-graph-2d, Lucide Icons |

---

## Quick Start (Reproducible Setup)

### Prerequisites

- Python 3.10+
- Node.js 18+ and npm
- Git

### 1. Clone and install dependencies

```bash
git clone https://github.com/manasa-manoj-nbr/CTI-BTP.git
cd CTI-BTP
```

**Backend (Python):**

```bash
python -m venv .venv

# Windows
.venv\Scripts\activate

# macOS/Linux
source .venv/bin/activate

pip install -r requirements.txt
```

**Frontend (Node):**

```bash
cd frontend
npm install
cd ..
```

### 2. Initialize the database and seed demo data

```bash
python -m scripts.seed_demo
```

This creates the SQLite database (`data/cti.db`) with:
- 3 organizations (Alpha Bank, City Hospital, Delta Insurance)
- 5 user accounts (see credentials below)
- 6 diverse CTI records with full STIX 2.1 bundles
- Submission history that sets Alpha Bank's trust score to 82 (High)

### 3. Start the application

**Terminal 1 — Backend (Flask API on port 5000):**

```bash
python -m backend.app
```

**Terminal 2 — Frontend (Vite dev server on port 5173):**

```bash
cd frontend
npm run dev
```

Open **http://localhost:5173** in your browser.

### Demo Credentials

| Email | Password | Organization | Sector | Trust |
|-------|----------|-------------|--------|-------|
| alice@alphabank.com | alice123 | Alpha Bank | Finance | 82 (High) |
| bob@cityhospital.com | bob123 | City Hospital | Healthcare | 50 (Medium) |
| carol@deltainsurance.com | carol123 | Delta Insurance | Finance | 50 (Medium) |
| admin@alphabank.com | admin123 | Alpha Bank | Finance | 82 (High) |
| eve@cityhospital.com | eve123 | City Hospital | Healthcare | 50 (Medium) |

> **Tip:** Log in as Alice (High trust) to see full decryption access, then as Bob (Medium trust) to see restricted access — this demonstrates the risk-adaptive PR-RABE access control in action.

---

## Base Paper

R. Yang, T. Wang, N. Jin, B. Yang, Y. Zhou, D. Zhang, and X. Xin, "PR-RABE: Privacy-preserving and Revocable Registered Attribute-Based Encryption with lightweight encryption," *Computer Standards & Interfaces*, vol. 98, p. 104158, 2026.

---

## License

This project is developed as part of the B.Tech curriculum at IIIT Kottayam and is intended for academic purposes.
