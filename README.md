# Cyber Threat Intelligence (CTI) Sharing Platform

## 1. Project Overview
The Cyber Threat Intelligence (CTI) Sharing Platform is an advanced, full-stack web application designed to help organizations process, analyze, correlate, and securely share cyber threat intelligence. 

Different organizations encounter different cyber threats. Sharing relevant intelligence helps them identify related attacks, understand potential risks, and make better security decisions. This project moves beyond basic rule-based matching to incorporate **Machine Learning risk prediction**, **Graph Theory (PageRank)**, **Temporal Risk Decay**, and **Attribute-Based Encryption (ABE)** for privacy-preserving sharing.

## 2. Core Objectives (Completed)
- **Automated Ingestion:** Extract indicators (IPs, Hashes, CVEs, ATT&CK techniques) from unstructured PDF threat reports.
- **Knowledge Graph Construction:** Build a Temporal Knowledge Graph connecting Organizations to Threat Actors.
- **AI Risk Prediction:** Use Machine Learning to predict the severity of incoming threats and mathematically decay the risk of outdated intelligence.
- **Privacy-Preserving Sharing:** Implement Attribute-Based Encryption (ABE) and key revocation to ensure only authorized sectors can decrypt shared data.
- **Adaptive Access Control:** Evaluate sharing policies dynamically based on organization trust, sector, and threat risk, with persistent audit logging.
- **Advanced UI/UX:** Provide a dark-mode, interactive dashboard with an ATT&CK Heatmap and Collaborative Filtering predictions.

---

## 3. Advanced Features (Implemented)

### 🛡️ Member 1: Ingestion, Normalization & Graph Intelligence
- **PDF Extraction Engine:** Extracts IPs, Domains, Hashes (MD5, SHA1, SHA256), CVEs, and MITRE ATT&CK IDs directly from PDFs.
- **Defang & Normalization:** Automatically cleans dirty data (e.g., converting `hxxp://198[.]51[.]100[.]77` to `http://198.51.100.77`).
- **STIX 2.1 Export:** Exports the entire SQLite database as a valid, industry-standard STIX 2.1 JSON bundle.
- **Temporal Knowledge Graph:** Visualizes relationships between Organizations and IOCs using `react-force-graph-2d`.
- **PageRank Centrality:** Mathematically ranks the most "dangerous" or influential nodes in the network.

### 🧠 Member 2: AI Prediction & Temporal Risk
- **AI Threat Prediction:** A pure-Python Machine Learning model (Weighted Naive Bayes logic) that predicts the next likely threat severity based on trust scores, source reliability, and report volume.
- **Dynamic Risk Decay:** Exponential decay formula that automatically lowers the risk score of IOCs as they become older.
- **Explainable Risk Scoring:** Breaks down the risk score into understandable points (Severity + Volume + Cross-sector impact + Recency).
- **ATT&CK Heatmap & Collaborative Filtering:** A dark-mode matrix showing tactic coverage, with an AI engine that predicts unseen techniques for an organization based on what *other* similar organizations are seeing.

### 🔒 Member 3: Privacy-Preserving Cryptography
- **Attribute-Based Encryption (PR-RABE):** Pure-Python cryptographic engine that derives keys based on organizational attributes (e.g., Finance sector). 
- **Revocation:** Allows admins to instantly revoke an organization's keys, preventing decryption of future intelligence.
- **Tamper-Proof:** Data cannot be decrypted by organizations that do not match the attribute policy.

### 🚦 Member 4: Adaptive Access Control & Auditing
- **Policy Decision Engine:** Evaluates access requests based on Organization Trust Score, Historical Violations, and Threat Risk.
- **Persistent Audit Logs:** Every access request (Granted or Denied) is permanently written to a SQLite `audit_logs` table for compliance.
- **Per-Organization Workspace:** A two-tier UI where analysts can view a global dashboard or drill down into a specific organization's isolated workspace.

---

## 4. System Architecture
The platform consists of the following major components:
- **Frontend:** React + Vite. Features advanced data grids, force-directed graphs, and a cyber-command dark-mode theme.
- **Backend API:** Flask (Python). Coordinates all modules and handles REST API requests.
- **AI & Graph Modules:** Pure Python implementations of PageRank, Naive Bayes classification, and dynamic decay math.
- **Crypto Engine:** Custom XOR/PBKDF2-based Attribute-Based Encryption simulation.
- **Database:** SQLite. Stores records, submissions, organizations, users, and persistent audit logs.

### Data Flow
1. A user uploads a PDF or submits CTI data.
2. Member 1's ingestion engine normalizes the data and saves it to the database.
3. Member 2's AI engine scans the database to predict future threats and applies decay to older IOCs.
4. Member 4's Policy Engine evaluates if a requesting organization is allowed to see the data.
5. Member 3's Crypto Engine encrypts the payload based on sector attributes.
6. The React frontend visualizes the graph, heatmap, and timelines.

---

## 5. Technologies Used

| Component | Technology |
| :--- | :--- |
| **Frontend** | React, Vite, React-Force-Graph-2D, Lucide Icons |
| **Backend** | Python, Flask, Flask-CORS |
| **Database** | SQLite 3 |
| **Threat Format** | STIX 2.1 (JSON) |
| **AI / Math** | Pure Python (Jaccard Similarity, Exponential Decay, PageRank) |
| **Cryptography** | Hashlib, OS (PBKDF2-style Key Derivation) |

---

## 6. Project Structure

```text
CTI-BTP/
├── backend/
│   ├── app.py                     # Main Flask routes and API orchestration
│   ├── database.py                # SQLite connection and schema
│   ├── pdf_cti_extractor.py       # Member 1: PDF parsing and normalization
│   ├── knowledge_graph.py         # Member 1: Graph data builder
│   ├── graph_analytics.py         # Member 1: PageRank algorithm
│   ├── ai_predictor.py            # Member 2: ML severity prediction
│   ├── temporal_engine.py         # Member 2: Dynamic Risk Decay math
│   ├── crypto_engine.py           # Member 3: Attribute-Based Encryption
│   ├── policy_engine.py           # Member 4: Access control logic
│   ├── organizations.py           # Organization CRUD
│   ├── authentication.py          # JWT Authentication
│   └── advanced_cti.py            # Blueprint for advanced routes
├── frontend/
│   ├── src/
│   │   ├── App.jsx                # Two-tier navigation & App shell
│   │   ├── DashboardOverview.jsx  # Global KPI & AI dashboard
│   │   ├── PDFIntelligence.jsx    # Member 1: PDF upload & extraction UI
│   │   ├── KnowledgeGraph.jsx     # Member 1: Force-directed graph UI
│   │   ├── TemporalIntelligence.jsx# Member 2: Risk timeline UI
│   │   ├── ATTACKNavigator.jsx    # Member 2: Heatmap & Collaborative AI
│   │   ├── AccessControl.jsx      # Member 4: Policy engine UI
│   │   ├── CryptoSharing.jsx      # Member 3: Encryption UI
│   │   └── api.js                 # Fetch wrapper and auth tokens
│   ├── package.json
│   └── vite.config.js
├── data/
│   └── cti.db                     # SQLite database
└── README.md

```

Copy this directly into your `README.md` file.

markdown
````
## ⚙️ Installation and Setup

### Prerequisites

Ensure the following tools are installed on your system:

- Python 3.10 or later
- Node.js and npm
- Git

### Step 1: Clone the Repository

```bash
git clone https://github.com/jadhav1919/CTI-BTP.git
cd CTI-BTP
````

### Step 2: Set Up the Backend

Create a Python virtual environment:

bash
```
python -m venv .venv
```

Activate the virtual environment.

Windows (PowerShell):

powershell
```
.\.venv\Scripts\Activate.ps1
```

macOS/Linux:

bash
```
source .venv/bin/activate
```

Install the required dependencies:

bash
```
pip install flask flask-cors pypdf
```

### Step 3: Set Up the Frontend

Navigate to the frontend directory:

bash
```
cd frontend
```

Install the Node.js dependencies:

bash
```
npm install
```

Return to the project root:

bash
```
cd ..
```

### Step 4: Run the Backend Server

From the project root, execute:

bash
```
python -m backend.app
```

The Flask backend will run at:

`http://127.0.0.1:5000`

### Step 5: Run the Frontend Server

Open a second terminal and navigate to the frontend directory:

bash
```
cd CTI-BTP/frontend
```

Start the Vite development server:

bash
```
npm run dev
```

The frontend will typically be available at:

`http://localhost:5173`

### Step 6: Access the Application

1. Ensure both the backend and frontend servers are running.
2. Open `http://localhost:5173` in your browser.
3. Register or log in as an organization.
4. Explore the CTI dashboard, PDF intelligence extraction, knowledge graph, AI predictions, access control, and cryptographic sharing features.

Note: If the repository contains a `requirements.txt` file, install all backend dependencies using `pip install -r requirements.txt`. Additional configuration may be required depending on your local environment.

```

```
