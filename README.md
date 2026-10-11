# Cyber Threat Intelligence (CTI) Sharing Platform

## 1. Project Overview

The **Cyber Threat Intelligence (CTI) Sharing Platform** is a web-based application designed to help organizations process, analyze, correlate, and share cyber threat intelligence securely.

Different organizations encounter different cyber threats. Sharing relevant threat intelligence can help them identify related attacks, understand potential risks, and make better security decisions.

This project focuses on processing threat intelligence, identifying relationships between threat records, analyzing risk levels, and applying policy-based access control.

## 2. Objectives

- Process and manage Cyber Threat Intelligence (CTI) records.
- Represent threat intelligence using the STIX 2.x data format.
- Identify relationships between related threat records.
- Analyze potential threat risks.
- Apply policy-based access control to CTI resources.
- Provide a web interface for interacting with the platform.
- Establish a foundation for secure cross-organizational CTI sharing.

## 3. Key Features

### 3.1 Threat Intelligence Processing

Accepts and processes CTI records to extract relevant threat information for further analysis.

### 3.2 CTI Correlation

Analyzes threat intelligence records to identify potential relationships between indicators and other threat information.

### 3.3 Risk Analysis

Evaluates available threat information using the implemented risk-analysis logic to help assess potential security risks.

### 3.4 Policy-Based Access Control

Uses access-control policies to determine whether a user or organization can access protected CTI resources.

### 3.5 Authentication and Authorization

Provides user authentication and protected API endpoints. Authorization checks help restrict access to protected resources.

### 3.6 Web Dashboard

Provides a frontend interface for interacting with the CTI platform and its available functionality.

## 4. System Architecture

The platform consists of the following major components:

1. **Frontend:** Provides the user interface using React.
2. **Backend API:** Uses Flask to handle requests and coordinate application functionality.
3. **CTI Processing Module:** Processes incoming threat intelligence.
4. **Correlation Module:** Identifies relationships between threat records.
5. **Risk Analysis Module:** Evaluates threat information using risk-analysis logic.
6. **Policy Engine:** Applies access-control rules.
7. **Database:** Uses SQLite for local data persistence.

### Data Flow

1. A user interacts with the web application.
2. The frontend sends requests to the Flask backend.
3. The backend processes the submitted information.
4. CTI processing, correlation, and risk analysis are performed as required.
5. Access-control policies are applied to protected resources.
6. The backend returns the appropriate response to the frontend.

## 5. Technologies Used

| Component | Technology |
|---|---|
| Frontend | React |
| Frontend tooling | Vite |
| Backend | Python, Flask |
| Database | SQLite |
| API communication | HTTP/REST |
| Threat intelligence format | STIX 2.x |
| Testing | Python test scripts |
| Version control | Git and GitHub |

## 6. Project Structure

```text
CTI-BTP/
├── backend/
│   ├── app.py
│   ├── authentication.py
│   ├── advanced_cti.py
│   ├── advanced_cti_processor.py
│   ├── correlation.py
│   ├── cti_processor.py
│   ├── database.py
│   ├── organizations.py
│   ├── policy_engine.py
│   └── risk_analysis.py
├── frontend/
│   ├── public/
│   ├── src/
│   │   ├── App.jsx
│   │   ├── CTISubmissionForm.jsx
│   │   ├── LandingPage.jsx
│   │   └── api.js
│   ├── package.json
│   └── vite.config.js
├── test_auth.py
├── test_authorization.py
├── test_authorization_valid.py
├── test_cti.py
├── test_role_decorator.py
├── .gitignore
└── README.md
```

## 7. Prerequisites

Install the following software before running the project:

- Python 3.12 or a compatible Python version
- Node.js and npm
- Git
- Visual Studio Code (recommended)

## 8. Installation and Setup

### Step 1: Clone the repository

```bash
git clone https://github.com/jadhav1919/CTI-BTP.git
cd CTI-BTP
```

### Step 2: Create a Python virtual environment

```bash
python -m venv .venv
```

Activate it on Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

### Step 3: Install backend dependencies

Install the Python dependencies required by the project. If a `requirements.txt` file is available, run:

```bash
pip install -r requirements.txt
```

If that file is not present, install the dependencies listed or imported by the backend code.

### Step 4: Install frontend dependencies

Open a terminal in the frontend directory:

```bash
cd frontend
npm install
```

### Step 5: Start the backend

From the project root, activate the virtual environment and run:

```bash
python -m backend.app
```

The backend is expected to run at:

```text
http://127.0.0.1:5000
```

### Step 6: Start the frontend

Open a second terminal:

```bash
cd frontend
npm run dev
```

Open the local URL printed by Vite, normally:

```text
http://localhost:5173
```

## 9. Testing

The repository includes Python test scripts for authentication, authorization, CTI processing, and role-based access-control behavior.

Run the relevant tests from the project root. For example:

```bash
python -m pytest
```

This command requires `pytest` to be installed. Review the test results to identify any failing tests.

## 10. Current Implementation Scope

The current project focuses on the initial implementation of:

- Threat intelligence processing
- CTI correlation
- Risk analysis
- Authentication and authorization
- Policy-based access control
- Frontend and backend integration

The exact behavior and completeness of each feature depend on the current implementation and its tests.

## 11. Planned Enhancements

The following capabilities are potential future extensions of the platform:

- Registered Policy-Revocable Attribute-Based Encryption (PR-RABE) integration
- Fine-grained cryptographic access control for shared CTI
- Revocation-aware access to previously shared threat intelligence
- Re-encryption or key-update mechanisms where required
- Audit logging for cross-organizational CTI sharing
- Integration with additional CTI sources and STIX-compatible workflows
- Expanded automated testing and deployment support

These items should be considered planned work until their implementations are completed and validated.

## 12. Security Considerations

- Do not commit API keys, passwords, access tokens, or environment files containing secrets.
- Use authentication and authorization checks for protected API endpoints.
- Validate incoming CTI data before processing it.
- Use a production-grade database and secure deployment configuration before production use.
- Test access-control behavior before sharing sensitive threat intelligence.

## 13. Project Repository

GitHub: https://github.com/jadhav1919/CTI-BTP

## 14. License

No license has been specified yet. Add a suitable license before permitting others to reuse or redistribute the project.

---

**Project:** Cyber Threat Intelligence Sharing Platform  
**Domain:** Cybersecurity  
**Focus:** CTI processing, correlation, risk analysis, and policy-based access control
