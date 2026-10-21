"""Seed organizations, test users, and CTI records for demo.

Run from the project root:
    python -m scripts.seed_demo
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.database import get_connection, initialize_database
from werkzeug.security import generate_password_hash
import json
import uuid
from datetime import datetime, timedelta, timezone

initialize_database()
conn = get_connection()
now = datetime.now(timezone.utc)

# ── 1. Organizations ──────────────────────────────────────────────

orgs = [
    ("Alpha Bank", "Finance", 50),
    ("City Hospital", "Healthcare", 50),
    ("Delta Insurance", "Finance", 50),
]

org_ids = {}
for name, sector, trust in orgs:
    existing = conn.execute("SELECT id FROM organizations WHERE name = ?", (name,)).fetchone()
    if existing:
        org_ids[name] = existing["id"]
        print(f"  Org '{name}' already exists (id={existing['id']})")
    else:
        cursor = conn.execute(
            "INSERT INTO organizations (name, sector, trust_score) VALUES (?, ?, ?)",
            (name, sector, trust),
        )
        org_ids[name] = cursor.lastrowid
        print(f"  Created org: {name} (id={org_ids[name]})")

conn.commit()

# ── 2. Test users ─────────────────────────────────────────────────

users = [
    ("Alice Morgan", "alice@alphabank.com", "alice123", org_ids["Alpha Bank"], "analyst"),
    ("Bob Chen", "bob@cityhospital.com", "bob123", org_ids["City Hospital"], "analyst"),
    ("Carol Davis", "carol@deltainsurance.com", "carol123", org_ids["Delta Insurance"], "analyst"),
    ("Admin", "admin@alphabank.com", "admin123", org_ids["Alpha Bank"], "admin"),
    ("Eve Taylor", "eve@cityhospital.com", "eve123", org_ids["City Hospital"], "analyst"),
]

for name, email, pw, oid, role in users:
    existing = conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
    if existing:
        print(f"  User {email} already exists (id={existing['id']})")
    else:
        pw_hash = generate_password_hash(pw)
        conn.execute(
            "INSERT INTO users (name, email, password_hash, organization_id, role, is_active) "
            "VALUES (?, ?, ?, ?, ?, 1)",
            (name, email, pw_hash, oid, role),
        )
        print(f"  Created user: {email} (org_id={oid})")

conn.commit()

# ── 3. CTI records ────────────────────────────────────────────────

conn.execute("PRAGMA foreign_keys = OFF")
for table in ("cti_submissions", "cti_records"):
    try:
        conn.execute(f"DELETE FROM {table}")
    except Exception:
        pass
try:
    conn.execute("DELETE FROM policy_record_state")
    conn.execute("DELETE FROM policy_record_labels")
except Exception:
    pass
conn.execute("PRAGMA foreign_keys = ON")


def stix_bundle(objects):
    return json.dumps({"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects})


def mk_indicator(name, desc, pattern, labels):
    return {
        "type": "indicator", "spec_version": "2.1", "id": f"indicator--{uuid.uuid4()}",
        "created": now.isoformat() + "Z", "modified": now.isoformat() + "Z",
        "name": name, "description": desc,
        "pattern": pattern, "pattern_type": "stix", "valid_from": now.isoformat() + "Z",
        "labels": labels,
    }


def mk_malware(name, desc, types):
    return {
        "type": "malware", "spec_version": "2.1", "id": f"malware--{uuid.uuid4()}",
        "created": now.isoformat() + "Z", "modified": now.isoformat() + "Z",
        "name": name, "description": desc, "malware_types": types, "is_family": True,
    }


def mk_attack(name, desc):
    return {
        "type": "attack-pattern", "spec_version": "2.1", "id": f"attack-pattern--{uuid.uuid4()}",
        "created": now.isoformat() + "Z", "modified": now.isoformat() + "Z",
        "name": name, "description": desc,
    }


def mk_identity(name, desc, sectors):
    return {
        "type": "identity", "spec_version": "2.1", "id": f"identity--{uuid.uuid4()}",
        "created": now.isoformat() + "Z", "modified": now.isoformat() + "Z",
        "name": name, "description": desc, "identity_class": "class", "sectors": sectors,
    }


def mk_observed(first_days_ago, count):
    return {
        "type": "observed-data", "spec_version": "2.1", "id": f"observed-data--{uuid.uuid4()}",
        "created": now.isoformat() + "Z", "modified": now.isoformat() + "Z",
        "first_observed": (now - timedelta(days=first_days_ago)).isoformat() + "Z",
        "last_observed": now.isoformat() + "Z",
        "number_observed": count,
    }


records = [
    {
        "title": "Emotet Banking Trojan Campaign",
        "category": "malware",
        "indicator_type": "ipv4-addr",
        "indicator_value": "203.0.113.45",
        "description": "Emotet variant targeting financial institutions via phishing emails with weaponized Excel macros. Exfiltrates banking credentials and installs TrickBot as secondary payload.",
        "severity": "critical",
        "confidence": "high",
        "sharing_sector": "Finance",
        "risk_score": 95,
        "risk_level": "Critical",
        "stix_data": stix_bundle([
            mk_indicator("Emotet C2 Server", "Command and control server for Emotet banking trojan variant",
                         "[ipv4-addr:value = '203.0.113.45']", ["malware", "banking-trojan"]),
            mk_malware("Emotet", "Banking trojan that steals financial credentials. Uses modular architecture with loader, credential harvester, and lateral movement modules.", ["trojan", "credential-stealer"]),
            mk_attack("Spearphishing Attachment (T1566.001)", "Weaponized Excel documents with VBA macros distributed via targeted phishing campaigns to banking employees."),
            mk_observed(5, 347),
        ]),
    },
    {
        "title": "Ransomware Attack on Hospital Network",
        "category": "ransomware",
        "indicator_type": "domain-name",
        "indicator_value": "evil-update.health-portal.xyz",
        "description": "LockBit 3.0 ransomware deployed via compromised healthcare software update mechanism. Encrypted patient records and demanded 50 BTC ransom. Targeted DICOM imaging servers and EHR databases.",
        "severity": "critical",
        "confidence": "high",
        "sharing_sector": "Healthcare",
        "risk_score": 98,
        "risk_level": "Critical",
        "stix_data": stix_bundle([
            mk_indicator("LockBit C2 Domain", "Malicious domain impersonating healthcare software update portal",
                         "[domain-name:value = 'evil-update.health-portal.xyz']", ["ransomware", "healthcare-targeted"]),
            mk_malware("LockBit 3.0", "Ransomware-as-a-service targeting healthcare infrastructure. Encrypts DICOM imaging files and EHR databases. Uses double extortion -- threatens to publish patient data.", ["ransomware"]),
            mk_identity("Healthcare Sector Victims", "14 hospitals and 3 medical imaging centers affected across the region.", ["healthcare"]),
            mk_observed(12, 17),
        ]),
    },
    {
        "title": "Supply Chain Compromise -- Insurance Platform",
        "category": "intrusion",
        "indicator_type": "file",
        "indicator_value": "sha256:a1b2c3d4e5f6789012345678abcdef01",
        "description": "Backdoored npm package in insurance claims processing platform. Exfiltrates policyholder PII including SSN, health records, and financial data to attacker-controlled S3 bucket.",
        "severity": "high",
        "confidence": "medium",
        "sharing_sector": "Finance",
        "risk_score": 88,
        "risk_level": "High",
        "stix_data": stix_bundle([
            mk_indicator("Malicious Package Hash", "SHA256 hash of backdoored insurance-claims-sdk npm package v3.2.1",
                         "[file:hashes.'SHA-256' = 'a1b2c3d4e5f6789012345678abcdef01']", ["supply-chain", "backdoor"]),
            mk_attack("Supply Chain Compromise (T1195.002)", "Compromised npm registry package used by insurance claim processing systems."),
            mk_observed(30, 8500),
        ]),
    },
    {
        "title": "Phishing Campaign Targeting Bank Employees",
        "category": "phishing",
        "indicator_type": "url",
        "indicator_value": "https://secure-banking-login.attacker.com/verify",
        "description": "Credential harvesting campaign targeting SWIFT operator accounts at regional banks. Uses cloned internal banking portal with valid SSL certificate.",
        "severity": "high",
        "confidence": "high",
        "sharing_sector": "Finance",
        "risk_score": 82,
        "risk_level": "High",
        "stix_data": stix_bundle([
            mk_indicator("Phishing URL", "Cloned banking portal used for SWIFT operator credential harvesting",
                         "[url:value = 'https://secure-banking-login.attacker.com/verify']", ["phishing", "credential-harvesting"]),
            mk_attack("Phishing for Information (T1598)", "Targeted spearphishing campaign against SWIFT operators at 12 regional banks. Emails impersonate internal IT security team requesting MFA re-enrollment."),
            mk_observed(3, 156),
        ]),
    },
    {
        "title": "Medical Device IoT Botnet",
        "category": "malware",
        "indicator_type": "ipv4-addr",
        "indicator_value": "198.51.100.200",
        "description": "Mirai variant targeting unpatched infusion pumps and patient monitors. Compromised devices used for DDoS and as pivot points into hospital networks. 230+ devices affected.",
        "severity": "medium",
        "confidence": "medium",
        "sharing_sector": "Healthcare",
        "risk_score": 65,
        "risk_level": "Medium",
        "stix_data": stix_bundle([
            mk_indicator("IoT Botnet C2", "Command and control for Mirai variant targeting medical IoT devices",
                         "[ipv4-addr:value = '198.51.100.200']", ["botnet", "iot", "medical-devices"]),
            mk_malware("Mirai-MedIoT", "Medical IoT variant of Mirai botnet. Targets infusion pumps (Baxter/BD), patient monitors, and PACS servers via default credentials and CVE-2024-3400.", ["botnet", "remote-access-trojan"]),
            mk_observed(20, 230),
        ]),
    },
    {
        "title": "Insider Threat -- Data Exfiltration",
        "category": "data-breach",
        "indicator_type": "email-addr",
        "indicator_value": "exfil-drop@protonmail.com",
        "description": "Disgruntled employee at insurance firm exfiltrating actuarial models and customer PII via encrypted email. 50,000+ policyholder records compromised over 3-month period.",
        "severity": "low",
        "confidence": "low",
        "sharing_sector": "Finance",
        "risk_score": 40,
        "risk_level": "Low",
        "stix_data": stix_bundle([
            mk_indicator("Exfiltration Drop Email", "Encrypted email address used for data exfiltration of actuarial data",
                         "[email-addr:value = 'exfil-drop@protonmail.com']", ["insider-threat", "data-exfiltration"]),
            mk_attack("Exfiltration Over Web Service (T1567)", "Data exfiltrated via encrypted email to external mailbox. 50,000+ policyholder records sent over 3 months in password-protected ZIP attachments."),
        ]),
    },
]

record_ids = []
for i, r in enumerate(records):
    cursor = conn.execute("""
        INSERT INTO cti_records (category, indicator_type, indicator_value, title, description,
            severity, confidence, sharing_sector, stix_data, risk_score, risk_level, status, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Under Review', ?)
    """, (
        r["category"], r["indicator_type"], r["indicator_value"], r["title"], r["description"],
        r["severity"], r["confidence"], r["sharing_sector"], r["stix_data"],
        r["risk_score"], r["risk_level"], (now - timedelta(hours=i * 6)).isoformat(),
    ))
    record_ids.append(cursor.lastrowid)
    print(f"  Created CTI: {r['title']} [{r['sharing_sector']}/{r['severity']}]")

conn.commit()

# ── 4. Submissions to boost Alpha Bank trust to 82 ───────────────

alpha_id = org_ids["Alpha Bank"]
for j, rid in enumerate(record_ids[:5]):
    conn.execute("""
        INSERT INTO cti_submissions
            (cti_record_id, organization_id, source_type, source_reliability,
             observed_at, submitted_severity, confidence, evidence, created_at)
        VALUES (?, ?, 'internal', 'high', ?, 'high', 'high', 'Automated feed', ?)
    """, (
        rid, alpha_id,
        (now - timedelta(hours=j * 3)).isoformat(),
        (now - timedelta(hours=j * 3)).isoformat(),
    ))

conn.execute(
    "UPDATE organizations SET trust_score = 82 WHERE id = ?",
    (alpha_id,),
)
conn.commit()

# ── 5. Seed incentive wallets ─────────────────────────────────────

for name, oid in org_ids.items():
    existing = conn.execute(
        "SELECT id FROM incentive_wallet WHERE organization_id = ?", (oid,)
    ).fetchone()
    if existing:
        print(f"  Wallet for {name} already exists")
        continue

    if name == "Alpha Bank":
        balance, earned = 65.0, 65.0
    elif name == "City Hospital":
        balance, earned = 20.0, 20.0
    else:
        balance, earned = 10.0, 10.0

    conn.execute(
        "INSERT INTO incentive_wallet (organization_id, balance, lifetime_earned, lifetime_spent) "
        "VALUES (?, ?, ?, 0)",
        (oid, balance, earned),
    )
    print(f"  Wallet for {name}: ${balance}")

conn.commit()

# Seed some transactions for Alpha Bank
alpha_wallet = conn.execute(
    "SELECT id FROM incentive_transactions WHERE organization_id = ?",
    (alpha_id,),
).fetchone()
if not alpha_wallet:
    txns = [
        (alpha_id, 10.0, "shared_cti", "1", 10.0),
        (alpha_id, 5.0, "high_confidence_bonus", "1", 15.0),
        (alpha_id, 10.0, "shared_cti", "2", 25.0),
        (alpha_id, 10.0, "shared_cti", "3", 35.0),
        (alpha_id, 5.0, "high_confidence_bonus", "3", 40.0),
        (alpha_id, 3.0, "cross_sector_bonus", "3", 43.0),
        (alpha_id, 10.0, "shared_cti", "4", 53.0),
        (alpha_id, 10.0, "shared_cti", "5", 63.0),
        (alpha_id, 2.0, "high_confidence_bonus", "5", 65.0),
    ]
    for org, amt, reason, ref, bal in txns:
        conn.execute(
            "INSERT INTO incentive_transactions "
            "(organization_id, amount, reason, reference_id, balance_after) "
            "VALUES (?, ?, ?, ?, ?)",
            (org, amt, reason, ref, bal),
        )
    print(f"  Seeded {len(txns)} wallet transactions for Alpha Bank")

conn.commit()
conn.close()

print("\nSeed complete!")
print("  3 organizations  (Alpha Bank trust=82, others trust=50)")
print("  5 users           (alice, bob, carol, admin, eve)")
print("  6 CTI records     (with STIX 2.1 bundles)")
print("  5 submissions     (Alpha Bank contribution history)")
print("  3 wallets         (Alpha=$65, City=$20, Delta=$10)")
