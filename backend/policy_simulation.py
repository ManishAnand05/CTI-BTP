"""
Synthetic workload for the policy engine.

Stands in for the inputs other parts of the project do not send yet
(trust levels from the trust engine, multi-sector onboarding, TLP
labels) so the policy engine can be tested and measured on its own.
Everything runs in a temporary database; the real data/cti.db is never
touched.

    python -m backend.policy_simulation                 # metrics report
    python -m backend.policy_simulation --scenario      # slide-17 walkthrough
    python -m backend.policy_simulation --orgs 100 --records 500 --changes 300
"""

import argparse
import random
import statistics
import tempfile
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from backend import database
from backend import policy_engine as pe
from backend.prrabe_interface import MockPRRABE, get_backend, set_backend


RISK_LEVELS = ["Low", "Medium", "High", "Critical"]
STATUSES = ["Under Review", "Verified", "Disputed", "Rejected"]
SECTORS = sorted(pe.VALID_SECTORS)


@contextmanager
def synthetic_environment():
    """A throwaway database plus a fresh mock PR-RABE backend."""
    with tempfile.TemporaryDirectory() as tmp:
        data_dir = Path(tmp)
        with patch.object(database, "DATA_DIR", data_dir), \
                patch.object(database, "DB_PATH", data_dir / "cti.db"):
            database.initialize_database()
            previous_backend = get_backend()
            set_backend(MockPRRABE())
            try:
                yield
            finally:
                set_backend(previous_backend)


# --------------------------------------------------
# SYNTHETIC DATA
# --------------------------------------------------

def add_org(name, sectors, trust_level="Medium", active=True):
    """Insert an organization and onboard it with several sectors."""
    with database.get_connection() as connection:
        org_id = connection.execute(
            """
            INSERT INTO organizations (name, sector, trust_score, is_active)
            VALUES (?, ?, 50, ?)
            """,
            (name, sectors[0], int(active)),
        ).lastrowid
    pe.set_org_sectors(org_id, sectors, trigger="onboarded")
    pe.update_trust(org_id, trust_level, trigger="onboarded")
    return org_id


def add_record(owner_ids, sectors, risk_level, tlp="GREEN",
               status="Under Review"):
    """Insert a CTI record reported by one or more organizations."""
    with database.get_connection() as connection:
        record_id = connection.execute(
            """
            INSERT INTO cti_records (
                category, indicator_type, indicator_value, title,
                description, severity, confidence, sharing_sector,
                stix_data, risk_score, risk_level, status
            )
            VALUES ('malware', 'sha256', ?, 'Synthetic CTI', 'Synthetic',
                    'high', 'high', ?, '{}', 0, ?, ?)
            """,
            (f"synthetic-{random.random()}", sectors[0], risk_level, status),
        ).lastrowid
        connection.executemany(
            """
            INSERT INTO cti_submissions (
                cti_record_id, organization_id, source_type,
                source_reliability, submitted_severity, confidence
            )
            VALUES (?, ?, 'edr', 'verified', 'high', 'high')
            """,
            [(record_id, owner) for owner in owner_ids],
        )
    pe.set_record_labels(record_id, tlp=tlp, sectors=sectors, trigger="submitted")
    return record_id


def generate(rng, n_orgs, n_records):
    orgs = []
    for i in range(n_orgs):
        sectors = rng.sample(SECTORS, rng.choice([1, 1, 2, 3]))
        level = rng.choice(pe.TRUST_LEVELS)
        orgs.append(add_org(f"Org {i + 1}", sectors, level, rng.random() > 0.05))

    records = []
    for _ in range(n_records):
        owners = rng.sample(orgs, rng.choice([1, 1, 1, 2, 3]))
        sectors = (
            [pe.ALL_SECTORS] if rng.random() < 0.3
            else rng.sample(SECTORS, rng.choice([1, 2]))
        )
        records.append(add_record(
            owners, sectors,
            rng.choice(RISK_LEVELS),
            rng.choice(list(pe.TLP_SENSITIVITY)),
            rng.choices(STATUSES, weights=[5, 3, 1, 1])[0],
        ))
    return orgs, records


# --------------------------------------------------
# REFERENCE ORACLE
# --------------------------------------------------

def expected_decision(org_id, record_id):
    """
    The access rule written directly from the decision tables, without
    the engine's attribute machinery, to cross-check every decision.
    """
    org = pe.get_org_policy_state(org_id)
    record = pe.get_record_policy(record_id)
    with database.get_connection() as connection:
        active = connection.execute(
            "SELECT is_active FROM organizations WHERE id = ?", (org_id,)
        ).fetchone()["is_active"]

    if org_id in record["owners"]:
        return "ALLOW"
    if not active or record["policy"] is None:
        return "DENY"

    required = pe.REQUIRED_TRUST[record["sensitivity"]]
    if pe.TRUST_LEVELS.index(org["trust_level"]) < pe.TRUST_LEVELS.index(required):
        return "DENY"

    sector_clauses = [c for c in record["policy"] if c[0].startswith("Sector:")]
    for clause in sector_clauses:
        allowed = {attr.split(":", 1)[1] for attr in clause}
        if not allowed & set(org["sectors"]):
            return "DENY"
    return "ALLOW"


# --------------------------------------------------
# EXPERIMENT
# --------------------------------------------------

def run(n_orgs=50, n_records=200, n_changes=100, seed=7, sample=200):
    """Drive synthetic trust changes and measure enforcement cost."""
    rng = random.Random(seed)
    random.seed(seed)

    with synthetic_environment():
        orgs, records = generate(rng, n_orgs, n_records)
        backend = get_backend()

        latencies, events_per_change, rekeyed = [], [], []
        no_op_changes = 0
        rewraps_before = len(pe.list_policy_events(event_type="REWRAP", limit=100000))

        # Synthetic trust engine: each step nudges one org up or down.
        for _ in range(n_changes):
            org_id = rng.choice(orgs)
            current = pe.get_org_policy_state(org_id)["trust_level"]
            index = pe.TRUST_LEVELS.index(current)
            new_index = min(max(index + rng.choice([-1, 1]), 0), len(pe.TRUST_LEVELS) - 1)
            versions = {a: g["version"] for a, g in backend.groups.items()}

            events = pe.update_trust(org_id, pe.TRUST_LEVELS[new_index])

            if not events:
                no_op_changes += 1
                continue
            events_per_change.append(len(events))
            rekeyed.append(sum(e["members_rekeyed"] for e in events))
            latencies.append(pe.list_policy_events(organization_id=org_id, limit=1)[0]["latency_ms"])
            rotated = {
                a for a, g in backend.groups.items()
                if g["version"] != versions.get(a)
            }
            revoked = {e["attribute"] for e in events if e["event_type"] == "REVOKE"}
            assert rotated == revoked, "a group key rotated without a REVOKE"

        rewraps = len(pe.list_policy_events(event_type="REWRAP", limit=100000)) - rewraps_before

        mismatches = 0
        allowed = 0
        pairs = [(rng.choice(orgs), rng.choice(records)) for _ in range(sample)]
        for org_id, record_id in pairs:
            decision = pe.generate_advanced_access_policy(org_id, record_id)["decision"]
            allowed += decision == "ALLOW"
            mismatches += decision != expected_decision(org_id, record_id)

        sensitivities = {}
        for record_id in records:
            level = pe.get_record_policy(record_id)["sensitivity"]
            sensitivities[level] = sensitivities.get(level, 0) + 1

    return {
        "organizations": n_orgs,
        "records": n_records,
        "trust_changes": n_changes,
        "changes_with_no_level_change": no_op_changes,
        "revocation_latency_ms": _summary(latencies),
        "attribute_events_per_change": _summary(events_per_change),
        "members_rekeyed_per_change": _summary(rekeyed),
        "records_reencrypted_by_trust_changes": rewraps,
        "records_by_sensitivity": sensitivities,
        "decisions_checked": sample,
        "decisions_allowed": allowed,
        "decisions_disagreeing_with_oracle": mismatches,
    }


def _summary(values):
    if not values:
        return None
    ordered = sorted(values)
    return {
        "mean": round(statistics.mean(ordered), 3),
        "p95": ordered[min(len(ordered) - 1, int(0.95 * len(ordered)))],
        "max": ordered[-1],
    }


def scenario():
    """Slide 17: Org B's trust drops; only Org B loses access."""
    with synthetic_environment():
        owner = add_org("Owner", ["Finance"], "Medium")
        org_a = add_org("Org A", ["Finance"], "High")
        org_b = add_org("Org B", ["Finance", "Healthcare"], "High")
        org_c = add_org("Org C", ["Healthcare"], "High")
        record = add_record([owner], ["Finance"], "High", tlp="GREEN")

        lines = []
        entry = pe.get_record_policy(record)
        lines.append(f"Record {record}: {entry['sensitivity']} -> {entry['policy_text']}")
        for name, org in (("Org A", org_a), ("Org B", org_b), ("Org C", org_c)):
            result = pe.generate_advanced_access_policy(org, record)
            lines.append(f"  {name}: {result['decision']:5}  {result['reason']}")

        lines.append("Trust engine: Org B misuse detected -> High to Medium")
        for event in pe.update_trust(org_b, "Medium", trigger="misuse_detected"):
            lines.append(
                f"  {event['event_type']} {event['attribute']} "
                f"(group key v{event['group_version']}, "
                f"{event['members_rekeyed']} remaining members rekeyed)"
            )

        for name, org in (("Org A", org_a), ("Org B", org_b)):
            result = pe.generate_advanced_access_policy(org, record)
            lines.append(f"  {name}: {result['decision']:5}  {result['reason']}")
        lines.append(
            "  Records re-encrypted: "
            f"{len(pe.list_policy_events(event_type='REWRAP'))}"
        )
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("--orgs", type=int, default=50)
    parser.add_argument("--records", type=int, default=200)
    parser.add_argument("--changes", type=int, default=100)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--scenario", action="store_true")
    args = parser.parse_args()

    if args.scenario:
        print(scenario())
        return

    report = run(args.orgs, args.records, args.changes, args.seed)
    width = max(len(key) for key in report)
    for key, value in report.items():
        print(f"{key:<{width}}  {value}")


if __name__ == "__main__":
    main()
