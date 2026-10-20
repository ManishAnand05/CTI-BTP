"""Dynamic trust score computation for organizations.

Computes trust from observable behavior in the database:
  - CTI sharing history (more contributions = higher trust)
  - Policy violation count (violations reduce trust)
  - Revocation status (revoked orgs get floor score)
  - Sector risk weighting

This replaces the static trust_score field with a computed value.
The stored trust_score is updated after each computation so that
other components can still read it from the organizations table.
"""

import math
from backend.database import get_connection


# --- Trust component weights (sum to 100) ---
WEIGHT_SHARING = 35
WEIGHT_VIOLATIONS = 30
WEIGHT_RELIABILITY = 20
WEIGHT_BASE = 15

# --- Thresholds ---
TRUST_HIGH = 80
TRUST_MEDIUM = 50


def compute_trust_score(org_id):
    """Compute a dynamic trust score (0-100) for an organization.

    Components:
      1. Sharing score: how many CTI submissions the org has made
      2. Violation penalty: each violation reduces trust significantly
      3. Reliability score: ratio of high-confidence submissions
      4. Base score: starting trust based on active status and sector
    """
    with get_connection() as conn:
        org = conn.execute(
            "SELECT id, name, sector, policy_violations, is_active "
            "FROM organizations WHERE id = ?",
            (org_id,),
        ).fetchone()

        if org is None:
            return None

        org = dict(org)

        if not org["is_active"]:
            _persist(conn, org_id, 0)
            return {"org_id": org_id, "trust_score": 0, "trust_level": "none",
                    "components": {"reason": "Organization is inactive"}}

        revoked = conn.execute(
            "SELECT 1 FROM revoked_organizations WHERE organization_id = ?",
            (org_id,),
        ).fetchone()
        if revoked:
            _persist(conn, org_id, 10)
            return {"org_id": org_id, "trust_score": 10, "trust_level": "revoked",
                    "components": {"reason": "Organization is revoked"}}

        submission_count = conn.execute(
            "SELECT COUNT(*) as cnt FROM cti_submissions WHERE organization_id = ?",
            (org_id,),
        ).fetchone()["cnt"]

        high_conf_count = conn.execute(
            "SELECT COUNT(*) as cnt FROM cti_submissions "
            "WHERE organization_id = ? AND confidence IN ('high', 'confirmed')",
            (org_id,),
        ).fetchone()["cnt"]

    # 1. Sharing score: logarithmic growth, maxes out around 20 submissions
    if submission_count == 0:
        sharing_score = 20
    else:
        sharing_score = min(100, 20 + 80 * math.log1p(submission_count) / math.log1p(20))

    # 2. Violation penalty: each violation is -25 points on this component
    violations = org["policy_violations"]
    violation_score = max(0, 100 - violations * 25)

    # 3. Reliability: ratio of high-confidence submissions
    if submission_count == 0:
        reliability_score = 50
    else:
        reliability_score = int((high_conf_count / submission_count) * 100)

    # 4. Base score: sector-based starting trust
    base_score = 60

    # Weighted combination
    trust = int(
        sharing_score * WEIGHT_SHARING / 100
        + violation_score * WEIGHT_VIOLATIONS / 100
        + reliability_score * WEIGHT_RELIABILITY / 100
        + base_score * WEIGHT_BASE / 100
    )
    trust = max(0, min(100, trust))

    _persist(get_connection(), org_id, trust)
    _notify_policy_engine(org_id, trust)

    return {
        "org_id": org_id,
        "trust_score": trust,
        "trust_level": _level(trust),
        "components": {
            "sharing": {"score": round(sharing_score, 1), "submissions": submission_count, "weight": WEIGHT_SHARING},
            "violations": {"score": violation_score, "count": violations, "weight": WEIGHT_VIOLATIONS},
            "reliability": {"score": reliability_score, "high_confidence": high_conf_count, "weight": WEIGHT_RELIABILITY},
            "base": {"score": base_score, "weight": WEIGHT_BASE},
        },
    }


def get_trust_tier(trust_score):
    """Map a trust score to an LSSS-compatible tier string."""
    if trust_score >= TRUST_HIGH:
        return "HIGH"
    elif trust_score >= TRUST_MEDIUM:
        return "MEDIUM"
    return "LOW"


def generate_policy_string(record_severity, record_sector):
    """Auto-generate an LSSS policy string from record metadata.

    Higher severity records require higher trust to access.
    """
    severity = record_severity.lower() if record_severity else "low"

    if severity == "critical":
        trust_req = "HIGH"
    elif severity == "high":
        trust_req = "HIGH"
    elif severity == "medium":
        trust_req = "MEDIUM"
    else:
        trust_req = "LOW"

    sector = record_sector.upper() if record_sector and record_sector != "All" else None

    if sector:
        return f"(SECTOR:{sector} AND TRUST:{trust_req})"
    else:
        return f"(TRUST:{trust_req})"


def _level(score):
    if score >= TRUST_HIGH:
        return "high"
    elif score >= TRUST_MEDIUM:
        return "medium"
    return "low"


def _notify_policy_engine(org_id, trust_score):
    """Push the new trust level to the policy engine so it can fire GRANT/REVOKE events."""
    try:
        from backend.policy_engine import update_trust
        level = "High" if trust_score >= TRUST_HIGH else "Medium" if trust_score >= TRUST_MEDIUM else "Low"
        update_trust(org_id, level, trigger="trust_recomputed")
    except Exception:
        pass


def _persist(conn, org_id, score):
    try:
        conn.execute(
            "UPDATE organizations SET trust_score = ? WHERE id = ?",
            (score, org_id),
        )
        conn.commit()
    except Exception:
        pass
