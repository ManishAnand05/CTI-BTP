from backend.database import get_connection
from backend.risk_analysis import (
    calculate_risk,
    calculate_advanced_risk,
)


def generate_access_policy(organization_id, indicator_id):
    """Evaluate access to a legacy CTI indicator."""

    with get_connection() as connection:
        organization = connection.execute(
            """
            SELECT id, name, sector, trust_score,
                   policy_violations, is_active
            FROM organizations
            WHERE id = ?
            """,
            (organization_id,),
        ).fetchone()

        if organization is None:
            return {
                "decision": "DENY",
                "reason": "Organization not found",
            }

        indicator = connection.execute(
            """
            SELECT id, ip_address, description, severity, sharing_sector
            FROM indicators
            WHERE id = ?
            """,
            (indicator_id,),
        ).fetchone()

        if indicator is None:
            return {
                "decision": "DENY",
                "reason": "CTI indicator not found",
            }

    organization = dict(organization)
    indicator = dict(indicator)

    risk_results = calculate_risk()

    risk_entry = next(
        (
            item
            for item in risk_results
            if item["indicator_id"] == indicator_id
        ),
        None,
    )

    if risk_entry is None:
        return {
            "decision": "DENY",
            "reason": "Risk assessment not available",
        }

    return _evaluate_access(
        organization=organization,
        record_id=indicator_id,
        record_type="legacy_indicator",
        indicator_sector=indicator.get("sharing_sector") or "All",
        risk_score=risk_entry["risk_score"],
        risk_level=risk_entry["risk_level"],
    )


def generate_advanced_access_policy(organization_id, record_id):
    """Evaluate access to an advanced CTI record."""

    with get_connection() as connection:
        organization = connection.execute(
            """
            SELECT id, name, sector, trust_score,
                   policy_violations, is_active
            FROM organizations
            WHERE id = ?
            """,
            (organization_id,),
        ).fetchone()

        if organization is None:
            return {
                "decision": "DENY",
                "reason": "Organization not found",
            }

        record = connection.execute(
            """
            SELECT id, title, category, indicator_type,
                   indicator_value, severity, sharing_sector, status
            FROM cti_records
            WHERE id = ?
            """,
            (record_id,),
        ).fetchone()

        if record is None:
            return {
                "decision": "DENY",
                "reason": "Advanced CTI record not found",
            }

    organization = dict(organization)
    record = dict(record)

    risk_results = calculate_advanced_risk()

    risk_entry = next(
        (
            item
            for item in risk_results
            if item["record_id"] == record_id
        ),
        None,
    )

    if risk_entry is None:
        return {
            "decision": "DENY",
            "reason": "Risk assessment not available",
        }

    result = _evaluate_access(
        organization=organization,
        record_id=record_id,
        record_type="advanced_cti",
        indicator_sector=record.get("sharing_sector") or "All",
        risk_score=risk_entry["risk_score"],
        risk_level=risk_entry["risk_level"],
    )

    result["record_id"] = record_id
    result["title"] = record["title"]
    result["category"] = record["category"]
    result["status"] = record["status"]

    return result


def _evaluate_access(
    organization,
    record_id,
    record_type,
    indicator_sector,
    risk_score,
    risk_level,
):
    """Apply the risk-adaptive CTI access policy."""

    organization_id = organization["id"]
    organization_sector = organization["sector"]
    trust_score = organization["trust_score"]
    policy_violations = organization["policy_violations"]
    is_active = bool(organization["is_active"])

    response = {
        "organization_id": organization_id,
        "indicator_id": record_id,
        "record_type": record_type,
        "trust_score": trust_score,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "sharing_sector": indicator_sector,
        "organization_active": is_active,
    }

    # Rule 1: Validate the trust score.
    if not isinstance(trust_score, (int, float)):
        return _deny(response, "Invalid organization trust score")

    if not 0 <= trust_score <= 100:
        return _deny(response, "Invalid organization trust score")

    # Rule 2: Inactive organizations cannot access CTI.
    if not is_active:
        return _deny(response, "Organization is inactive")

    # Rule 3: Check sector permissions.
    if (
        indicator_sector != "All"
        and indicator_sector != organization_sector
    ):
        return _deny(response, "Sector mismatch")

    # Rule 4: Deny organizations with policy violations.
    if policy_violations > 0:
        return _deny(
            response,
            "Organization has policy violations",
        )

    # Rule 5: Determine allowed risk levels using trust.
    if trust_score >= 80:
        allowed_risk_levels = {
            "low", "medium", "high", "critical"
        }
    elif trust_score >= 50:
        allowed_risk_levels = {"low", "medium"}
    else:
        allowed_risk_levels = {"low"}

    normalized_risk_level = str(risk_level).lower()

    # Rule 6: Validate the risk assessment.
    if normalized_risk_level not in {
        "low", "medium", "high", "critical"
    }:
        return _deny(response, "Invalid risk assessment")

    if not isinstance(risk_score, (int, float)):
        return _deny(response, "Invalid risk assessment")

    if not 0 <= risk_score <= 100:
        return _deny(response, "Invalid risk assessment")

    # Rule 7: Enforce trust-based risk permissions.
    if normalized_risk_level not in allowed_risk_levels:
        return _deny(
            response,
            "Risk level exceeds organization's trust permissions",
        )

    response["decision"] = "ALLOW"
    response["reason"] = (
        "Organization is active; sector, policy violation, "
        "trust, and risk checks passed"
    )

    return response


def _deny(response, reason):
    """Return a consistent denial response."""

    response["decision"] = "DENY"
    response["reason"] = reason
    return response