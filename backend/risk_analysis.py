from backend.database import get_connection
from backend.correlation import correlate_indicators


# Base risk scores based on severity.
SEVERITY_SCORES = {
    "low": 10,
    "medium": 30,
    "high": 60,
    "critical": 80,
}

# Additional risk for correlated CTI records.
CORRELATION_BONUS = 10


def get_risk_level(risk_score):
    """Convert a numerical risk score into a risk level."""

    if risk_score >= 80:
        return "Critical"
    elif risk_score >= 60:
        return "High"
    elif risk_score >= 30:
        return "Medium"

    return "Low"


def calculate_risk():
    """
    Calculate risk for legacy indicators.

    Preserves the existing output format expected by policy_engine.py.
    """

    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT id, ip_address, description, severity
            FROM indicators
            ORDER BY id
            """
        ).fetchall()

    indicators = [dict(row) for row in rows]

    # Get correlations across legacy and advanced CTI records.
    correlations = correlate_indicators()

    # Use record type as well as ID because IDs may overlap
    # between the two database tables.
    correlated_ids = set()

    for item in correlations:
        if item.get("record_1_type") == "legacy_indicator":
            correlated_ids.add(item["indicator_1"])

        if item.get("record_2_type") == "legacy_indicator":
            correlated_ids.add(item["indicator_2"])

    results = []

    for indicator in indicators:
        severity = (indicator.get("severity") or "low").lower()

        base_score = SEVERITY_SCORES.get(severity, 10)

        correlation_bonus = (
            CORRELATION_BONUS
            if indicator["id"] in correlated_ids
            else 0
        )

        risk_score = min(100, base_score + correlation_bonus)
        risk_level = get_risk_level(risk_score)

        results.append({
            "indicator_id": indicator["id"],
            "ip_address": indicator["ip_address"],
            "severity": severity,
            "base_score": base_score,
            "correlation_bonus": correlation_bonus,
            "risk_score": risk_score,
            "risk_level": risk_level,
        })

    return results


def calculate_advanced_risk():
    """Calculate risk for advanced CTI records."""

    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT id, title, category, indicator_type,
                   indicator_value, severity, sharing_sector,
                   risk_score, risk_level, status
            FROM cti_records
            ORDER BY id
            """
        ).fetchall()

    records = [dict(row) for row in rows]

    correlations = correlate_indicators()
    correlated_ids = set()

    for item in correlations:
        if item.get("record_1_type") == "advanced_cti":
            correlated_ids.add(item["indicator_1"])

        if item.get("record_2_type") == "advanced_cti":
            correlated_ids.add(item["indicator_2"])

    results = []

    for record in records:
        severity = (record.get("severity") or "low").lower()

        base_score = SEVERITY_SCORES.get(severity, 10)

        correlation_bonus = (
            CORRELATION_BONUS
            if record["id"] in correlated_ids
            else 0
        )

        risk_score = min(100, base_score + correlation_bonus)
        risk_level = get_risk_level(risk_score)

        results.append({
            "record_id": record["id"],
            "record_type": "advanced_cti",
            "title": record["title"],
            "category": record["category"],
            "indicator_type": record["indicator_type"],
            "indicator_value": record["indicator_value"],
            "severity": severity,
            "base_score": base_score,
            "correlation_bonus": correlation_bonus,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "sharing_sector": record["sharing_sector"],
            "status": record["status"],
        })

    return results