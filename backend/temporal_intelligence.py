"""
Temporal CTI Intelligence
Read-only analysis of CTI records and their submissions.

This first version uses explicit rules. It is not a trained
temporal graph learning model.
"""

import sqlite3
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATABASE_PATH = PROJECT_ROOT / "data" / "cti.db"

SEVERITY_LEVELS = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

# Initial configurable freshness window.
FRESHNESS_WINDOW_DAYS = 30

# Transparent initial reliability mapping.
RELIABILITY_SCORES = {
    "verified": 1.0,
    "reliable": 0.9,
    "partial": 0.6,
    "unverified": 0.3,
    "unknown": 0.3,
}


def normalize_label(value, default="unknown"):
    """Strip and lowercase a text label; fall back to default if empty."""
    text = str(value).strip().lower() if value is not None else ""
    return text or default


def parse_datetime(value):
    """Parse an ISO-like timestamp to UTC; return None if unknown or invalid."""
    if not value:
        return None

    try:
        parsed = datetime.fromisoformat(
            str(value).strip().replace("Z", "+00:00")
        )
    except (ValueError, TypeError):
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc)


def analyze_submission(submission, now, freshness_window_days=FRESHNESS_WINDOW_DAYS):
    """Assess one submission without inventing missing timestamps."""
    observed_at = parse_datetime(submission["observed_at"])
    created_at = parse_datetime(submission["created_at"])

    reliability_label = normalize_label(submission["source_reliability"])
    reliability_score = RELIABILITY_SCORES.get(
        reliability_label, RELIABILITY_SCORES["unknown"]
    )

    # --- Freshness (depends only on observation time) ---
    age_days = None
    freshness_status = "unknown"
    warnings = []

    if observed_at is None:
        warnings.append("Observation time is missing or invalid.")
    else:
        raw_age_days = (now - observed_at).total_seconds() / 86400

        if raw_age_days < 0:
            warnings.append("Observation time is in the future.")

        age_days = round(max(0.0, raw_age_days), 2)
        freshness_status = (
            "fresh" if age_days <= freshness_window_days else "stale"
        )

    # --- Reporting delay (needs both timestamps; independent of freshness) ---
    reporting_delay_hours = None
    reporting_delay_status = "unknown"

    if observed_at is not None and created_at is not None:
        reporting_delay_hours = round(
            (created_at - observed_at).total_seconds() / 3600, 2
        )
        if reporting_delay_hours >= 0:
            reporting_delay_status = "valid"
        else:
            reporting_delay_status = "submission_before_observation"
            warnings.append("Submission was created before the observation time.")

    if created_at is None:
        warnings.append("Submission creation time is missing or invalid.")

    return {
        "submission_id": submission["id"],
        "record_id": submission["cti_record_id"],
        "organization_id": submission["organization_id"],
        "source_type": submission["source_type"],
        "source_reliability": reliability_label,
        "reliability_score": reliability_score,
        "observed_at": submission["observed_at"],
        "submission_created_at": submission["created_at"],
        "submission_created_time_parsed": created_at is not None,
        "age_days": age_days,
        "reporting_delay_hours": reporting_delay_hours,
        "reporting_delay_status": reporting_delay_status,
        "freshness_status": freshness_status,
        "submitted_severity": normalize_label(submission["submitted_severity"]),
        "confidence": submission["confidence"],
        "warnings": warnings,
        # Kept for backward compatibility with the previous output format.
        "timestamp_warning": (
            "Observation time is missing or invalid."
            if observed_at is None
            else None
        ),
    }


def open_readonly(db_path):
    """Open the SQLite database strictly read-only, with a clear error if missing."""
    path = Path(db_path).resolve()

    if not path.is_file():
        raise FileNotFoundError(f"CTI database not found: {path}")

    connection = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    return connection


def analyze_temporal_intelligence(
    db_path=DATABASE_PATH,
    now=None,
    freshness_window_days=FRESHNESS_WINDOW_DAYS,
):
    """
    Return temporal evidence assessments and severity conflicts.

    Read-only: this function only executes SELECT statements.
    """
    now = now or datetime.now(timezone.utc)

    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)

    now = now.astimezone(timezone.utc)

    connection = open_readonly(db_path)

    try:
        records = connection.execute("""
            SELECT id, title, indicator_type, indicator_value,
                   severity, confidence, created_at
            FROM cti_records
            ORDER BY id
        """).fetchall()

        submissions = connection.execute("""
            SELECT id, cti_record_id, organization_id,
                   source_type, source_reliability, observed_at,
                   submitted_severity, confidence, created_at
            FROM cti_submissions
            ORDER BY cti_record_id, id
        """).fetchall()
    finally:
        connection.close()

    submissions_by_record = {}

    for submission in submissions:
        assessment = analyze_submission(submission, now, freshness_window_days)
        submissions_by_record.setdefault(
            submission["cti_record_id"], []
        ).append(assessment)

    known_record_ids = {record["id"] for record in records}
    orphan_submissions = sum(
        len(group)
        for record_id, group in submissions_by_record.items()
        if record_id not in known_record_ids
    )

    results = []
    conflicts = []

    for record in records:
        record_id = record["id"]
        evidence = submissions_by_record.get(record_id, [])

        known_severities = {
            item["submitted_severity"]
            for item in evidence
            if item["submitted_severity"] in SEVERITY_LEVELS
        }
        has_conflict = len(known_severities) > 1

        if has_conflict:
            conflicts.append({
                "record_id": record_id,
                "title": record["title"],
                "record_severity": record["severity"],
                "conflicting_submitted_severities": sorted(
                    known_severities,
                    key=SEVERITY_LEVELS.__getitem__,
                ),
                "submission_ids": [
                    item["submission_id"]
                    for item in evidence
                    if item["submitted_severity"] in known_severities
                ],
            })

        reliability_scores = [item["reliability_score"] for item in evidence]
        parsed_ages = [
            item["age_days"] for item in evidence
            if item["age_days"] is not None
        ]

        results.append({
            "record_id": record_id,
            "title": record["title"],
            "indicator_type": record["indicator_type"],
            "indicator_value": record["indicator_value"],
            "record_severity": record["severity"],
            "record_confidence": record["confidence"],
            "submissions_count": len(evidence),
            "submissions": evidence,
            "missing_observation_times": sum(
                item["freshness_status"] == "unknown" for item in evidence
            ),
            "fresh_submissions": sum(
                item["freshness_status"] == "fresh" for item in evidence
            ),
            "stale_submissions": sum(
                item["freshness_status"] == "stale" for item in evidence
            ),
            "invalid_reporting_delays": sum(
                item["reporting_delay_status"] == "submission_before_observation"
                for item in evidence
            ),
            "average_reliability_score": (
                round(sum(reliability_scores) / len(reliability_scores), 3)
                if reliability_scores else None
            ),
            "newest_observation_age_days": (
                min(parsed_ages) if parsed_ages else None
            ),
            "severity_conflict": has_conflict,
        })

    return {
        "analysis_type": "rule_based_temporal_evidence_analysis",
        "generated_at": now.isoformat(),
        "freshness_window_days": freshness_window_days,
        "records_analyzed": len(results),
        "submissions_analyzed": len(submissions),
        "orphan_submissions": orphan_submissions,
        "missing_observation_times": sum(
            item["missing_observation_times"] for item in results
        ),
        "severity_conflicts_count": len(conflicts),
        "severity_conflicts": conflicts,
        "records": results,
    }


if __name__ == "__main__":
    import json

    report = analyze_temporal_intelligence()
    print(json.dumps(report, indent=2))