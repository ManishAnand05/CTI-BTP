
from datetime import datetime, timezone

from flask import Blueprint, jsonify, request

from backend.database import get_connection
from backend.advanced_cti_processor import (
    CATEGORIES,
    INDICATOR_TYPES,
    SEVERITIES,
    CONFIDENCES,
    SECTORS,
    SOURCE_TYPES,
    RELIABILITIES,
    validate_indicator,
    normalize_cti,
)

advanced_cti_bp = Blueprint("advanced_cti", __name__)


def calculate_risk(severity, confidence, reliability, submissions):
    """Prototype risk score from 0 to 100."""

    severity_scores = {
        "low": 20,
        "medium": 40,
        "high": 70,
        "critical": 90,
        "unknown": 20,
    }

    confidence_scores = {
        "low": 40,
        "medium": 65,
        "high": 90,
        "unknown": 40,
    }

    reliability_scores = {
        "unverified": 30,
        "partial": 60,
        "verified": 90,
    }

    base = (
        severity_scores[severity] * 0.50
        + confidence_scores[confidence] * 0.30
        + reliability_scores[reliability] * 0.20
    )

    # Additional independent submissions increase corroboration.
    corroboration_bonus = min(max(submissions - 1, 0) * 5, 15)
    score = min(round(base + corroboration_bonus), 100)

    if score >= 80:
        level = "Critical"
    elif score >= 60:
        level = "High"
    elif score >= 35:
        level = "Medium"
    else:
        level = "Low"

    return score, level


@advanced_cti_bp.route("/api/cti/submit", methods=["POST"])
def submit_cti():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "error": "Send the submission as a JSON object."
        }), 400

    required_fields = [
        "organization_id",
        "category",
        "indicator_type",
        "title",
        "description",
        "severity",
        "confidence",
        "sharing_sector",
        "source_type",
        "source_reliability",
    ]

    missing = [
        field for field in required_fields
        if field not in data or data[field] is None
        or (isinstance(data[field], str) and not data[field].strip())
    ]

    if missing:
        return jsonify({
            "error": "Missing required fields.",
            "missing_fields": missing,
        }), 400

    try:
        organization_id = int(data["organization_id"])
    except (TypeError, ValueError):
        return jsonify({"error": "organization_id must be an integer."}), 400

    if organization_id < 1:
        return jsonify({"error": "Invalid organization_id."}), 400

    category = str(data["category"]).strip().lower()
    indicator_type = str(data["indicator_type"]).strip().lower()
    severity = str(data["severity"]).strip().lower()
    confidence = str(data["confidence"]).strip().lower()
    sharing_sector = str(data["sharing_sector"]).strip().title()
    source_type = str(data["source_type"]).strip().lower()
    reliability = str(data["source_reliability"]).strip().lower()

    if category not in CATEGORIES:
        return jsonify({"error": "Unsupported CTI category."}), 400

    if indicator_type not in INDICATOR_TYPES:
        return jsonify({"error": "Unsupported indicator type."}), 400

    if severity not in SEVERITIES:
        return jsonify({"error": "Unsupported severity."}), 400

    if confidence not in CONFIDENCES:
        return jsonify({"error": "Unsupported confidence."}), 400

    if sharing_sector not in SECTORS:
        return jsonify({"error": "Unsupported sharing sector."}), 400

    if source_type not in SOURCE_TYPES:
        return jsonify({"error": "Unsupported source type."}), 400

    if reliability not in RELIABILITIES:
        return jsonify({"error": "Unsupported source reliability."}), 400

    title = str(data["title"]).strip()
    description = str(data["description"]).strip()

    if len(title) > 200 or len(description) > 10000:
        return jsonify({
            "error": "Title must be at most 200 characters and description at most 10000."
        }), 400

    if not title or not description:
        return jsonify({
            "error": "Title and description cannot be empty."
        }), 400

    try:
        indicator_value = validate_indicator(
            indicator_type,
            data.get("indicator_value", ""),
        )
    except ValueError as error:
        return jsonify({"error": str(error)}), 400

    observed_at = data.get("observed_at")
    if observed_at is not None:
        if not isinstance(observed_at, str) or len(observed_at) > 50:
            return jsonify({
                "error": "observed_at must be an ISO timestamp string."
            }), 400

        try:
            datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
        except ValueError:
            return jsonify({
                "error": "Invalid observed_at timestamp."
            }), 400

    evidence = data.get("evidence", "")
    if not isinstance(evidence, str) or len(evidence) > 10000:
        return jsonify({
            "error": "Evidence must be text of at most 10000 characters."
        }), 400

    connection = get_connection()

    try:
        organization = connection.execute(
            "SELECT id, name FROM organizations WHERE id = ?",
            (organization_id,),
        ).fetchone()

        if organization is None:
            return jsonify({
                "error": "Organization not found. Register it first."
            }), 404

        # Find a duplicate indicator. Descriptive CTI without an indicator
        # is kept as a separate record.
        existing = None

        if indicator_type != "none":
            existing = connection.execute(
                """
                SELECT id, severity, confidence, risk_score
                FROM cti_records
                WHERE indicator_type = ?
                  AND indicator_value = ?
                  AND sharing_sector = ?
                ORDER BY id
                LIMIT 1
                """,
                (indicator_type, indicator_value, sharing_sector),
            ).fetchone()

        if existing:
            record_id = existing["id"]

            previous_count = connection.execute(
                """
                SELECT COUNT(*) FROM cti_submissions
                WHERE cti_record_id = ?
                """,
                (record_id,),
            ).fetchone()[0]

            # Retain the separate source report.
            connection.execute(
                """
                INSERT INTO cti_submissions (
                    cti_record_id, organization_id, source_type,
                    source_reliability, observed_at, submitted_severity,
                    confidence, evidence
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record_id,
                    organization_id,
                    source_type,
                    reliability,
                    observed_at,
                    severity,
                    confidence,
                    evidence,
                ),
            )

            # Use the strongest reported severity and confidence.
            severity_order = {
                "unknown": 0, "low": 1, "medium": 2,
                "high": 3, "critical": 4,
            }
            confidence_order = {
                "unknown": 0, "low": 1, "medium": 2, "high": 3,
            }

            final_severity = max(
                [existing["severity"], severity],
                key=lambda value: severity_order[value],
            )
            final_confidence = max(
                [existing["confidence"], confidence],
                key=lambda value: confidence_order[value],
            )

            # Conservative aggregation: use the strongest reliability
            # among submissions for this record.
            reliability_rows = connection.execute(
                """
                SELECT source_reliability
                FROM cti_submissions
                WHERE cti_record_id = ?
                """,
                (record_id,),
            ).fetchall()

            reliability_order = {
                "unverified": 0, "partial": 1, "verified": 2,
            }
            final_reliability = max(
                [row["source_reliability"] for row in reliability_rows],
                key=lambda value: reliability_order[value],
            )

            submission_count = previous_count + 1

            risk_score, risk_level = calculate_risk(
                final_severity,
                final_confidence,
                final_reliability,
                submission_count,
            )

            connection.execute(
                """
                UPDATE cti_records
                SET severity = ?, confidence = ?,
                    risk_score = ?, risk_level = ?,
                    status = 'Under Review'
                WHERE id = ?
                """,
                (
                    final_severity,
                    final_confidence,
                    risk_score,
                    risk_level,
                    record_id,
                ),
            )

            connection.commit()

            return jsonify({
                "message": "Duplicate indicator detected; submission recorded.",
                "duplicate": True,
                "record_id": record_id,
                "submission_count": submission_count,
                "risk_score": risk_score,
                "risk_level": risk_level,
            }), 200

        stix_data = normalize_cti(
            category,
            indicator_type,
            indicator_value,
            title,
            description,
            severity,
        )

        risk_score, risk_level = calculate_risk(
            severity, confidence, reliability, 1
        )

        cursor = connection.execute(
            """
            INSERT INTO cti_records (
                category, indicator_type, indicator_value, title,
                description, severity, confidence, sharing_sector,
                stix_data, risk_score, risk_level, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                category,
                indicator_type,
                indicator_value,
                title,
                description,
                severity,
                confidence,
                sharing_sector,
                stix_data,
                risk_score,
                risk_level,
                "Under Review",
            ),
        )

        record_id = cursor.lastrowid

        connection.execute(
            """
            INSERT INTO cti_submissions (
                cti_record_id, organization_id, source_type,
                source_reliability, observed_at, submitted_severity,
                confidence, evidence
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record_id,
                organization_id,
                source_type,
                reliability,
                observed_at,
                severity,
                confidence,
                evidence,
            ),
        )

        connection.commit()

        return jsonify({
            "message": "CTI submitted and normalized successfully.",
            "duplicate": False,
            "record_id": record_id,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "stix": stix_data,
        }), 201

    except Exception:
        connection.rollback()
        # Do not expose internal database or server details.
        return jsonify({
            "error": "The CTI submission could not be processed."
        }), 500

    finally:
        connection.close()


@advanced_cti_bp.route("/api/cti/advanced", methods=["GET"])
def list_advanced_cti():
    connection = get_connection()

    try:
        rows = connection.execute(
            """
            SELECT id, category, indicator_type, indicator_value,
                   title, description, severity, confidence,
                   sharing_sector, risk_score, risk_level, status,
                   created_at
            FROM cti_records
            ORDER BY id DESC
            """
        ).fetchall()

        return jsonify({"records": [dict(row) for row in rows]})

    finally:
        connection.close()


@advanced_cti_bp.route(
    "/api/cti/advanced/<int:record_id>/submissions",
    methods=["GET"],
)
def list_cti_submissions(record_id):
    connection = get_connection()

    try:
        record = connection.execute(
            "SELECT id FROM cti_records WHERE id = ?",
            (record_id,),
        ).fetchone()

        if record is None:
            return jsonify({"error": "CTI record not found."}), 404

        rows = connection.execute(
            """
            SELECT id, cti_record_id, organization_id, source_type,
                   source_reliability, observed_at, submitted_severity,
                   confidence, evidence, created_at
            FROM cti_submissions
            WHERE cti_record_id = ?
            ORDER BY id
            """,
            (record_id,),
        ).fetchall()

        return jsonify({"submissions": [dict(row) for row in rows]})

    finally:
        connection.close()
