from backend.database import get_connection


def predict_threat_severity():
    """Weighted heuristic that estimates the prevailing threat severity
    from historical CTI submissions.

    Not a trained ML model. Computes a weighted average across four
    observable features (org trust, source reliability, analyst
    confidence, report volume) and maps the result to a severity band.
    """
    with get_connection() as conn:
        rows = conn.execute("""
            SELECT
                rec.severity,
                rec.confidence,
                sub.source_reliability,
                org.trust_score,
                COUNT(sub.id) AS vol
            FROM cti_records rec
            JOIN cti_submissions sub ON rec.id = sub.cti_record_id
            JOIN organizations org ON sub.organization_id = org.id
            GROUP BY rec.id
        """).fetchall()

    if len(rows) < 3:
        return {
            "status": "Insufficient Data",
            "message": "Need at least 3 corroborated records for a severity estimate.",
        }

    total_score = 0.0

    for row in rows:
        trust = row["trust_score"] if row["trust_score"] else 50
        rel = 3 if row["source_reliability"] == "verified" else 2 if row["source_reliability"] == "partial" else 1
        conf = 3 if row["confidence"] == "high" else 2 if row["confidence"] == "medium" else 1

        score = (trust / 100) * 0.4 + (rel / 3) * 0.3 + (conf / 3) * 0.2 + min(row["vol"] / 5, 1) * 0.1
        total_score += score

    avg_score = (total_score / len(rows)) * 100

    if avg_score >= 75:
        prediction = "Critical"
    elif avg_score >= 50:
        prediction = "High"
    elif avg_score >= 25:
        prediction = "Medium"
    else:
        prediction = "Low"

    return {
        "status": "Success",
        "predicted_severity": prediction,
        "confidence_score": round(avg_score, 2),
        "method": "Weighted heuristic (not ML)",
        "features_used": [
            "Organization Trust Score",
            "Source Reliability",
            "Confidence Level",
            "Report Volume",
        ],
    }