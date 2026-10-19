"""Build a provenance-aware temporal CTI knowledge graph.

The graph is derived from the existing SQLite tables. It does not
modify or migrate the database.

This is a graph representation and rule-based correlation baseline,
not a trained temporal graph neural network.
"""

from collections import defaultdict
from datetime import datetime, timezone
import json

from backend.database import get_connection


GRAPH_VERSION = "1.0"


def normalize_indicator(indicator_type, indicator_value):
    """Normalize indicator values conservatively for entity resolution."""
    if not indicator_type or indicator_value is None:
        return None

    kind = str(indicator_type).strip().lower()
    value = str(indicator_value).strip()

    if not value or kind == "none":
        return None

    if kind in {"ip", "ipv4", "ipv6", "ip_address", "ip-address"}:
        return ("ip", value.lower())

    if kind in {"domain", "domain-name"}:
        return ("domain", value.rstrip(".").lower())

    if kind == "url":
        return ("url", value)

    if kind in {"sha256", "file_hash_sha256"}:
        return ("sha256", value.lower())

    if kind in {"cve", "vulnerability"}:
        return ("cve", value.upper())

    return (kind, value)


def parse_timestamp(value):
    """Parse an ISO timestamp without confusing missing data with current time."""
    if not isinstance(value, str) or not value.strip():
        return None

    try:
        parsed = datetime.fromisoformat(
            value.strip().replace("Z", "+00:00")
        )

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)

        return parsed.astimezone(timezone.utc).isoformat()
    except (ValueError, OverflowError):
        return None


def build_knowledge_graph():
    """Build graph nodes and edges from CTI records and their submissions."""
    connection = get_connection()

    try:
        records = connection.execute(
            """
            SELECT
                id, category, indicator_type, indicator_value,
                title, description, severity, confidence,
                sharing_sector, risk_score, risk_level,
                status, created_at
            FROM cti_records
            ORDER BY id
            """
        ).fetchall()

        organizations = connection.execute(
            """
            SELECT id, name, sector, trust_score, created_at
            FROM organizations
            ORDER BY id
            """
        ).fetchall()

        submissions = connection.execute(
            """
            SELECT
                s.id, s.cti_record_id, s.organization_id,
                s.source_type, s.source_reliability,
                s.observed_at, s.submitted_severity,
                s.confidence, s.evidence, s.created_at,
                o.name AS organization_name,
                o.sector AS organization_sector
            FROM cti_submissions AS s
            LEFT JOIN organizations AS o ON o.id = s.organization_id
            ORDER BY s.id
            """
        ).fetchall()

    finally:
        connection.close()

    nodes = []
    edges = []
    conflicts = []
    entity_index = defaultdict(list)
    submissions_by_record = defaultdict(list)

    for row in organizations:
        item = dict(row)
        nodes.append({
            "id": f"organization:{item['id']}",
            "type": "organization",
            "organization_id": item["id"],
            "name": item["name"],
            "sector": item["sector"],
            "trust_score": item["trust_score"],
            "created_at": parse_timestamp(item["created_at"]),
        })

    for row in records:
        item = dict(row)
        record_id = item["id"]
        node_id = f"cti:{record_id}"

        nodes.append({
            "id": node_id,
            "type": "cti_record",
            "record_id": record_id,
            "title": item["title"],
            "category": item["category"],
            "indicator_type": item["indicator_type"],
            "indicator_value": item["indicator_value"],
            "normalized_entity": normalize_indicator(
                item["indicator_type"],
                item["indicator_value"],
            ),
            "severity": item["severity"],
            "confidence": item["confidence"],
            "sharing_sector": item["sharing_sector"],
            "risk_score": item["risk_score"],
            "risk_level": item["risk_level"],
            "status": item["status"],
            "created_at": parse_timestamp(item["created_at"]),
        })

        key = normalize_indicator(
            item["indicator_type"],
            item["indicator_value"],
        )

        if key:
            entity_index[key].append(record_id)

    for row in submissions:
        item = dict(row)
        submission_id = item["id"]
        record_id = item["cti_record_id"]
        organization_id = item["organization_id"]

        observed_at = parse_timestamp(item["observed_at"])
        submitted_at = parse_timestamp(item["created_at"])

        submission_node_id = f"submission:{submission_id}"

        nodes.append({
            "id": submission_node_id,
            "type": "evidence_submission",
            "submission_id": submission_id,
            "record_id": record_id,
            "organization_id": organization_id,
            "organization_name": item["organization_name"],
            "source_type": item["source_type"],
            "source_reliability": item["source_reliability"],
            "observed_at": observed_at,
            "submitted_at": submitted_at,
            "submitted_severity": item["submitted_severity"],
            "confidence": item["confidence"],
            "evidence": item["evidence"] or "",
        })

        submissions_by_record[record_id].append(item)

        edges.append({
            "id": f"supports:{submission_id}:{record_id}",
            "source": submission_node_id,
            "target": f"cti:{record_id}",
            "type": "supports",
            "submission_id": submission_id,
            "observed_at": observed_at,
            "submitted_at": submitted_at,
            "source_type": item["source_type"],
            "source_reliability": item["source_reliability"],
            "confidence": item["confidence"],
            "submitted_severity": item["submitted_severity"],
        })

        if organization_id is not None:
            edges.append({
                "id": f"submitted_by:{submission_id}:{organization_id}",
                "source": submission_node_id,
                "target": f"organization:{organization_id}",
                "type": "submitted_by",
                "submission_id": submission_id,
                "submitted_at": submitted_at,
                "source_type": item["source_type"],
                "source_reliability": item["source_reliability"],
            })

    # Detect exact normalized indicator matches across different records.
    for key, record_ids in entity_index.items():
        unique_ids = sorted(set(record_ids))

        for index, first_id in enumerate(unique_ids):
            for second_id in unique_ids[index + 1:]:
                edges.append({
                    "id": f"same_entity:{first_id}:{second_id}",
                    "source": f"cti:{first_id}",
                    "target": f"cti:{second_id}",
                    "type": "same_entity",
                    "match_method": "normalized_exact_indicator",
                    "normalized_type": key[0],
                })

    # Preserve disagreements rather than silently overwriting reports.
    for record_id, items in submissions_by_record.items():
        severity_groups = defaultdict(list)

        for item in items:
            severity = item["submitted_severity"]

            if severity:
                severity_groups[str(severity).strip().lower()].append(
                    item["id"]
                )

        if len(severity_groups) > 1:
            conflict = {
                "record_id": record_id,
                "type": "severity_conflict",
                "reported_severities": sorted(severity_groups.keys()),
                "submission_ids_by_severity": dict(severity_groups),
            }
            conflicts.append(conflict)

            edges.append({
                "id": f"severity_conflict:{record_id}",
                "source": f"cti:{record_id}",
                "target": f"cti:{record_id}",
                "type": "has_severity_conflict",
                "reported_severities": conflict["reported_severities"],
            })

    return {
        "graph_version": GRAPH_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "node_count": len(nodes),
            "edge_count": len(edges),
            "organization_count": len(organizations),
            "cti_record_count": len(records),
            "submission_count": len(submissions),
            "exact_entity_relationship_count": sum(
                1 for edge in edges if edge["type"] == "same_entity"
            ),
            "severity_conflict_count": len(conflicts),
            "missing_observation_time_count": sum(
                1
                for row in submissions
                if not parse_timestamp(row["observed_at"])
            ),
        },
        "nodes": nodes,
        "edges": edges,
        "conflicts": conflicts,
    }


def export_graph_json(output_path=None):
    """Serialize the graph; optionally write it to a requested path."""
    graph = build_knowledge_graph()
    serialized = json.dumps(graph, indent=2, ensure_ascii=False)

    if output_path is not None:
        with open(output_path, "w", encoding="utf-8") as output:
            output.write(serialized)

    return serialized
