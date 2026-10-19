import json
from backend.database import get_connection

def build_temporal_graph():
    """
    Builds a Knowledge Graph with Nodes (Organizations, IOCs) and Edges (Submissions).
    Includes timestamps for temporal analysis.
    """
    with get_connection() as conn:
        # 1. Fetch all submitted threat records with their provenance
        rows = conn.execute("""
            SELECT 
                sub.id as submission_id,
                sub.observed_at,
                sub.submitted_severity,
                sub.confidence as sub_confidence,
                org.name as org_name,
                org.sector as org_sector,
                rec.id as record_id,
                rec.indicator_value,
                rec.indicator_type,
                rec.category,
                rec.severity as base_severity
            FROM cti_submissions sub
            JOIN organizations org ON sub.organization_id = org.id
            JOIN cti_records rec ON sub.cti_record_id = rec.id
        """).fetchall()

    nodes = []
    links = []
    seen_nodes = set()

    # Add Organization Nodes
    for row in rows:
        org_id = f"org_{row['org_name']}"
        if org_id not in seen_nodes:
            nodes.append({
                "id": org_id,
                "label": row['org_name'],
                "type": "organization",
                "sector": row['org_sector']
            })
            seen_nodes.add(org_id)

    # Add IOC Nodes and Submission Edges
    for row in rows:
        ioc_id = f"ioc_{row['record_id']}"
        org_id = f"org_{row['org_name']}"
        
        if ioc_id not in seen_nodes:
            nodes.append({
                "id": ioc_id,
                "label": row['indicator_value'],
                "type": row['indicator_type'],
                "category": row['category']
            })
            seen_nodes.add(ioc_id)

        # Create the temporal edge (Organization -> Submitted -> IOC)
        links.append({
            "source": org_id,
            "target": ioc_id,
            "type": "submitted",
            "timestamp": row['observed_at'],
            "severity": row['submitted_severity'],
            "confidence": row['sub_confidence']
        })

    return {"nodes": nodes, "links": links}

def detect_contradictions():
    """
    Finds IOCs where multiple organizations submitted conflicting severities.
    """
    with get_connection() as conn:
        # Find IOCs that have more than one distinct submitted severity
        contradictions = conn.execute("""
            SELECT 
                rec.indicator_value,
                rec.indicator_type,
                GROUP_CONCAT(org.name || ': ' || sub.submitted_severity, ' | ') as reports
            FROM cti_submissions sub
            JOIN organizations org ON sub.organization_id = org.id
            JOIN cti_records rec ON sub.cti_record_id = rec.id
            GROUP BY rec.id
            HAVING COUNT(DISTINCT sub.submitted_severity) > 1
        """).fetchall()

    return [dict(row) for row in contradictions]