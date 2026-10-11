import re

from backend.database import get_connection


# Common words that do not help identify relationships.
STOP_WORDS = {
    "the", "a", "an", "and", "or", "for", "to",
    "of", "in", "on", "with", "is", "are", "this",
    "that", "example", "indicator", "testing",
    "threat", "attack", "suspicious", "detected",
    "activity", "unknown", "multiple",
}


def get_keywords(description):
    """Extract meaningful words from a description."""

    if not description:
        return set()

    words = re.findall(r"[a-zA-Z0-9]+", str(description).lower())

    return {
        word
        for word in words
        if word not in STOP_WORDS and len(word) > 2
    }


def normalize_value(value):
    """Normalize an indicator value for exact-match comparisons."""

    if value is None:
        return ""

    return str(value).strip().lower()


def normalize_indicator_type(indicator_type):
    """Normalize common names for IP indicator types."""

    value = normalize_value(indicator_type)

    if value in {"ip", "ipv4", "ipv6", "ip_address", "ip-address"}:
        return "ip"

    return value


def load_legacy_indicators():
    """Load indicators from the existing indicators table."""

    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT id, ip_address, description, severity,
                   sharing_sector
            FROM indicators
            ORDER BY id
            """
        ).fetchall()

    records = []

    for row in rows:
        item = dict(row)

        records.append({
            "record_type": "legacy_indicator",
            "record_id": item["id"],
            "title": item.get("description") or "",
            "description": item.get("description") or "",
            "indicator_type": "ip",
            "indicator_value": item.get("ip_address") or "",
            "severity": item.get("severity"),
            "sharing_sector": item.get("sharing_sector") or "All",
        })

    return records


def load_advanced_cti_records():
    """Load records from the advanced CTI table."""

    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT id, title, category, indicator_type,
                   indicator_value, severity, sharing_sector
            FROM cti_records
            ORDER BY id
            """
        ).fetchall()

    records = []

    for row in rows:
        item = dict(row)

        records.append({
            "record_type": "advanced_cti",
            "record_id": item["id"],
            "title": item.get("title") or "",
            "description": item.get("category") or "",
            "indicator_type": item.get("indicator_type") or "",
            "indicator_value": item.get("indicator_value") or "",
            "severity": item.get("severity"),
            "sharing_sector": item.get("sharing_sector") or "All",
        })

    return records


def correlate_indicators():
    """
    Find potential relationships across legacy and advanced CTI records.

    Matching rules:
    1. Exact indicator value with compatible indicator types.
    2. Shared meaningful keywords in record text.

    Records are identified by both their type and ID because the two
    database tables may contain the same numeric ID.
    """

    indicators = (
        load_legacy_indicators()
        + load_advanced_cti_records()
    )

    correlations = []

    # Compare every unique pair of records.
    for i in range(len(indicators)):
        for j in range(i + 1, len(indicators)):
            first = indicators[i]
            second = indicators[j]

            # Do not correlate a record with itself.
            if (
                first["record_type"] == second["record_type"]
                and first["record_id"] == second["record_id"]
            ):
                continue

            reasons = []
            common_keywords = []

            value1 = normalize_value(first["indicator_value"])
            value2 = normalize_value(second["indicator_value"])

            type1 = normalize_indicator_type(first["indicator_type"])
            type2 = normalize_indicator_type(second["indicator_type"])

            # Rule 1: Exact indicator value match.
            # IP values are compared only with IP values.
            if value1 and value1 == value2:
                if type1 == type2 or not type1 or not type2:
                    reasons.append("exact_indicator_match")

                    if type1 == "ip" and type2 == "ip":
                        reasons.append("exact_ip_match")

            # Rule 2: Shared meaningful keywords.
            text1 = (
                first["title"] + " " + first["description"]
            ).strip()

            text2 = (
                second["title"] + " " + second["description"]
            ).strip()

            keywords1 = get_keywords(text1)
            keywords2 = get_keywords(text2)

            common_keywords = sorted(keywords1 & keywords2)

            if common_keywords:
                reasons.append("shared_description_keywords")

            # Include only pairs that match at least one rule.
            if reasons:
                correlations.append({
                    "indicator_1": first["record_id"],
                    "indicator_2": second["record_id"],
                    "record_1_type": first["record_type"],
                    "record_2_type": second["record_type"],
                    "title_1": first["title"],
                    "title_2": second["title"],
                    "ip_1": (
                        first["indicator_value"]
                        if type1 == "ip"
                        else None
                    ),
                    "ip_2": (
                        second["indicator_value"]
                        if type2 == "ip"
                        else None
                    ),
                    "value_1": first["indicator_value"],
                    "value_2": second["indicator_value"],
                    "type_1": first["indicator_type"],
                    "type_2": second["indicator_type"],
                    "severity_1": first["severity"],
                    "severity_2": second["severity"],
                    "sector_1": first["sharing_sector"],
                    "sector_2": second["sharing_sector"],
                    "reasons": reasons,
                    "common_keywords": common_keywords,
                })

    return correlations
