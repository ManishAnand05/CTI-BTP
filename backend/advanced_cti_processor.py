
import ipaddress
import re
from urllib.parse import urlparse
from datetime import datetime, timezone

from stix2 import (
    Bundle,
    Indicator,
    Vulnerability,
    Malware,
    Identity,
    Report,
)


CATEGORIES = {
    "network",
    "malware",
    "phishing",
    "vulnerability",
    "campaign",
    "cloud",
    "incident",
    "other",
}

INDICATOR_TYPES = {
    "ip",
    "domain",
    "url",
    "sha256",
    "cve",
    "none",
    "attack_technique",
}

SEVERITIES = {
    "low",
    "medium",
    "high",
    "critical",
    "unknown",
}

CONFIDENCES = {
    "low",
    "medium",
    "high",
    "unknown",
}

SECTORS = {
    "Finance",
    "Healthcare",
    "Education",
    "Technology",
    "Government",
    "Energy",
    "All",
}

SOURCE_TYPES = {
    "siem",
    "edr",
    "incident_response",
    "threat_research",
    "external_feed",
    "user_report",
    "other",
}

RELIABILITIES = {
    "unverified",
    "partial",
    "verified",
}


def validate_indicator(indicator_type, value):
    if indicator_type == "attack_technique":
        v = str(value or "").strip().upper()
        if not re.match(r"^T\d{4}(\.\d{3})?$", v):
            raise ValueError("Invalid ATT&CK technique ID.")
        return v
    """Validate an indicator based on its type."""

    value = (value or "").strip()

    if indicator_type == "none":
        return None

    if not value:
        raise ValueError("Indicator value is required.")

    if len(value) > 2048:
        raise ValueError("Indicator value is too long.")

    if indicator_type == "ip":
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            raise ValueError("Enter a valid IPv4 or IPv6 address.")

    if indicator_type == "domain":
        domain = value.rstrip(".").lower()

        if len(domain) > 253 or "." not in domain:
            raise ValueError("Enter a valid domain name.")

        labels = domain.split(".")

        for label in labels:
            if (
                not label
                or len(label) > 63
                or not re.fullmatch(
                    r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?",
                    label,
                )
            ):
                raise ValueError("Invalid domain format.")

        return domain

    if indicator_type == "url":
        parsed = urlparse(value)

        if parsed.scheme not in {"http", "https"}:
            raise ValueError("URL must start with http:// or https://.")

        if not parsed.hostname:
            raise ValueError("URL hostname is missing.")

        if parsed.username or parsed.password:
            raise ValueError(
                "URLs containing embedded credentials are not accepted."
            )

        return value

    if indicator_type == "sha256":
        if not re.fullmatch(r"[0-9a-fA-F]{64}", value):
            raise ValueError(
                "SHA-256 must contain exactly 64 hexadecimal characters."
            )

        return value.lower()

    if indicator_type == "cve":
        if not re.fullmatch(
            r"CVE-\d{4}-\d{4,}",
            value,
            re.IGNORECASE,
        ):
            raise ValueError("Enter a valid CVE identifier format.")

        return value.upper()

    raise ValueError("Unsupported indicator type.")


def normalize_cti(
    category,
    indicator_type,
    indicator_value,
    title,
    description,
    severity,
):
    """Convert supported CTI into appropriate STIX objects."""

    now = datetime.now(timezone.utc)
    objects = []

    if indicator_type in {"ip", "domain", "url", "sha256"}:
        value = (
            indicator_value
            .replace("\\", "\\\\")
            .replace("'", "\\'")
        )

        if indicator_type == "ip":
            pattern = f"[ipv4-addr:value = '{value}']"

            if ":" in value:
                pattern = f"[ipv6-addr:value = '{value}']"

        elif indicator_type == "domain":
            pattern = f"[domain-name:value = '{value}']"

        elif indicator_type == "url":
            pattern = f"[url:value = '{value}']"

        else:
            pattern = (
                f"[file:hashes.'SHA-256' = '{value}']"
            )

        indicator = Indicator(
            name=title,
            description=description,
            pattern=pattern,
            pattern_type="stix",
            valid_from=now,
            labels=[category],
        )

        objects.append(indicator)

    elif indicator_type == "cve":
        vulnerability = Vulnerability(
            name=indicator_value,
            description=description,
        )

        objects.append(vulnerability)

    elif category == "malware":
        malware = Malware(
            name=title,
            is_family=False,
            description=description,
            malware_types=["unknown"],
        )

        objects.append(malware)

    else:
        # Create a report for incidents, campaigns,
        # cloud observations and descriptive CTI.

        platform_identity = Identity(
            name="CTI Sharing Platform",
            identity_class="organization",
        )

        report = Report(
            name=title,
            description=description,
            report_types=["threat-report"],
            published=now,
            object_refs=[platform_identity.id],
        )

        objects.extend([
            platform_identity,
            report,
        ])

    bundle = Bundle(objects=objects)

    return bundle.serialize(pretty=True)
