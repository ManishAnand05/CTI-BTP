
from stix2 import Indicator, Bundle
from datetime import datetime, timezone


def process_cti(ip_address, description, severity):
    # Create a standard STIX Indicator
    indicator = Indicator(
        name="Suspicious IP Address",
        description=description,
        pattern=f"[ipv4-addr:value = '{ip_address}']",
        pattern_type="stix",
        valid_from=datetime.now(timezone.utc),
        labels=["malicious-activity"]
    )

    # Create a STIX Bundle
    bundle = Bundle(objects=[indicator])

    # Keep project-specific severity outside the STIX object
    result = {
        "severity": severity,
        "stix_data": bundle.serialize(pretty=True)
    }

    return result
