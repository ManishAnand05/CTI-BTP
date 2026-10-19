import unittest
from unittest.mock import patch

from backend import correlation


class TestCorrelationHelpers(unittest.TestCase):

    def test_keywords_ignore_stop_words(self):
        result = correlation.get_keywords(
            "The suspicious malware attack targets Finance"
        )

        self.assertEqual(result, {"malware", "targets", "finance"})

    def test_empty_description_returns_empty_set(self):
        self.assertEqual(correlation.get_keywords(None), set())
        self.assertEqual(correlation.get_keywords(""), set())

    def test_normalize_value(self):
        self.assertEqual(
            correlation.normalize_value("  EXAMPLE.COM  "),
            "example.com",
        )
        self.assertEqual(correlation.normalize_value(None), "")

    def test_normalize_ip_type_aliases(self):
        for value in ("ip", "ipv4", "ipv6", "ip_address", "ip-address"):
            with self.subTest(value=value):
                self.assertEqual(
                    correlation.normalize_indicator_type(value),
                    "ip",
                )

    def test_different_indicator_types_do_not_exact_match(self):
        legacy = [{
            "record_type": "legacy_indicator",
            "record_id": 1,
            "title": "Alpha phishing",
            "description": "Alpha phishing",
            "indicator_type": "domain",
            "indicator_value": "shared-value",
            "severity": "High",
            "sharing_sector": "All",
        }]

        advanced = [{
            "record_type": "advanced_cti",
            "record_id": 2,
            "title": "Beta ransomware",
            "description": "Beta ransomware",
            "indicator_type": "hash",
            "indicator_value": "shared-value",
            "severity": "Medium",
            "sharing_sector": "All",
        }]

        with (
            patch.object(correlation, "load_legacy_indicators", return_value=legacy),
            patch.object(correlation, "load_advanced_cti_records", return_value=advanced),
        ):
            results = correlation.correlate_indicators()

        self.assertEqual(results, [])

    def test_exact_indicator_match_preserves_output_fields(self):
        legacy = [{
            "record_type": "legacy_indicator",
            "record_id": 1,
            "title": "Alpha phishing",
            "description": "Alpha phishing",
            "indicator_type": "ip",
            "indicator_value": "192.0.2.10",
            "severity": "High",
            "sharing_sector": "Finance",
        }]

        advanced = [{
            "record_type": "advanced_cti",
            "record_id": 1,
            "title": "Beta ransomware",
            "description": "Beta ransomware",
            "indicator_type": "ipv4",
            "indicator_value": "192.0.2.10",
            "severity": "Medium",
            "sharing_sector": "Healthcare",
        }]

        with (
            patch.object(correlation, "load_legacy_indicators", return_value=legacy),
            patch.object(correlation, "load_advanced_cti_records", return_value=advanced),
        ):
            results = correlation.correlate_indicators()

        self.assertEqual(len(results), 1)
        result = results[0]

        self.assertEqual(result["record_1_type"], "legacy_indicator")
        self.assertEqual(result["record_2_type"], "advanced_cti")
        self.assertEqual(result["indicator_1"], 1)
        self.assertEqual(result["indicator_2"], 1)
        self.assertIn("exact_indicator_match", result["reasons"])
        self.assertIn("exact_ip_match", result["reasons"])

        for field in (
            "title_1", "title_2", "ip_1", "ip_2",
            "value_1", "value_2", "type_1", "type_2",
            "severity_1", "severity_2", "sector_1", "sector_2",
            "reasons", "common_keywords",
        ):
            self.assertIn(field, result)

    def test_same_table_record_is_not_correlated_with_itself(self):
        record = {
            "record_type": "legacy_indicator",
            "record_id": 7,
            "title": "Shared malware",
            "description": "Shared malware",
            "indicator_type": "ip",
            "indicator_value": "192.0.2.20",
            "severity": "High",
            "sharing_sector": "All",
        }

        with (
            patch.object(correlation, "load_legacy_indicators", return_value=[record]),
            patch.object(correlation, "load_advanced_cti_records", return_value=[]),
        ):
            results = correlation.correlate_indicators()

        self.assertEqual(results, [])

    def test_shared_keywords_are_reported(self):
        legacy = [{
            "record_type": "legacy_indicator",
            "record_id": 1,
            "title": "Orchid malware campaign",
            "description": "",
            "indicator_type": "ip",
            "indicator_value": "192.0.2.30",
            "severity": "High",
            "sharing_sector": "All",
        }]

        advanced = [{
            "record_type": "advanced_cti",
            "record_id": 2,
            "title": "Orchid malware campaign",
            "description": "",
            "indicator_type": "domain",
            "indicator_value": "example.test",
            "severity": "Medium",
            "sharing_sector": "All",
        }]

        with (
            patch.object(correlation, "load_legacy_indicators", return_value=legacy),
            patch.object(correlation, "load_advanced_cti_records", return_value=advanced),
        ):
            results = correlation.correlate_indicators()

        self.assertEqual(len(results), 1)
        self.assertIn("shared_description_keywords", results[0]["reasons"])
        self.assertEqual(
            results[0]["common_keywords"],
            ["campaign", "malware", "orchid"],
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)

