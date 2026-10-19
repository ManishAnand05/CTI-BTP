import unittest
from unittest.mock import patch

from backend.pdf_cti_extractor import (
    MAX_EVIDENCE_PER_GROUP,
    detect_indicators,
    group_indicators,
    refang_pages,
)


def page(number, text):
    return {"page": number, "text": text}


def finding(indicator_type, value, page_number=1, evidence="", **extra):
    return {
        "type": indicator_type,
        "value": value,
        "page": page_number,
        "evidence": evidence,
        "method": "regex_rule",
        "review_status": "unreviewed",
        **extra,
    }


def pairs(findings):
    return {(item["type"], item["value"]) for item in findings}


class PDFCTIExtractorTests(unittest.TestCase):

    # ------------------------------------------------------
    # Core detection
    # ------------------------------------------------------

    def test_detects_expected_indicator_types(self):
        pages = [page(1, (
            "IP 198.51.100.10 "
            "CVE-2024-12345 "
            "T1059.001 "
            "https://example.com/test "
            "evil-example.org"
        ))]

        self.assertEqual(
            pairs(detect_indicators(pages)),
            {
                ("ip", "198.51.100.10"),
                ("cve", "CVE-2024-12345"),
                ("attack_technique", "T1059.001"),
                ("url", "https://example.com/test"),
                ("domain", "evil-example.org"),
            },
        )

    def test_preserves_page_number_and_evidence(self):
        findings = detect_indicators([page(3, "Suspicious IP: 198.51.100.10")])

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["page"], 3)
        self.assertIn("198.51.100.10", findings[0]["evidence"])
        self.assertEqual(findings[0]["review_status"], "unreviewed")

    def test_ignores_invalid_ipv4_address(self):
        findings = detect_indicators([page(1, "Invalid IP: 999.999.999.999")])

        self.assertFalse(any(item["type"] == "ip" for item in findings))

    def test_does_not_duplicate_domain_inside_url(self):
        findings = detect_indicators([page(1, "Visit https://example.com/test")])

        self.assertIn(("url", "https://example.com/test"), pairs(findings))
        self.assertNotIn(("domain", "example.com"), pairs(findings))

    def test_does_not_classify_executable_filenames_as_domains(self):
        findings = detect_indicators([page(1, (
            "Files observed: SVCHost.dll, PSexesvc.exe, "
            "HRsword.exe, Usysdiag.exe"
        ))])

        self.assertEqual(
            [item for item in findings if item["type"] == "domain"],
            [],
        )

    def test_detects_real_domains(self):
        findings = detect_indicators([page(1, (
            "Official advisory: cisa.gov and stopransomware.gov"
        ))])

        domains = {
            item["value"] for item in findings if item["type"] == "domain"
        }

        self.assertIn("cisa.gov", domains)
        self.assertIn("stopransomware.gov", domains)

    def test_ignores_known_non_domain_terms(self):
        findings = detect_indicators([page(1, "Press power.off to stop.")])

        self.assertEqual(findings, [])

    def test_preserves_repeated_indicator_evidence_across_pages(self):
        findings = detect_indicators([
            page(1, "Observed indicator: 198.51.100.10"),
            page(2, "The same indicator appears again: 198.51.100.10"),
        ])

        ip_findings = [
            item for item in findings
            if item["type"] == "ip" and item["value"] == "198.51.100.10"
        ]

        self.assertEqual(len(ip_findings), 2)
        self.assertEqual({item["page"] for item in ip_findings}, {1, 2})

    # ------------------------------------------------------
    # Normalization
    # ------------------------------------------------------

    def test_cve_is_uppercased(self):
        findings = detect_indicators([page(1, "See cve-2024-12345 for details.")])

        self.assertEqual(pairs(findings), {("cve", "CVE-2024-12345")})

    def test_sha256_is_lowercased(self):
        value = "ABCDEF0123456789" * 4
        findings = detect_indicators([page(1, f"Hash {value}")])

        self.assertEqual(pairs(findings), {("sha256", value.lower())})

    # ------------------------------------------------------
    # Hashes
    # ------------------------------------------------------

    def test_detects_md5_and_sha1(self):
        md5 = "d41d8cd98f00b204e9800998ecf8427e"
        sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"

        findings = detect_indicators([page(1, f"MD5 {md5} SHA1 {sha1}")])

        self.assertEqual(pairs(findings), {("md5", md5), ("sha1", sha1)})

    def test_rejects_numeric_and_trivial_hashes(self):
        findings = detect_indicators([page(1, (
            f"ID {'1234567890' * 3}12 filler {'0' * 32}"
        ))])

        self.assertEqual(findings, [])

    # ------------------------------------------------------
    # IP scope
    # ------------------------------------------------------

    def test_flags_ip_scope(self):
        findings = detect_indicators([page(1, "Seen 8.8.8.8 and 10.0.0.5.")])

        scopes = {item["value"]: item["ip_scope"] for item in findings}

        self.assertEqual(scopes["8.8.8.8"], "public")
        self.assertEqual(scopes["10.0.0.5"], "private")

    # ------------------------------------------------------
    # Defanged indicators
    # ------------------------------------------------------

    def test_restores_defanged_indicators(self):
        pages, changed = refang_pages([page(1, (
            "Beacon hxxps://evil[.]example[.]com/a and c2[.]bad-site[.]net"
        ))])

        findings = detect_indicators(pages)

        self.assertEqual(changed, 1)
        self.assertIn(("url", "https://evil.example.com/a"), pairs(findings))
        self.assertIn(("domain", "c2.bad-site.net"), pairs(findings))

    def test_refang_leaves_clean_text_unchanged(self):
        pages, changed = refang_pages([page(1, "Nothing to restore here.")])

        self.assertEqual(changed, 0)
        self.assertEqual(pages[0]["text"], "Nothing to restore here.")

    # ------------------------------------------------------
    # Options, ordering and limits
    # ------------------------------------------------------

    def test_enabled_types_limits_detection(self):
        findings = detect_indicators(
            [page(1, "CVE-2024-12345 from 8.8.8.8")],
            enabled_types={"cve"},
        )

        self.assertEqual(pairs(findings), {("cve", "CVE-2024-12345")})

    def test_findings_follow_reading_order(self):
        findings = detect_indicators([page(1, (
            "CVE-2024-11111 then 8.8.8.8 then CVE-2024-22222"
        ))])

        self.assertEqual(
            [item["value"] for item in findings],
            ["CVE-2024-11111", "8.8.8.8", "CVE-2024-22222"],
        )

    def test_respects_findings_limit(self):
        text = " ".join(f"CVE-2024-{number}" for number in range(10000, 10010))

        with patch("backend.pdf_cti_extractor.MAX_FINDINGS", 3):
            findings = detect_indicators([page(1, text)])

        self.assertEqual(len(findings), 3)


class GroupIndicatorsTests(unittest.TestCase):

    def test_groups_same_indicator_ignoring_case(self):
        findings = [
            finding("domain", "CISA.GOV", 2, "First mention"),
            finding("domain", "cisa.gov", 5, "Second mention"),
        ]

        grouped = group_indicators(findings)

        self.assertEqual(len(grouped), 1)
        self.assertEqual(grouped[0]["value"], "cisa.gov")

    def test_collects_sorted_unique_pages_and_counts_occurrences(self):
        findings = [
            finding("cve", "CVE-2024-12345", 5),
            finding("cve", "CVE-2024-12345", 2),
            finding("cve", "CVE-2024-12345", 5),
        ]

        grouped = group_indicators(findings)

        self.assertEqual(len(grouped), 1)
        self.assertEqual(grouped[0]["pages"], [2, 5])
        self.assertEqual(grouped[0]["occurrences"], 3)

    def test_keeps_url_paths_case_sensitive(self):
        findings = [
            finding("url", "https://example.com/Admin", 1),
            finding("url", "https://example.com/admin", 1),
        ]

        self.assertEqual(len(group_indicators(findings)), 2)

    def test_does_not_merge_different_types(self):
        findings = [
            finding("ip", "8.8.8.8", 1),
            finding("domain", "8.8.8.8", 1),
        ]

        self.assertEqual(len(group_indicators(findings)), 2)

    def test_limits_evidence_samples_but_counts_every_occurrence(self):
        findings = [
            finding("ip", "8.8.8.8", number, f"mention {number}")
            for number in range(1, 9)
        ]

        grouped = group_indicators(findings)

        self.assertEqual(grouped[0]["occurrences"], 8)
        self.assertEqual(len(grouped[0]["evidence"]), MAX_EVIDENCE_PER_GROUP)
        self.assertEqual(grouped[0]["evidence"][0]["page"], 1)

    def test_preserves_ip_scope(self):
        findings = [finding("ip", "10.0.0.5", 1, ip_scope="private")]

        self.assertEqual(group_indicators(findings)[0]["ip_scope"], "private")

    def test_keeps_first_seen_order(self):
        findings = [
            finding("cve", "CVE-2024-22222", 1),
            finding("ip", "8.8.8.8", 1),
            finding("cve", "CVE-2024-22222", 2),
        ]

        self.assertEqual(
            [item["value"] for item in group_indicators(findings)],
            ["CVE-2024-22222", "8.8.8.8"],
        )

    def test_empty_input_returns_empty_list(self):
        self.assertEqual(group_indicators([]), [])

    def test_skips_findings_without_type_or_value(self):
        findings = [
            {"page": 1, "evidence": "broken"},
            finding("cve", "CVE-2024-12345", 1),
        ]

        self.assertEqual(len(group_indicators(findings)), 1)

    def test_groups_repeated_indicator_found_by_detection(self):
        findings = detect_indicators([
            page(1, "Observed indicator: 198.51.100.10"),
            page(2, "The same indicator appears again: 198.51.100.10"),
        ])

        grouped = group_indicators(findings)

        self.assertEqual(len(grouped), 1)
        self.assertEqual(grouped[0]["value"], "198.51.100.10")
        self.assertEqual(grouped[0]["pages"], [1, 2])
        self.assertEqual(grouped[0]["occurrences"], 2)


if __name__ == "__main__":
    unittest.main()