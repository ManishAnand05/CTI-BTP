import unittest

try:
    from backend import pdf_cti_extractor as ex
except ImportError:  # run from inside the backend folder
    import pdf_cti_extractor as ex


H = "0123456789abcdef" * 4  # a 64-character SHA-256 style value
H2 = "fedcba9876543210" * 4
MD5_A = "d41d8cd98f00b204e9800998ecf8427e"
MD5_B = "0cc175b9c0f1b6a831c399e269772661"


def findings(text, indicator_type, rejoined=None):
    pages = [{"page": 1, "text": text}]
    return [
        f for f in ex.detect_indicators(pages, rejoined_hashes=rejoined)
        if f["type"] == indicator_type
    ]


class IpTests(unittest.TestCase):
    def test_labelled_and_embedded_versions_are_dropped(self):
        text = (
            "Grixba version 1.1.3.0, v1.1.3.0, Build: 2.1.1.3.0, "
            "Version | 9.9.9.9, Grixba_1.1.3.0.exe"
        )
        self.assertEqual(findings(text, "ip"), [])

    def test_file_name_with_extension_is_dropped(self):
        self.assertEqual(findings("Run Grixba 1.1.3.0.exe now", "ip"), [])

    def test_real_ip_at_sentence_end(self):
        result = findings("C2 server 185.2.3.4.", "ip")
        self.assertEqual([f["value"] for f in result], ["185.2.3.4"])
        self.assertEqual(result[0]["ip_scope"], "public")

    def test_product_name_before_small_quad_is_flagged(self):
        result = findings("The tool Grixba 1.1.3.0 was used", "ip")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["ip_scope"], "possible_version")

    def test_network_word_keeps_public_scope(self):
        result = findings("beacon to the server 8.8.4.4", "ip")
        self.assertEqual(result[0]["ip_scope"], "public")

    def test_ordinary_word_before_small_public_ip_stays_public(self):
        for text in ("The attacker used 8.8.8.8", "Resolver 1.1.1.1"):
            result = findings(text, "ip")
            self.assertEqual(result[0]["ip_scope"], "public", text)

    def test_private_scope_is_not_overwritten(self):
        result = findings("Grixba 10.0.0.5", "ip")
        self.assertEqual(result[0]["ip_scope"], "private")


class HashRepairTests(unittest.TestCase):
    def wrap(self, value, cut):
        return value[:cut] + "\n" + value[cut:]

    def test_repeated_wrap_shape_is_rejoined(self):
        text = "SHA256\n" + self.wrap(H, 40) + "\nSHA256\n" + self.wrap(H2, 40)
        pages, changed = ex.repair_wrapped_hashes([{"page": 1, "text": text}])
        self.assertEqual(changed, 1)
        values = [f["value"] for f in ex.detect_indicators(pages)]
        self.assertEqual(values, [H, H2])

    def test_single_wrap_with_valid_length_head_is_not_rejoined(self):
        pages, changed = ex.repair_wrapped_hashes(
            [{"page": 1, "text": self.wrap(H, 40)}]
        )
        self.assertEqual(changed, 0)

    def test_single_wrap_with_non_hash_length_head_is_rejoined(self):
        pages, changed = ex.repair_wrapped_hashes(
            [{"page": 1, "text": self.wrap(H, 36)}]
        )
        self.assertEqual(changed, 1)
        self.assertEqual(pages[0]["text"], H)

    def test_adjacent_complete_hashes_stay_separate(self):
        pages, changed = ex.repair_wrapped_hashes(
            [{"page": 1, "text": MD5_A + "\n" + MD5_B}]
        )
        self.assertEqual(changed, 0)
        values = [f["value"] for f in findings(pages[0]["text"], "md5")]
        self.assertEqual(values, [MD5_A, MD5_B])

    def test_word_like_tail_is_not_joined(self):
        text = "0123456789abcdef01234567\ndeadbeef"
        _, changed = ex.repair_wrapped_hashes([{"page": 1, "text": text}])
        self.assertEqual(changed, 0)

    def test_digit_only_tail_is_not_joined(self):
        text = "0123456789abcdef01234567\n20240115"
        _, changed = ex.repair_wrapped_hashes([{"page": 1, "text": text}])
        self.assertEqual(changed, 0)

    def test_rejoined_hash_is_marked(self):
        text = self.wrap(H, 36)
        pages, _, rejoined = ex.repair_wrapped_hashes_detailed(
            [{"page": 1, "text": text}]
        )
        result = findings(pages[0]["text"], "sha256", rejoined)
        self.assertEqual(result[0]["method"], "regex_rule_rejoined")

    def test_plain_hash_is_not_marked(self):
        result = findings(H, "sha256", rejoined=set())
        self.assertEqual(result[0]["method"], "regex_rule")


class AttackEvidenceTests(unittest.TestCase):
    def evidence(self, text):
        return {
            f["value"]: f["evidence"]
            for f in findings(text, "attack_technique")
        }

    def test_rows_on_separate_lines_stay_separate(self):
        text = (
            "Impact T1486 Data Encrypted for Impact\n"
            "T1059.001\nPowerShell\n"
            "T1105 Ingress Tool Transfer"
        )
        ev = self.evidence(text)
        self.assertEqual(ev["T1486"], "Impact T1486 Data Encrypted for Impact")
        self.assertEqual(ev["T1059.001"], "T1059.001 PowerShell")
        self.assertEqual(ev["T1105"], "T1105 Ingress Tool Transfer")

    def test_flat_row_is_split_at_next_id(self):
        text = "Execution T1059.001 PowerShell Impact T1486 Data Encrypted for Impact"
        ev = self.evidence(text)
        self.assertNotIn("T1486", ev["T1059.001"])
        self.assertTrue(ev["T1486"].startswith("T1486"))

    def test_id_list_falls_back_to_whole_line(self):
        text = "Techniques observed: T1059, T1486, T1105"
        ev = self.evidence(text)
        for value in ("T1059", "T1486", "T1105"):
            self.assertIn("Techniques observed", ev[value])

    def test_long_line_is_capped(self):
        text = "x " * 300 + "T1486 " + "y " * 300
        ev = self.evidence(text)
        self.assertLessEqual(len(ev["T1486"]), ex.MAX_ATTACK_EVIDENCE_CHARS)
        self.assertIn("T1486", ev["T1486"])


class HashTableAssociationTests(unittest.TestCase):
    HASH_A = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    HASH_B = "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"

    def table_text(self):
        return (
            "Hashes (SHA 256) Description\n"
            f"{self.HASH_A} SVCHost.dll Backdoor\n"
            f"{self.HASH_B} Gt_net.exe Custom data gathering tool\n"
        )

    def associate(self, text):
        parser = getattr(ex, "associate_hashes_with_table_rows", None)
        self.assertTrue(
            callable(parser),
            "Implement associate_hashes_with_table_rows() in the extractor",
        )
        return parser(text)

    def associations(self, text):
        return {
            item["value"]: (item["filename"], item["description"])
            for item in self.associate(text)
        }

    def test_both_table_hashes_are_detected(self):
        detected = {
            item["value"] for item in findings(self.table_text(), "sha256")
        }
        self.assertEqual(detected, {self.HASH_A, self.HASH_B})

    def test_table_filenames_are_not_reported_as_domains(self):
        self.assertEqual(findings(self.table_text(), "domain"), [])

    def test_table_parser_associates_hash_with_its_row(self):
        self.assertEqual(
            self.associations(self.table_text()),
            {
                self.HASH_A: ("SVCHost.dll", "Backdoor"),
                self.HASH_B: (
                    "Gt_net.exe",
                    "Custom data gathering tool",
                ),
            },
        )

    def test_hash_type_follows_length(self):
        text = f"{MD5_A} a.exe Dropper\n{H} b.dll Loader\n"
        types = {
            item["value"]: item["type"] for item in self.associate(text)
        }
        self.assertEqual(types, {MD5_A: "md5", H: "sha256"})

    def test_row_without_filename_keeps_whole_text_as_description(self):
        text = f"{self.HASH_A} Backdoor used for persistence\n"
        self.assertEqual(
            self.associations(text),
            {self.HASH_A: (None, "Backdoor used for persistence")},
        )

    def test_hash_only_row_has_no_filename_or_description(self):
        self.assertEqual(
            self.associations(f"{self.HASH_A}\n"),
            {self.HASH_A: (None, None)},
        )

    def test_filename_without_description(self):
        self.assertEqual(
            self.associations(f"{self.HASH_A} svc.dll\n"),
            {self.HASH_A: ("svc.dll", None)},
        )

    def test_version_number_is_not_a_filename(self):
        self.assertEqual(
            self.associations(f"{self.HASH_A} 1.2 Beta build\n"),
            {self.HASH_A: (None, "1.2 Beta build")},
        )

    def test_header_and_prose_lines_are_ignored(self):
        text = (
            "Hashes (SHA 256) Description\n"
            f"The actor dropped {self.HASH_A} on the host\n"
        )
        self.assertEqual(self.associate(text), [])

    def test_trivial_hash_row_is_ignored(self):
        self.assertEqual(self.associate("a1" * 32 + " SVCHost.dll Backdoor\n"), [])

    def test_vertical_rows_are_associated(self):
        text = (
            f"{self.HASH_A}\nSVCHost.dll\nBackdoor\n"
            f"{self.HASH_B}\nGt_net.exe\nCustom data gathering tool\n"
        )
        self.assertEqual(
            self.associations(text),
            {
                self.HASH_A: ("SVCHost.dll", "Backdoor"),
                self.HASH_B: ("Gt_net.exe", "Custom data gathering tool"),
            },
        )

    def test_description_only_block_does_not_invent_a_filename(self):
        text = f"{self.HASH_A}\nPublic key used by the actor\nto sign payloads\n"
        self.assertEqual(
            self.associations(text),
            {self.HASH_A: (None, "Public key used by the actor to sign payloads")},
        )

    def test_association_reliability_label(self):
        same = self.associate(f"{self.HASH_A} a.dll Backdoor\n")[0]
        vertical = self.associate(f"{self.HASH_A}\na.dll\nBackdoor\n")[0]
        bare = self.associate(f"{self.HASH_A}\n")[0]
        self.assertEqual(same["association"], "same_line")
        self.assertEqual(vertical["association"], "following_lines")
        self.assertEqual(bare["association"], "hash_only")

    def test_blank_line_ends_a_block(self):
        text = f"{self.HASH_A} a.dll Backdoor\n\nSome unrelated paragraph text\n"
        self.assertEqual(
            self.associations(text), {self.HASH_A: ("a.dll", "Backdoor")}
        )

    def test_long_prose_line_is_not_absorbed(self):
        text = f"{self.HASH_A} a.dll Backdoor\n" + "word " * 30 + "\n"
        self.assertEqual(
            self.associations(text), {self.HASH_A: ("a.dll", "Backdoor")}
        )

    def test_continuation_lines_are_limited_and_flagged(self):
        limit = ex.MAX_ROW_CONTINUATION_LINES
        words = [f"w{i}" for i in range(limit + 2)]
        text = f"{self.HASH_A}\n" + "\n".join(words) + "\n"
        row = self.associate(text)[0]
        self.assertEqual(row["description"], " ".join(words[:limit]))
        self.assertTrue(row["truncated"])

    def test_block_that_fits_is_not_flagged_truncated(self):
        row = self.associate(f"{self.HASH_A}\na.dll\nBackdoor\n")[0]
        self.assertFalse(row["truncated"])

    def test_description_is_capped(self):
        text = f"{self.HASH_A} a.dll " + "x" * 500 + "\n"
        description = self.associations(text)[self.HASH_A][1]
        self.assertLessEqual(len(description), ex.MAX_ROW_DESCRIPTION_CHARS)

    def test_dotted_word_after_the_first_word_is_not_a_filename(self):
        text = f"{self.HASH_A}\nBackdoor that contacts mail.example.com\n"
        self.assertEqual(
            self.associations(text),
            {self.HASH_A: (None, "Backdoor that contacts mail.example.com")},
        )

    def test_real_play_pdf_svchost_backdoor_row(self):
        text = (
            f"{self.HASH_A}\n"
            "SVCHost.dll\n"
            "Backdoor\n"
            f"{self.HASH_B}\n"
        )

        row = self.associate(text)[0]
        self.assertEqual(row["filename"], "SVCHost.dll")
        self.assertEqual(row["description"], "Backdoor")
        self.assertEqual(row["association"], "following_lines")

    PAGE6 = (
        "Hashes (SHA 256 and SHA 1) Description \n"
        "47B7B2DD88959CD7224A5542AE8D5BCE928BFC986BF0D0321532A7515C244A1E  \n"
        "SVCHost.dll \nBackdoor \n"
        "75B525B220169F07AECFB3B1991702FBD9A1E170CAF0040D1FCB07C3E819F54A \n"
        "453257C3494ADDAFB39CB6815862403E827947A1E7737EB8168CD10522465DEB \n"
        "C59F3C8D61D940B56436C14BC148C1FE98862921B8F7BAD97FBC96B31D71193C \n"
        "GRIXBA \nGt_net.exe \nCustom data \ngathering tool \n"
        "1409E010675BF4A40DB0A845B60DB3AAE5B302834E80ADEEC884AEBC55ECCBF7 \n"
        "PSexesvc.exe \nCustom Play \n\u201cpsexesvc\u201d \n"
        "0E408AED1ACF902A9F97ABF71CF0DD354024109C5D52A79054C421BE35D93549 \n"
        "HRsword.exe \nDisables \nendpoint \nprotection "
    )

    PAGE7 = (
        "90040340EE101CAC7831D7035230AC8AD4224D432E5636F34F13AA1C4A0C2041 \n"
        "Usysdiag.exe \nAssociated \nwith \nHRsword; \nchanges \n"
        "settings of \nSystem \ncertificates \n"
        "3D86555ACAA19AEDDB5896071D1E3711B062EDBE fThe9C.exe \n"
        "6DE8DD5757F9A3AC5E2AC28E8A77682D7A29BE25C106F785A061DCF582A20DC6 \n"
        "Hi.exe \nAssociated \nwith \nransomware \n"
        "75404543DE25513B376F097CEB383E8EFB9C9B95DA8945FD4AA37C7B2F226212 \n"
        "SystemBC \nMalware EXE \n"
        "7A42F96599DF8090CF89D6E3CE4316D24C6C00E499C8557A2E09D61C00C11986 \n"
        "7DEA671BE77A2CA5772B86CF8831B02BFF0567BCE6A3AE023825AA40354F8ACA \n"
        "SystemBC \nmalware DLL \n"
        "967DAFF362E63FF45526F585B7944488ACE1BB5BB5B30FA40D56557F1C538D09 \n"
        "SHA256 \nHash of \npublic ECDSA \nkey \n"
        "859165041D75FBA3759C5533E324225F355C8A07B4645B984192AD6BEF06DB1A \n"
        "SHA-256  \nHash of \npublic \nED25519 \nKey for \nWinSCP \nServer "
    )

    def by_prefix(self, text):
        return {
            item["value"][:8]: item for item in self.associate(text)
        }

    def test_real_page6_layout(self):
        rows = self.by_prefix(self.PAGE6)
        self.assertEqual(len(rows), 6)
        self.assertEqual(
            (rows["47b7b2dd"]["filename"], rows["47b7b2dd"]["description"]),
            ("SVCHost.dll", "Backdoor"),
        )
        self.assertEqual(
            (rows["1409e010"]["filename"], rows["1409e010"]["description"]),
            ("PSexesvc.exe", "Custom Play \u201cpsexesvc\u201d"),
        )
        self.assertEqual(
            (rows["0e408aed"]["filename"], rows["0e408aed"]["description"]),
            ("HRsword.exe", "Disables endpoint protection"),
        )

    def test_real_page6_hash_group_shares_text_and_is_labelled(self):
        rows = self.by_prefix(self.PAGE6)

        for prefix in ("75b525b2", "453257c3", "c59f3c8d"):
            row = rows[prefix]
            self.assertEqual(row["filename"], "Gt_net.exe")
            self.assertEqual(
                row["description"], "GRIXBA Custom data gathering tool"
            )
            self.assertEqual(row["association"], "shared_following")
            self.assertEqual(row["group_size"], 3)

        self.assertEqual(rows["47b7b2dd"]["association"], "following_lines")

    def test_real_page7_layout(self):
        rows = self.by_prefix(self.PAGE7)
        self.assertEqual(len(rows), 8)
        self.assertEqual(
            (rows["90040340"]["filename"], rows["90040340"]["description"]),
            (
                "Usysdiag.exe",
                "Associated with HRsword; changes settings of System certificates",
            ),
        )
        self.assertEqual(
            (rows["3d86555a"]["filename"], rows["3d86555a"]["description"]),
            ("fThe9C.exe", None),
        )
        self.assertEqual(rows["3d86555a"]["type"], "sha1")
        self.assertEqual(
            (rows["6de8dd57"]["filename"], rows["6de8dd57"]["description"]),
            ("Hi.exe", "Associated with ransomware"),
        )

    def test_real_page7_description_only_rows_have_no_filename(self):
        rows = self.by_prefix(self.PAGE7)
        expected = {
            "75404543": "SystemBC Malware EXE",
            "7a42f965": "SystemBC malware DLL",
            "7dea671b": "SystemBC malware DLL",
            "967daff3": "SHA256 Hash of public ECDSA key",
            "85916504": "SHA-256 Hash of public ED25519 Key for WinSCP Server",
        }
        for prefix, description in expected.items():
            self.assertIsNone(rows[prefix]["filename"], prefix)
            self.assertEqual(rows[prefix]["description"], description, prefix)

        self.assertEqual(rows["7a42f965"]["association"], "shared_following")
        self.assertEqual(rows["7dea671b"]["group_size"], 2)

    def test_bare_hash_before_a_hash_with_its_own_text_is_not_grouped(self):
        text = f"{self.HASH_A}\n{self.HASH_B} svc.dll Backdoor\n"
        rows = {item["value"]: item for item in self.associate(text)}
        self.assertEqual(rows[self.HASH_A]["association"], "hash_only")
        self.assertIsNone(rows[self.HASH_A]["description"])
        self.assertEqual(rows[self.HASH_B]["filename"], "svc.dll")
        self.assertEqual(rows[self.HASH_B]["group_size"], 1)

    def test_filename_inside_a_sentence_line_is_not_taken(self):
        text = f"{self.HASH_A}\nDropper named svc.dll on disk\n"
        row = self.associate(text)[0]
        self.assertIsNone(row["filename"])
        self.assertEqual(row["description"], "Dropper named svc.dll on disk")

    def test_uppercase_hash_is_normalized(self):
        text = f"{self.HASH_A.upper()} SVCHost.dll Backdoor\n"
        self.assertEqual(
            self.associations(text),
            {self.HASH_A: ("SVCHost.dll", "Backdoor")},
        )

    # -- regression for the Play advisory page 8 heading leak ----------

    def test_page8_heading_does_not_leak_into_description(self):
        # Verbatim tail of page 8 of AA23-352A after the second hash.
        text = (
            f"{self.HASH_B}\n"
            "SHA-256 \n"
            "Hash of \n"
            "public \n"
            "ED25519 \n"
            "Key WinSCP \n"
            "Server  \n"
            "End Update \n"
            "MITRE ATT&CK Tactics and Techniques \n"
            "See Table 3 through Table 11 for all referenced threat actor "
            "tactics and techniques in this advisory. \n"
        )
        row = self.associate(text)[0]
        self.assertEqual(
            row["description"],
            "SHA-256 Hash of public ED25519 Key WinSCP Server",
        )
        self.assertNotIn("End Update", row["description"])
        self.assertNotIn("MITRE ATT&CK", row["description"])
        self.assertNotIn("See Table 3", row["description"])

    def test_page8_pair_keeps_identical_clean_description(self):
        text = (
            "511F63455CA4F83B0347B65DDA17585AD02591A9F23D8E234E5CE1321AA3381A\n"
            "SHA-256\nHash of\npublic\nED25519\nKey WinSCP\nServer\n"
            "372F7B45A141BB0709D578BC716CBCA03104258822C4290CCBEB600223850158\n"
            "SHA-256\nHash of\npublic\nED25519\nKey WinSCP\nServer\n"
            "End Update\n"
            "MITRE ATT&CK Tactics and Techniques\n"
        )
        rows = {r["value"][:8]: r for r in self.associate(text)}
        self.assertEqual(
            rows["511f6345"]["description"],
            "SHA-256 Hash of public ED25519 Key WinSCP Server",
        )
        self.assertEqual(
            rows["372f7b45"]["description"],
            "SHA-256 Hash of public ED25519 Key WinSCP Server",
        )


class HashContextIntegrationTests(unittest.TestCase):
    PAGE = HashTableAssociationTests.PAGE6

    def context_findings(self):
        pages = [{"page": 6, "text": self.PAGE}]
        found = ex.detect_indicators(pages)
        ex.attach_hash_context(found, ex.build_hash_context(pages))
        return {
            item["value"][:8]: item for item in found if item["type"] == "sha256"
        }

    def test_hash_findings_get_context(self):
        item = self.context_findings()["47b7b2dd"]
        self.assertEqual(item["context"]["filename"], "SVCHost.dll")
        self.assertEqual(item["context"]["description"], "Backdoor")
        self.assertEqual(item["context"]["association"], "following_lines")
        self.assertFalse(item["context"]["truncated"])

    def test_grouped_hashes_are_labelled_shared(self):
        item = self.context_findings()["453257c3"]
        self.assertEqual(item["context"]["association"], "shared_following")
        self.assertEqual(item["context"]["group_size"], 3)

    def test_hash_without_nearby_text_gets_no_context(self):
        text = "SHA256\n" + HashTableAssociationTests.HASH_A + "\n"
        pages = [{"page": 1, "text": text}]
        found = ex.detect_indicators(pages)
        ex.attach_hash_context(found, ex.build_hash_context(pages))
        hashes = [f for f in found if f["type"] == "sha256"]
        self.assertEqual(len(hashes), 1)
        self.assertNotIn("context", hashes[0])

    def test_context_is_only_added_to_hash_findings(self):
        text = "CVE-2023-27350 and T1486 were used\n" + self.PAGE
        pages = [{"page": 1, "text": text}]
        found = ex.detect_indicators(pages)
        ex.attach_hash_context(found, ex.build_hash_context(pages))
        for item in found:
            if item["type"] not in ex.HASH_TYPES:
                self.assertNotIn("context", item)

    def test_group_carries_the_first_context(self):
        pages = [{"page": 6, "text": self.PAGE}]
        found = ex.detect_indicators(pages)
        ex.attach_hash_context(found, ex.build_hash_context(pages))
        groups = {
            g["value"][:8]: g
            for g in ex.group_indicators(found)
            if g["type"] == "sha256"
        }
        self.assertEqual(groups["0e408aed"]["context"]["filename"], "HRsword.exe")

    def test_group_without_context_has_no_context_key(self):
        found = ex.detect_indicators([{"page": 1, "text": "CVE-2023-27350"}])
        self.assertNotIn("context", ex.group_indicators(found)[0])

    def test_context_is_matched_per_page(self):
        pages = [
            {"page": 1, "text": self.PAGE},
            {"page": 2, "text": HashTableAssociationTests.HASH_A + "\n"},
        ]
        context = ex.build_hash_context(pages)
        self.assertNotIn((2, HashTableAssociationTests.HASH_A), context)
        self.assertIn(
            (1, "47b7b2dd88959cd7224a5542ae8d5bce928bfc986bf0d0321532a7515c244a1e"),
            context,
        )


if __name__ == "__main__":
    unittest.main()