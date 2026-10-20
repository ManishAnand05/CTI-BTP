import itertools
import os
import unittest

from backend import database
from backend import policy_engine as pe
from backend import policy_simulation as sim
from backend.prrabe_interface import get_backend


SENSITIVITIES = pe.SENSITIVITY_LEVELS
SECTOR_CHOICES = [["Finance"], ["Healthcare"], ["Finance", "Healthcare"], ["All"]]


class SyntheticDatabaseMixin:
    """Each test runs on a throwaway database with a fresh mock PR-RABE."""

    def setUp(self):
        self._env = sim.synthetic_environment()
        self._env.__enter__()

    def tearDown(self):
        self._env.__exit__(None, None, None)

    def decision(self, org_id, record_id):
        return pe.generate_advanced_access_policy(org_id, record_id)["decision"]

    def events(self, event_type):
        return pe.list_policy_events(event_type=event_type, limit=500)

    def summary(self, events):
        return [(e["event_type"], e["attribute"]) for e in events]


# --------------------------------------------------
# DECISION TABLES
# --------------------------------------------------

class TestClassification(unittest.TestCase):

    def test_high_water_mark_takes_highest_factor(self):
        self.assertEqual(pe.classify("High", "GREEN", "Verified")[0], "Confidential")
        self.assertEqual(pe.classify("Low", "RED", "Verified")[0], "Restricted")

    def test_unverified_record_is_at_least_internal(self):
        self.assertEqual(pe.classify("Low", "CLEAR", "Under Review")[0], "Internal")

    def test_corroboration_counts_as_verification(self):
        level, _ = pe.classify("Low", "CLEAR", "Under Review", corroborating_orgs=2)
        self.assertEqual(level, "Public")

    def test_disputed_record_is_at_least_confidential(self):
        self.assertEqual(pe.classify("Low", "CLEAR", "Disputed")[0], "Confidential")

    def test_unknown_risk_level_fails_closed(self):
        self.assertEqual(pe.classify("Bogus", "CLEAR", "Verified")[0], "Restricted")

    def test_invalid_tlp_is_rejected(self):
        with self.assertRaises(ValueError):
            pe.classify("Low", "PURPLE")


class TestPolicyBuilding(unittest.TestCase):

    def test_multi_sector_confidential_policy(self):
        policy = pe.build_policy("Confidential", ["Healthcare", "Finance"])
        self.assertEqual(
            pe.policy_to_string(policy),
            "(Sector:Finance OR Sector:Healthcare) AND Trust>=High",
        )

    def test_broadcast_internal_policy_has_no_sector_clause(self):
        self.assertEqual(
            pe.policy_to_string(pe.build_policy("Internal", ["All"])),
            "Trust>=Medium",
        )

    def test_restricted_broadcast_falls_back_to_owner_sectors(self):
        policy = pe.build_policy("Restricted", ["All"], owner_sectors=["Energy"])
        self.assertEqual(pe.policy_to_string(policy), "Sector:Energy AND Trust>=High")

    def test_restricted_broadcast_without_owner_is_not_shared(self):
        self.assertIsNone(pe.build_policy("Restricted", ["All"]))

    def test_sectors_are_validated(self):
        with self.assertRaises(ValueError):
            pe.normalize_sectors(["Finanse"])
        self.assertEqual(pe.normalize_sectors(["finance", "All"]), ["All"])


class TestAttributes(unittest.TestCase):

    def test_trust_attributes_are_cumulative(self):
        attrs, rule = pe.compute_attributes(["Finance", "Healthcare"], "High")
        self.assertEqual(attrs, {
            "Sector:Finance", "Sector:Healthcare",
            "Trust>=Low", "Trust>=Medium", "Trust>=High",
        })
        self.assertIsNone(rule)

    def test_inactive_org_gets_no_attributes(self):
        attrs, rule = pe.compute_attributes(["Finance"], "High", is_active=False)
        self.assertEqual(attrs, set())
        self.assertEqual(rule, "Organization is inactive")

    def test_trust_level_input_is_validated(self):
        self.assertEqual(pe.normalize_trust_level("high"), "High")
        with self.assertRaises(ValueError):
            pe.normalize_trust_level("Very High")


# --------------------------------------------------
# FORMAL PROPERTIES (checked exhaustively over the small domain)
# --------------------------------------------------

class TestPolicyProperties(unittest.TestCase):

    def cases(self):
        for sensitivity, record_sectors, org_sectors, level in itertools.product(
            SENSITIVITIES, SECTOR_CHOICES, SECTOR_CHOICES[:3], pe.TRUST_LEVELS
        ):
            policy = pe.build_policy(sensitivity, record_sectors, owner_sectors=["Energy"])
            attrs, _ = pe.compute_attributes(org_sectors, level)
            yield sensitivity, record_sectors, org_sectors, policy, attrs, level

    def test_no_read_up(self):
        for sensitivity, _, _, policy, attrs, level in self.cases():
            if pe.satisfies(attrs, policy):
                self.assertGreaterEqual(
                    pe.TRUST_LEVELS.index(level),
                    pe.TRUST_LEVELS.index(pe.REQUIRED_TRUST[sensitivity]),
                )

    def test_monotonicity(self):
        for _, _, org_sectors, policy, attrs, level in self.cases():
            if not pe.satisfies(attrs, policy):
                continue
            for higher in pe.TRUST_LEVELS[pe.TRUST_LEVELS.index(level):]:
                for extra in pe.VALID_SECTORS:
                    more, _ = pe.compute_attributes(org_sectors + [extra], higher)
                    self.assertTrue(pe.satisfies(more, policy))

    def test_sector_isolation(self):
        for sensitivity, record_sectors, org_sectors, policy, attrs, _ in self.cases():
            if (
                sensitivity in pe.SECTOR_BOUND_LEVELS
                and record_sectors != ["All"]
                and not set(record_sectors) & set(org_sectors)
            ):
                self.assertFalse(pe.satisfies(attrs, policy))

    def test_default_deny(self):
        self.assertFalse(pe.satisfies({"Trust>=High", "Sector:Finance"}, None))
        for sensitivity in SENSITIVITIES:
            self.assertFalse(pe.satisfies(set(), pe.build_policy(sensitivity, ["Finance"])))


# --------------------------------------------------
# EVENT-DRIVEN ENFORCEMENT
# --------------------------------------------------

class TestSlide17Scenario(SyntheticDatabaseMixin, unittest.TestCase):
    """Org B's trust drops; only Org B loses Confidential Finance CTI."""

    def setUp(self):
        super().setUp()
        self.owner = sim.add_org("Owner", ["Finance"], "Medium")
        self.org_a = sim.add_org("Org A", ["Finance"], "High")
        self.org_b = sim.add_org("Org B", ["Finance", "Healthcare"], "High")
        self.org_c = sim.add_org("Org C", ["Healthcare"], "High")
        self.record = sim.add_record([self.owner], ["Finance"], "High")

    def test_initial_policy_and_decisions(self):
        entry = pe.get_record_policy(self.record)
        self.assertEqual(entry["sensitivity"], "Confidential")
        self.assertEqual(entry["policy_text"], "Sector:Finance AND Trust>=High")
        self.assertEqual(self.decision(self.org_a, self.record), "ALLOW")
        self.assertEqual(self.decision(self.org_b, self.record), "ALLOW")
        self.assertEqual(self.decision(self.org_c, self.record), "DENY")
        self.assertEqual(self.decision(self.owner, self.record), "ALLOW")

    def test_trust_drop_revokes_one_attribute_and_nothing_else(self):
        backend = get_backend()
        versions = {a: g["version"] for a, g in backend.groups.items()}
        attrs_a = pe.get_org_policy_state(self.org_a)["attributes"]
        rewraps = len(self.events("REWRAP"))

        events = pe.update_trust(self.org_b, "Medium")

        self.assertEqual(self.summary(events), [("REVOKE", "Trust>=High")])
        self.assertEqual(self.decision(self.org_b, self.record), "DENY")
        self.assertEqual(self.decision(self.org_a, self.record), "ALLOW")
        self.assertEqual(pe.get_org_policy_state(self.org_a)["attributes"], attrs_a)

        rotated = {a for a, g in backend.groups.items() if g["version"] != versions.get(a)}
        self.assertEqual(rotated, {"Trust>=High"})
        self.assertEqual(len(self.events("REWRAP")), rewraps)

        logged = self.events("REVOKE")[0]
        self.assertEqual(logged["trigger"], "trust_changed")
        self.assertEqual((logged["old_value"], logged["new_value"]), ("High", "Medium"))
        self.assertIsNotNone(logged["latency_ms"])

    def test_unchanged_trust_level_does_nothing(self):
        self.assertEqual(pe.update_trust(self.org_b, "High"), [])

    def test_trust_recovery_grants_again(self):
        pe.update_trust(self.org_b, "Medium")
        events = pe.update_trust(self.org_b, "High")
        self.assertEqual(self.summary(events), [("GRANT", "Trust>=High")])
        self.assertEqual(self.decision(self.org_b, self.record), "ALLOW")

    def test_leaving_a_sector_revokes_only_that_sector(self):
        events = pe.set_org_sectors(self.org_b, ["Healthcare"])
        self.assertEqual(self.summary(events), [("REVOKE", "Sector:Finance")])
        self.assertEqual(self.decision(self.org_b, self.record), "DENY")

    def test_deactivation_made_elsewhere_is_picked_up_on_access(self):
        database.set_organization_status(self.org_a, False)
        result = pe.generate_advanced_access_policy(self.org_a, self.record)
        self.assertEqual(result["decision"], "DENY")
        self.assertEqual(result["reason"], "Organization is inactive")
        revoked = {e["attribute"] for e in self.events("REVOKE")}
        self.assertEqual(
            revoked, {"Sector:Finance", "Trust>=Low", "Trust>=Medium", "Trust>=High"}
        )

    def test_access_decisions_are_audited(self):
        self.decision(self.org_c, self.record)
        logged = self.events("ACCESS")[0]
        self.assertEqual(logged["organization_id"], self.org_c)
        self.assertEqual(logged["new_value"], "DENY")


class TestRecordChanges(SyntheticDatabaseMixin, unittest.TestCase):

    def setUp(self):
        super().setUp()
        self.owner = sim.add_org("Owner", ["Energy"], "Medium")
        self.medium = sim.add_org("Medium Org", ["Finance"], "Medium")
        self.record = sim.add_record([self.owner], ["All"], "Medium")

    def test_new_record_gets_policy_set_event(self):
        events = self.events("POLICY_SET")
        self.assertEqual([e["new_value"] for e in events], ["Trust>=Medium"])
        self.assertEqual(self.decision(self.medium, self.record), "ALLOW")

    def test_sensitivity_increase_rewraps_and_denies(self):
        event = pe.set_record_labels(self.record, tlp="AMBER")
        self.assertEqual(event["event_type"], "REWRAP")
        self.assertEqual(event["sensitivity"], "Confidential")
        self.assertEqual(event["key_version"], 2)
        self.assertEqual(self.decision(self.medium, self.record), "DENY")

    def test_unchanged_policy_does_not_rewrap(self):
        self.assertIsNone(pe.set_record_labels(self.record, tlp="GREEN"))

    def test_status_change_made_elsewhere_is_picked_up_on_access(self):
        with database.get_connection() as connection:
            connection.execute(
                "UPDATE cti_records SET status = 'Rejected' WHERE id = ?",
                (self.record,),
            )
        result = pe.generate_advanced_access_policy(self.medium, self.record)
        self.assertEqual(result["decision"], "DENY")
        self.assertEqual(result["policy_string"], "NONE")
        self.assertEqual(self.events("REWRAP")[0]["trigger"], "reconcile")
        self.assertEqual(self.decision(self.owner, self.record), "ALLOW")

    def test_response_keeps_access_control_page_format(self):
        result = pe.generate_advanced_access_policy(self.medium, self.record)
        self.assertIsInstance(result["policy"], dict)
        self.assertTrue(all(isinstance(v, str) for v in result["policy"].values()))


class TestTrustInput(SyntheticDatabaseMixin, unittest.TestCase):

    def test_without_trust_engine_the_existing_score_is_used(self):
        with database.get_connection() as connection:
            org_id = connection.execute(
                "INSERT INTO organizations (name, sector, trust_score) VALUES ('X', 'Finance', 85)"
            ).lastrowid
        self.assertEqual(pe.get_org_policy_state(org_id)["trust_level"], "High")

    def test_trust_engine_level_takes_precedence(self):
        org_id = sim.add_org("Y", ["Finance"], "Low")
        with database.get_connection() as connection:
            connection.execute("UPDATE organizations SET trust_score = 95 WHERE id = ?", (org_id,))
        self.assertEqual(pe.get_org_policy_state(org_id)["trust_level"], "Low")


class TestMockPRRABE(SyntheticDatabaseMixin, unittest.TestCase):

    def test_encrypt_decrypt_follows_attributes(self):
        finance = sim.add_org("Fin", ["Finance"], "High")
        health = sim.add_org("Health", ["Healthcare"], "High")
        bundle = get_backend().encrypt(
            b"c2: 203.0.113.7", pe.build_policy("Confidential", ["Finance"])
        )

        self.assertEqual(get_backend().decrypt(finance, bundle), b"c2: 203.0.113.7")
        with self.assertRaises(PermissionError):
            get_backend().decrypt(health, bundle)

        pe.update_trust(finance, "Medium")
        with self.assertRaises(PermissionError):
            get_backend().decrypt(finance, bundle)


class TestSimulation(unittest.TestCase):

    def test_engine_agrees_with_oracle_on_synthetic_workload(self):
        report = sim.run(n_orgs=20, n_records=60, n_changes=40, seed=3, sample=150)
        self.assertEqual(report["decisions_disagreeing_with_oracle"], 0)
        self.assertEqual(report["records_reencrypted_by_trust_changes"], 0)
        self.assertEqual(report["attribute_events_per_change"]["max"], 1)


class TestExistingRoute(SyntheticDatabaseMixin, unittest.TestCase):
    """The unmodified /api/advanced-policies route uses the new engine."""

    def test_route_returns_engine_decision(self):
        os.environ.setdefault("CTI_SECRET_KEY", "x" * 40)
        from backend.app import app
        from backend.authentication import create_access_token, register_user

        org = sim.add_org("Home", ["Finance"], "Medium")
        record = sim.add_record([sim.add_org("Other", ["Energy"])], ["Finance"], "Low")
        user = register_user("Ana", "ana@example.org", "password123", org)

        response = app.test_client().post(
            "/api/advanced-policies",
            json={"organization_id": org, "record_id": record},
            headers={"Authorization": f"Bearer {create_access_token(user['id'])}"},
        )
        body = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(body["decision"], "ALLOW")
        self.assertEqual(body["policy"]["Required policy"], "Trust>=Medium")


if __name__ == "__main__":
    unittest.main()
