
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from backend.app import app


class EvidenceTimelineTests(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_cti.db"

        self.connection = sqlite3.connect(self.db_path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")

        self.create_schema()
        self.seed_data()

        self.connection.commit()
        self.connection.close()

        # Redirect this test's API database connections to the
        # temporary database, leaving data/cti.db untouched.
        self.connection_patcher = patch(
            "backend.advanced_cti.get_connection",
            side_effect=self.get_test_connection,
        )
        self.connection_patcher.start()

        self.client = app.test_client()

    def tearDown(self):
        self.connection_patcher.stop()
        self.temp_dir.cleanup()

    def get_test_connection(self):
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def create_schema(self):
        self.connection.executescript(
            """
            CREATE TABLE organizations (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                sector TEXT NOT NULL
            );

            CREATE TABLE cti_records (
                id INTEGER PRIMARY KEY,
                category TEXT NOT NULL,
                indicator_type TEXT NOT NULL,
                indicator_value TEXT,
                title TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                severity TEXT NOT NULL,
                confidence TEXT NOT NULL,
                sharing_sector TEXT NOT NULL DEFAULT 'All',
                stix_data TEXT NOT NULL DEFAULT '',
                risk_score INTEGER NOT NULL DEFAULT 0,
                risk_level TEXT NOT NULL DEFAULT 'Low',
                status TEXT NOT NULL DEFAULT 'Under Review',
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE cti_submissions (
                id INTEGER PRIMARY KEY,
                cti_record_id INTEGER NOT NULL,
                organization_id INTEGER NOT NULL,
                source_type TEXT NOT NULL,
                source_reliability TEXT NOT NULL,
                observed_at TEXT,
                submitted_severity TEXT NOT NULL,
                confidence TEXT NOT NULL,
                evidence TEXT DEFAULT '',
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (cti_record_id)
                    REFERENCES cti_records(id),
                FOREIGN KEY (organization_id)
                    REFERENCES organizations(id)
            );
            """
        )

    def seed_data(self):
        self.connection.execute(
            """
            INSERT INTO organizations (id, name, sector)
            VALUES (1, 'Test Organization', 'Finance')
            """
        )

        # Record 1: no observation timestamps.
        # Record 2: one timestamp present, one missing.
        # Record 3: every submission has a timestamp.
        records = [
            (1, "Missing timestamps"),
            (2, "Partial timestamps"),
            (3, "Complete timestamps"),
        ]

        for record_id, title in records:
            self.connection.execute(
                """
                INSERT INTO cti_records (
                    id, category, indicator_type, indicator_value,
                    title, description, severity, confidence,
                    sharing_sector, stix_data, risk_score, risk_level
                )
                VALUES (?, 'network', 'ip', ?, ?, '',
                        'high', 'medium', 'Finance', '{}', 50, 'Medium')
                """,
                (record_id, f"192.0.2.{record_id}", title),
            )

        submissions = [
            # Record 1: missing
            (1, None, "high"),
            (1, None, "critical"),

            # Record 2: partial
            (2, "2026-10-10T10:00:00Z", "high"),
            (2, None, "medium"),

            # Record 3: complete
            (3, "2026-10-10T10:00:00Z", "high"),
            (3, "2026-10-10T11:00:00Z", "high"),
        ]

        for record_id, observed_at, severity in submissions:
            self.connection.execute(
                """
                INSERT INTO cti_submissions (
                    cti_record_id,
                    organization_id,
                    source_type,
                    source_reliability,
                    observed_at,
                    submitted_severity,
                    confidence,
                    evidence
                )
                VALUES (?, 1, 'threat_research', 'verified',
                        ?, ?, 'high', '')
                """,
                (record_id, observed_at, severity),
            )

    def get_timeline(self, record_id):
        return self.client.get(
            f"/api/cti/advanced/{record_id}/evidence-timeline"
        )

    def test_existing_record_returns_timeline(self):
        response = self.get_timeline(1)

        self.assertEqual(response.status_code, 200)

        data = response.get_json()

        self.assertIn("record", data)
        self.assertIn("timeline", data)
        self.assertEqual(data["submission_count"], 2)

    def test_nonexistent_record_returns_404(self):
        response = self.get_timeline(999999)

        self.assertEqual(response.status_code, 404)
        self.assertEqual(
            response.get_json()["error"],
            "CTI record not found.",
        )

    def test_record_reports_severity_conflict(self):
        response = self.get_timeline(1)

        self.assertEqual(response.status_code, 200)

        data = response.get_json()

        self.assertTrue(data["severity_conflict"])
        self.assertEqual(
            set(data["reported_severities"]),
            {"high", "critical"},
        )

    def test_missing_observation_times_are_reported(self):
        response = self.get_timeline(1)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.get_json()["observation_time_status"],
            "missing",
        )

    def test_partial_observation_times_are_reported(self):
        response = self.get_timeline(2)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.get_json()["observation_time_status"],
            "partial",
        )

    def test_complete_observation_times_are_reported(self):
        response = self.get_timeline(3)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.get_json()["observation_time_status"],
            "complete",
        )

    def test_timeline_preserves_observation_and_submission_times(self):
        response = self.get_timeline(3)

        self.assertEqual(response.status_code, 200)

        data = response.get_json()
        first_submission = data["timeline"][0]

        self.assertEqual(
            first_submission["observed_at"],
            "2026-10-10T10:00:00Z",
        )
        self.assertIn("submitted_at", first_submission)
        self.assertNotEqual(
            first_submission["observed_at"],
            first_submission["submitted_at"],
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
