
import unittest
from datetime import datetime, timezone

from backend.temporal_intelligence import analyze_submission


class TemporalIntelligenceTests(unittest.TestCase):

    def setUp(self):
        self.now = datetime(
            2026, 10, 17, 12, 0, 0, tzinfo=timezone.utc
        )

    def make_submission(self, observed_at, created_at):
        return {
            "id": 101,
            "cti_record_id": 10,
            "organization_id": 1,
            "source_type": "threat_research",
            "source_reliability": "verified",
            "observed_at": observed_at,
            "created_at": created_at,
            "submitted_severity": "high",
            "confidence": "high",
        }

    def test_valid_reporting_delay(self):
        submission = self.make_submission(
            "2026-10-17T11:00:00Z",
            "2026-10-17T12:00:00Z",
        )

        result = analyze_submission(submission, self.now)

        self.assertEqual(result["reporting_delay_hours"], 1.0)
        self.assertEqual(result["reporting_delay_status"], "valid")

    def test_missing_observation_time(self):
        submission = self.make_submission(
            None,
            "2026-10-17T12:00:00Z",
        )

        result = analyze_submission(submission, self.now)

        self.assertIsNone(result["reporting_delay_hours"])
        self.assertEqual(result["reporting_delay_status"], "unknown")
        self.assertEqual(result["freshness_status"], "unknown")

    def test_submission_before_observation(self):
        submission = self.make_submission(
            "2026-10-17T13:00:00Z",
            "2026-10-17T12:00:00Z",
        )

        result = analyze_submission(submission, self.now)

        self.assertEqual(
            result["reporting_delay_hours"], -1.0
        )
        self.assertEqual(
            result["reporting_delay_status"],
            "submission_before_observation",
        )
        self.assertTrue(result["warnings"])

    def test_stale_observation(self):
        submission = self.make_submission(
            "2026-09-01T12:00:00Z",
            "2026-10-17T12:00:00Z",
        )

        result = analyze_submission(submission, self.now)

        self.assertEqual(result["freshness_status"], "stale")
        self.assertEqual(result["age_days"], 46.0)

    def test_custom_freshness_window(self):
        submission = self.make_submission(
            "2026-10-07T12:00:00Z",
            "2026-10-17T12:00:00Z",
        )

        result = analyze_submission(
            submission,
            self.now,
            freshness_window_days=5,
        )

        self.assertEqual(result["age_days"], 10.0)
        self.assertEqual(result["freshness_status"], "stale")


if __name__ == "__main__":
    unittest.main()
