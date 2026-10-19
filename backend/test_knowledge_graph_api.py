import unittest
from unittest.mock import patch

from backend.app import app


class KnowledgeGraphAPITests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = app.test_client()

    def test_knowledge_graph_endpoint_returns_json(self):
        response = self.client.get("/api/cti/knowledge-graph")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.mimetype,
            "application/json",
        )

    def test_response_contains_expected_graph_sections(self):
        response = self.client.get("/api/cti/knowledge-graph")

        self.assertEqual(response.status_code, 200)
        data = response.get_json()

        self.assertIn("summary", data)
        self.assertIn("nodes", data)
        self.assertIn("edges", data)
        self.assertIn("conflicts", data)

    def test_graph_summary_matches_returned_data(self):
        response = self.client.get("/api/cti/knowledge-graph")
        self.assertEqual(response.status_code, 200)

        data = response.get_json()
        summary = data["summary"]

        self.assertEqual(summary["node_count"], len(data["nodes"]))
        self.assertEqual(summary["edge_count"], len(data["edges"]))
        self.assertEqual(
            summary["severity_conflict_count"],
            len(data["conflicts"]),
        )

    @patch(
        "backend.advanced_cti.build_knowledge_graph",
        side_effect=RuntimeError("Simulated graph failure"),
    )
    def test_graph_failure_returns_generic_error(self, mocked_builder):
        response = self.client.get("/api/cti/knowledge-graph")

        self.assertEqual(response.status_code, 500)
        self.assertEqual(
            response.get_json(),
            {"error": "Unable to build the CTI knowledge graph"},
        )


if __name__ == "__main__":
    unittest.main()
