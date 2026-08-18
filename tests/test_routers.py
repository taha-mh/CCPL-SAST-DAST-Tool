"""
Regression Tests for FastAPI Router Endpoints (targets, reports, scan).
"""

import unittest
from fastapi.testclient import TestClient
from main import app


class TestFastAPIRouters(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_targets_endpoint(self):
        """Verify GET /api/targets returns 200 OK and valid targets structure."""
        response = self.client.get("/api/targets")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("targets", data)
        self.assertIsInstance(data["targets"], list)

    def test_reports_html_endpoint(self):
        """Verify GET /api/reports/html returns 200 OK or 404 cleanly."""
        response = self.client.get("/api/reports/html")
        self.assertIn(response.status_code, [200, 404])

    def test_reports_md_endpoint(self):
        """Verify GET /api/reports/md returns 200 OK or 404 cleanly."""
        response = self.client.get("/api/reports/md")
        self.assertIn(response.status_code, [200, 404])

    def test_root_frontend_dashboard(self):
        """Verify GET / serves frontend dashboard or API status message."""
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)

    def test_scan_invalid_target_404(self):
        """Verify POST /api/scan with non-existent target returns 404."""
        response = self.client.post(
            "/api/scan",
            json={"target_name": "NON_EXISTENT_TARGET_XYZ", "pipeline": "web_sast"}
        )
        self.assertEqual(response.status_code, 404)


if __name__ == "__main__":
    unittest.main()
