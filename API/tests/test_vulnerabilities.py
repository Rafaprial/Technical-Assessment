import unittest
from fastapi.testclient import TestClient
from main import app

from dotenv import load_dotenv
import os

load_dotenv()

# Get API key from environment variables
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY")

HEADERS = {"x-api-key": ADMIN_API_KEY}

class TestVulnerabilities(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)
        self.headers = {"x-api-key": ADMIN_API_KEY}

    def test_create_vulnerability(self):
        # This tests the creation of a new vulnerability.
        response = self.client.post("/vulnerability", json={
            "title": "Test",
            "cve": "CVE-0000-1234",
            "criticality": 5,
            "description": "Test description"
        }, headers=self.headers)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data.get("cve"), "CVE-0000-1234")
        self.assertEqual(data.get("title"), "Test")
        self.assertEqual(data.get("criticality"), 5)
        self.assertEqual(data.get("description"), "Test description")

    def test_get_vulnerability(self):
        # This test assumes that the vulnerability with the provided CVE doesn't exist.
        response = self.client.get("/vulnerability/CVE-0000-1234", headers=self.headers)
        self.assertEqual(response.status_code, 404)

    def test_delete_vulnerability(self):
        # This tests deletion for a non-existent vulnerability.
        response = self.client.delete("/vulnerability/CVE-0000-1234", headers=self.headers)
        self.assertEqual(response.status_code, 200)

if __name__ == "__main__":
    unittest.main()
