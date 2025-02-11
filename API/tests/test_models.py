import unittest
from models.vulnerabilities import Vulnerability

class TestModels(unittest.TestCase):
    def test_vulnerability_creation(self):
        vuln = Vulnerability(
            title="Test",
            cve="CVE-2025-1234",
            criticality=5,
            description="Test description"
        )
        self.assertEqual(vuln.title, "Test")
        self.assertEqual(vuln.cve, "CVE-2025-1234")
        self.assertEqual(vuln.criticality, 5)
        self.assertEqual(vuln.description, "Test description")

if __name__ == "__main__":
    unittest.main()
