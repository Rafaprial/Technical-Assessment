import unittest
from fastapi.testclient import TestClient
from main import app

class TestMain(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_read_root(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"message": "Vulnerability API is running!"})

if __name__ == "__main__":
    unittest.main()
