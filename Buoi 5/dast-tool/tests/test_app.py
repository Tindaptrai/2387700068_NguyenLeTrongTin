import unittest

from app import app


class TestSandboxAPI(unittest.TestCase):
    def setUp(self):
        app.config.update(TESTING=True, PROPAGATE_EXCEPTIONS=False)
        self.client = app.test_client()

    def test_rejects_non_object_json(self):
        bodies = ('[1]', '[]', '"echo test"', '""', '1', '0', 'true', 'false', 'null')
        for body in bodies:
            with self.subTest(body=body):
                response = self.client.post(
                    "/api/sandbox", data=body, content_type="application/json"
                )
                self.assertEqual(response.status_code, 400)
                self.assertIn("error", response.get_json())

    def test_rejects_malformed_json(self):
        response = self.client.post(
            "/api/sandbox", data='{"command":', content_type="application/json"
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("error", response.get_json())

    def test_rejects_empty_object(self):
        response = self.client.post("/api/sandbox", json={})
        self.assertEqual(response.status_code, 400)
        self.assertIn("error", response.get_json())

    def test_allowed_echo_returns_output(self):
        response = self.client.post("/api/sandbox", json={"command": "echo test"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), {"stdout": "test\n", "stderr": ""})

    def test_rejects_other_commands(self):
        response = self.client.post("/api/sandbox", json={"command": "python -V"})
        self.assertEqual(response.status_code, 400)
        self.assertIn("error", response.get_json())
