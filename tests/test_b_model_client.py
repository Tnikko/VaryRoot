"""Offline transport tests; no network requests."""

import json
import os
import tempfile
import unittest
from pathlib import Path

from varyroot.b_model_client import post_once


class _Response:
    status = 200
    headers = {"Content-Type": "application/json"}

    def __init__(self, body):
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self):
        return self.body


class ModelClientTest(unittest.TestCase):
    def test_saves_exact_request_and_response_bodies_before_parsing(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            key = root / "secret.key"
            key.write_text("sk-fixture\n")
            os.chmod(key, 0o600)
            body = json.dumps({"choices": [{"finish_reason": "stop", "message": {
                "content": '{"proposals": []}'}}], "model": "deepseek-flash"}).encode()
            requests = []
            def opener(request, timeout):
                requests.append(request)
                return _Response(body)
            payload = {"model": "deepseek-flash", "messages": [], "max_tokens": 12}
            result = post_once(payload, root / "out", 1, key, root / "project", opener=opener)
            self.assertEqual(result, {"proposals": []})
            self.assertEqual(json.loads((root / "out/round-01.request.json").read_bytes()), payload)
            self.assertEqual((root / "out/round-01.response.json").read_bytes(), body)
            self.assertEqual(json.loads((root / "out/round-01.meta.json").read_text())["status"],
                             "valid_output")
            self.assertNotIn(b"sk-fixture", (root / "out/round-01.request.json").read_bytes())
            self.assertEqual(len(requests), 1)
            with self.assertRaises(FileExistsError):
                post_once(payload, root / "out", 1, key, root / "project", opener=opener)
            self.assertEqual(len(requests), 1)

    def test_length_finish_is_recorded_as_response_failure(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            key = root / "secret.key"
            key.write_text("sk-fixture")
            os.chmod(key, 0o600)
            body = b'{"choices":[{"finish_reason":"length","message":{"content":"{}"}}]}'
            result = post_once({"model": "deepseek-flash", "messages": []}, root / "out", 1,
                               key, root / "project", opener=lambda request, timeout: _Response(body))
            self.assertEqual(result["failure"], "truncated")
            self.assertEqual((root / "out/round-01.response.json").read_bytes(), body)


if __name__ == "__main__":
    unittest.main()
