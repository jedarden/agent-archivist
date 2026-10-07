#!/usr/bin/env python3
"""Credential-free regressions for the live qualification transport."""

import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import MagicMock, patch


SPEC = importlib.util.spec_from_file_location(
    "live_storage_lane", Path(__file__).with_name("live-storage-lane.py")
)
LANE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LANE)


class RequestSigningTests(unittest.TestCase):
    def test_transport_host_is_signed_and_kept_out_of_evidence(self):
        for endpoint, transport, host in (
            ("https://storage.example.invalid", "HTTPSConnection", "storage.example.invalid"),
            ("http://localhost:9000", "HTTPConnection", "localhost:9000"),
        ):
            with self.subTest(endpoint=endpoint):
                response = MagicMock(status=200)
                response.read.return_value = b"<ListBucketResult/>"
                response.getheaders.return_value = []
                connection = MagicMock()
                connection.getresponse.return_value = response
                signer = LANE.SigV4("synthetic-access", "synthetic-secret", "test-region")
                lane = LANE.Lane(endpoint, "synthetic-bucket", signer, signer)
                with patch.object(LANE.http.client, transport, return_value=connection):
                    status, _, _ = lane.request(
                        "calibration-list", "raw", "GET", "",
                        headers={"Host": "wrong.example.invalid"},
                    )
                self.assertEqual(status, 200)
                headers = connection.request.call_args.kwargs["headers"]
                signed_names = headers["Authorization"].split("SignedHeaders=", 1)[1].split(",", 1)[0].split(";")
                self.assertIn("host", signed_names)
                self.assertEqual(headers["host"], host)
                self.assertEqual(sum(key.lower() == "host" for key in headers), 1)
                evidence = json.dumps(lane.transcript)
                for private_value in (host, "wrong.example.invalid", "synthetic-access", "synthetic-secret"):
                    self.assertNotIn(private_value, evidence)


if __name__ == "__main__":
    unittest.main()
