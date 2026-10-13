import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

import gcp_probe


class MetadataProbeTests(unittest.TestCase):
    def test_probe_does_not_request_or_return_access_token(self):
        requested_urls = []

        class MockResponse:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc_value, traceback):
                return False

            def read(self, limit):
                return b"mocked-metadata"

        def mocked_urlopen(request, timeout):
            requested_urls.append(request.full_url)
            return MockResponse()

        output = io.StringIO()
        with patch("gcp_probe.urllib.request.urlopen", side_effect=mocked_urlopen):
            with redirect_stdout(output):
                results = gcp_probe.probe_metadata()

        token_url = (
            gcp_probe.METADATA_URL
            + "instance/service-accounts/default/token"
        )
        self.assertNotIn(token_url, requested_urls)
        self.assertNotIn("instance_service-accounts_default_token", results)
        self.assertNotIn("token", output.getvalue().lower())
        self.assertIn(
            "instance_service-accounts_default_email",
            results,
        )


if __name__ == "__main__":
    unittest.main()
