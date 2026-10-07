"""What the HTTP layer sends when nobody asked it to send anything.

`urllib` adds no `Accept` header at all. Every other client sends one - curl and
browsers default to `*/*` - and some servers do not tolerate its absence:
Scorpio answers an NGSI-LD query with no Accept with

    406 {"title":"Not an acceptable request.",
         "detail":{"message":"Provided accept types are not supported"}}

That is how the last step of the EDC flow failed on a deployment where
everything else worked. The negotiation finalized, the transfer started, the EDR
was fetched, the token validated at the gateway and the request reached the
broker - which then refused it over a header the tool never sent. Measured
against demo's Scorpio: 406 with no header, 200 with `*/*`.

`*/*` is strictly more permissive than sending nothing, so this cannot take a
response away from a check that was working.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fdsc_verify import http  # noqa: E402


class Captured:
    """Stand in for urlopen and remember the request it was handed."""

    def __init__(self):
        self.request = None

    def __call__(self, req, timeout=None, **kw):
        self.request = req
        raise RuntimeError("stop here; the headers are what this test is about")


class TestTheAcceptHeader(unittest.TestCase):
    def setUp(self):
        self.captured = Captured()
        self._real = http.urllib.request.build_opener
        http.urllib.request.build_opener = lambda *a, **k: type(
            "O", (), {"open": self.captured})()

    def tearDown(self):
        http.urllib.request.build_opener = self._real

    def _headers(self, **kw):
        http.get("https://example.org/thing", **kw)
        # urllib title-cases header names as they are added
        return {k.lower(): v for k, v in self.captured.request.header_items()}

    def test_every_request_says_what_it_accepts(self):
        self.assertEqual(self._headers().get("accept"), "*/*")

    def test_a_caller_that_cares_still_wins(self):
        headers = self._headers(headers={"Accept": "application/ld+json"})
        self.assertEqual(headers.get("accept"), "application/ld+json")

    def test_it_does_not_disturb_the_other_headers(self):
        headers = self._headers(headers={"Authorization": "Bearer x"})
        self.assertEqual(headers.get("authorization"), "Bearer x")
        self.assertEqual(headers.get("accept"), "*/*")


if __name__ == "__main__":
    unittest.main()
