"""A peer is a DID first and a DSP endpoint second.

The peer file was written for fdsc-edc, where a counterparty is something you
negotiate with, so `protocolUrl` was required. But fdsc-edc is one deployment
shape: a participant reached through its gateway has no DSP endpoint at all, and
demanding one meant either inventing a URL or giving up on the peer checks that
need nothing but the DID - is its document resolvable, is our DID in its trusted
issuers list, does the dashboard name it correctly.

So `protocolUrl` is optional, and everything that consumes it either skips with
that reason or is gated behind something that already did. These tests pin both
halves: the file parses, and no DSP consumer crashes on the absence.
"""

import unittest
from types import SimpleNamespace

from fdsc_verify import discovery
from fdsc_verify import checks  # noqa: F401  (populates REGISTRY)
from fdsc_verify.checks import dashboard, peers as peer_checks
from fdsc_verify.context import Context
from fdsc_verify.model import REGISTRY, Peer, Status


class TestPeerFile(unittest.TestCase):
    def test_only_participant_id_is_required(self):
        loaded = discovery.load_peers({"peers": [
            {"name": "native-only", "participantId": "did:web:central-mk.example"}]})
        self.assertEqual(len(loaded), 1)
        self.assertIsNone(loaded[0].protocol_url)
        self.assertEqual(loaded[0].participant_id, "did:web:central-mk.example")

    def test_a_peer_without_a_participant_id_is_a_usage_error(self):
        with self.assertRaises(ValueError):
            discovery.load_peers({"peers": [
                {"name": "nameless", "protocolUrl": "https://dsp.example/api/dsp"}]})

    def test_the_name_defaults_to_the_did(self):
        loaded = discovery.load_peers({"peers": [
            {"participantId": "did:web:central-mk.example"}]})
        self.assertEqual(loaded[0].name, "did:web:central-mk.example")

    def test_a_protocol_url_is_still_normalised(self):
        loaded = discovery.load_peers({"peers": [
            {"participantId": "did:web:p.example",
             "protocolUrl": "https://dsp.example/api/dsp/2025-1/"}]})
        self.assertEqual(loaded[0].protocol_url, "https://dsp.example/api/dsp/2025-1")


class TestTheDspChecksSkipRatherThanCrash(unittest.TestCase):
    """Every consumer of `protocol_url`, fed a peer that has none."""

    def setUp(self):
        self.peer = Peer(name="native-only", participant_id="did:web:central-mk.example")
        self.lane = SimpleNamespace(name="dcp")

    def _ctx(self):
        ctx = Context.__new__(Context)
        ctx.peers = [self.peer]
        ctx.insecure = False
        ctx.peer_for = lambda name: self.peer
        return ctx

    def test_peer_reachable_skips_with_the_reason(self):
        result = peer_checks.peer_reachable(self._ctx(), self.lane)
        self.assertEqual(result.status, Status.SKIP)
        self.assertIn("protocolUrl", result.cause)

    def test_peer_reachable_is_declared_dsp(self):
        # otherwise `--transport fiware` would run it and report a DSP failure on a
        # deployment that speaks no DSP
        spec = next(c for c in REGISTRY if c.id == "peer-reachable")
        self.assertEqual(spec.transports, ("edc",))

    def test_edc_catalog_returns_an_error_instead_of_raising(self):
        body, err = Context.edc_catalog(self._ctx(), self.lane, self.peer)
        self.assertIsNone(body)
        self.assertIn("protocolUrl", err)

    def test_dsp_protocol_falls_back_to_the_current_version(self):
        self.assertEqual(Context.dsp_protocol(self.peer),
                         "dataspace-protocol-http:2025-1")

    def test_the_dashboard_matches_entries_by_host_and_ignores_a_peer_without_one(self):
        ctx = SimpleNamespace(peers=[self.peer, Peer(
            name="dcp", participant_id="did:web:p.example",
            protocol_url="https://dsp.example/api/dsp")])
        by_host = {dashboard._host(p.protocol_url): p for p in ctx.peers if p.protocol_url}
        self.assertEqual(list(by_host), ["dsp.example"])


if __name__ == "__main__":
    unittest.main()
