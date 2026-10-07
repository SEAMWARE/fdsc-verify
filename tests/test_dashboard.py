"""dashboard-config, and the entries it must NOT complain about.

The fault this encodes was found on a real dashboard, where the counterparty's entries
carried the demo's own DID - a copy-paste of its `provider` entry with only the
URL changed. It cost an afternoon because the symptom appears on the *peer's*
side and only when the peer initiates, so everything tested from here looked
healthy.

The negative cases matter as much: a dashboard legitimately lists connectors in
other namespaces (the demo's does, with cross-namespace management URLs), and an
entry whose DID we have no way to verify must not be reported as wrong.
"""

import unittest
from types import SimpleNamespace

from fdsc_verify.checks import dashboard
from fdsc_verify.model import Status

OUR_DID = "did:web:connector.example.es"
DEMO_DID = "did:web:did-provider.example.org:did"


def lane(name, hostname, service=None):
    service = service if service is not None else "provider-fdsc-edc-%s" % name
    return SimpleNamespace(name=name, hostname=hostname, service=service, deployment=service)


def peer(name, url, did):
    return SimpleNamespace(name=name, protocol_url=url, participant_id=did)


def entry(name, url, did, **extra):
    body = {"connectorName": name, "protocolUrl": url, "did": did}
    body.update(extra)
    return body


def context(entries, err=None, our_did=OUR_DID, lanes=(), peers=(), services=("dashboard",)):
    return SimpleNamespace(
        dashboard_connectors=lambda: (entries, err),
        any_participant_id=lambda: our_did,
        deployment=SimpleNamespace(
            edc_lanes={l.name: l for l in lanes},
            # a dashboard that is deployed but unreadable is a gap; one that is not
            # deployed at all is not this check's business
            service=lambda name: name if name in services else None),
        peers=list(peers),
    )


# The four entries that deployment actually serves, as read from the running dashboard.
OUR_LANES = (lane("oid4vc", "dsp.example.es"), lane("dcp", "edc.example.es"))
OUR_ENTRIES = [
    entry("Our FDSC (OID4VC)", "https://dsp.example.es/api/dsp/2025-1", OUR_DID),
    entry("Our FDSC (DCP)", "https://edc.example.es/api/dsp/2025-1", OUR_DID),
    entry("Demo FIWARE DSC (OID4VC)", "https://dsp-provider.example.org/api/dsp/2025-1", DEMO_DID),
    entry("Demo FIWARE DSC (DCP)", "https://dcp-provider.example.org/api/dsp/2025-1", DEMO_DID),
]


class TestHealthy(unittest.TestCase):
    def test_a_real_connector_list_passes(self):
        result = dashboard.dashboard_config(context(OUR_ENTRIES, lanes=OUR_LANES))
        self.assertIs(result.status, Status.OK)
        self.assertIn("4 connector(s)", result.summary)

    def test_a_counterparty_did_we_cannot_verify_is_not_a_finding(self):
        """Without --peer there is nothing to compare a foreign DID against."""
        entries = [entry("Someone", "https://dsp.example.org/api/dsp", "did:web:example.org")]
        result = dashboard.dashboard_config(context(entries, lanes=OUR_LANES))
        self.assertIs(result.status, Status.OK)

    def test_an_entry_with_no_did_is_ignored_rather_than_failed(self):
        entries = OUR_ENTRIES + [{"connectorName": "half configured",
                                  "protocolUrl": "https://x.example.org/api/dsp"}]
        result = dashboard.dashboard_config(context(entries, lanes=OUR_LANES))
        self.assertIs(result.status, Status.OK)

    def test_a_cross_namespace_management_url_is_not_a_finding(self):
        """The demo's dashboard manages connectors in another namespace on purpose."""
        entries = [entry("Producer (DCP)", "https://dcp-provider.example.org/api/dsp", DEMO_DID,
                         managementUrl="http://producer-fdsc-edc-dcp.producer.svc"
                                       ".cluster.local:8085/api/v1/management")]
        result = dashboard.dashboard_config(
            context(entries, our_did="did:web:did-consumer.example.net:did",
                    lanes=(lane("dcp", "dcp-consumer.example.net"),)))
        self.assertIs(result.status, Status.OK)


class TestTellingOurEntriesApart(unittest.TestCase):
    """The classification that decides whether "carries our DID" is a fault.

    Getting this wrong is worse than not checking: it reports a healthy ConfigMap
    as broken, which is how an operator learns to stop reading the output.
    """

    def test_an_entry_reached_by_an_alias_is_recognised_by_its_management_url(self):
        entries = [entry("Ours (DCP)", "https://an-alias.example.es/api/dsp", OUR_DID,
                         managementUrl="http://provider-fdsc-edc-dcp.provider.svc"
                                       ".cluster.local:8085/api/v1/management")]
        result = dashboard.dashboard_config(context(entries, lanes=OUR_LANES))
        self.assertIs(result.status, Status.OK, result.cause)

    def test_with_no_lanes_it_skips_instead_of_calling_our_own_entry_a_fault(self):
        result = dashboard.dashboard_config(context(OUR_ENTRIES, lanes=()))
        self.assertIs(result.status, Status.SKIP)
        self.assertIn("cannot be told apart", result.cause)

    def test_the_declared_configmap_shape_does_not_crash_the_check(self):
        """`protocolUrl` is {url, proxy} in the ConfigMap and a string once served."""
        entries = [{"connectorName": "declared shape",
                    "protocolUrl": {"url": "https://edc.example.es/api/dsp",
                                    "proxy": False},
                    "did": DEMO_DID}]
        result = dashboard.dashboard_config(context(entries, lanes=OUR_LANES))
        self.assertIs(result.status, Status.FAIL)
        self.assertIn("lane dcp", result.cause)

    def test_with_no_lanes_a_named_peer_mismatch_is_still_caught(self):
        entries = [entry("Demo", "https://dcp-provider.example.org/api/dsp", "did:web:wrong")]
        result = dashboard.dashboard_config(context(
            entries, lanes=(),
            peers=(peer("demo", "https://dcp-provider.example.org/api/dsp", DEMO_DID),)))
        self.assertIs(result.status, Status.FAIL)
        self.assertIn("demo identifies as", result.cause)


class TestWrongDid(unittest.TestCase):
    def test_a_counterparty_entry_carrying_our_own_did_fails(self):
        entries = [entry("Demo (DCP)", "https://dcp-provider.example.org/api/dsp", OUR_DID)]
        result = dashboard.dashboard_config(context(entries, lanes=OUR_LANES))
        self.assertIs(result.status, Status.FAIL)
        self.assertIn("our own DID", result.cause)
        self.assertIn("aud", result.cause)
        self.assertEqual(result.doc, dashboard.DOC_AUD)

    def test_our_own_entry_carrying_a_foreign_did_fails_and_names_the_lane(self):
        entries = [entry("Ours (DCP)", "https://edc.example.es/api/dsp", DEMO_DID)]
        result = dashboard.dashboard_config(context(entries, lanes=OUR_LANES))
        self.assertIs(result.status, Status.FAIL)
        self.assertIn("lane dcp", result.cause)
        self.assertIn(DEMO_DID, result.cause)

    def test_a_named_peer_with_the_wrong_did_is_caught_even_when_it_is_not_ours(self):
        entries = [entry("Demo", "https://dcp-provider.example.org/api/dsp",
                         "did:web:someone-else.example")]
        result = dashboard.dashboard_config(context(
            entries, lanes=OUR_LANES,
            peers=(peer("demo", "https://dcp-provider.example.org/api/dsp", DEMO_DID),)))
        self.assertIs(result.status, Status.FAIL)
        self.assertIn("demo identifies as %s" % DEMO_DID, result.cause)

    def test_the_fix_names_our_own_did_suffix_trap(self):
        entries = [entry("Demo", "https://dcp-provider.example.org/api/dsp", OUR_DID)]
        result = dashboard.dashboard_config(context(entries, lanes=OUR_LANES))
        self.assertIn(OUR_DID, result.fix)
        self.assertIn("rollout restart", result.fix)


class TestLeakedDefaults(unittest.TestCase):
    def test_the_images_localhost_default_is_reported(self):
        entries = OUR_ENTRIES + [entry("consumer", "http://localhost:8084/protocol", OUR_DID)]
        result = dashboard.dashboard_config(context(entries, lanes=OUR_LANES))
        self.assertIs(result.status, Status.FAIL)
        self.assertIn("localhost:8084", result.cause)
        self.assertEqual(result.doc, dashboard.DOC_DEFAULTS)

    def test_a_wrong_did_outranks_a_leaked_default(self):
        """Both are real, but only one of them is why the handshake fails."""
        entries = [entry("Demo", "https://dcp-provider.example.org/api/dsp", OUR_DID),
                   entry("consumer", "http://localhost:8084/protocol", OUR_DID)]
        result = dashboard.dashboard_config(context(entries, lanes=OUR_LANES))
        self.assertEqual(result.doc, dashboard.DOC_AUD)


class TestDegradation(unittest.TestCase):
    def test_a_deployed_but_unreadable_dashboard_skips_with_the_reason(self):
        # the dashboard IS here and the tool could not read it: a coverage gap, and
        # the row has to stay visible
        result = dashboard.dashboard_config(context(None, err="connection refused"))
        self.assertIs(result.status, Status.SKIP)
        self.assertTrue(result.applicable)
        self.assertIn("connection refused", result.cause)

    def test_no_dashboard_deployed_is_not_applicable(self):
        # nothing is owed: there is no list here to get wrong
        result = dashboard.dashboard_config(
            context(None, err="no connector dashboard service in this namespace",
                    services=()))
        self.assertIs(result.status, Status.SKIP)
        self.assertFalse(result.applicable)

    def test_an_empty_list_warns(self):
        result = dashboard.dashboard_config(context([]))
        self.assertIs(result.status, Status.WARN)

    def test_no_participant_id_skips_rather_than_passing(self):
        result = dashboard.dashboard_config(
            context(OUR_ENTRIES, our_did=None, lanes=OUR_LANES))
        self.assertIs(result.status, Status.SKIP)
        self.assertIn("4 entries", result.cause)


if __name__ == "__main__":
    unittest.main()
