"""The native FIWARE path, probed without a credential, and the transport axis.

Two things are being pinned. The first is that a deployment running both
transports keeps them apart: one APISIX fronts `dsp-producer` and
`mp-data-service` alike, and the DSP hosts belong to `dsp-route`, not here.

The second is restraint. This probe cannot tell whether a real credential would
be accepted - it never presents one - so it must not pretend to. `401` with a
challenge is the gate working; `404` on `/` is ambiguous, because APISIX routes by
path and a host with no route for the root answers exactly like a host pointing at
somebody else's server; and `200` is worth a look but not a verdict, because `/`
may legitimately be public. Each of those is a different line here.
"""

import unittest
from types import SimpleNamespace

from fdsc_verify import http
from fdsc_verify.checks import fiware
from fdsc_verify.model import Status


def response(status=200, headers=None, body=b"{}"):
    return http.Response(status=status, body=body, headers=headers or {})


class FakeHttp:
    """Answers by URL, and records what was asked for."""

    def __init__(self, answers):
        self.answers = answers
        self.asked = []

    def get(self, url, **kw):
        self.asked.append(url)
        for fragment, resp in self.answers.items():
            if fragment in url:
                return resp
        return response(404)


def context(hosts=(), err=None, services=None, values=None, insecure=False):
    return SimpleNamespace(
        gateway_hosts=lambda: (list(hosts), err),
        verifier_services=lambda: (services, None) if services is not None
        else (None, "no verifier"),
        values=values or SimpleNamespace(
            get_at=lambda keys, default=None: default,
            get=lambda dotted, default=None: default),
        deployment=SimpleNamespace(edc_lanes={}, services={}),
        insecure=insecure)


class TestGate(unittest.TestCase):
    def run_with(self, ctx, answers):
        original = fiware.http
        fiware.http = FakeHttp(answers)
        try:
            return fiware.flow_native_gate(ctx), fiware.http.asked
        finally:
            fiware.http = original

    def test_a_challenge_is_the_gate_working(self):
        result, _ = self.run_with(
            context(hosts=["mp-data-service.example.org"]),
            {"mp-data-service": response(401, {"www-authenticate": 'Bearer realm="apisix"'})})
        self.assertIs(result.status, Status.OK)
        self.assertIn('Bearer realm="apisix"', result.summary)

    def test_a_policy_denial_counts_as_guarded(self):
        """403 means it authenticated the request and OPA said no. Still a gate."""
        result, _ = self.run_with(context(hosts=["x.example.org"]),
                                  {"x.example.org": response(403)})
        self.assertIs(result.status, Status.OK)

    def test_a_published_host_that_answers_nothing_is_the_finding(self):
        ctx = context(hosts=["dead.example.org"])
        original = fiware.http
        fiware.http = SimpleNamespace(
            get=lambda url, **kw: http.Response(status=0, body=b"", error="timed out"))
        try:
            result = fiware.flow_native_gate(ctx)
        finally:
            fiware.http = original
        self.assertIs(result.status, Status.FAIL)
        self.assertIn("somebody meant them to be", result.cause)

    def test_answering_without_a_credential_warns_rather_than_fails(self):
        """`/` may legitimately be public; this probe cannot tell. Say so."""
        result, _ = self.run_with(context(hosts=["open.example.org"]),
                                  {"open.example.org": response(200)})
        self.assertIs(result.status, Status.WARN)
        self.assertIn("may be a public landing path", result.cause)

    def test_a_404_on_the_root_does_not_hide_the_hosts_that_are_guarded(self):
        result, _ = self.run_with(
            context(hosts=["guarded.example.org", "rootless.example.org"]),
            {"guarded.example.org": response(401), "rootless.example.org": response(404)})
        self.assertIs(result.status, Status.OK)
        self.assertIn("1 of 2", result.summary)

    def test_no_gateway_host_skips_with_the_reason(self):
        result, _ = self.run_with(context(hosts=[]), {})
        self.assertIs(result.status, Status.SKIP)
        self.assertIn("dsp-route", result.cause)

    def test_it_never_probes_a_dsp_host(self):
        """`gateway_hosts` filters them out; this asserts nothing sneaks back in."""
        _, asked = self.run_with(context(hosts=["mp-data-service.example.org"]),
                                 {"mp-data-service": response(401)})
        self.assertEqual(asked, ["https://mp-data-service.example.org/"])


class TestDiscovery(unittest.TestCase):
    VALUES = SimpleNamespace(
        get_at=lambda keys, default=None: (
            {"id": "x509_san_dns:verifier.example.org"}
            if keys[-1] == "clientIdentification" else default),
        get=lambda dotted, default=None: default)

    def run_with(self, ctx, answers):
        original = fiware.http
        fiware.http = FakeHttp(answers)
        try:
            return fiware.flow_native_discovery(ctx)
        finally:
            fiware.http = original

    def test_every_registered_service_served_is_an_ok(self):
        ctx = context(services=[{"id": "data-service"}, {"id": "contract-management"}],
                      values=self.VALUES)
        result = self.run_with(ctx, {
            "openid-configuration": response(
                200, body=b'{"jwks_uri": "https://verifier.example.org/.well-known/jwks"}'),
            "/.well-known/jwks": response(200, body=b'{"keys": [{"kid": "k"}]}')})
        self.assertIs(result.status, Status.OK)
        self.assertIn("2 service(s) served", result.summary)

    def test_a_registered_service_with_no_document_fails(self):
        """Registered but not served is a login nothing can validate."""
        ctx = context(services=[{"id": "ghost"}], values=self.VALUES)
        result = self.run_with(ctx, {"openid-configuration": response(404)})
        self.assertIs(result.status, Status.FAIL)
        self.assertIn("ghost: HTTP 404", result.cause)
        self.assertIn("could not process the information request", result.cause)

    def test_a_document_without_a_jwks_uri_is_useless_to_the_gateway(self):
        ctx = context(services=[{"id": "data-service"}], values=self.VALUES)
        result = self.run_with(ctx, {"openid-configuration": response(200, body=b"{}")})
        self.assertIs(result.status, Status.FAIL)
        self.assertIn("no jwks_uri", result.cause)

    def test_an_empty_jwks_is_reported_separately(self):
        ctx = context(services=[{"id": "data-service"}], values=self.VALUES)
        result = self.run_with(ctx, {
            "openid-configuration": response(
                200, body=b'{"jwks_uri": "https://verifier.example.org/.well-known/jwks"}'),
            "/.well-known/jwks": response(200, body=b'{"keys": []}')})
        self.assertIs(result.status, Status.FAIL)
        self.assertIn("no key", result.cause)

    def test_an_unreadable_config_repo_skips(self):
        result = self.run_with(context(values=self.VALUES), {})
        self.assertIs(result.status, Status.SKIP)
        self.assertIn("no verifier", result.cause)


class TestTransportDeclarations(unittest.TestCase):
    def test_a_declared_transport_is_a_known_one(self):
        from fdsc_verify import checks  # noqa: F401
        from fdsc_verify.model import REGISTRY, TRANSPORTS

        wrong = [spec.id for spec in REGISTRY
                 if any(name not in TRANSPORTS for name in spec.transports)]
        self.assertEqual(wrong, [])

    def test_a_check_serving_both_paths_declares_none_and_is_never_filtered(self):
        """Not every flow check belongs to one transport.

        The TMForum storage layer is underneath both - the EDC keeps its
        negotiations in a Quote and the native path serves the same APIs through
        the gateway - so `--transport edc` must not hide a fault that breaks
        native too. Declaring nothing is how a check says "both", and the runner
        has to honour that rather than treat it as unselected.
        """
        from fdsc_verify import checks  # noqa: F401
        from fdsc_verify.model import REGISTRY
        from fdsc_verify.runner import _skip_reason

        shared = [spec for spec in REGISTRY
                  if spec.phase == "flow" and not spec.transports]
        self.assertTrue(shared, "expected at least one transport-agnostic flow check")
        for spec in shared:
            for selection in (["edc"], ["fiware"]):
                reason = _skip_reason(
                    SimpleNamespace(
                        values=SimpleNamespace(trust="effective", source=""),
                        deployment=SimpleNamespace(primary_release="r", edc_lanes={},
                                                   services={}),
                        profile=None, peers=[]),
                    spec, "", cluster=True, allow_writes=True,
                    selected_transports=selection)
                self.assertNotIn("--transport", reason or "",
                                 "%s was filtered out by --transport %s"
                                 % (spec.id, selection))

    def test_both_transports_are_represented(self):
        from fdsc_verify import checks  # noqa: F401
        from fdsc_verify.model import REGISTRY

        declared = {name for spec in REGISTRY for name in spec.transports}
        self.assertEqual(declared, {"fiware", "edc"})


if __name__ == "__main__":
    unittest.main()
