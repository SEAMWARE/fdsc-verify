"""Discovery and context plumbing: the two places where a wrong guess goes silent.

Neither of these produces a finding of its own. They feed the checks, so when they
guess wrong the checks SKIP with a reason that blames the deployment ("this
deployment's credential has a different shape", "identity secret not resolved") for
what is actually a tool assumption. Both cases below were observed in a live
deployment.
"""

import base64
import unittest
from types import SimpleNamespace

from fdsc_verify import discovery
from fdsc_verify.context import Context
from fdsc_verify.model import Deployment, EdcLane


def lane(name="dcp", **props):
    return EdcLane(name=name, release="provider", deployment="provider-fdsc-edc-%s" % name,
                service="provider-fdsc-edc-%s" % name,
                configmap="provider-fdsc-edc-%s" % name, props=props)


class FakeKube:
    """Answers only the two get_json shapes discovery asks for."""

    def __init__(self, volumes=(), secrets=None):
        self.volumes = list(volumes)
        self.secrets = secrets or {}
        self.context = None

    def get_json(self, kind, name, namespace=None, check=True):
        if kind == "deployment":
            return {"spec": {"template": {"spec": {"volumes": self.volumes}}}}
        if kind == "secret":
            return self.secrets.get(name)
        return None

    def secret(self, name, namespace=None):
        data = (self.secrets.get(name) or {}).get("data") or {}
        return {k: base64.b64decode(v) for k, v in data.items()}


def secret(kind_type, *keys):
    return {"type": kind_type,
            "data": {k: base64.b64encode(b"x").decode() for k in keys}}


def deployment_with_lanes():
    dep = Deployment(context=None, namespace="provider-dsc", release="provider")
    dep.edc_lanes["dcp"] = lane("dcp", **{"oid4vp.holder.key.path": "/signing-key/tls.key"})
    return dep


class TestServiceDiscovery(unittest.TestCase):
    """Every component of the matrix has to be findable, by whatever name it carries.

    The names below are the real ones: `odrl-pap` and `contract-management` are
    pinned by a fullnameOverride in both environments inspected, while keycloak,
    did-helper and the ccs carry the release in front. The near-miss that matters
    is `provider-apisix-admin`, which must NOT be mistaken for the gateway - the
    gateway is the one that fronts /api/dsp and the admin API is a different port
    with a different contract.
    """

    REAL_NAMES = [
        "identityhub-service", "verifier", "trusted-issuers-list",
        "data-service-scorpio", "tm-forum-api-svc", "odrl-pap", "contract-management",
        "provider-keycloak", "provider-did", "provider-apisix-gateway",
        "provider-apisix-admin", "provider-vault", "edc-dashboard-data-dashboard",
        "provider-credentials-config-service", "postgres-cluster", "dss",
    ]

    def discovered(self, names=None):
        kube = SimpleNamespace(
            list_names=lambda kind, namespace=None: names if names is not None
            else self.REAL_NAMES)
        dep = Deployment(context=None, namespace="provider", release=None)
        discovery._discover_services(kube, "provider", dep)
        return dep.services

    def test_every_component_is_found(self):
        services = self.discovered()
        self.assertEqual(services["apisix"], "provider-apisix-gateway")
        self.assertEqual(services["keycloak"], "provider-keycloak")
        self.assertEqual(services["did"], "provider-did")
        self.assertEqual(services["ccs"], "provider-credentials-config-service")
        self.assertEqual(services["odrlpap"], "odrl-pap")
        self.assertEqual(services["contractmanagement"], "contract-management")
        self.assertEqual(services["dashboard"], "edc-dashboard-data-dashboard")

    def test_the_apisix_admin_service_is_not_the_gateway(self):
        services = self.discovered(["provider-apisix-admin"])
        self.assertNotIn("apisix", services)

    def test_nothing_deployed_finds_nothing_rather_than_guessing(self):
        self.assertEqual(self.discovered([]), {})

    def test_a_component_deployed_under_a_bare_name_is_still_found(self):
        """did-helper as its own release with no prefix, which dsc-local does."""
        self.assertEqual(self.discovered(["did-helper"])["did"], "did-helper")


class TestIdentitySecretDiscovery(unittest.TestCase):
    def test_a_tls_typed_secret_is_taken_directly(self):
        kube = FakeKube(volumes=[{"secret": {"secretName": "host-tls"}}],
                        secrets={"host-tls": secret("kubernetes.io/tls", "tls.crt", "tls.key")})
        dep = deployment_with_lanes()
        discovery._discover_identity_secret(kube, "provider-dsc", dep)
        self.assertEqual(dep.identity_secret, "host-tls")
        self.assertEqual(dep.identity_secret_key, "tls.key")
        self.assertEqual(dep.notes, [])

    def test_an_opaque_secret_carrying_both_halves_is_accepted_with_a_note(self):
        """A SealedSecret leaves `type` at Opaque unless its template sets it.

        The pair of keys is what makes it an identity key; the type is a label
        that is easy to leave at the default, and refusing on that alone turned
        every key-consistency check into a SKIP on a deployment where the key was
        perfectly fine.
        """
        kube = FakeKube(volumes=[{"secret": {"secretName": "fdsc-identity-key"}}],
                        secrets={"fdsc-identity-key": secret("Opaque", "tls.crt", "tls.key")})
        dep = deployment_with_lanes()
        discovery._discover_identity_secret(kube, "provider-dsc", dep)
        self.assertEqual(dep.identity_secret, "fdsc-identity-key")
        self.assertEqual(dep.identity_secret_key, "tls.key")
        self.assertIn("resolved by content", dep.notes[0])

    def test_a_typed_secret_wins_over_an_opaque_one_whatever_the_mount_order(self):
        kube = FakeKube(
            volumes=[{"secret": {"secretName": "opaque-pair"}},
                     {"secret": {"secretName": "host-tls"}}],
            secrets={"opaque-pair": secret("Opaque", "tls.crt", "tls.key"),
                     "host-tls": secret("kubernetes.io/tls", "tls.crt", "tls.key")})
        dep = deployment_with_lanes()
        discovery._discover_identity_secret(kube, "provider-dsc", dep)
        self.assertEqual(dep.identity_secret, "host-tls")
        self.assertEqual(dep.notes, [])

    def test_half_a_keypair_is_not_an_identity_secret(self):
        """A CA bundle is `ca.crt` only; a signing key may be `tls.key` only."""
        kube = FakeKube(volumes=[{"secret": {"secretName": "ca-cert"}},
                                 {"secret": {"secretName": "key-only"}}],
                        secrets={"ca-cert": secret("Opaque", "ca.crt"),
                                 "key-only": secret("Opaque", "tls.key")})
        dep = deployment_with_lanes()
        discovery._discover_identity_secret(kube, "provider-dsc", dep)
        self.assertIsNone(dep.identity_secret)
        self.assertIn("set identity.secret in --config", dep.notes[0])

    def test_a_deployment_without_lanes_is_searched_too(self):
        """It used to look only at lanes, so a DSC without a connector had no
        identity secret and identity-key-consistency could never run on one."""
        kube = FakeKube(volumes=[{"secret": {"secretName": "did.example.org-tls"}}],
                        secrets={"did.example.org-tls": secret("kubernetes.io/tls",
                                                               "tls.crt", "tls.key")})
        dep = Deployment(context=None, namespace="ns", release=None)
        dep.services["did"] = "provider-did"          # the did-helper serves the document
        discovery._discover_identity_secret(kube, "ns", dep)
        self.assertEqual(dep.identity_secret, "did.example.org-tls")
        self.assertEqual(dep.identity_secret_key, "tls.key")

    def test_the_cert_manager_convention_is_the_last_resort_and_is_verified(self):
        """`<did host>-tls` is derived from the values, then confirmed to exist."""
        from fdsc_verify import values as V
        kube = FakeKube(secrets={"did.example.org-tls": secret("kubernetes.io/tls",
                                                              "tls.crt", "tls.key")})
        kube.get_json = lambda kind, name="", namespace=None, check=True: (
            None if kind == "deployment" else kube.secrets.get(name))
        dep = Deployment(context=None, namespace="ns", release=None)
        dep.values = V.Values(
            defaults={"did": {"config": {"server": {"hostUrl": "https://did.example.org"}}}},
            trust="effective", source="test")
        discovery._discover_identity_secret(kube, "ns", dep)
        self.assertEqual(dep.identity_secret, "did.example.org-tls")
        self.assertIn("naming convention", dep.notes[0])

    def test_a_convention_name_that_does_not_exist_is_not_adopted(self):
        kube = FakeKube()
        kube.get_json = lambda kind, name="", namespace=None, check=True: None
        dep = Deployment(context=None, namespace="ns", release=None)
        discovery._discover_identity_secret(kube, "ns", dep)
        self.assertIsNone(dep.identity_secret)
        self.assertIn("not resolvable", dep.notes[0])


PREFIX = base64.b64encode(b"super-user").decode()


def context_with_superuser(value):
    kube = FakeKube(secrets={"identityhub-secret": {
        "type": "Opaque",
        "data": {"superuser": base64.b64encode(value.encode()).decode()}}})
    dep = SimpleNamespace(namespace="provider-dsc")
    return Context(kube, dep)


class TestIdentityhubToken(unittest.TestCase):
    """`base64(super-user).<secret>` - but only one of the halves may be stored."""

    def test_a_stored_secret_half_gets_the_prefix(self):
        ctx = context_with_superuser("s3cr3t")
        self.assertEqual(ctx._identityhub_token(), "%s.s3cr3t" % PREFIX)

    def test_an_already_composed_token_is_used_verbatim(self):
        """Prefixing it again yields a 401 that reads like a broken credential.

        This is what the identityhub's own participant-creation response hands
        back, so a deployment that stored it whole is not unusual - and the
        resulting SKIP asked the operator to supply a token the tool was holding.
        """
        stored = "%s.L9wCPhqVsvjce3fIAHtE" % PREFIX
        ctx = context_with_superuser(stored)
        self.assertEqual(ctx._identityhub_token(), stored)

    def test_a_secret_half_containing_a_dot_is_still_prefixed(self):
        """Why the test is `startswith(prefix + '.')` and not `'.' in stored`."""
        ctx = context_with_superuser("aa.bb")
        self.assertEqual(ctx._identityhub_token(), "%s.aa.bb" % PREFIX)

    def test_the_config_override_still_wins(self):
        kube = FakeKube(secrets={})
        ctx = Context(kube, SimpleNamespace(namespace="ns"),
                      config={"identityhub": {"token": "handed-over"}})
        self.assertEqual(ctx._identityhub_token(), "handed-over")

    def test_a_missing_secret_yields_none_rather_than_a_broken_token(self):
        ctx = Context(FakeKube(secrets={}), SimpleNamespace(namespace="ns"))
        self.assertIsNone(ctx._identityhub_token())



class TestRegistrationServicesPresent(unittest.TestCase):
    """The declaration and the outcome are different facts.

    `registration-job-hooks` can only prove the job cannot have re-run. Whether a
    service is actually missing is a question for the live config repo, and the
    two answers genuinely diverge: a domain migration leaves a misconfigured hook
    behind a complete repo, because somebody re-registered by hand.
    """

    @staticmethod
    def context(declared, registered=None, err=None):
        from fdsc_verify.checks import identity
        values = SimpleNamespace(get=lambda path, default=None: declared)
        return SimpleNamespace(
            values=values,
            deployment=SimpleNamespace(namespace="provider-dsc"),
            verifier_services=lambda: (registered, err)), identity

    def test_every_declared_service_registered_is_ok(self):
        from fdsc_verify.model import Status
        ctx, identity = self.context(
            [{"id": "did:web:example:did"}, {"id": "dsp"}],
            registered=[{"id": "did:web:example:did"}, {"id": "dsp"}, {"id": "extra"}])
        result = identity.registration_services_present(ctx)
        self.assertIs(result.status, Status.OK)
        # a service nobody declared is reported, not treated as a fault
        self.assertEqual(result.detail["unmanaged"], ["extra"])

    def test_a_missing_service_fails_with_both_lists(self):
        from fdsc_verify.model import Status
        ctx, identity = self.context(
            [{"id": "did:web:new:did"}, {"id": "dsp"}],
            registered=[{"id": "did:web:old:did"}, {"id": "dsp"}])
        result = identity.registration_services_present(ctx)
        self.assertIs(result.status, Status.FAIL)
        self.assertEqual(result.detail["missing"], ["did:web:new:did"])
        self.assertIn("presentation_definition", result.cause)

    def test_an_unreadable_repo_skips_with_the_reason(self):
        from fdsc_verify.model import Status
        ctx, identity = self.context([{"id": "dsp"}], err="verifier service not found")
        result = identity.registration_services_present(ctx)
        self.assertIs(result.status, Status.SKIP)
        self.assertIn("verifier service not found", result.cause)

    def test_nothing_declared_skips(self):
        from fdsc_verify.model import Status
        ctx, identity = self.context(None)
        self.assertIs(identity.registration_services_present(ctx).status, Status.SKIP)


class TestCertSanVsClientIdScheme(unittest.TestCase):
    """It must not diagnose a certificate the deployment does not identify with."""

    @staticmethod
    def context(client_id):
        from fdsc_verify.checks import certs
        tree = {"decentralizedIam": {"vcAuthentication": {"vcverifier": {
            "verifier": {"clientIdentification": {"id": client_id} if client_id else {}}}}}}

        def get_at(keys, default=None):
            cur = tree
            for key in keys:
                if not isinstance(cur, dict) or key not in cur:
                    return default
                cur = cur[key]
            return cur

        values = SimpleNamespace(get_at=get_at, get=lambda dotted, default=None:
                                 get_at(dotted.split("."), default))
        return SimpleNamespace(values=values,
                               deployment=SimpleNamespace(edc_lanes={})), certs

    def test_a_redirect_uri_deployment_skips_instead_of_blaming_the_certificate(self):
        from fdsc_verify.model import Status
        ctx, certs = self.context("redirect_uri:https://verifier.example/cb")
        result = certs.cert_san_vs_client_id(ctx)
        self.assertIs(result.status, Status.SKIP)
        self.assertIn("redirect_uri", result.summary)

    def test_a_did_deployment_skips(self):
        from fdsc_verify.model import Status
        ctx, certs = self.context("did:web:example.com:did")
        result = certs.cert_san_vs_client_id(ctx)
        self.assertIs(result.status, Status.SKIP)
        self.assertIn("did", result.summary)

    def test_an_unset_client_id_skips_rather_than_assuming_x509(self):
        from fdsc_verify.model import Status
        ctx, certs = self.context(None)
        self.assertIs(certs.cert_san_vs_client_id(ctx).status, Status.SKIP)

    def test_the_host_comes_from_the_client_id_itself(self):
        """`x509_san_dns:<name>` names the very SAN it claims, so no lane is needed.

        Asserted on the helper rather than the check, which would otherwise make a
        real TLS connection to the name under test.
        """
        ctx, certs = self.context("x509_san_dns:verifier.example")
        self.assertEqual(certs._verifier_host(ctx, "x509_san_dns:verifier.example"),
                         "verifier.example")

    def test_the_ingress_host_is_the_fallback_when_the_scheme_is_not_x509(self):
        from fdsc_verify.checks import certs
        tree = {"decentralizedIam": {"vcAuthentication": {"vcverifier": {
            "ingress": {"hosts": [{"host": "verifier.example.org"}]}}}}}

        def get_at(keys, default=None):
            cur = tree
            for key in keys:
                if not isinstance(cur, dict) or key not in cur:
                    return default
                cur = cur[key]
            return cur

        ctx = SimpleNamespace(
            values=SimpleNamespace(get_at=get_at,
                                   get=lambda d, default=None: get_at(d.split("."), default)),
            deployment=SimpleNamespace(edc_lanes={}))
        self.assertEqual(certs._verifier_host(ctx, "did:web:example.org"),
                         "verifier.example.org")

    def test_the_verifiers_own_configmap_answers_when_nothing_else_does(self):
        """A GitOps install has no release, so the values are empty, and a provider
        with no EDC has no lane either - which left all three sources of the host
        blank and skipped flow-fiware-discovery on a deployment that publishes the
        host in `server.host` of the ConfigMap the tool already reads for the DID."""
        from fdsc_verify.checks import certs
        ctx = SimpleNamespace(
            values=SimpleNamespace(get_at=lambda keys, default=None: default,
                                   get=lambda d, default=None: default),
            deployment=SimpleNamespace(edc_lanes={}),
            verifier_config=lambda: {
                "server": {"host": "https://verifier.example.org:443/"},
                "verifier": {"clientIdentification": {
                    "id": "x509_san_dns:verifier.example.org", "kid": None}}})
        self.assertEqual(certs._verifier_host(ctx, ""), "verifier.example.org")
        self.assertEqual(certs._client_id_scheme(ctx),
                         ("x509_san_dns", "x509_san_dns:verifier.example.org"))

    def test_the_values_still_win_over_the_cluster(self):
        """The cluster may only fill a gap. Measured before shipping: with this
        fallback added, not one verdict moves on any deployment that has values."""
        from fdsc_verify.checks import certs
        tree = {"decentralizedIam": {"vcAuthentication": {"vcverifier": {
            "deployment": {"verifier": {"clientIdentification": {
                "id": "x509_san_dns:from-the-values.example.org"}}}}}}}

        def get_at(keys, default=None):
            cur = tree
            for key in keys:
                if not isinstance(cur, dict) or key not in cur:
                    return default
                cur = cur[key]
            return cur

        ctx = SimpleNamespace(
            values=SimpleNamespace(get_at=get_at,
                                   get=lambda d, default=None: get_at(d.split("."), default)),
            deployment=SimpleNamespace(edc_lanes={}),
            verifier_config=lambda: {"verifier": {"clientIdentification": {
                "id": "x509_san_dns:from-the-cluster.example.org"}}})
        _, client_id = certs._client_id_scheme(ctx)
        self.assertEqual(client_id, "x509_san_dns:from-the-values.example.org")

    def test_a_context_without_the_accessor_is_tolerated(self):
        """Several test contexts are plain namespaces, and this is only a fallback."""
        from fdsc_verify.checks import certs
        ctx = SimpleNamespace(
            values=SimpleNamespace(get_at=lambda keys, default=None: default,
                                   get=lambda d, default=None: default),
            deployment=SimpleNamespace(edc_lanes={}))
        self.assertIsNone(certs._verifier_host(ctx, ""))
        self.assertEqual(certs._client_id_scheme(ctx), ("unknown", None))

if __name__ == "__main__":
    unittest.main()


class TestTheMarketplaceResolvesToItsFrontDoor(unittest.TestCase):
    """The BAE ships several services and only one of them is the way in.

    Discovery used to loop over service NAMES in sorted order and let the first
    component that matched claim each one, which made alphabetical order of the
    names the preference. `marketplace` therefore resolved to
    `*-biz-ecosystem-charging-backend` on both demo deployments, because it sorts
    before `*-biz-ecosystem-logic-proxy` - while the comment beside the table said,
    correctly, that the logic proxy is the front door. Anything port-forwarding to
    `service("marketplace")` was talking to the wrong component.

    The loop is over components now, and the tails are tried in the order they are
    declared. That order is the preference, which is what the table always meant.
    """

    def _services(self, names):
        from fdsc_verify.discovery import _discover_services
        from fdsc_verify.model import Deployment

        dep = Deployment(context="c", namespace="ns", release="")
        kube = SimpleNamespace(list_names=lambda kind, namespace=None: list(names))
        _discover_services(kube, "ns", dep)
        return dep.services

    def test_the_logic_proxy_wins_over_the_charging_backend(self):
        services = self._services(["producer-biz-ecosystem-charging-backend",
                                   "producer-biz-ecosystem-logic-proxy"])
        self.assertEqual(services.get("marketplace"),
                         "producer-biz-ecosystem-logic-proxy")

    def test_it_does_not_depend_on_the_order_they_are_listed(self):
        services = self._services(["producer-biz-ecosystem-logic-proxy",
                                   "producer-biz-ecosystem-charging-backend"])
        self.assertEqual(services.get("marketplace"),
                         "producer-biz-ecosystem-logic-proxy")

    def test_the_charging_backend_is_its_own_component(self):
        """The BAE is not one service, and half of it is not a marketplace.

        The charging backend used to double as a fallback for `marketplace`, which
        made a deployment missing the logic proxy look complete. They are separate
        keys now and `IMPLIES` ties them together, so the gap is reported instead
        of being papered over.
        """
        services = self._services(["central-mk-biz-ecosystem-charging-backend"])
        self.assertIsNone(services.get("marketplace"))
        self.assertEqual(services.get("marketplacecharging"),
                         "central-mk-biz-ecosystem-charging-backend")

    def test_both_halves_resolve_separately(self):
        services = self._services(["producer-biz-ecosystem-logic-proxy",
                                   "producer-biz-ecosystem-charging-backend"])
        self.assertEqual(services.get("marketplace"),
                         "producer-biz-ecosystem-logic-proxy")
        self.assertEqual(services.get("marketplacecharging"),
                         "producer-biz-ecosystem-charging-backend")

    def test_one_service_name_still_serves_one_component(self):
        """The invariant the old loop had, kept deliberately."""
        services = self._services(["provider-keycloak", "provider-vault",
                                   "provider-biz-ecosystem-logic-proxy"])
        self.assertEqual(len(set(services.values())), len(services))
