"""A provider that publishes through somebody else's marketplace.

The shape needs all three of its conditions, and the two that look sufficient are
not: a **consumer** running contract-management and no marketplace matches the two
Service lookups exactly, and was reported as a provider with a broken
central-marketplace route before the declared flag was added. The flag alone is no
better - it is true on deployments that run their own marketplace as well.

Each check is exercised with the fault and without it, because a check that cannot
come back OK is indistinguishable from a broken one.
"""

import unittest
from types import SimpleNamespace

from fdsc_verify.checks import centralmp
from fdsc_verify.model import Status
from fdsc_verify.values import Values

CM_ROUTE = {
    "host": "provider-cm.example.org",
    "uri": "/*",
    "upstream": {"nodes": {"contract-management:8080": 1}},
    "plugins": {"openid-connect": {"client_id": "contract-management",
                                   "bearer_only": True},
                "opa": {"policy": "policy/main"}},
}
DATA_ROUTE = {
    "host": "mp-data-service.example.org",
    "uri": "/*",
    "upstream": {"nodes": {"data-service-scorpio:9090": 1}},
    "plugins": {"openid-connect": {"client_id": "data-service", "bearer_only": True}},
}


def values(routes=None, central=True, services=None, flags=None):
    contract = {"enableCentralMarketplace": central}
    contract.update(flags or {})
    if services is not None:
        contract["services"] = services
    tree = {"contract-management": contract}
    if routes is not None:
        tree["decentralizedIam"] = {"odrlAuthorization": {"apisix": {"routes": routes}}}
    return Values(defaults=tree, trust="effective", source="test")


def context(routes=None, central=True, marketplace=False, contractmanagement=True,
            hosts=("provider-cm.example.org",), registered=("contract-management",),
            services=None, flags=None, deployed=()):
    def service(name):
        if name == "contractmanagement":
            return "contract-management" if contractmanagement else None
        if name == "marketplace":
            return "bae-logic-proxy" if marketplace else None
        return None

    def get_json(kind, name=None, namespace=None, check=True, selector=None):
        if kind == "service":
            return {"metadata": {"name": name}} if name in deployed else None
        return None

    return SimpleNamespace(
        values=values(routes, central, services, flags),
        deployment=SimpleNamespace(namespace="ns", service=service),
        kube=SimpleNamespace(get_json=get_json),
        gateway_hosts=lambda: (list(hosts), None),
        verifier_services=lambda: ([{"id": i} for i in registered], None))


class TestTheShape(unittest.TestCase):
    def test_a_consumer_running_contract_management_is_not_this_shape(self):
        """It has contract-management and no marketplace, which is two thirds of the
        test. Measured: without the flag it was reported as a provider whose central
        marketplace could not reach it."""
        result = centralmp.central_mp_contract_management_route(
            context(routes=[CM_ROUTE], central=None))
        self.assertIs(result.status, Status.SKIP)
        self.assertFalse(result.applicable)
        self.assertIn("does not declare a central marketplace", result.summary)

    def test_a_provider_with_its_own_marketplace_is_not_this_shape(self):
        """The flag is true on deployments that run their own marketplace too, so it
        cannot be the discriminator on its own."""
        result = centralmp.central_mp_contract_management_route(
            context(routes=[CM_ROUTE], marketplace=True, central=True))
        self.assertIs(result.status, Status.SKIP)
        self.assertFalse(result.applicable)
        self.assertIn("runs its own marketplace", result.summary)

    def test_no_contract_management_is_not_this_shape(self):
        result = centralmp.central_mp_contract_management_route(
            context(routes=[CM_ROUTE], contractmanagement=False))
        self.assertIs(result.status, Status.SKIP)
        self.assertFalse(result.applicable)


class TestTheRoute(unittest.TestCase):
    def test_a_route_that_is_published_registered_and_bearer_only_passes(self):
        result = centralmp.central_mp_contract_management_route(
            context(routes=[DATA_ROUTE, CM_ROUTE]))
        self.assertIs(result.status, Status.OK)
        self.assertIn("provider-cm.example.org", result.summary)

    def test_no_route_to_contract_management_fails(self):
        result = centralmp.central_mp_contract_management_route(
            context(routes=[DATA_ROUTE]))
        self.assertIs(result.status, Status.FAIL)
        self.assertIn("no way in", result.cause)

    def test_a_route_whose_host_is_not_published_fails(self):
        result = centralmp.central_mp_contract_management_route(
            context(routes=[CM_ROUTE], hosts=("mp-data-service.example.org",)))
        self.assertIs(result.status, Status.FAIL)
        self.assertIn("provider-cm.example.org", result.cause)

    def test_a_client_id_the_verifier_does_not_know_fails(self):
        result = centralmp.central_mp_contract_management_route(
            context(routes=[CM_ROUTE], registered=("data-service",)))
        self.assertIs(result.status, Status.FAIL)
        self.assertIn("client `contract-management`", result.cause)

    def test_bearer_only_off_is_a_warning_not_a_pass(self):
        """`bearer_only: false` is not "unguarded" - it refuses by redirecting to the
        IdP, which is right for a browser and useless for a machine-to-machine
        caller. Reading it as guarded is the mistake the gateway probe made once."""
        route = dict(CM_ROUTE, plugins={"openid-connect": {
            "client_id": "contract-management", "bearer_only": False}})
        result = centralmp.central_mp_contract_management_route(
            context(routes=[route]))
        self.assertIs(result.status, Status.WARN)
        self.assertIn("redirect", result.cause)

    def test_the_upstream_is_read_from_the_mapping_keys(self):
        """`upstream.nodes` maps `host:port` to a weight; it is not a list, and the
        service name is what precedes the colon in each key."""
        self.assertEqual(centralmp._upstream_services(CM_ROUTE),
                         ["contract-management"])
        self.assertEqual(centralmp._upstream_services({}), [])

    def test_a_release_prefixed_upstream_still_matches(self):
        route = dict(CM_ROUTE,
                     upstream={"nodes": {"provider-contract-management:8080": 1}})
        result = centralmp.central_mp_contract_management_route(
            context(routes=[route]))
        self.assertIs(result.status, Status.OK)

    def test_no_routes_in_the_values_skips_visibly(self):
        """A coverage gap, not a verdict: the Ingress only says every host goes to
        APISIX, and they all answer the same 401."""
        result = centralmp.central_mp_contract_management_route(context(routes=None))
        self.assertIs(result.status, Status.SKIP)
        self.assertTrue(result.applicable)


class TestTheWiring(unittest.TestCase):
    def test_everything_configured_and_deployed_passes(self):
        result = centralmp.central_mp_contract_management_wiring(context(
            services={"product-catalog": {"url": "http://tm-forum-api:8080"}},
            flags={"enableTmForum": True}, deployed=("tm-forum-api",)))
        self.assertIs(result.status, Status.OK)
        self.assertIn("1 configured integration", result.summary)

    def test_an_integration_pointing_at_nothing_warns(self):
        """Measured live: enableTmForum on, six endpoint keys naming
        http://tm-forum-api:8080, and no such Service in the namespace."""
        result = centralmp.central_mp_contract_management_wiring(context(
            services={"product-catalog": {"url": "http://tm-forum-api:8080"},
                      "quote": {"url": "http://tm-forum-api:8080"}},
            flags={"enableTmForum": True}))
        self.assertIs(result.status, Status.WARN)
        self.assertIn("1 configured service(s)", result.summary)
        # aggregated by host: one missing service, not one line per endpoint key
        self.assertIn("2 endpoint(s)", result.cause)
        self.assertEqual(result.detail["endpoints"],
                         {"tm-forum-api": ["product-catalog", "quote"]})

    def test_a_configured_url_whose_flag_is_off_is_not_held_against_it(self):
        """`services.rainbow` is configured on every deployment inspected and
        `enableRainbow` is false on all of them. Checking the URL without its flag
        reports a fault on every one."""
        result = centralmp.central_mp_contract_management_wiring(context(
            services={"rainbow": {"url": "http://rainbow:8080"}},
            flags={"enableRainbow": False}))
        self.assertIs(result.status, Status.OK)
        self.assertEqual(result.detail["checked"], 0)

    def test_an_external_url_is_not_ours_to_resolve(self):
        result = centralmp.central_mp_contract_management_wiring(context(
            services={"product-catalog": {"url": "https://tmf.example.net/api"}},
            flags={"enableTmForum": True}))
        self.assertIs(result.status, Status.OK)
        self.assertEqual(result.detail["checked"], 0)


class TestEveryFindingCanBeActedOn(unittest.TestCase):
    def _findings(self):
        yield centralmp.central_mp_contract_management_route(
            context(routes=[DATA_ROUTE]))
        yield centralmp.central_mp_contract_management_route(
            context(routes=[CM_ROUTE], registered=("data-service",)))
        yield centralmp.central_mp_contract_management_wiring(context(
            services={"product-catalog": {"url": "http://tm-forum-api:8080"}},
            flags={"enableTmForum": True}))

    def test_each_one_names_a_cause_a_fix_and_a_section(self):
        for result in self._findings():
            self.assertIn(result.status, (Status.WARN, Status.FAIL))
            self.assertTrue(result.cause, result.summary)
            self.assertTrue(result.fix, result.summary)
            self.assertTrue(result.doc, result.summary)


if __name__ == "__main__":
    unittest.main()
