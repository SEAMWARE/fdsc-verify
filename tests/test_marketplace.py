"""The local marketplace checks, and the four assumptions they must not make.

Every one of these was measured on the two marketplaces in the demo dataspace,
and each breaks the obvious implementation:

1. The logic proxy is a **StatefulSet**, so nothing may assume a Deployment.
2. `service("marketplace")` used to resolve to the charging backend rather than
   the logic proxy, because discovery let alphabetical order of service names
   decide. Fixed in discovery.py; pinned there.
3. The two deployments use **different auth stacks** - producer OIDC with
   `BAE_LP_OAUTH2_CLIENT_ID`, central-mk SIOP with `BAE_LP_SIOP_CLIENT_ID`, the
   other variable absent entirely. Reading one fixed name is a false negative on
   one of the two.
4. The **lifecycle vocabularies disagree** (`Launched` vs `Active`) and a catalog
   can carry no `lifecycleStatus` at all - which a naive filter drops in silence.
"""

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fdsc_verify.checks import marketplace  # noqa: E402
from fdsc_verify.model import Status  # noqa: E402

OIDC = {"BAE_LP_OIDC_ENABLED": "true", "BAE_LP_SIOP_ENABLED": "false",
        "BAE_LP_OAUTH2_CLIENT_ID": "did:web:producer.example:did"}
SIOP = {"BAE_LP_SIOP_ENABLED": "true", "BAE_LP_OIDC_ENABLED": "false",
        "BAE_LP_SIOP_CLIENT_ID": "did:web:dso.example"}


def context(env=None, services=None, marketplace_present=True, declared=None,
            catalogue=None):
    """Only what the checks under test actually touch."""
    registered = ([{"id": i} for i in services] if services is not None else None)
    return SimpleNamespace(
        deployment=SimpleNamespace(
            namespace="ns",
            service=lambda name: {"marketplace": "bae-logic-proxy",
                                  "tmforum": "tm-forum-api-svc"}.get(name)
            if (name != "marketplace" or marketplace_present) else None),
        workload_env=lambda svc: dict(env or {}),
        verifier_services=lambda: (registered, None if registered is not None
                                   else "no verifier"),
        values=SimpleNamespace(get=lambda path, default=None: declared or default),
        _cache=dict(catalogue or {}))


class TestNoMarketplaceIsAShape(unittest.TestCase):
    """A provider integrated with a central MP has none, and that is not a fault."""

    def test_all_three_are_not_applicable(self):
        ctx = context(marketplace_present=False)
        for fn in (marketplace.marketplace_login_service,
                   marketplace.marketplace_services_beyond_login,
                   marketplace.marketplace_offerings):
            result = fn(ctx)
            self.assertIs(result.status, Status.SKIP, fn.__name__)
            self.assertFalse(result.applicable, fn.__name__)


class TestTheLoginClientIsFoundInEitherStack(unittest.TestCase):
    def test_oidc(self):
        result = marketplace.marketplace_login_service(
            context(env=OIDC, services=["did:web:producer.example:did", "data-service"]))
        self.assertIs(result.status, Status.OK)
        self.assertIn("oidc", result.summary)

    def test_siop(self):
        """The variable OIDC uses is absent here; reading it alone would fail."""
        result = marketplace.marketplace_login_service(
            context(env=SIOP, services=["did:web:dso.example", "other"]))
        self.assertIs(result.status, Status.OK)
        self.assertIn("siop", result.summary)

    def test_an_unregistered_client_is_the_failure(self):
        result = marketplace.marketplace_login_service(
            context(env=OIDC, services=["data-service"]))
        self.assertIs(result.status, Status.FAIL)
        self.assertIn("presentation_definition", result.cause)

    def test_a_suffix_difference_is_not_a_match(self):
        """did:web:host and did:web:host:did are different participants."""
        result = marketplace.marketplace_login_service(
            context(env=OIDC, services=["did:web:producer.example"]))
        self.assertIs(result.status, Status.FAIL)

    def test_neither_stack_on_is_a_skip_not_a_verdict(self):
        result = marketplace.marketplace_login_service(context(env={"SOMETHING": "x"}))
        self.assertIs(result.status, Status.SKIP)
        self.assertTrue(result.applicable)


class TestDriftAndPlaceholders(unittest.TestCase):
    def test_values_disagreeing_with_the_pod_is_a_warning(self):
        """The pod is what runs; the values are drift, not the fault."""
        result = marketplace.marketplace_login_service(context(
            env=OIDC, services=["did:web:producer.example:did", "x"],
            declared=[{"name": "BAE_LP_OAUTH2_CLIENT_ID", "value": "did:web:stale"}]))
        self.assertIs(result.status, Status.WARN)
        self.assertIn("drift", result.cause)

    def test_an_unexpanded_placeholder_is_reported(self):
        result = marketplace.marketplace_login_service(context(
            env=OIDC, services=["did:web:producer.example:did", "${DID}"]))
        self.assertIs(result.status, Status.WARN)
        self.assertIn("${DID}", result.cause)

    def test_the_placeholder_does_not_mask_a_real_failure(self):
        """An unregistered login client outranks tidiness."""
        result = marketplace.marketplace_login_service(
            context(env=OIDC, services=["${DID}"]))
        self.assertIs(result.status, Status.FAIL)


class TestSomethingBehindTheGate(unittest.TestCase):
    def test_only_the_login_client_warns(self):
        result = marketplace.marketplace_services_beyond_login(
            context(env=SIOP, services=["did:web:dso.example"]))
        self.assertIs(result.status, Status.WARN)
        self.assertIn("nothing", result.cause)

    def test_any_other_service_is_enough(self):
        result = marketplace.marketplace_services_beyond_login(
            context(env=SIOP, services=["did:web:dso.example", "data-service"]))
        self.assertIs(result.status, Status.OK)


class TestTheCatalogue(unittest.TestCase):
    def _ctx(self, offerings, catalogs=()):
        return context(env=OIDC, catalogue={
            "catalogue:productOffering": (list(offerings), None),
            "catalogue:catalog": (list(catalogs), None)})

    def test_both_vocabularies_count_as_discoverable(self):
        """Launched on one chart, Active on the other; pinning one misfires."""
        for status in ("Launched", "Active"):
            result = marketplace.marketplace_offerings(
                self._ctx([{"lifecycleStatus": status}]))
            self.assertIs(result.status, Status.OK, status)

    def test_an_empty_catalogue_warns_rather_than_fails(self):
        # a fresh install has nothing published yet, and a red first report over
        # something that is not broken teaches people to ignore the tool
        result = marketplace.marketplace_offerings(self._ctx([]))
        self.assertIs(result.status, Status.WARN)
        self.assertIn("empty", result.summary)

    def test_all_retired_is_a_different_sentence(self):
        result = marketplace.marketplace_offerings(
            self._ctx([{"lifecycleStatus": "Retired"}, {"lifecycleStatus": "Retired"}]))
        self.assertIs(result.status, Status.WARN)
        self.assertIn("none of them discoverable", result.summary)

    def test_a_catalog_without_a_status_is_named_not_dropped(self):
        result = marketplace.marketplace_offerings(
            self._ctx([{"lifecycleStatus": "Launched"}], [{"name": "Demo Catalog"}]))
        self.assertIs(result.status, Status.OK)
        self.assertIn("Demo Catalog", result.detail["catalogsWithoutStatus"])


if __name__ == "__main__":
    unittest.main()


class TestOfferingCompleteness(unittest.TestCase):
    """A published offering that can never be used, and the two ways to misread one.

    contract-management turns an offering's `authorizationPolicy` into the Rego
    OPA evaluates and its credentials characteristic into the service entry that
    decides what a caller must present. One carrying neither is discoverable and
    inert - selectable in the catalogue, impossible to obtain anything through,
    and silent about why.

    Both traps below were met on demo, and a first cut of this check fell into the
    first: it knew only `credentialsConfig` and would have reported an offering
    spelling it `credentialsConfiguration` as missing its credentials.
    """

    def _ctx(self, offerings, specs):
        return context(env=OIDC, catalogue={
            "catalogue:productOffering": (list(offerings), None),
            "catalogue:productSpecification": (list(specs), None)})

    def _pair(self, statuses, spec_id="s1", status="Launched", name="an offer"):
        offering = {"name": name, "lifecycleStatus": status,
                    "productSpecification": {"id": spec_id}}
        spec = {"id": spec_id, "name": "a spec", "productSpecCharacteristic":
                [{"valueType": v} for v in statuses]}
        return [offering], [spec]

    def test_a_complete_offering_passes(self):
        result = marketplace.marketplace_offering_completeness(self._ctx(
            *self._pair(["authorizationPolicy", "credentialsConfig", "endpointUrl"])))
        self.assertIs(result.status, Status.OK)

    def test_the_other_spelling_counts(self):
        """Air Quality on demo spells it this way and is complete."""
        result = marketplace.marketplace_offering_completeness(self._ctx(
            *self._pair(["authorizationPolicy", "credentialsConfiguration"])))
        self.assertIs(result.status, Status.OK)

    def test_no_policy_is_a_failure(self):
        result = marketplace.marketplace_offering_completeness(self._ctx(
            *self._pair(["credentialsConfig"])))
        self.assertIs(result.status, Status.FAIL)
        self.assertIn("nothing authorises access", result.cause)

    def test_no_credentials_in_either_spelling_is_a_failure(self):
        result = marketplace.marketplace_offering_completeness(self._ctx(
            *self._pair(["authorizationPolicy"])))
        self.assertIs(result.status, Status.FAIL)
        self.assertIn("what to demand", result.cause)

    def test_one_good_offering_among_bad_ones_is_a_warning(self):
        """Severity follows what the deployment can still do. A catalogue with junk
        in it next to something that works is not a broken deployment - and the
        common case is somebody adding one good offering to a pile of samples, so
        the complete one has to be named or the answer they came for is invisible."""
        bad, bad_spec = self._pair(["string"], spec_id="s1", name="sample offer")
        good, good_spec = self._pair(["authorizationPolicy", "credentialsConfig"],
                                     spec_id="s2", name="the real one")
        result = marketplace.marketplace_offering_completeness(
            self._ctx(bad + good, bad_spec + good_spec))
        self.assertIs(result.status, Status.WARN)
        self.assertIn("only 1 of 2", result.summary)
        self.assertIn("the real one", result.summary)
        self.assertEqual(result.detail["complete"], ["the real one"])
        # the cause aggregates; it must not spell the shortfall out per offering,
        # which is what made a ten-offering catalogue produce fifteen lines
        self.assertNotIn("sample offer", result.cause)
        self.assertIn("-v", result.cause)
        self.assertIn("sample offer", result.detail["unusable"][0])

    def test_a_catalogue_where_nothing_works_is_still_a_failure(self):
        """A Provider whose every discoverable offering is inert provides nothing,
        and that is a statement about the deployment rather than about content."""
        one, one_spec = self._pair(["string"], spec_id="s1", name="first")
        two, two_spec = self._pair(["authorizationPolicy"], spec_id="s2", name="second")
        result = marketplace.marketplace_offering_completeness(
            self._ctx(one + two, one_spec + two_spec))
        self.assertIs(result.status, Status.FAIL)
        self.assertIn("none of the 2", result.summary)
        self.assertEqual(result.detail["complete"], [])

    def test_a_dangling_specification_fails_even_beside_a_good_offering(self):
        """A broken reference is not incompleteness, so the downgrade does not
        apply to it."""
        good, good_spec = self._pair(["authorizationPolicy", "credentialsConfig"],
                                     spec_id="s2", name="the real one")
        broken, _ = self._pair([], spec_id="gone", name="points nowhere")
        result = marketplace.marketplace_offering_completeness(
            self._ctx(good + broken, good_spec))
        self.assertIs(result.status, Status.FAIL)
        self.assertIn("gone", result.cause)

    def test_a_retired_offering_is_not_judged(self):
        """Nobody will find it, so an incomplete one is not a fault."""
        result = marketplace.marketplace_offering_completeness(self._ctx(
            *self._pair([], status="Retired")))
        self.assertIs(result.status, Status.SKIP)
        self.assertFalse(result.applicable)

    def test_a_specification_that_is_not_there_is_named(self):
        offerings, _ = self._pair([], spec_id="gone")
        result = marketplace.marketplace_offering_completeness(
            self._ctx(offerings, []))
        self.assertIs(result.status, Status.FAIL)
        self.assertIn("gone", result.cause)

    def test_two_spellings_in_one_catalogue_is_a_warning(self):
        offerings, specs = self._pair(["authorizationPolicy", "credentialsConfig"])
        more_off, more_spec = self._pair(
            ["authorizationPolicy", "credentialsConfiguration"], spec_id="s2")
        result = marketplace.marketplace_offering_completeness(
            self._ctx(offerings + more_off, specs + more_spec))
        self.assertIs(result.status, Status.WARN)
        self.assertIn("spelled two ways", result.summary)

    def test_missing_transport_characteristics_are_reported_not_judged(self):
        """An offering served only through the gateway has no DSP endpoint."""
        result = marketplace.marketplace_offering_completeness(self._ctx(
            *self._pair(["authorizationPolicy", "credentialsConfig"])))
        self.assertIs(result.status, Status.OK)
        self.assertEqual(result.detail["withoutTransportCharacteristics"], ["an offer"])


if __name__ == "__main__":
    unittest.main()
