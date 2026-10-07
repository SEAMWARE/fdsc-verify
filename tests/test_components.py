"""The role matrix, and the four ways it nearly over-reported.

Every case below that says "must not" was a real false positive, found by running
the checks against the four demo deployments before trusting them. All four
failed identically at first, which is the signature of a check measuring the
wrong thing rather than of four broken deployments:

1. **A requirement is a capability, not a Deployment object.** The DID document is
   served by the did-helper *or* by the IdentityHub, and in these chart versions
   the credentials-config API is served by the verifier's own config port. Both
   were reported missing on deployments that have them.
2. **"Listed as a dependency" is not "deployed".** provider-central's release
   lists `fdsc-edc` and its rendered manifest holds not one object of it, which
   came out as "enabled but not running" and would have sent somebody hunting a
   crashed workload that was never created.
3. **The either/or has to compare the real services.** Once the DID requirement
   was satisfiable by the IdentityHub, asking the same question for the XOR
   answered "both deployed" on every DCP deployment.
4. **A pure Consumer needs none of the provider stack**, and saying otherwise is
   how a correctly built deployment gets told it is broken.
"""

import unittest
from types import SimpleNamespace

from fdsc_verify import components as matrix
from fdsc_verify import values as V
from fdsc_verify.checks import components as checks
from fdsc_verify.model import Status
from fdsc_verify.profile import Profile


def deployment(services=None, lanes=(), release=None):
    return SimpleNamespace(services=dict(services or {}),
                           edc_lanes={name: SimpleNamespace(name=name) for name in lanes},
                           namespace="ns")


def values(tree=None, trust="effective", release=None):
    return V.Values(defaults=tree or {}, trust=trust, source="test", release=release)


def context(services=None, lanes=(), tree=None, profile=None, trust="effective",
            release=None, document_server="unknown"):
    dep = deployment(services, lanes)
    return SimpleNamespace(deployment=dep, values=values(tree, trust, release),
                           profile=profile or Profile(),
                           participant=SimpleNamespace(document_server=document_server))


# What a provider without EDC really runs, by the service names the demo uses.
PROVIDER_SERVICES = {"verifier": "verifier", "til": "trusted-issuers-list",
                     "apisix": "x-apisix-gateway", "odrlpap": "odrl-pap",
                     "keycloak": "x-keycloak", "did": "x-did"}
# And a DCP one, where the IdentityHub replaces the did-helper.
DCP_SERVICES = dict(PROVIDER_SERVICES, identityhub="identityhub-service")
DCP_SERVICES.pop("did")


class TestRoles(unittest.TestCase):
    def test_a_declared_role_wins_and_says_so(self):
        profile = Profile()
        profile.roles, profile._origins["roles"] = ("provider",), "--role"
        roles, how = matrix.roles_for(deployment(), profile)
        self.assertEqual(roles, ("provider",))
        self.assertEqual(how, "--role")

    def test_the_provider_stack_makes_a_provider(self):
        roles, how = matrix.roles_for(deployment(PROVIDER_SERVICES), Profile())
        self.assertIn("provider", roles)
        self.assertIn("verifier", how)

    def test_an_identity_only_deployment_is_a_consumer(self):
        roles, _ = matrix.roles_for(deployment({"keycloak": "k", "did": "d"}), Profile())
        self.assertEqual(roles, ("consumer",))

    def test_an_empty_namespace_yields_no_role_rather_than_a_guess(self):
        roles, how = matrix.roles_for(deployment(), Profile())
        self.assertEqual(roles, ())
        self.assertIn("nothing deployed", how)


class TestPresence(unittest.TestCase):
    def test_a_service_is_enough_whoever_deployed_it(self):
        state = matrix.presence(deployment({"did": "sibling-release-did"}), values(),
                                Profile(), "did")
        self.assertTrue(state.present)

    def test_the_identityhub_satisfies_the_did_document_requirement(self):
        """A DCP deployment has no did-helper and is not missing a DID document."""
        state = matrix.presence(deployment(DCP_SERVICES), values(), Profile(), "did")
        self.assertTrue(state.present)
        self.assertIn("IdentityHub", state.why)

    def test_the_verifier_satisfies_the_credentials_config_requirement(self):
        state = matrix.presence(deployment(PROVIDER_SERVICES), values(), Profile(), "ccs")
        self.assertTrue(state.present)
        self.assertIn("VCVerifier", state.why)

    def test_a_declared_component_beats_the_cluster(self):
        profile = Profile()
        profile.components = {"marketplace": False}
        state = matrix.presence(deployment({"marketplace": "mk"}), values(), profile,
                                "marketplace")
        self.assertFalse(state.present)

    def test_lanes_count_as_the_edc_being_there(self):
        state = matrix.presence(deployment(lanes=("dcp",)), values(), Profile(), "edc")
        self.assertTrue(state.present)

    def test_a_rendered_manifest_beats_the_dependency_list(self):
        """provider-central lists fdsc-edc and renders nothing from it."""
        release = SimpleNamespace(
            name="provider-central", revision=21, chart="data-space-connector-9.0.5",
            manifest="x",
            manifest_index=lambda: [SimpleNamespace(kind="Service", name="verifier",
                                                    source="dsc/charts/vcverifier/x.yaml")],
            dependency=lambda key: SimpleNamespace(key="fdsc-edc", condition=None))
        state = matrix.presence(deployment(), values({}, release=release), Profile(), "edc")
        self.assertFalse(state.present)
        self.assertFalse(state.wanted)
        self.assertIn("rendered no fdsc-edc", state.why)

    def test_unreadable_values_leave_it_undetermined(self):
        state = matrix.presence(deployment(), V.Values.empty("no cluster"), Profile(),
                                "marketplace")
        self.assertTrue(state.unknown)


class TestInventory(unittest.TestCase):
    def test_a_consumer_is_not_asked_for_the_provider_stack(self):
        profile = Profile()
        profile.roles, profile._origins["roles"] = ("consumer",), "--role"
        result = checks.component_inventory(
            context({"keycloak": "k", "did": "d"}, profile=profile))
        self.assertIs(result.status, Status.OK)

    def test_a_provider_without_a_verifier_fails_and_names_the_key(self):
        profile = Profile()
        profile.roles, profile._origins["roles"] = ("provider",), "--role"
        result = checks.component_inventory(
            context({"keycloak": "k", "did": "d"}, profile=profile,
                    tree={"decentralizedIam": {"vcAuthentication": {
                        "vcverifier": {"enabled": False}}}}))
        self.assertIs(result.status, Status.FAIL)
        self.assertIn("VCVerifier", result.cause)
        self.assertIn("vcverifier.enabled", result.cause)

    def test_a_dcp_provider_is_complete(self):
        profile = Profile()
        profile.roles, profile._origins["roles"] = ("provider",), "--role"
        result = checks.component_inventory(context(DCP_SERVICES, profile=profile))
        self.assertIs(result.status, Status.OK)

    def test_no_role_skips_rather_than_measuring_against_nothing(self):
        result = checks.component_inventory(context())
        self.assertIs(result.status, Status.SKIP)
        self.assertIn("deployment-role", result.cause)


class TestConsistency(unittest.TestCase):
    def test_a_dcp_deployment_does_not_have_two_document_servers(self):
        result = checks.component_consistency(context(DCP_SERVICES))
        self.assertIs(result.status, Status.OK)

    def test_two_document_servers_are_reported(self):
        both = dict(DCP_SERVICES, did="x-did")
        result = checks.component_consistency(context(both))
        self.assertIs(result.status, Status.FAIL)
        self.assertIn("whichever one the ingress routes to", result.cause)

    def test_nothing_serving_the_document_is_reported(self):
        result = checks.component_consistency(
            context({"verifier": "v", "til": "t", "apisix": "a", "odrlpap": "o"}))
        self.assertIs(result.status, Status.FAIL)
        self.assertIn("no counterparty can", result.cause)

    def test_a_gateway_without_a_policy_point_is_reported(self):
        services = dict(PROVIDER_SERVICES)
        services.pop("odrlpap")
        result = checks.component_consistency(
            context(services, tree={"decentralizedIam": {"odrlAuthorization": {
                "odrl-pap": {"enabled": False}}}}))
        self.assertIs(result.status, Status.FAIL)
        self.assertIn("odrl-pap", result.cause)


if __name__ == "__main__":
    unittest.main()


class TestDrift(unittest.TestCase):
    """Rendered but not running. The seam the values and the cluster leave between them.

    Not hypothetical: one deployment here has its dashboard ConfigMap applied by
    hand, a volume swapped with `kubectl patch` and an STS alias tried with
    `kubectl set env`. None of that is in any values file, and all of it survives
    only until the next upgrade.
    """

    def context(self, rendered, live, manifest="x"):
        release = SimpleNamespace(
            name="rel", revision=3, chart="c-1.0", manifest=manifest,
            manifest_index=lambda: [
                SimpleNamespace(kind=kind, name=name, source="chart/templates/x.yaml")
                for kind, name in rendered])

        def get_json(kind, name="", namespace=None, check=True, selector=None):
            return {"items": [{"metadata": {"name": n}}
                              for k, n in live if k.lower() == kind]}

        return SimpleNamespace(
            values=V.Values(trust="effective", source="t", release=release),
            deployment=SimpleNamespace(namespace="ns", services={}, edc_lanes={}),
            kube=SimpleNamespace(get_json=get_json), profile=Profile())

    def test_everything_rendered_is_running(self):
        ctx = self.context([("Deployment", "verifier"), ("Service", "verifier")],
                           [("Deployment", "verifier"), ("Service", "verifier")])
        result = checks.deployment_drift(ctx)
        self.assertIs(result.status, Status.OK)
        self.assertIn("2 rendered object(s)", result.summary)

    def test_something_rendered_and_missing_is_reported_with_its_source(self):
        ctx = self.context([("Deployment", "verifier"), ("Deployment", "odrl-pap")],
                           [("Deployment", "verifier")])
        result = checks.deployment_drift(ctx)
        self.assertIs(result.status, Status.FAIL)
        self.assertIn("Deployment/odrl-pap", result.cause)
        self.assertIn("chart/templates/x.yaml", result.cause)
        self.assertIn("an upgrade will put them back", result.cause)

    def test_jobs_are_not_compared_because_helm_deletes_them(self):
        """A hook Job carrying hook-succeeded is gone by design; its absence proves nothing."""
        ctx = self.context([("Job", "registration-job")], [])
        result = checks.deployment_drift(ctx)
        self.assertIs(result.status, Status.SKIP)

    def test_no_manifest_skips_rather_than_claiming_agreement(self):
        ctx = self.context([("Deployment", "x")], [], manifest="")
        result = checks.deployment_drift(ctx)
        self.assertIs(result.status, Status.SKIP)
        self.assertIn("helm template", result.cause)


class TestReservedWordVersions(unittest.TestCase):
    """The version gate, which answers without writing anything.

    The exposed window has two edges and both are real commits: the
    read-merge-write path arrived with the Scorpio 6 patch in tm-forum-api 1.16.1,
    and the re-escape that fixes it landed in 1.18.0 (PR #168). Whether being in
    that window destroys data depends on the broker, because Scorpio only discards
    raw keywords from 6.0.0 - which is why the demo, on 1.14.1 and Scorpio 4, is
    not at risk for two independent reasons.
    """

    def context(self, tmforum=None, scorpio=None):
        from fdsc_verify.profile import Profile
        images = []
        if tmforum:
            images.append(("tmf", "quay.io/fiware/tmforum-all-in-one:%s" % tmforum))
        if scorpio:
            images.append(("scorpio", "scorpiobroker/all-in-one-runner:java-%s" % scorpio))

        def image_of(*fragments):
            for name, image in images:
                if any(f in image for f in fragments):
                    return name, image
            return None, None

        return SimpleNamespace(image_of=image_of, profile=Profile(),
                               deployment=SimpleNamespace(namespace="ns", services={},
                                                          edc_lanes={}))

    def result(self, **kw):
        from fdsc_verify.checks import broker
        return broker.tmforum_reserved_words(self.context(**kw))

    def test_the_fixed_version_is_clean(self):
        self.assertIs(self.result(tmforum="1.18.0", scorpio="6.0.2").status, Status.OK)
        self.assertIs(self.result(tmforum="1.18.5", scorpio="6.0.2").status, Status.OK)

    def test_inside_the_window_with_a_dropping_broker_is_the_failure(self):
        result = self.result(tmforum="1.17.0", scorpio="6.0.2")
        self.assertIs(result.status, Status.FAIL)
        self.assertIn("1.16.1", result.summary)
        self.assertIn("1.18.0", result.summary)
        self.assertIn("upgrade tm-forum-api to 1.18.0", result.fix)

    def test_inside_the_window_with_an_older_broker_is_only_fragile(self):
        """Raw keywords go on the wire, but Scorpio 4 keeps them. Not lost - yet."""
        result = self.result(tmforum="1.17.0", scorpio="4.1.10")
        self.assertIs(result.status, Status.WARN)
        self.assertIn("the moment the broker is upgraded", result.cause)

    def test_before_the_window_cannot_lose_the_escape(self):
        self.assertIs(self.result(tmforum="1.14.1", scorpio="4.1.10").status, Status.OK)

    def test_before_the_window_on_scorpio_6_has_the_other_fault_instead(self):
        """Half an answer would be worse than none: that pairing appends on PATCH."""
        result = self.result(tmforum="1.14.1", scorpio="6.0.2")
        self.assertIs(result.status, Status.WARN)
        self.assertIn("appends to array attributes", result.cause)

    def test_no_tmforum_deployed_is_not_a_finding(self):
        result = self.result(scorpio="6.0.2")
        self.assertIs(result.status, Status.SKIP)
        self.assertIn("nothing stores TMForum resources", result.cause)

    def test_an_unreadable_tag_skips_rather_than_guessing(self):
        result = self.result(tmforum="latest")
        self.assertIs(result.status, Status.SKIP)
        self.assertIn("could not be read", result.summary)

    def test_the_demo_pairing_is_safe_for_two_independent_reasons(self):
        """1.14.1 + Scorpio 4.1.10, which is what one real deployment runs."""
        self.assertIs(self.result(tmforum="1.14.1", scorpio="4.1.10").status, Status.OK)


class TestTheBaeIsNotOneService(unittest.TestCase):
    """Half a marketplace is not a marketplace.

    The BAE ships the logic proxy - which authenticates the user and owns the
    login client id - and the charging backend, which turns an order into
    something billable. Discovery used to let the charging backend stand in for
    `marketplace` when the logic proxy was missing, so a deployment with only half
    of it read as complete. They are separate components now, tied by IMPLIES, so
    the gap is reported.

    The charging backend deliberately does NOT share `marketplace.enabled` as its
    values path: sharing it would make it read as present whenever the marketplace
    was switched on, whatever the cluster held, which is precisely the question
    being asked.
    """

    SERVICES = dict(PROVIDER_SERVICES, tmforum="tm-forum-api-svc")

    def test_both_halves_present_is_a_relationship_that_holds(self):
        result = checks.component_consistency(context(
            services=dict(self.SERVICES, marketplace="bae-logic-proxy",
                          marketplacecharging="bae-charging-backend"),
            tree={"marketplace": {"enabled": True,
                                  "bizEcosystemChargingBackend": {"enabled": True}}},
            document_server="did-helper"))
        self.assertIs(result.status, Status.OK)
        self.assertIn("marketplace -> marketplacecharging", str(result.detail))
        self.assertIn("marketplace -> tmforum", str(result.detail))

    def test_a_marketplace_without_its_charging_backend_is_reported(self):
        result = checks.component_consistency(context(
            services=dict(self.SERVICES, marketplace="bae-logic-proxy"),
            tree={"marketplace": {"enabled": True,
                                  "bizEcosystemChargingBackend": {"enabled": False}}},
            document_server="did-helper"))
        self.assertIs(result.status, Status.FAIL)
        self.assertIn("charging backend", result.cause)

    def test_no_marketplace_at_all_is_not_a_relationship_to_check(self):
        result = checks.component_consistency(context(
            services=self.SERVICES, tree={"marketplace": {"enabled": False}},
            document_server="did-helper"))
        self.assertIs(result.status, Status.OK)
