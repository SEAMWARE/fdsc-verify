"""The participant's identity, resolved without an EDC lane.

This is the change that makes the tool useful on a Consumer. The DID used to come
from `edc.participant.id` in a lane's ConfigMap and nowhere else, so a deployment
without fdsc-edc had no identity and every identity check skipped - on a role for
which the canonical matrix makes the connector optional.

The fixtures mirror the real files: a GitOps consumer's `values.yaml` has
nothing but a did-helper hostUrl and a `${DID}` placeholder in Keycloak, which is
the hardest case and the most common one.
"""

import unittest
from types import SimpleNamespace

from fdsc_verify import participant as P
from fdsc_verify import values as V
from fdsc_verify.checks import identity
from fdsc_verify.model import Status
from fdsc_verify.profile import Profile

DID = "did:web:did-provider.example.org"

# What dev's consumer really declares: a did-helper URL and a placeholder.
CONSUMER = {"did": {"config": {"server": {"hostUrl": "https://did-consumer.example.net"}}},
            "keycloak": {"issuerDid": "${DID}"}}
PROVIDER = {"did": {"config": {"server": {"hostUrl": "https://did-provider.example.org"}}},
            "keycloak": {"issuerDid": "${DID}"},
            "contract-management": {"did": DID},
            "decentralizedIam": {"vcAuthentication": {"vcverifier": {
                "deployment": {"verifier": {"did": DID,
                                            "tirAddress": "http://trusted-issuers-list:8080/"}}}}}}


def values(tree, trust="effective"):
    return V.Values(defaults=tree, trust=trust, source="test")


def deployment(lanes=(), services=None, secret=None):
    return SimpleNamespace(
        edc_lanes={l.name: l for l in lanes},
        identity_secret=secret, identity_secret_key="tls.key",
        service=lambda name: (services or {}).get(name),
        namespace="ns")


def kube(did=DID, host_url="https://did-provider.example.org",
         verifier_body=None):
    """The two ConfigMaps the cluster tier reads, in the shape the real ones have.

    `HOST_URL` is a configMapKeyRef in every deployment inspected, never a
    literal, which is why `Context.workload_env` cannot see it.
    """
    if verifier_body is None:
        verifier_body = ("verifier:\n  did: %s\n"
                         "  tirAddress: http://trusted-issuers-list:8080/\n" % did)
    maps = {"verifier": {"server.yaml": verifier_body},
            "provider-did-cm": {"hostUrl": host_url}}

    def get_json(kind, name=None, namespace=None, check=True, selector=None):
        if kind == "service":
            if name == "provider-did":
                return {"spec": {"selector": {"app": "did"}}}
            if name == "provider-keycloak":
                return {"spec": {"selector": {"app": "keycloak"}}}
            return None
        if kind == "pod":
            if selector == "app=keycloak":
                return {"items": [{"spec": {"containers": [{"env": [
                    {"name": "DID", "value": did}]}]}}]}
            return {"items": [{"spec": {"containers": [{"env": [
                {"name": "HOST_URL", "valueFrom": {"configMapKeyRef": {
                    "name": "provider-did-cm", "key": "hostUrl"}}}]}]}}]}
        return None

    return SimpleNamespace(
        get_json=get_json,
        configmap=lambda name, namespace=None: maps.get(name, {}))


def lane(name="dcp", did=None, **props):
    props.setdefault("edc.participant.id", did)
    return SimpleNamespace(name=name, participant_id=did,
                           prop=lambda key, default=None: props.get(key, default))


class TestDidFromHostUrl(unittest.TestCase):
    def test_a_bare_host(self):
        self.assertEqual(P.did_from_host_url("https://did.example.org"),
                         "did:web:did.example.org")

    def test_a_path_becomes_colon_segments(self):
        """The form demo uses; getting it wrong renames the participant."""
        self.assertEqual(P.did_from_host_url("https://did.example.org/did"),
                         "did:web:did.example.org:did")

    def test_a_trailing_slash_is_not_a_segment(self):
        self.assertEqual(P.did_from_host_url("https://did.example.org/"),
                         "did:web:did.example.org")

    def test_it_is_the_inverse_of_did_to_url(self):
        for did in ("did:web:did.example.org", "did:web:did.example.org:did"):
            url = identity.did_to_url(did).replace("/.well-known/did.json", "") \
                                          .replace("/did.json", "")
            self.assertEqual(P.did_from_host_url(url), did)


class TestResolution(unittest.TestCase):
    def test_a_consumer_with_only_a_did_helper_still_has_an_identity(self):
        who = P.resolve(deployment(), Profile(), values(CONSUMER))
        self.assertEqual(who.did, "did:web:did-consumer.example.net")
        self.assertEqual(who.origin, "did-helper")

    def test_a_placeholder_is_recorded_but_never_compared(self):
        who = P.resolve(deployment(), Profile(), values(CONSUMER))
        self.assertIn("keycloak", who.placeholders)
        self.assertNotIn("keycloak", who.did_sources)

    def test_every_source_is_kept_even_when_they_agree(self):
        who = P.resolve(deployment(), Profile(), values(PROVIDER))
        self.assertEqual(set(who.did_sources), {"verifier", "contract-management",
                                                "did-helper"})
        self.assertEqual(who.disagreements(), [])

    def test_the_lane_wins_so_no_edc_deployment_changes_verdict(self):
        who = P.resolve(deployment(lanes=[lane(did="did:web:from-the-lane")]),
                        Profile(), values(PROVIDER))
        self.assertEqual(who.did, "did:web:from-the-lane")
        self.assertEqual(who.origin, "lane dcp")

    def test_a_declared_did_beats_everything(self):
        profile = Profile()
        profile.did, profile._origins["did"] = "did:web:declared", "--did"
        who = P.resolve(deployment(lanes=[lane(did="did:web:from-the-lane")]),
                        profile, values(PROVIDER))
        self.assertEqual(who.did, "did:web:declared")

    def test_unreadable_values_and_no_lane_means_no_identity(self):
        who = P.resolve(deployment(), Profile(), V.Values.empty("nothing"))
        self.assertIsNone(who.did)
        self.assertEqual(who.did_sources, {})

    def test_the_cluster_answers_when_a_gitops_install_left_no_values(self):
        """dev's provider: Argo renders with `helm template`, so there is no release
        Secret and `values.trust` is "none". It had a did-helper, a verifier and a
        TIL all running and still reported "no source states a DID", which skipped
        five identity checks on a deployment able to answer every one of them."""
        who = P.resolve(deployment(services={"verifier": "verifier", "did": "provider-did"}),
                        Profile(), V.Values.empty("no release"), kube=kube())
        self.assertEqual(who.did, DID)
        self.assertEqual(who.origin, "verifier (cluster)")
        self.assertEqual(who.did_sources,
                         {"verifier (cluster)": DID, "did-helper (cluster)": DID})
        self.assertEqual(who.til_address, "http://trusted-issuers-list:8080/")

    def test_keycloak_states_the_did_on_its_pod_and_nowhere_else(self):
        """`keycloak.issuerDid` is in the DID path table, and a recursive sweep of
        the full values of every deployment reachable from here found no key of that
        shape at all. What Keycloak really carries is a literal `DID` env var on its
        pod, present and correct on every one of them."""
        who = P.resolve(deployment(services={"keycloak": "provider-keycloak"}),
                        Profile(), V.Values.empty("no release"), kube=kube())
        self.assertEqual(who.did_sources, {"keycloak (cluster)": DID})
        self.assertEqual(who.origin, "keycloak (cluster)")

    def test_a_placeholder_on_the_pod_is_not_a_source(self):
        """The same rule the values-side keycloak path follows: `${DID}` reaching a
        pod verbatim is a registration defect, not a participant identity."""
        who = P.resolve(deployment(services={"keycloak": "provider-keycloak"}),
                        Profile(), V.Values.empty("no release"),
                        kube=kube(did="${DID}"))
        self.assertEqual(who.did_sources, {})

    def test_the_cluster_never_outranks_a_source_that_already_answered(self):
        """Measured before shipping: with this tier added, not one verdict moves on
        any of the four demo deployments. It may only fill a gap."""
        who = P.resolve(deployment(lanes=[lane(did="did:web:from-the-lane")],
                                   services={"verifier": "verifier"}),
                        Profile(), values(PROVIDER), kube=kube())
        self.assertEqual(who.did, "did:web:from-the-lane")
        self.assertEqual(who.origin, "lane dcp")
        # ...and it is still recorded, because the comparison is the diagnosis
        self.assertEqual(who.did_sources["verifier (cluster)"], DID)

    def test_a_cluster_did_that_disagrees_is_recorded_not_hidden(self):
        who = P.resolve(deployment(services={"verifier": "verifier"}), Profile(),
                        values(PROVIDER), kube=kube(did="did:web:somebody-else"))
        self.assertEqual(who.did, DID)                      # the values still decide
        self.assertEqual(who.did_sources["verifier (cluster)"], "did:web:somebody-else")
        self.assertEqual(identity.identity_did_consistency(
            SimpleNamespace(participant=who)).status, Status.FAIL)

    def test_without_pyyaml_the_verifier_source_is_lost_and_nothing_else(self):
        """PyYAML is optional in this tool. Its absence may cost a source; it may
        never turn one into a wrong answer."""
        who = P.resolve(deployment(services={"verifier": "verifier", "did": "provider-did"}),
                        Profile(), V.Values.empty("no release"),
                        kube=kube(verifier_body="}not yaml{"))
        self.assertEqual(who.did_sources, {"did-helper (cluster)": DID})
        self.assertEqual(who.did, DID)

    def test_the_did_helper_is_found_through_the_service_selector(self):
        """dso-infra runs two did-helpers; only the discovered one may be read."""
        k = kube(host_url="https://did-provider.example.org")
        self.assertEqual(
            P._workload_env_value(k, "ns", "provider-did", "HOST_URL"),
            "https://did-provider.example.org")
        # no Service, no guess at the workload's name
        self.assertIsNone(P._workload_env_value(k, "ns", "not-a-service", "HOST_URL"))

    def test_the_til_address_comes_from_the_verifier_without_a_lane(self):
        who = P.resolve(deployment(), Profile(), values(PROVIDER))
        self.assertEqual(who.til_address, "http://trusted-issuers-list:8080/")

    def test_who_serves_the_document_is_read_from_the_services(self):
        self.assertEqual(
            P.resolve(deployment(services={"identityhub": "identityhub-service"}),
                      Profile(), values(PROVIDER)).document_server, "identityhub")
        self.assertEqual(
            P.resolve(deployment(services={"did": "provider-did"}),
                      Profile(), values(PROVIDER)).document_server, "did-helper")

    def test_the_did_host_is_a_host_worth_a_certificate(self):
        who = P.resolve(deployment(), Profile(), values(CONSUMER))
        self.assertIn("did-consumer.example.net", who.hosts)


class TestConsistencyCheck(unittest.TestCase):
    def context(self, tree, lanes=(), profile=None):
        vals = values(tree)
        dep = deployment(lanes=lanes)
        return SimpleNamespace(
            values=vals, deployment=dep, profile=profile or Profile(),
            participant=P.resolve(dep, profile or Profile(), vals))

    def test_sources_that_agree_pass(self):
        result = identity.identity_did_consistency(self.context(PROVIDER))
        self.assertIs(result.status, Status.OK)
        self.assertIn("3 sources agree", result.summary)

    def test_a_placeholder_is_explained_rather_than_flagged(self):
        result = identity.identity_did_consistency(self.context(PROVIDER))
        self.assertIn("placeholder", result.summary)
        self.assertIn("meant to", result.summary)

    def test_a_single_source_is_not_a_finding(self):
        result = identity.identity_did_consistency(self.context(CONSUMER))
        self.assertIs(result.status, Status.OK)
        self.assertIn("one source", result.summary)

    def test_the_odd_one_out_is_named_not_the_majority(self):
        drifted = dict(PROVIDER)
        drifted["contract-management"] = {"did": "did:web:stale.example.org"}
        result = identity.identity_did_consistency(self.context(drifted))
        self.assertIs(result.status, Status.FAIL)
        self.assertIn("1 of 3", result.summary)
        self.assertIn("contract-management says did:web:stale.example.org", result.cause)

    def test_a_two_way_split_picks_no_side(self):
        split = {"contract-management": {"did": "did:web:a"},
                 "decentralizedIam": {"vcAuthentication": {"vcverifier": {
                     "deployment": {"verifier": {"did": "did:web:b"}}}}}}
        result = identity.identity_did_consistency(self.context(split))
        self.assertIs(result.status, Status.FAIL)
        self.assertIn("2 different participants", result.summary)

    def test_nothing_to_read_skips_with_the_reason(self):
        ctx = SimpleNamespace(values=V.Values.empty("cluster unreachable"),
                              deployment=deployment(), profile=Profile(),
                              participant=P.resolve(deployment(), Profile(),
                                                    V.Values.empty("cluster unreachable")))
        result = identity.identity_did_consistency(ctx)
        self.assertIs(result.status, Status.SKIP)
        self.assertIn("--did", result.cause)


if __name__ == "__main__":
    unittest.main()


class TestTilRegistrationSeverity(unittest.TestCase):
    """Whose DID is missing decides the verdict, not whether --peer was passed.

    It used to be the second: with no peer the check assumed loopback DSP flows
    were the target and failed. That is a DSP-shaped criterion applied to every
    deployment, including ones with no connector at all - and on a consumer it
    called a normal state broken. The TIL a participant runs is consulted by *its
    own* verifier, so a DID missing from ours only ever breaks something coming in.
    """

    def context(self, registered, peers=(), services=None, lanes=()):
        from fdsc_verify.profile import Profile
        dep = SimpleNamespace(
            edc_lanes={l.name: l for l in lanes}, services=services or {},
            namespace="ns", service=lambda n: (services or {}).get(n))
        return SimpleNamespace(
            deployment=dep, profile=Profile(), peers=list(peers),
            participant=SimpleNamespace(did="did:web:us", til_address="http://til:8080"),
            til_issuer=lambda address, subject: (
                ({"attributes": []}, None) if subject in registered else (None, None)),
            til_credential_types=lambda body: [])

    def peer(self, did="did:web:them"):
        return SimpleNamespace(name="them", participant_id=did)

    def test_our_own_did_missing_is_a_warning_even_with_no_peer(self):
        result = identity.til_registration(self.context(registered=set()))
        self.assertIs(result.status, Status.WARN)
        self.assertIn("Nothing we do outwards depends on this", result.cause)

    def test_it_says_outbound_access_is_unaffected(self):
        """The question this answers most often: can I still reach the central MP?"""
        result = identity.til_registration(self.context(registered=set()))
        self.assertIn("central marketplace", result.cause)

    def test_a_peers_did_missing_is_still_a_failure(self):
        result = identity.til_registration(
            self.context(registered={"did:web:us"}, peers=[self.peer()]))
        self.assertIs(result.status, Status.FAIL)
        self.assertIn("did:web:them", result.cause)
        self.assertIn("every presentation from that peer is refused", result.cause)

    def test_both_missing_leads_with_the_peer(self):
        """The peer's absence is the one that breaks interop; ours is a footnote."""
        result = identity.til_registration(
            self.context(registered=set(), peers=[self.peer()]))
        self.assertIs(result.status, Status.FAIL)
        self.assertIn("a peer's DID", result.summary)

    def test_a_deployment_with_lanes_is_told_loopback_breaks(self):
        result = identity.til_registration(
            self.context(registered=set(), lanes=[lane("dcp", did="did:web:us")]))
        self.assertIn("loopback DSP flow", result.cause)

    def test_a_deployment_without_lanes_is_not(self):
        result = identity.til_registration(self.context(registered=set()))
        self.assertNotIn("loopback", result.cause)

    def test_a_provider_is_told_its_own_users_are_affected(self):
        result = identity.til_registration(self.context(
            registered=set(),
            services={"verifier": "v", "til": "t", "apisix": "a", "odrlpap": "o"}))
        self.assertIn("our own users", result.cause)

    def test_everything_registered_is_a_clean_pass(self):
        result = identity.til_registration(
            self.context(registered={"did:web:us", "did:web:them"}, peers=[self.peer()]))
        self.assertIs(result.status, Status.OK)
