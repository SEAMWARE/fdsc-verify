"""The realm's two decisions: how long a credential lives, and in what format.

Each check is exercised twice - once on a deployment carrying the fault and once
on one that does not - because a check that cannot come back OK is
indistinguishable from a broken one.

The rest of these tests are the four shapes that would have made a naive
implementation lie, all of them measured on real deployments before any of this
was written. They are the reason the check is longer than "compare two strings".
"""

import json
import unittest
from types import SimpleNamespace

from fdsc_verify.checks import keycloak
from fdsc_verify.model import Status
from fdsc_verify.values import Values


def realm(*blocks):
    """`keycloak.realm.verifiableCredentials` as the chart writes it."""
    return {"keycloak": {"realm": {"verifiableCredentials": dict(blocks)}}}


def credential(name, vc_type=None, fmt=None, expiry=None, refresh=None, **extra):
    attributes = dict(extra)
    if vc_type is not None:
        attributes["verifiable_credential_type"] = vc_type
    if fmt is not None:
        attributes["format"] = fmt
    if expiry is not None:
        attributes["expiry_in_seconds"] = expiry
    if refresh is not None:
        attributes["refresh_interval_in_seconds"] = refresh
    return name, {"attributes": attributes}


def context(tree, services=None, verifier="verifier"):
    values = Values(defaults=tree or {}, trust="effective", source="test")
    return SimpleNamespace(
        values=values,
        deployment=SimpleNamespace(
            namespace="provider",
            service=lambda name: verifier if name == "verifier" else None),
        verifier_services=lambda: (services, None) if services is not None
        else (None, "config repo unreachable"))


def scope(vc_type, pd_formats=(), dcql=(), scope_name="openid", service_id="svc"):
    """One registered service with one scope, in the shape the config repo serves."""
    body = {"credentials": [{"type": vc_type}]}
    if pd_formats:
        body["presentationDefinition"] = {"format": {f: {} for f in pd_formats}}
    if dcql:
        body["dcql"] = {"credentials": [
            {"format": f, "meta": {"vct_values": [vc_type]}} for f in dcql]}
    return {"id": service_id, "oidcScopes": {scope_name: body}}


class TestCredentialLifetime(unittest.TestCase):
    def test_both_attributes_agreeing_passes(self):
        result = keycloak.keycloak_credential_lifetime(context(realm(
            credential("LegalPersonCredential", expiry="31536000",
                       refresh="31536000"))))
        self.assertIs(result.status, Status.OK)
        self.assertEqual(result.detail["agreed"], ["LegalPersonCredential"])

    def test_an_unset_refresh_interval_is_the_finding(self):
        """Two real deployments are in exactly this state. Keycloak defaults it to
        604800 and that is what reaches `exp`, while the UI shows the other one."""
        result = keycloak.keycloak_credential_lifetime(context(realm(
            credential("user-sd", expiry="31536000"))))
        self.assertIs(result.status, Status.WARN)
        self.assertIn("604800", result.summary)
        self.assertIn("user-sd", result.cause)
        self.assertEqual(result.detail["unset"], ["user-sd (the UI will show 31536000)"])

    def test_two_numbers_that_disagree_are_named_both(self):
        result = keycloak.keycloak_credential_lifetime(context(realm(
            credential("c", expiry="31536000", refresh="604800"))))
        self.assertIs(result.status, Status.WARN)
        self.assertIn("UI 31536000, credential 604800", result.cause)

    def test_the_fix_says_both_and_says_admin_api(self):
        """Moving expiry_in_seconds alone changes nothing, and a realm that already
        exists does not pick either of them up from the chart."""
        result = keycloak.keycloak_credential_lifetime(context(realm(
            credential("c", expiry="31536000"))))
        self.assertIn("both attributes", result.fix)
        self.assertIn("Admin API", result.fix)

    def test_no_realm_block_is_not_applicable(self):
        result = keycloak.keycloak_credential_lifetime(context({}))
        self.assertIs(result.status, Status.SKIP)
        self.assertFalse(result.applicable)

    def test_the_admin_api_spelling_is_accepted_too(self):
        """The chart writes these bare and the Admin API prefixes them with `vc.`."""
        result = keycloak.keycloak_credential_lifetime(context(realm(
            ("c", {"attributes": {"vc.expiry_in_seconds": "31536000",
                                  "vc.refresh_interval_in_seconds": "31536000"}}))))
        self.assertIs(result.status, Status.OK)


class TestVerifierFormats(unittest.TestCase):
    def test_a_format_both_sides_agree_on_passes(self):
        ctx = context(realm(credential("LegalPersonCredential",
                                       vc_type="LegalPersonCredential",
                                       fmt="dc+sd-jwt")),
                      services=[scope("LegalPersonCredential",
                                      pd_formats=("dc+sd-jwt", "vc+sd-jwt"))])
        result = keycloak.keycloak_verifier_formats(ctx)
        self.assertIs(result.status, Status.OK)
        self.assertEqual(result.detail["compared"], 1)

    def test_a_scope_that_will_not_take_what_we_issue_warns(self):
        """Seen live: a realm issuing dc+sd-jwt against a scope accepting only
        vc+sd-jwt. The wallet has nothing to present and says so generically."""
        ctx = context(realm(credential("LegalPersonCredential",
                                       vc_type="LegalPersonCredential",
                                       fmt="dc+sd-jwt")),
                      services=[scope("LegalPersonCredential",
                                      pd_formats=("vc+sd-jwt",))])
        result = keycloak.keycloak_verifier_formats(ctx)
        self.assertIs(result.status, Status.WARN)
        self.assertIn("dc+sd-jwt", result.cause)
        self.assertIn("vc+sd-jwt", result.cause)

    def test_the_block_name_is_not_the_credential_type(self):
        """`membership-credential` issues `MembershipCredential`. Matching on the
        block name reports a disagreement that is not there."""
        ctx = context(realm(credential("membership-credential",
                                       vc_type="MembershipCredential",
                                       fmt="jwt_vc_json")),
                      services=[scope("MembershipCredential",
                                      dcql=("jwt_vc_json",))])
        result = keycloak.keycloak_verifier_formats(ctx)
        self.assertIs(result.status, Status.OK)
        self.assertEqual(result.detail["issued"], {"MembershipCredential": "jwt_vc_json"})

    def test_a_block_with_no_type_is_skipped_not_guessed(self):
        """Older charts omit `verifiable_credential_type` entirely. Two deployments
        here are in that state, and the block name is not a substitute."""
        ctx = context(realm(("user-sd", {"attributes": {"format": "vc+sd-jwt"}})),
                      services=[scope("user-sd", pd_formats=("dc+sd-jwt",))])
        result = keycloak.keycloak_verifier_formats(ctx)
        self.assertIs(result.status, Status.SKIP)
        self.assertFalse(result.applicable)
        self.assertIn("user-sd", result.cause)

    def test_a_scope_stating_no_format_is_not_a_disagreement(self):
        """Nine registered services on one real deployment declare a type with
        neither a presentation definition format nor a dcql entry. Treating an
        empty set as a mismatch reported nine faults on a healthy deployment."""
        ctx = context(realm(credential("c", vc_type="MembershipCredential",
                                       fmt="jwt_vc_json")),
                      services=[scope("MembershipCredential")])
        result = keycloak.keycloak_verifier_formats(ctx)
        self.assertIs(result.status, Status.SKIP)
        self.assertFalse(result.applicable)
        self.assertIn("never told a format", result.cause)
        self.assertIn("svc/openid", result.cause)

    def test_the_dcql_format_counts_even_with_no_presentation_definition(self):
        """The two live independently: a scope may carry either or both."""
        ctx = context(realm(credential("c", vc_type="MembershipCredential",
                                       fmt="jwt_vc_json")),
                      services=[scope("MembershipCredential", dcql=("jwt_vc_json",))])
        self.assertIs(keycloak.keycloak_verifier_formats(ctx).status, Status.OK)

    def test_the_older_dcql_type_spelling_is_accepted(self):
        """`meta.type_values` nests one level; newer versions use `vct_values`."""
        service = {"id": "svc", "oidcScopes": {"openid": {"dcql": {"credentials": [
            {"format": "jwt_vc_json",
             "meta": {"type_values": [["MembershipCredential"]]}}]}}}}
        ctx = context(realm(credential("c", vc_type="MembershipCredential",
                                       fmt="jwt_vc_json")), services=[service])
        self.assertIs(keycloak.keycloak_verifier_formats(ctx).status, Status.OK)

    def test_a_type_we_do_not_issue_is_not_judged(self):
        """In a working dataspace a counterparty issues it, so complaining would put
        a permanent finding in every report."""
        ctx = context(realm(credential("c", vc_type="LegalPersonCredential",
                                       fmt="dc+sd-jwt")),
                      services=[scope("SomebodyElsesCredential",
                                      pd_formats=("jwt_vc",))])
        result = keycloak.keycloak_verifier_formats(ctx)
        self.assertIs(result.status, Status.SKIP)
        self.assertFalse(result.applicable)

    def test_an_unreadable_config_repo_skips_visibly(self):
        """A coverage gap, not a verdict: the question arises and went unanswered."""
        ctx = context(realm(credential("c", vc_type="LegalPersonCredential",
                                       fmt="dc+sd-jwt")))
        result = keycloak.keycloak_verifier_formats(ctx)
        self.assertIs(result.status, Status.SKIP)
        self.assertTrue(result.applicable)
        self.assertIn("config repo unreachable", result.cause)

    def test_unreadable_values_skip_visibly_rather_than_claim_an_empty_realm(self):
        """A GitOps install has no release, and the realm is a values-only source.
        Saying "this realm issues no credential" there asserts something the tool
        never read - a coverage gap has to stay visible as one."""
        from fdsc_verify.values import Values as V
        ctx = context({})
        ctx.values = V.empty("no DSC release could be read")
        result = keycloak.keycloak_verifier_formats(ctx)
        self.assertIs(result.status, Status.SKIP)
        self.assertTrue(result.applicable)
        self.assertIn("could not be read", result.summary)

    def test_no_verifier_is_not_applicable(self):
        ctx = context(realm(credential("c", vc_type="LegalPersonCredential",
                                       fmt="dc+sd-jwt")), verifier=None)
        result = keycloak.keycloak_verifier_formats(ctx)
        self.assertIs(result.status, Status.SKIP)
        self.assertFalse(result.applicable)


DID = "did:web:provider.example.org:did"
PUBLISHED_EC = {"kty": "EC", "crv": "P-256", "x": "QQ", "y": "Ug"}


def signing_ctx(kid="#key-1", algorithm=None, method="key-1", jwk=None,
                keystore="identity-tls", identity="identity-tls",
                realm_kid=None, service="provider-keycloak"):
    """A deployment whose Keycloak signs, with every source the check consults."""
    tree = {"keycloak": {"signingKey": {}}}
    if kid is not None:
        tree["keycloak"]["signingKey"]["did"] = kid
    if algorithm:
        tree["keycloak"]["signingKey"]["keyAlgorithm"] = algorithm
    document = {"verificationMethod": [
        {"id": method, "publicKeyJwk": jwk or PUBLISHED_EC}]}

    realm_json = json.dumps({"clients": [{"attributes": {
        "vc.signing_key_id": realm_kid}}]}) if realm_kid else None

    def configmap(name, namespace=None):
        return {"provider-realm.json": realm_json} if realm_json else {}

    def get_json(kind, name=None, namespace=None, check=True, selector=None):
        if kind == "service":
            return {"spec": {"selector": {"app": "kc"}}} if name == service else None
        if kind == "pod":
            return {"items": [{"spec": {
                "volumes": [{"name": "did-priv-key",
                             "secret": {"secretName": keystore}},
                            {"name": "ca-cert", "secret": {"secretName": "ca-cert"}},
                            {"name": "realm", "configMap": {"name": "provider-realm"}}],
                "initContainers": [{
                    "name": "get-did",
                    "command": ["/bin/sh", "-c", "openssl pkcs12 -export ..."],
                    "volumeMounts": [{"name": "did-priv-key"}, {"name": "ca-cert"}]}],
                "containers": []}}]}
        return None

    ctx = SimpleNamespace(
        insecure=False,
        values=Values(defaults=tree, trust="effective", source="test"),
        kube=SimpleNamespace(get_json=get_json, configmap=configmap,
                             secret=lambda name, namespace=None: {}),
        any_participant_id=lambda: DID,
        deployment=SimpleNamespace(
            namespace="provider", identity_secret=identity,
            identity_secret_key="tls.key",
            service=lambda n: service if n == "keycloak" else None))
    keycloak.fetch_did_document = lambda did, insecure=False: (document, None)
    return ctx


class TestSigningKey(unittest.TestCase):
    """Whether anybody can verify what Keycloak signs.

    The two kid shapes below are both live and both correct, which is the whole
    reason the rule is "the kid is a published method id" rather than "the kid
    carries a fragment".
    """

    def setUp(self):
        self._real = keycloak.fetch_did_document

    def tearDown(self):
        keycloak.fetch_did_document = self._real

    def test_a_relative_kid_against_a_relative_method_passes(self):
        result = keycloak.keycloak_signing_key(signing_ctx(kid="#key-1",
                                                           method="key-1"))
        self.assertIs(result.status, Status.OK)
        self.assertIn("identity secret", result.summary)

    def test_an_absolute_kid_against_a_relative_method_passes(self):
        """One shape names `<did>#key-1` while the document publishes `key-1`.
        Comparing the strings literally calls a healthy deployment broken."""
        result = keycloak.keycloak_signing_key(
            signing_ctx(kid=DID + "#key-1", method="key-1"))
        self.assertIs(result.status, Status.OK)

    def test_the_bare_did_as_a_method_id_passes(self):
        """The other live shape: no fragment on either side."""
        result = keycloak.keycloak_signing_key(signing_ctx(kid=DID, method=DID))
        self.assertIs(result.status, Status.OK)

    def test_a_kid_the_document_does_not_publish_fails(self):
        result = keycloak.keycloak_signing_key(signing_ctx(kid="#key-9",
                                                           method="key-1"))
        self.assertIs(result.status, Status.FAIL)
        self.assertIn("key-9", result.cause)
        self.assertIn("key-1", result.cause)

    def test_an_algorithm_the_published_key_cannot_carry_fails(self):
        """RS256 against an EC key. The RSA families were missing from the table
        at first, so this passed an RS256 realm against a P-256 document."""
        result = keycloak.keycloak_signing_key(
            signing_ctx(kid="#key-1", method="key-1", algorithm="RS256"))
        self.assertIs(result.status, Status.FAIL)
        self.assertIn("RSA", result.cause)

    def test_the_matching_algorithm_passes(self):
        result = keycloak.keycloak_signing_key(
            signing_ctx(kid="#key-1", method="key-1", algorithm="ES256"))
        self.assertIs(result.status, Status.OK)

    def test_the_realm_configmap_answers_when_the_values_do_not(self):
        """A GitOps install has no values, and the realm Keycloak mounts carries
        the same string. The ConfigMap is found through the pod's volumes: its
        name does not follow the release, so `<release>-realm` matches nothing."""
        ctx = signing_ctx(kid=None, method="key-1", realm_kid=DID + "#key-1")
        result = keycloak.keycloak_signing_key(ctx)
        self.assertIs(result.status, Status.OK)
        self.assertEqual(result.detail["kidFrom"], "the realm ConfigMap")

    def test_a_placeholder_kid_is_not_compared(self):
        ctx = signing_ctx(kid="${DID}#key-1", method="key-1")
        result = keycloak.keycloak_signing_key(ctx)
        self.assertIs(result.status, Status.SKIP)
        self.assertTrue(result.applicable)

    def test_a_keystore_built_from_another_secret_is_examined(self):
        """Not judged on the name: a different name holding the same key is drift,
        and a different key is fatal. Here the second secret cannot be read."""
        ctx = signing_ctx(kid="#key-1", method="key-1",
                          keystore="somebody-elses-tls", identity="identity-tls")
        result = keycloak.keycloak_signing_key(ctx)
        self.assertIs(result.status, Status.SKIP)
        self.assertIn("somebody-elses-tls", result.cause)

    def test_no_keycloak_is_not_applicable(self):
        ctx = signing_ctx()
        ctx.deployment.service = lambda n: None
        result = keycloak.keycloak_signing_key(ctx)
        self.assertIs(result.status, Status.SKIP)
        self.assertFalse(result.applicable)

    def test_the_ca_bundle_mounted_beside_the_key_is_not_mistaken_for_it(self):
        """The init container mounts the key and the CA bundle. Taking the first
        secret it finds would pick whichever kubectl happened to list first."""
        result = keycloak.keycloak_signing_key(signing_ctx(kid="#key-1",
                                                           method="key-1"))
        self.assertEqual(result.detail["keystoreSecret"], "identity-tls")


class TestEveryFindingCanBeActedOn(unittest.TestCase):
    """A WARN with no cause, fix or see: line is an incomplete check."""

    def _findings(self):
        yield keycloak.keycloak_credential_lifetime(context(realm(
            credential("c", expiry="31536000"))))
        yield keycloak.keycloak_credential_lifetime(context(realm(
            credential("c", expiry="31536000", refresh="604800"))))
        yield keycloak.keycloak_verifier_formats(context(
            realm(credential("c", vc_type="LegalPersonCredential", fmt="dc+sd-jwt")),
            services=[scope("LegalPersonCredential", pd_formats=("vc+sd-jwt",))]))

    def test_each_one_names_a_cause_a_fix_and_a_section(self):
        for result in self._findings():
            self.assertIn(result.status, (Status.WARN, Status.FAIL))
            self.assertTrue(result.cause, result.summary)
            self.assertTrue(result.fix, result.summary)
            self.assertTrue(result.doc, result.summary)


if __name__ == "__main__":
    unittest.main()
