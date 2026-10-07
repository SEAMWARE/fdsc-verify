"""The declared profile, and the contradictions it has to catch.

Two properties matter here and neither is about parsing. The first is that a bad
declaration is a **usage error**: `--role providr` must stop the run, because a
typo that silently disables a role gate would remove checks without saying so -
the exact failure `Check.families` has today, where a misspelled family skips a
check everywhere and nothing complains.

The second is that a declaration is an assertion. Saying `--edc` where no lane
exists is a finding, not an override, and the run with no flags at all - the
normal case - must stay clean.
"""

import unittest
from types import SimpleNamespace

from fdsc_verify.checks import profile as profile_check
from fdsc_verify.model import Status
from fdsc_verify.profile import Profile, ProfileError


def args(**kw):
    """argparse's Namespace as main() hands it over: every field present, mostly None."""
    base = dict(role=None, edc=None, edc_protocol=None, did=None, identity_secret=None,
                values_root=None, component=None, release=None)
    base.update(kw)
    return SimpleNamespace(**base)


def lane(name, did=None, identity="unknown"):
    return SimpleNamespace(name=name, participant_id=did, identity=identity)


def context(profile=None, lanes=(), releases=(), namespace="provider", primary=None,
            inspected=True):
    return SimpleNamespace(
        profile=profile if profile is not None else Profile(),
        kube=SimpleNamespace(available=lambda: inspected),
        deployment=SimpleNamespace(
            namespace=namespace,
            edc_lanes={l.name: l for l in lanes},
            releases={name: object() for name in releases},
            primary_release=primary),
    )


class TestRoles(unittest.TestCase):
    def test_a_single_role(self):
        self.assertEqual(Profile.from_args(args(role="provider")).roles, ("provider",))

    def test_the_combined_role_expands(self):
        self.assertEqual(Profile.from_args(args(role="consumer+provider")).roles,
                         ("consumer", "provider"))

    def test_a_comma_list_is_the_same_value_as_the_combined_form(self):
        self.assertEqual(Profile.from_args(args(role="provider,consumer")).roles,
                         Profile.from_args(args(role="consumer+provider")).roles)

    def test_a_typo_is_a_usage_error_not_a_silent_skip(self):
        with self.assertRaises(ProfileError) as caught:
            Profile.from_args(args(role="providr"))
        self.assertIn("providr", str(caught.exception))
        self.assertIn("--role", str(caught.exception))

    def test_operator_is_not_a_role_this_tool_accepts(self):
        """Out of scope on purpose; accepting it would promise checks that do not exist."""
        with self.assertRaises(ProfileError):
            Profile.from_args(args(role="operator"))


class TestEdc(unittest.TestCase):
    def test_edc_and_no_edc_are_distinct_from_undeclared(self):
        self.assertIs(Profile.from_args(args(edc=True)).edc, True)
        self.assertIs(Profile.from_args(args(edc=False)).edc, False)
        self.assertIsNone(Profile.from_args(args()).edc)

    def test_declaring_a_protocol_implies_the_connector(self):
        profile = Profile.from_args(args(edc_protocol="dcp"))
        self.assertIs(profile.edc, True)
        self.assertIn("--edc-protocol", profile.origin("edc"))

    def test_oid4vp_is_accepted_as_the_deployments_own_spelling(self):
        self.assertEqual(Profile.from_args(args(edc_protocol="oid4vp")).edc_protocol,
                         "oid4vc")

    def test_no_edc_with_a_protocol_is_refused(self):
        with self.assertRaises(ProfileError) as caught:
            Profile.from_args(args(edc=False, edc_protocol="dcp"))
        self.assertIn("contradict", str(caught.exception))

    def test_an_unknown_protocol_is_a_usage_error(self):
        with self.assertRaises(ProfileError):
            Profile.from_args(args(edc_protocol="dsp"))


class TestScalarsAndFile(unittest.TestCase):
    def test_a_did_must_look_like_one(self):
        with self.assertRaises(ProfileError) as caught:
            Profile.from_args(args(did="connector.example.es"))
        self.assertIn("did:", str(caught.exception))

    def test_the_did_is_mirrored_where_discovery_already_reads_it(self):
        profile = Profile.from_args(args(did="did:web:example.org"))
        self.assertEqual(profile.raw["identity"]["participantId"], "did:web:example.org")

    def test_the_identity_secret_is_mirrored_for_apply_overrides(self):
        profile = Profile.from_args(args(identity_secret="atd-tls"))
        self.assertEqual(profile.raw["identity"]["secret"], "atd-tls")

    def test_the_file_supplies_the_same_fields_as_the_flags(self):
        profile = Profile.from_args(args(), {"role": "provider", "edc": {"enabled": False},
                                            "did": "did:web:example.org"})
        self.assertEqual(profile.roles, ("provider",))
        self.assertIs(profile.edc, False)
        self.assertEqual(profile.origin("roles"), "--config")

    def test_a_flag_beats_the_file(self):
        profile = Profile.from_args(args(role="consumer"), {"role": "provider"})
        self.assertEqual(profile.roles, ("consumer",))
        self.assertEqual(profile.origin("roles"), "--role")

    def test_values_root_is_split_into_keys(self):
        self.assertEqual(Profile.from_args(args(values_root="dsc")).values_root, ("dsc",))
        self.assertEqual(Profile.from_args(args(values_root="a.b")).values_root, ("a", "b"))

    def test_components_accept_on_off(self):
        profile = Profile.from_args(args(component=["did-helper=on", "marketplace=off"]))
        self.assertEqual(profile.components, {"did-helper": True, "marketplace": False})

    def test_a_component_without_a_state_is_a_usage_error(self):
        with self.assertRaises(ProfileError):
            Profile.from_args(args(component=["did-helper"]))

    def test_an_empty_profile_knows_it_is_empty(self):
        self.assertTrue(Profile.from_args(args()).is_empty())
        self.assertFalse(Profile.from_args(args(role="provider")).is_empty())


class TestDeclaredCheck(unittest.TestCase):
    def test_no_declarations_is_a_clean_ok(self):
        result = profile_check.deployment_profile(context())
        self.assertIs(result.status, Status.OK)
        self.assertIn("inferred", result.summary)

    def test_declaring_edc_where_there_is_no_lane_fails(self):
        result = profile_check.deployment_profile(
            context(profile=Profile.from_args(args(edc=True))))
        self.assertIs(result.status, Status.FAIL)
        self.assertIn("no fdsc-edc lane", result.cause)
        self.assertIn("--edc", result.cause)

    def test_declaring_no_edc_where_a_lane_exists_fails(self):
        result = profile_check.deployment_profile(
            context(profile=Profile.from_args(args(edc=False)), lanes=[lane("dcp")]))
        self.assertIs(result.status, Status.FAIL)
        self.assertIn("dcp", result.cause)

    def test_a_protocol_that_contradicts_the_lane_fails(self):
        result = profile_check.deployment_profile(context(
            profile=Profile.from_args(args(edc_protocol="dcp")),
            lanes=[lane("oid4vc", identity="oid4vc")]))
        self.assertIs(result.status, Status.FAIL)
        self.assertIn("oid4vc", result.cause)

    def test_a_protocol_matching_one_of_two_lanes_is_not_a_contradiction(self):
        """demo runs both lanes at once; naming one of them is not a mismatch."""
        result = profile_check.deployment_profile(context(
            profile=Profile.from_args(args(edc_protocol="dcp")),
            lanes=[lane("dcp", identity="dcp"), lane("oid4vc", identity="oid4vc")]))
        self.assertIs(result.status, Status.OK)

    def test_a_lane_that_cannot_say_what_it_speaks_is_not_a_contradiction(self):
        result = profile_check.deployment_profile(context(
            profile=Profile.from_args(args(edc_protocol="dcp")),
            lanes=[lane("edc", identity="unknown")]))
        self.assertIs(result.status, Status.OK)

    def test_a_did_that_disagrees_with_the_lane_fails(self):
        result = profile_check.deployment_profile(context(
            profile=Profile.from_args(args(did="did:web:example.org")),
            lanes=[lane("dcp", did="did:web:connector.example.es")]))
        self.assertIs(result.status, Status.FAIL)
        self.assertIn("did:web:connector.example.es", result.cause)

    def test_a_did_with_no_lane_to_compare_against_is_accepted(self):
        result = profile_check.deployment_profile(context(
            profile=Profile.from_args(args(did="did:web:example.org"))))
        self.assertIs(result.status, Status.OK)

    def test_a_release_that_is_not_in_the_namespace_fails(self):
        result = profile_check.deployment_profile(context(
            profile=Profile.from_args(args(release="nope")),
            releases=("central-mk", "trust-anchor")))
        self.assertIs(result.status, Status.FAIL)
        self.assertIn("central-mk", result.cause)

    def test_an_unreachable_cluster_cannot_contradict_anything(self):
        """"No lane found" means "nobody looked"; blaming the operator for that is wrong."""
        result = profile_check.deployment_profile(context(
            profile=Profile.from_args(args(edc=True)), inspected=False))
        self.assertIs(result.status, Status.SKIP)
        self.assertIn("could not be read", result.cause)

    def test_an_unreachable_cluster_with_nothing_declared_is_still_clean(self):
        result = profile_check.deployment_profile(context(inspected=False))
        self.assertIs(result.status, Status.OK)

    def test_consistent_declarations_are_reported_with_their_origin(self):
        result = profile_check.deployment_profile(context(
            profile=Profile.from_args(args(role="provider", edc=False))))
        self.assertIs(result.status, Status.OK)
        self.assertIn("--role", result.summary)


if __name__ == "__main__":
    unittest.main()
