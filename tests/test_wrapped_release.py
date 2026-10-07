"""The DSC deployed as a dependency of another chart, which is a whole environment.

The dev environment packages the connector as `consumer` / `provider` v1.0.0 with
`data-space-connector` as a dependency aliased `dsc`. Two things follow, and both
used to be silent:

1. The release is invisible. `discover_releases` matched on the chart *name*, so a
   wrapper was skipped and the namespace looked like it held no DSC at all.
2. Every values path is off by one level. `did.enabled` is really
   `dsc.did.enabled`, and reading the unprefixed path does not error - it reports
   every component as absent. A tool that says "nothing is deployed" about a
   healthy deployment is worse than one that says nothing.

The fixtures here mirror the real files of a GitOps install (its `values.yaml`
and `provider/values.yaml`), trimmed to the keys under test.
"""

import unittest

from fdsc_verify import values as V
from tests.test_values import as_secret, helm_payload

DSC_DEP = [{"name": "data-space-connector", "alias": "dsc", "version": "10.4.12",
            "repository": "oci://quay.io/fiware/helm-charts"}]

# What dev actually declares, nested under the alias the way Helm nests it.
DEV_CONSUMER = {"dsc": {"fdsc-edc": {"enabled": False},
                        "did": {"enabled": True},
                        "marketplace": {"enabled": False},
                        "tm-forum-api": {"enabled": False},
                        "scorpio": {"enabled": False},
                        "decentralizedIam": {"vcAuthentication": {}}}}


def wrapper(config=None, chart="consumer"):
    return helm_payload(name=chart, chart=chart, chart_version="1.0.0",
                        dependencies=DSC_DEP, config=config or DEV_CONSUMER)


class TestRecognisingTheWrapper(unittest.TestCase):
    def test_a_wrapper_chart_counts_as_a_participant(self):
        info, _ = V.decode_release(as_secret(wrapper()))
        self.assertEqual(info.family, "participant")

    def test_the_values_root_is_the_dependency_alias(self):
        info, _ = V.decode_release(as_secret(wrapper()))
        self.assertEqual(info.values_root, ("dsc",))

    def test_the_umbrella_itself_has_no_root(self):
        info, _ = V.decode_release(as_secret(helm_payload()))
        self.assertEqual(info.values_root, ())
        self.assertEqual(info.family, "participant")

    def test_an_unrelated_chart_is_still_not_a_dsc(self):
        info, _ = V.decode_release(as_secret(
            helm_payload(chart="keycloak", dependencies=[])))
        self.assertEqual(info.family, "unknown")
        self.assertEqual(info.values_root, ())


class TestReadingThroughTheRoot(unittest.TestCase):
    def values(self):
        info, _ = V.decode_release(as_secret(wrapper()))
        return V.Values(defaults={}, user=info.user, trust="effective", release=info,
                        root=info.values_root)

    def test_a_check_asks_for_the_plain_path_and_gets_the_right_answer(self):
        vals = self.values()
        self.assertTrue(vals.tri("did.enabled").is_true)
        self.assertTrue(vals.tri("fdsc-edc.enabled").is_false)
        self.assertTrue(vals.tri("marketplace.enabled").is_false)

    def test_get_and_origin_are_rooted_too(self):
        vals = self.values()
        self.assertEqual(vals.get("did.enabled"), True)
        self.assertEqual(vals.origin("did.enabled"), "user")

    def test_the_unprefixed_read_is_what_this_prevents(self):
        """Without a root the same file reports every component absent."""
        info, _ = V.decode_release(as_secret(wrapper()))
        unrooted = V.Values(user=info.user, trust="effective", release=info)
        self.assertEqual(unrooted.get("did.enabled"), None)

    def test_dependency_kind_refuses_to_answer_through_a_root(self):
        """The release records the wrapper's dependencies, not the DSC's own.

        Answering "not listed, therefore off" there would be a confident wrong
        answer about every optional component at once.
        """
        vals = self.values()
        tri = vals.tri("fdsc-dashboard.enabled", kind="dependency")
        self.assertTrue(tri.unknown)
        self.assertIn("wraps the DSC", tri.why)


class TestRootResolution(unittest.TestCase):
    def test_declared_root_wins(self):
        vals = V.resolve(None, "ns", {}, None, overrides={
            "valuesRoot": "custom", "values": ["f.yaml"]},
            load_document=lambda p: {"custom": {"did": {"enabled": True}}})
        self.assertEqual(vals.root, ("custom",))
        self.assertTrue(vals.tri("did.enabled").is_true)

    def test_a_values_file_with_no_release_is_sniffed(self):
        """The case that needs it most: GitOps leaves no release to ask."""
        vals = V.resolve(None, "ns", {}, None, overrides={"values": ["f.yaml"]},
                         load_document=lambda p: DEV_CONSUMER)
        self.assertEqual(vals.root, ("dsc",))
        self.assertTrue(vals.tri("did.enabled").is_true)

    def test_an_unwrapped_file_is_left_alone(self):
        vals = V.resolve(None, "ns", {}, None, overrides={"values": ["f.yaml"]},
                         load_document=lambda p: DEV_CONSUMER["dsc"])
        self.assertEqual(vals.root, ())
        self.assertTrue(vals.tri("did.enabled").is_true)

    def test_one_marker_is_not_enough_to_claim_a_root(self):
        """A lone `keycloak:` key is a Keycloak values file, not a wrapped DSC."""
        vals = V.resolve(None, "ns", {}, None, overrides={"values": ["f.yaml"]},
                         load_document=lambda p: {"keycloak": {"marketplace": {}}})
        self.assertEqual(vals.root, ())

    def test_the_root_is_noted_so_the_operator_can_see_it(self):
        vals = V.resolve(None, "ns", {}, None, overrides={"values": ["f.yaml"]},
                         load_document=lambda p: DEV_CONSUMER)
        self.assertTrue(any("dsc" in note for note in vals.notes), vals.notes)


class TestChoosingAmongReleases(unittest.TestCase):
    def releases(self, *payloads):
        out = {}
        for payload in payloads:
            info, _ = V.decode_release(as_secret(payload))
            out[info.name] = info
        return out

    def test_a_participant_beside_a_trust_anchor_is_not_an_ambiguity(self):
        """demo/dso-infra holds both, and used to yield no primary at all."""
        releases = self.releases(
            helm_payload(name="central-mk"),
            helm_payload(name="trust-anchor", chart="trust-anchor"))
        primary, notes = V.choose_primary(releases)
        self.assertEqual(primary, "central-mk")
        self.assertTrue(any("only participant" in note for note in notes))

    def test_two_participants_still_need_an_answer_from_the_operator(self):
        releases = self.releases(helm_payload(name="a"), helm_payload(name="b"))
        primary, notes = V.choose_primary(releases)
        self.assertIsNone(primary)
        self.assertTrue(any("--release" in note for note in notes))

    def test_an_explicit_release_always_wins(self):
        releases = self.releases(
            helm_payload(name="central-mk"),
            helm_payload(name="trust-anchor", chart="trust-anchor"))
        self.assertEqual(V.choose_primary(releases, preferred="trust-anchor")[0],
                         "trust-anchor")


if __name__ == "__main__":
    unittest.main()
