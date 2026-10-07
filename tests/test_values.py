"""The Helm release decoder, the merge, and the confidence model.

Fixtures here are built in memory rather than captured from a cluster, and that is
a hard rule: a real release Secret embeds the whole rendered manifest, which
contains rendered `Secret` objects - Postgres passwords, signing keys - plus the
`config` the operator supplied. Committing one would leak a deployment. So the
tests assemble the same shape themselves and gzip+base64 it the way Helm does.

The shape was checked against the real thing (a provider at rev 18,
`<cluster>` consumer rev 36), where our merge came out byte-identical
to `helm get values --all` over 2592 and 2194 leaf keys respectively.
"""

import base64
import gzip
import json
import unittest

from fdsc_verify import values as V


def helm_payload(name="rel", namespace="ns", chart="data-space-connector",
                 chart_version="10.4.12", revision=7, status="deployed",
                 defaults=None, config=None, dependencies=None, hooks=None,
                 manifest=""):
    return {
        "name": name,
        "namespace": namespace,
        "version": revision,
        "info": {"status": status, "last_deployed": "2026-08-01T00:00:00Z"},
        "chart": {
            "metadata": {
                "name": chart,
                "version": chart_version,
                "appVersion": "1.0",
                "dependencies": dependencies if dependencies is not None else [],
            },
            "values": defaults if defaults is not None else {},
        },
        "config": config if config is not None else {},
        "hooks": hooks if hooks is not None else [],
        "manifest": manifest,
    }


def as_secret(payload):
    """Exactly what Helm's default (secret) driver stores: base64(base64(gzip(json)))."""
    inner = base64.b64encode(gzip.compress(json.dumps(payload).encode()))
    return base64.b64encode(inner).decode()


def as_configmap(payload):
    """The configmap driver: one layer less."""
    return base64.b64encode(gzip.compress(json.dumps(payload).encode())).decode()


class TestDeepMerge(unittest.TestCase):
    def test_dicts_merge_recursively(self):
        self.assertEqual(V.deep_merge({"a": {"b": 1, "c": 2}}, {"a": {"c": 3}}),
                         {"a": {"b": 1, "c": 3}})

    def test_none_in_the_override_deletes_the_key(self):
        """Helm's way of disabling a default - not 'set it to null'."""
        self.assertEqual(V.deep_merge({"a": {"b": 1, "c": 2}}, {"a": {"c": None}}),
                         {"a": {"b": 1}})

    def test_lists_replace_wholesale(self):
        """Why `--set features.enabled={a}` silently drops b and c."""
        self.assertEqual(V.deep_merge({"f": ["a", "b", "c"]}, {"f": ["a"]}), {"f": ["a"]})

    def test_a_scalar_replaces_a_dict(self):
        self.assertEqual(V.deep_merge({"a": {"b": 1}}, {"a": 5}), {"a": 5})

    def test_the_inputs_are_not_mutated(self):
        base, over = {"a": {"b": 1}}, {"a": {"c": 2}}
        V.deep_merge(base, over)
        self.assertEqual(base, {"a": {"b": 1}})
        self.assertEqual(over, {"a": {"c": 2}})

    def test_a_missing_override_is_fine(self):
        self.assertEqual(V.deep_merge({"a": 1}, None), {"a": 1})


class TestDecodeRelease(unittest.TestCase):
    def test_the_secret_driver_double_base64(self):
        info, error = V.decode_release(as_secret(helm_payload()))
        self.assertIsNone(error)
        self.assertEqual((info.name, info.chart_name, info.revision), ("rel", "data-space-connector", 7))

    def test_the_configmap_driver_single_base64(self):
        info, error = V.decode_release(as_configmap(helm_payload()))
        self.assertIsNone(error)
        self.assertEqual(info.name, "rel")

    def test_raw_gzipped_json(self):
        info, error = V.decode_release(gzip.compress(json.dumps(helm_payload()).encode()))
        self.assertIsNone(error)
        self.assertEqual(info.name, "rel")

    def test_plain_json_bytes(self):
        info, error = V.decode_release(json.dumps(helm_payload()).encode())
        self.assertIsNone(error)
        self.assertEqual(info.name, "rel")

    def test_garbage_returns_an_error_and_never_raises(self):
        info, error = V.decode_release("not base64 at all !!!")
        self.assertIsNone(info)
        self.assertTrue(error)

    def test_none_returns_an_error(self):
        info, error = V.decode_release(None)
        self.assertIsNone(info)
        self.assertTrue(error)

    def test_a_json_array_is_refused(self):
        info, error = V.decode_release(base64.b64encode(json.dumps([1, 2]).encode()))
        self.assertIsNone(info)
        self.assertIn("not an object", error)

    def test_family_comes_from_the_chart_name(self):
        participant, _ = V.decode_release(as_secret(helm_payload(chart="data-space-connector")))
        operator, _ = V.decode_release(as_secret(helm_payload(chart="trust-anchor")))
        other, _ = V.decode_release(as_secret(helm_payload(chart="cert-manager")))
        self.assertEqual(participant.family, "participant")
        self.assertEqual(operator.family, "operator")
        self.assertEqual(other.family, "unknown")

    def test_dependencies_keep_their_alias_as_the_values_key(self):
        info, _ = V.decode_release(as_secret(helm_payload(dependencies=[
            {"name": "decentralized-iam", "alias": "decentralizedIam",
             "condition": "decentralizedIam.enabled", "version": "2.1.19"},
            {"name": "fdsc-edc", "condition": "fdsc-edc.enabled", "version": "0.4.0"},
        ])))
        self.assertEqual([dep.key for dep in info.dependencies],
                         ["decentralizedIam", "fdsc-edc"])
        self.assertEqual(info.dependency("decentralizedIam").name, "decentralized-iam")
        self.assertIsNone(info.dependency("nope"))

    def test_hook_events_are_read_from_the_release_not_the_cluster(self):
        """Helm deletes hook Jobs that succeeded, so their absence proves nothing."""
        info, _ = V.decode_release(as_secret(helm_payload(hooks=[
            {"name": "verifier-job", "events": ["post-install"]},
            {"name": "apisix-routes-job", "events": ["post-install", "post-upgrade"]},
        ])))
        self.assertEqual(info.hook_events(),
                         [("verifier-job", ["post-install"]),
                          ("apisix-routes-job", ["post-install", "post-upgrade"])])

    def test_manifest_index_records_kind_name_and_provenance(self):
        manifest = (
            "---\n# Source: data-space-connector/templates/dsconfig-service.yaml\n"
            "apiVersion: v1\nkind: Service\nmetadata:\n  name: dsconfig\nspec:\n"
            "  ports:\n    - name: http\n"
            "---\n# Source: data-space-connector/charts/vcverifier/templates/deploy.yaml\n"
            "kind: Deployment\nmetadata:\n  name: verifier\n"
        )
        info, _ = V.decode_release(as_secret(helm_payload(manifest=manifest)))
        index = info.manifest_index()
        self.assertEqual([(o.kind, o.name) for o in index],
                         [("Service", "dsconfig"), ("Deployment", "verifier")])
        self.assertIn("dsconfig-service.yaml", index[0].source)

    def test_to_json_never_carries_the_manifest_or_the_values(self):
        info, _ = V.decode_release(as_secret(helm_payload(
            manifest="kind: Secret\nmetadata:\n  name: db\ndata:\n  password: aGVsbG8=\n",
            defaults={"a": 1}, config={"password": "hunter2"})))
        blob = json.dumps(info.to_json())
        self.assertNotIn("hunter2", blob)
        self.assertNotIn("aGVsbG8", blob)
        self.assertNotIn("manifest\":", blob.replace("manifestObjects", ""))


class TestChartVersion(unittest.TestCase):
    def test_parses_the_shapes_seen_in_the_wild(self):
        self.assertEqual(V.chart_version_tuple("10.4.12-173"), (10, 4, 12))
        self.assertEqual(V.chart_version_tuple("9.0.5"), (9, 0, 5))
        self.assertEqual(V.chart_version_tuple("v1.21.1"), (1, 21, 1))
        self.assertIsNone(V.chart_version_tuple("nightly"))
        self.assertIsNone(V.chart_version_tuple(None))

    def test_chart_at_least_is_none_when_it_cannot_tell(self):
        info, _ = V.decode_release(as_secret(helm_payload(chart_version="10.3.2")))
        self.assertTrue(info.chart_at_least("10.0.0"))
        self.assertFalse(info.chart_at_least("10.4.0"))
        info, _ = V.decode_release(as_secret(helm_payload(chart_version="nightly")))
        self.assertIsNone(info.chart_at_least("10.0.0"))


class TestPlaceholders(unittest.TestCase):
    def test_detects_both_kinds_actually_found_in_values(self):
        self.assertTrue(V.has_placeholder("${DID}"))
        self.assertTrue(V.has_placeholder("http://{{ .Release.Name }}-vault:8200"))
        self.assertFalse(V.has_placeholder("did:web:connector.example.es#key-1"))
        self.assertFalse(V.has_placeholder(None))
        self.assertFalse(V.has_placeholder(True))


class TestTri(unittest.TestCase):
    def values(self, defaults=None, user=None, trust="effective", release=None, source=""):
        return V.Values(defaults=defaults, user=user, trust=trust, release=release,
                        source=source)

    def test_a_user_value_wins_and_says_so(self):
        tri = self.values(defaults={"a": {"enabled": False}},
                          user={"a": {"enabled": True}}).tri("a.enabled")
        self.assertTrue(tri.is_true)
        self.assertEqual(tri.origin, "user")
        self.assertIn("user values", tri.why)

    def test_a_chart_default_is_used_and_named_as_such(self):
        tri = self.values(defaults={"a": {"enabled": False}}).tri("a.enabled")
        self.assertTrue(tri.is_false)
        self.assertEqual(tri.origin, "chart")
        self.assertIn("chart default", tri.why)

    def test_an_absent_dependency_key_means_ENABLED(self):
        """The fdsc-edc case: Helm enables a dependency whose condition does not resolve."""
        info, _ = V.decode_release(as_secret(helm_payload(dependencies=[
            {"name": "fdsc-edc", "condition": "fdsc-edc.enabled", "version": "0.4.0"}])))
        tri = self.values(release=info).tri("fdsc-edc.enabled", kind="dependency")
        self.assertTrue(tri.is_true, "an unset dependency condition must read as enabled")
        self.assertEqual(tri.origin, "dependency")

    def test_an_absent_dependency_not_listed_in_the_release_means_disabled(self):
        info, _ = V.decode_release(as_secret(helm_payload(dependencies=[])))
        tri = self.values(release=info).tri("rainbow.enabled", kind="dependency")
        self.assertTrue(tri.is_false)

    def test_an_absent_template_key_means_DISABLED(self):
        tri = self.values().tri("dataSpaceConfig.enabled", kind="template")
        self.assertTrue(tri.is_false)
        self.assertIn("treats that as disabled", tri.why)

    def test_user_only_trust_cannot_answer_an_absent_key(self):
        tri = self.values(user={"x": 1}, trust="user").tri("did.enabled")
        self.assertTrue(tri.unknown)
        self.assertEqual(tri.origin, "missing")
        self.assertIn("--effective-values", tri.why)

    def test_no_values_at_all_is_unknown_not_false(self):
        tri = V.Values.empty("cluster unreachable").tri("did.enabled")
        self.assertTrue(tri.unknown)
        self.assertEqual(tri.origin, "unknown")
        self.assertIn("cluster unreachable", tri.why)

    def test_tri_has_no_bool_so_it_cannot_be_misused(self):
        """`if values.tri(p):` must not compile away to 'disabled'."""
        self.assertIs(type(V.Tri(None, "", "unknown")).__dict__.get("__bool__"), None)

    def test_string_booleans_are_understood(self):
        self.assertTrue(self.values(defaults={"a": {"enabled": "true"}}).tri("a.enabled").is_true)
        self.assertTrue(self.values(defaults={"a": {"enabled": "no"}}).tri("a.enabled").is_false)

    def test_a_non_boolean_under_enabled_is_unknown_rather_than_truthy(self):
        tri = self.values(defaults={"a": {"enabled": {"oops": 1}}}).tri("a.enabled")
        self.assertTrue(tri.unknown)


class TestValuesAccess(unittest.TestCase):
    def test_get_at_reaches_keys_containing_dots(self):
        """Annotation keys really do contain dots: `prometheus.io/port`, `helm.sh/hook`."""
        vals = V.Values(defaults={"a": {"podAnnotations": {"prometheus.io/port": "9091"}}},
                        trust="effective")
        self.assertEqual(vals.get_at(["a", "podAnnotations", "prometheus.io/port"]), "9091")
        self.assertIsNone(vals.get("a.podAnnotations.prometheus.io/port"))

    def test_origin_reports_where_a_value_came_from(self):
        vals = V.Values(defaults={"a": 1, "b": 2}, user={"b": 3}, trust="effective")
        self.assertEqual(vals.origin("b"), "user")
        self.assertEqual(vals.origin("a"), "chart")
        self.assertEqual(vals.origin("c"), "missing")

    def test_count_counts_leaves(self):
        vals = V.Values(defaults={"a": {"b": 1, "c": {"d": 2}}, "e": 3}, trust="effective")
        self.assertEqual(vals.count(), 3)

    def test_to_json_is_metadata_only(self):
        vals = V.Values(defaults={"password": "hunter2"}, trust="effective", source="s")
        self.assertNotIn("hunter2", json.dumps(vals.to_json()))


class TestChoosePrimary(unittest.TestCase):
    def _releases(self, *names):
        out = {}
        for name in names:
            info, _ = V.decode_release(as_secret(helm_payload(name=name)))
            out[name] = info
        return out

    def test_no_releases_is_not_an_error(self):
        primary, notes = V.choose_primary({})
        self.assertIsNone(primary)
        self.assertEqual(notes, [])

    def test_a_single_candidate_is_chosen_silently(self):
        primary, notes = V.choose_primary(self._releases("provider"))
        self.assertEqual(primary, "provider")
        self.assertEqual(notes, [])

    def test_several_candidates_refuse_to_guess_and_say_how_to_choose(self):
        primary, notes = V.choose_primary(self._releases("central-mk", "trust-anchor"))
        self.assertIsNone(primary)
        self.assertIn("--release", notes[0])

    def test_the_lane_owner_breaks_the_tie(self):
        primary, notes = V.choose_primary(self._releases("central-mk", "producer"),
                                          lane_release="producer")
        self.assertEqual(primary, "producer")
        self.assertEqual(notes, [])

    def test_an_explicit_release_wins(self):
        primary, _ = V.choose_primary(self._releases("a", "b"), preferred="b",
                                      lane_release="a")
        self.assertEqual(primary, "b")

    def test_an_explicit_release_that_does_not_exist_is_reported(self):
        primary, notes = V.choose_primary(self._releases("a"), preferred="nope")
        self.assertIsNone(primary)
        self.assertIn("nope", notes[0])


class TestResolve(unittest.TestCase):
    def _release(self, **kwargs):
        info, _ = V.decode_release(as_secret(helm_payload(**kwargs)))
        info.secret = "sh.helm.release.v1.%s.v%d" % (info.name, info.revision)
        return {info.name: info}

    def test_the_live_release_gives_effective_trust(self):
        releases = self._release(defaults={"a": {"enabled": False}},
                                 config={"b": {"enabled": True}})
        vals = V.resolve(None, "ns", releases, "rel")
        self.assertEqual(vals.trust, "effective")
        self.assertTrue(vals.tri("a.enabled").is_false)
        self.assertTrue(vals.tri("b.enabled").is_true)
        self.assertIn("rev 7", vals.source)

    def test_values_file_replaces_the_user_layer_but_keeps_chart_defaults(self):
        releases = self._release(defaults={"a": {"enabled": False}},
                                 config={"a": {"enabled": True}})
        vals = V.resolve(None, "ns", releases, "rel",
                         overrides={"values": ["f.yaml"]},
                         load_document=lambda path: {"c": {"enabled": True}})
        self.assertEqual(vals.trust, "effective")
        self.assertTrue(vals.tri("a.enabled").is_false, "the file replaced the user layer")
        self.assertTrue(vals.tri("c.enabled").is_true)
        self.assertIn("--values", vals.source)

    def test_values_file_without_a_release_degrades_to_user_trust(self):
        vals = V.resolve(None, "ns", {}, None, overrides={"values": ["f.yaml"]},
                         load_document=lambda path: {"c": {"enabled": True}})
        self.assertEqual(vals.trust, "user")
        self.assertTrue(vals.tri("c.enabled").is_true)
        self.assertTrue(vals.tri("did.enabled").unknown,
                        "an absent key is unknowable without the chart defaults")

    def test_effective_values_file_is_full_precision_without_a_cluster(self):
        vals = V.resolve(None, "ns", {}, None,
                         overrides={"effectiveValues": "merged.json"},
                         load_document=lambda path: {"did": {"enabled": False}})
        self.assertEqual(vals.trust, "effective")
        self.assertTrue(vals.tri("did.enabled").is_false)
        self.assertIn("revision unknown", vals.source)

    def test_nothing_available_explains_itself_and_says_what_to_do(self):
        """A GitOps install leaves no release; the message must not read as a dead end."""
        vals = V.resolve(None, "provider", {}, None)
        self.assertEqual(vals.trust, "none")
        self.assertIn("provider", vals.source)
        self.assertIn("--values", vals.source)
        self.assertIn("cluster checks still run", vals.source)

    def test_an_unreadable_file_is_noted_and_does_not_raise(self):
        def boom(path):
            raise OSError("no such file")
        vals = V.resolve(None, "ns", {}, None, overrides={"values": ["missing.yaml"]},
                         load_document=boom)
        self.assertTrue(any("no such file" in note for note in vals.notes))

    def test_a_values_file_that_is_not_a_mapping_is_noted(self):
        vals = V.resolve(None, "ns", {}, None, overrides={"values": ["list.yaml"]},
                         load_document=lambda path: ["a", "b"])
        self.assertTrue(any("mapping" in note for note in vals.notes))


class TestDiscoverReleases(unittest.TestCase):
    class FakeKube:
        """Records the selector, because getting it wrong downloads tens of megabytes."""

        def __init__(self, items_by_kind):
            self.items_by_kind = items_by_kind
            self.calls = []
            self.context = None

        def get_json(self, kind, name="", namespace=None, check=True, selector=None):
            self.calls.append((kind, selector))
            return {"items": self.items_by_kind.get(kind, [])}

    def _item(self, name, payload):
        return {"metadata": {"name": name}, "data": {"release": as_secret(payload)}}

    def test_only_dsc_family_charts_are_kept(self):
        kube = self.FakeKube({"secret": [
            self._item("sh.helm.release.v1.provider.v18",
                       helm_payload(name="provider", chart="data-space-connector")),
            self._item("sh.helm.release.v1.trust-anchor.v4",
                       helm_payload(name="trust-anchor", chart="trust-anchor")),
            self._item("sh.helm.release.v1.traefik.v1",
                       helm_payload(name="traefik", chart="traefik")),
        ]})
        found, notes = discover(kube)
        self.assertEqual(sorted(found), ["provider", "trust-anchor"])
        self.assertEqual(notes, [])

    def test_the_deployed_selector_is_always_used(self):
        kube = self.FakeKube({"secret": []})
        discover(kube)
        self.assertEqual(kube.calls[0][1], V.HELM_SELECTOR)
        self.assertIn("status=deployed", kube.calls[0][1])

    def test_the_secret_name_is_recorded_for_the_evidence_line(self):
        kube = self.FakeKube({"secret": [
            self._item("sh.helm.release.v1.provider.v18", helm_payload(name="provider"))]})
        found, _ = discover(kube)
        self.assertEqual(found["provider"].secret, "sh.helm.release.v1.provider.v18")

    def test_an_undecodable_release_is_noted_and_the_rest_still_load(self):
        kube = self.FakeKube({"secret": [
            {"metadata": {"name": "sh.helm.release.v1.broken.v1"},
             "data": {"release": "###"}},
            self._item("sh.helm.release.v1.provider.v1", helm_payload(name="provider")),
        ]})
        found, notes = discover(kube)
        self.assertEqual(sorted(found), ["provider"])
        self.assertTrue(any("broken" in note for note in notes))

    def test_the_configmap_driver_is_tried_when_no_secret_matched(self):
        kube = self.FakeKube({"secret": [], "configmap": [
            self._item("sh.helm.release.v1.provider.v1", helm_payload(name="provider"))]})
        found, _ = discover(kube)
        self.assertEqual(sorted(found), ["provider"])
        self.assertEqual([kind for kind, _ in kube.calls], ["secret", "configmap"])


def discover(kube):
    return V.discover_releases(kube, "ns")


if __name__ == "__main__":
    unittest.main()
