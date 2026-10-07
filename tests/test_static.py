"""The static checks, including the false positives they must not produce.

Each check here is exercised twice: once on a deployment that has the fault, and
once on one that does not. That second half is the point. Three of these checks
were written against real deployments where an early version fired on all of them,
and a check that cannot come back OK is indistinguishable from a broken one.
"""

import unittest
from types import SimpleNamespace

from fdsc_verify.checks import certs, static
from fdsc_verify.model import Status
from fdsc_verify.values import ReleaseInfo, Dependency, Values


def release(name="provider", revision=18, status="deployed",
            chart_name="data-space-connector", chart_version="10.3.2",
            dependencies=(), hooks=()):
    return ReleaseInfo(
        name=name, namespace="provider", chart_name=chart_name,
        chart_version=chart_version, revision=revision, status=status,
        dependencies=list(dependencies), hooks=list(hooks),
        secret="sh.helm.release.v1.%s.v%d" % (name, revision))


def context(defaults=None, user=None, trust="effective", rel=None, namespace="provider"):
    info = rel if rel is not None else release()
    values = Values(defaults=defaults or {}, user=user or {}, trust=trust,
                    source="secret %s" % (info.secret if info else "?"), release=info)
    deployment = SimpleNamespace(namespace=namespace, values=values,
                                 primary_release=info.name if info else None,
                                 releases={info.name: info} if info else {})
    return SimpleNamespace(values=values, deployment=deployment)


class TestValuesSource(unittest.TestCase):
    def test_effective_values_are_reported_as_usable(self):
        result = static.values_source(context(defaults={"a": {"enabled": True}}))
        self.assertIs(result.status, Status.OK)

    def test_user_only_values_warn_and_say_how_to_do_better(self):
        result = static.values_source(context(user={"a": 1}, trust="user"))
        self.assertIs(result.status, Status.WARN)
        self.assertIn("--effective-values", result.fix)
        self.assertIn("credentials-config-service", result.cause)

    def test_no_values_skips_rather_than_passing(self):
        ctx = context()
        ctx.values.trust = "none"
        ctx.values.source = "cluster unreachable"
        result = static.values_source(ctx)
        self.assertIs(result.status, Status.SKIP)
        self.assertIn("cluster unreachable", result.cause)


class TestReleaseStatus(unittest.TestCase):
    def test_a_deployed_release_is_fine(self):
        result = static.release_status(context())
        self.assertIs(result.status, Status.OK)

    def test_a_pending_upgrade_is_flagged_with_the_literal_status(self):
        result = static.release_status(context(rel=release(status="pending-upgrade")))
        self.assertIs(result.status, Status.WARN)
        self.assertIn("pending-upgrade", result.cause)
        self.assertIn("helm history", result.fix)


def annotations(hook, enabled=None, extra_depth=False):
    """Build a registration block the way the chart does.

    `extra_depth` reproduces the vcverifier shape, where the annotations sit under
    `registration.job` while `enabled` sits on `registration` - one level further
    up, which is the case that breaks a naive sibling lookup.
    """
    block = {"annotations": {static.HOOK_KEY: hook}}
    inner = {"job": block} if extra_depth else dict(block)
    if enabled is not None:
        inner["enabled"] = enabled
    return inner


class TestRegistrationJobHooks(unittest.TestCase):
    def test_a_post_install_only_hook_on_an_upgraded_release_warns(self):
        """WARN, not FAIL: the declaration cannot prove a service is missing.

        A post-install-only hook proves it cannot have re-run. Whether anything
        is actually unregistered depends on whether the values changed since
        install - and a deployment where somebody re-registered by hand is
        complete while the hook stays misconfigured. That question belongs to
        `registration-services-present`, which reads the live config repo.
        """
        ctx = context(defaults={"registration": annotations("post-install", enabled=True)},
                      rel=release(revision=18, hooks=[
                          {"name": "til-registration-job", "events": ["post-install"]}]))
        result = static.registration_job_hooks(ctx)
        self.assertIs(result.status, Status.WARN)
        self.assertIn("registration.annotations", result.cause)
        self.assertIn("revision 18", result.cause)
        self.assertIn("17 upgrades", result.cause)
        self.assertIn("til-registration-job", result.cause)
        # it must hand the reader on to the check that can settle it
        self.assertIn("registration-services-present", result.cause)

    def test_on_a_fresh_release_it_is_only_a_warning(self):
        ctx = context(defaults={"registration": annotations("post-install", enabled=True)},
                      rel=release(revision=1))
        result = static.registration_job_hooks(ctx)
        self.assertIs(result.status, Status.WARN)
        self.assertIn("nothing has been missed yet", result.cause)

    def test_a_hook_that_re_runs_on_upgrade_passes(self):
        ctx = context(defaults={
            "registration": annotations("post-install,post-upgrade", enabled=True)})
        self.assertIs(static.registration_job_hooks(ctx).status, Status.OK)

    def test_an_inert_block_is_not_a_finding(self):
        """demo/producer really does ship this: post-install only, but disabled."""
        ctx = context(defaults={
            "tm-forum-api": {"registration": annotations("post-install", enabled=False)}})
        result = static.registration_job_hooks(ctx)
        self.assertIs(result.status, Status.OK)
        self.assertIn("tm-forum-api.registration.annotations", result.detail["inert"])

    def test_the_enabled_flag_is_found_on_an_ancestor_not_just_the_sibling(self):
        """`...vcverifier.registration.job.annotations` is governed by
        `...vcverifier.registration.enabled`, one level further up."""
        ctx = context(defaults={"vcverifier": {
            "registration": annotations("post-install", enabled=False, extra_depth=True)}})
        result = static.registration_job_hooks(ctx)
        self.assertIs(result.status, Status.OK)
        self.assertEqual(result.detail["inert"],
                         ["vcverifier.registration.job.annotations"])

    def test_a_disabled_subchart_disables_what_is_nested_inside_it(self):
        """demo's provider-central: `tm-forum-api.enabled` is false while the chart's
        own default leaves `tm-forum-api.registration.enabled` true. Stopping at the
        nearest ancestor that declares `enabled` reported a job Helm never renders,
        alongside one that was a genuine finding - so the report was half wrong in a
        way nothing on it distinguished."""
        ctx = context(defaults={
            "tm-forum-api": {"enabled": False,
                             "registration": annotations("post-install", enabled=True)},
            "registration": annotations("post-install", enabled=True)},
            rel=release(revision=24, hooks=[
                {"name": "provider-til-registration-job", "events": ["post-install"]}]))
        result = static.registration_job_hooks(ctx)
        self.assertIs(result.status, Status.WARN)
        # the real one is still reported...
        self.assertEqual(result.detail["paths"], ["registration.annotations"])
        self.assertIn("1 registration hook(s)", result.summary)
        # ...and the one inside the disabled subchart is inert, not a finding
        self.assertEqual(result.detail["inertPostInstallOnly"],
                         ["tm-forum-api.registration.annotations"])

    def test_an_unrelated_pre_upgrade_or_test_hook_is_ignored(self):
        ctx = context(defaults={"etcd": {"annotations": {static.HOOK_KEY: "pre-upgrade"}},
                                "vault": {"annotations": {static.HOOK_KEY: "test"}}})
        self.assertIs(static.registration_job_hooks(ctx).status, Status.OK)

    def test_no_hook_annotations_at_all_skips(self):
        """The trust-anchor chart declares none, and that is not a finding."""
        ctx = context(defaults={"tir": {"enabled": True}},
                      rel=release(name="trust-anchor", chart_name="trust-anchor",
                                  chart_version="1.0.0", revision=4))
        result = static.registration_job_hooks(ctx)
        self.assertIs(result.status, Status.SKIP)
        self.assertIn("no hook annotations", result.summary)


class TestValuesUnknownKeys(unittest.TestCase):
    def test_a_key_the_chart_never_reads_warns(self):
        ctx = context(defaults={"keycloak": {"enabled": True}},
                      user={"keycloak": {"enabled": False}, "mysql": {"enabled": True}})
        result = static.values_unknown_keys(ctx)
        self.assertIs(result.status, Status.WARN)
        self.assertIn("mysql", result.summary)
        self.assertEqual(result.detail["keys"], ["mysql"])

    def test_a_clean_values_file_passes(self):
        """demo/producer: 19 top-level keys, all consumed. It must come back OK."""
        ctx = context(defaults={"keycloak": {}, "scorpio": {}},
                      user={"keycloak": {"enabled": True}})
        self.assertIs(static.values_unknown_keys(ctx).status, Status.OK)

    def test_a_dependency_alias_counts_as_known_even_without_a_default(self):
        """`fdsc-edc.enabled` has no chart default and is still perfectly valid."""
        ctx = context(defaults={"keycloak": {"enabled": True}},
                      user={"fdsc-edc": {"enabled": True}},
                      rel=release(dependencies=[
                          Dependency(name="fdsc-edc", condition="fdsc-edc.enabled")]))
        self.assertIs(static.values_unknown_keys(ctx).status, Status.OK)

    def test_x_prefixed_anchor_holders_are_allowlisted(self):
        ctx = context(defaults={"keycloak": {}}, user={"x-certs": {"a": 1}})
        self.assertIs(static.values_unknown_keys(ctx).status, Status.OK)

    def test_singular_and_plural_phrasing_are_both_grammatical(self):
        one = static.values_unknown_keys(
            context(defaults={"keycloak": {}}, user={"mysql": 1}))
        many = static.values_unknown_keys(
            context(defaults={"keycloak": {}}, user={"mysql": 1, "postgresql": 2}))
        self.assertIn("no `mysql` key", one.cause)
        self.assertIn("ignored it", one.cause)
        self.assertIn("none of them", many.cause)
        self.assertIn("ignored them", many.cause)

    def test_a_release_without_chart_defaults_skips(self):
        ctx = context(defaults={}, user={"mysql": 1})
        result = static.values_unknown_keys(ctx)
        self.assertIs(result.status, Status.SKIP)
        self.assertIn("no chart defaults", result.summary)


class TestEveryFailureCarriesACause(unittest.TestCase):
    """The project's own invariant: a FAIL or WARN without a cause is incomplete."""

    def _all_results(self):
        cases = [
            static.values_source(context(user={"a": 1}, trust="user")),
            static.release_status(context(rel=release(status="failed"))),
            static.registration_job_hooks(context(
                defaults={"registration": annotations("post-install", enabled=True)},
                rel=release(revision=9))),
            static.values_unknown_keys(context(defaults={"keycloak": {}}, user={"mysql": 1})),
        ]
        return cases

    def test_causes_and_fixes_and_docs_are_all_present(self):
        for result in self._all_results():
            self.assertIn(result.status, (Status.WARN, Status.FAIL))
            self.assertTrue(result.cause, "%s has no cause" % result.summary)
            self.assertTrue(result.fix, "%s has no fix" % result.summary)
            self.assertTrue(result.doc, "%s has no doc anchor" % result.summary)


if __name__ == "__main__":
    unittest.main()


def client_ident(**kw):
    """A verifier clientIdentification block, nested where the umbrella puts it."""
    return {"decentralizedIam": {"vcAuthentication": {"vcverifier": {
        "verifier": {"clientIdentification": kw}}}}}


class TestClientIdScheme(unittest.TestCase):
    """The three combinations VCVerifier cannot enforce for itself.

    It has no `client_id_scheme` logic: `id` is opaque, the request object is
    always signed, and `client_metadata` is never emitted. So each prefix's
    obligations have to be checked against the rest of the config.
    """

    def test_redirect_uri_with_a_signing_key_warns(self):
        ctx = context(defaults=client_ident(
            id="redirect_uri:https://verifier.example/api/v1/authentication_response",
            keyPath="/certs/tls.key", kid="did:web:example:did#key-1"))
        result = certs.client_id_scheme(ctx)
        self.assertIs(result.status, Status.WARN)
        self.assertIn("MUST NOT be signed", result.cause)
        self.assertIn("client_metadata", result.cause)

    def test_redirect_uri_without_signing_is_left_alone(self):
        ctx = context(defaults=client_ident(
            id="redirect_uri:https://verifier.example/api/v1/authentication_response"))
        self.assertIs(certs.client_id_scheme(ctx).status, Status.OK)

    def test_x509_without_a_certificate_warns(self):
        ctx = context(defaults=client_ident(id="x509_san_dns:verifier.example",
                                            keyPath="/certs/tls.key"))
        result = certs.client_id_scheme(ctx)
        self.assertIs(result.status, Status.WARN)
        self.assertIn("certificatePath is unset", result.cause)

    def test_x509_with_a_certificate_is_ok(self):
        ctx = context(defaults=client_ident(id="x509_san_dns:verifier.example",
                                            keyPath="/certs/tls.key",
                                            certificatePath="/certs/tls.crt"))
        self.assertIs(certs.client_id_scheme(ctx).status, Status.OK)

    def test_a_bare_did_kid_warns_because_it_names_no_verification_method(self):
        ctx = context(defaults=client_ident(id="did:web:example.com:did",
                                            kid="did:web:example.com:did",
                                            keyPath="/certs/tls.key"))
        result = certs.client_id_scheme(ctx)
        self.assertIs(result.status, Status.WARN)
        self.assertIn("bare DID", result.cause)

    def test_an_unset_kid_falls_back_to_the_id_and_is_reported_as_such(self):
        ctx = context(defaults=client_ident(id="did:web:example.com:did",
                                            keyPath="/certs/tls.key"))
        result = certs.client_id_scheme(ctx)
        self.assertIs(result.status, Status.WARN)
        self.assertIn("kid is unset", result.cause)

    def test_a_did_with_a_fragment_is_ok(self):
        ctx = context(defaults=client_ident(id="did:web:example.com:did",
                                            kid="did:web:example.com:did#key-1",
                                            keyPath="/certs/tls.key"))
        self.assertIs(certs.client_id_scheme(ctx).status, Status.OK)

    def test_no_client_id_skips_rather_than_guessing(self):
        self.assertIs(certs.client_id_scheme(context()).status, Status.SKIP)
