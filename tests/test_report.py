"""The report's two contracts: the JSON shape, and what must never appear in it.

`--json | jq` is used from CI, so `results` is a contract: fields may be added,
never renamed or removed. And the rendered Helm manifest must stay out entirely -
it embeds rendered `Secret` objects, so leaking it would turn a diagnostic tool
into an exfiltration one.
"""

import json
import unittest

from fdsc_verify.model import PHASES, Result, Status
from fdsc_verify.report import render_json, render_text, exit_code

RESULT_FIELDS = {"phase", "check", "lane", "status", "applicable", "summary", "cause",
                 "fix", "doc", "detail"}


def rows():
    return [
        ("static", "values-source", "", Result.ok("2592 keys")),
        ("static", "registration-job-hooks", "",
         Result.fail("2 hooks stale", cause="c", fix="f", doc="a-doc-anchor")),
        ("preflight", "did-document", "", Result.warn("odd", cause="c")),
        ("flow", "flow-catalog", "dcp", Result.skip("not run", cause="c")),
    ]


def discovery(**extra):
    base = {
        "context": "ctx", "namespace": "provider", "release": "provider",
        "family": "participant",
        "primaryRelease": {"name": "provider", "chart": "data-space-connector-10.3.2",
                           "revision": 18, "status": "deployed", "family": "participant"},
        "otherReleases": ["edc-dashboard"],
        "values": {"trust": "effective", "source": "secret x", "keys": 2592, "notes": []},
        "identitySecret": "atd-tls", "services": {}, "lanes": {"dcp": {}}, "notes": [],
    }
    base.update(extra)
    return base


class TestJsonContract(unittest.TestCase):
    def test_the_three_top_level_keys_are_stable(self):
        out = json.loads(render_json(rows(), discovery()))
        self.assertEqual(sorted(out), ["discovery", "results", "summary"])

    def test_every_result_keeps_exactly_its_documented_fields(self):
        out = json.loads(render_json(rows(), discovery()))
        for result in out["results"]:
            self.assertEqual(set(result), RESULT_FIELDS)

    def test_the_summary_counts_every_status(self):
        out = json.loads(render_json(rows(), discovery()))
        self.assertEqual(set(out["summary"]), {status.value for status in Status})
        self.assertEqual(out["summary"]["FAIL"], 1)

    def test_the_doc_anchor_is_rendered_as_a_reference(self):
        out = json.loads(render_json(rows(), discovery()))
        stale = [r for r in out["results"] if r["check"] == "registration-job-hooks"][0]
        self.assertIn("#a-doc-anchor", stale["doc"])

    def test_the_manifest_never_reaches_the_output(self):
        """A release's manifest contains rendered Secrets. It stays in memory."""
        blob = render_json(rows(), discovery())
        self.assertNotIn('"manifest"', blob)


class TestTextHeader(unittest.TestCase):
    def test_the_header_leads_with_what_this_deployment_is(self):
        """Not with the lanes. Most DSC deployments have none, and announcing an
        absence as the headline buried the role, the identity and the release."""
        lines = render_text(rows(), discovery(roles=["provider"],
                                              roleSource="--role"),
                            colour=False).splitlines()
        self.assertTrue(lines[0].startswith("FDSC ctx / provider"), lines[0])
        # a blank line, then aligned `label  value` columns
        self.assertEqual(lines[1], "")
        self.assertEqual(lines[2], "role      provider  (--role)")

    def test_an_undetermined_role_says_how_to_settle_it(self):
        text = render_text(rows(), discovery(), colour=False)
        self.assertIn("role      undetermined", text)
        self.assertIn("--role", text)

    def test_the_release_line_names_revision_and_chart(self):
        text = render_text(rows(), discovery(), colour=False)
        self.assertIn("release   provider  rev 18  chart data-space-connector-10.3.2", text)

    def test_the_identity_line_says_where_the_did_came_from(self):
        text = render_text(rows(), discovery(participant={
            "did": "did:web:example.org", "from": "did-helper",
            "documentServer": "did-helper", "identitySecret": "example-tls"}),
            colour=False)
        self.assertIn("identity  did:web:example.org  (from did-helper)", text)
        self.assertIn("document served by did-helper", text)
        self.assertIn("key     secret example-tls", text)

    def test_the_lanes_are_a_line_rather_than_the_headline(self):
        text = render_text(rows(), discovery(), colour=False)
        self.assertIn("EDC       1 lane(s): dcp", text)
        self.assertNotIn("lanes: none found", text)

    def test_no_lanes_is_asserted_rather_than_left_to_be_noticed(self):
        """The line that replaced sixteen skipped rows.

        The lane checks no longer print one row each when there is no connector, so
        this is the only place the report says whether fdsc-edc is part of the
        deployment. Saying nothing would make a discovery failure - which has
        happened, the dev wrapper chart hid a whole release - read as a clean run.
        """
        text = render_text(rows(), discovery(lanes={}), colour=False)
        self.assertIn("EDC       not deployed  (inferred)", text)

    def test_a_declared_absence_says_who_declared_it(self):
        text = render_text(rows(), discovery(lanes={}, declared={
            "edc": {"value": False, "from": "--no-edc"}}), colour=False)
        self.assertIn("EDC       not deployed  (declared --no-edc)", text)

    def test_declarations_are_echoed_so_the_reader_knows_what_was_assumed(self):
        text = render_text(rows(), discovery(declared={
            "roles": {"value": ["provider"], "from": "--role"},
            "edc": {"value": False, "from": "--no-edc"}}), colour=False)
        self.assertIn("declared  ", text)
        self.assertIn("edc=False", text)

    def test_the_values_trust_is_shown(self):
        self.assertIn("values    effective  (2592 keys)",
                      render_text(rows(), discovery(), colour=False))

    def test_other_releases_read_as_also_when_one_was_picked(self):
        self.assertIn("also here edc-dashboard",
                      render_text(rows(), discovery(), colour=False))

    def test_other_releases_read_as_candidates_when_none_was_picked(self):
        text = render_text(rows(), discovery(primaryRelease=None), colour=False)
        self.assertIn("candidates edc-dashboard", text)

    def test_the_identity_secret_falls_back_when_no_participant_was_resolved(self):
        """Older callers pass no participant; the secret line still has to appear."""
        text = render_text(rows(), discovery(), colour=False)
        self.assertIn("identity  secret atd-tls", text)

    def test_every_phase_gets_a_heading_when_it_has_rows(self):
        text = render_text(rows(), discovery(), colour=False)
        for phase in PHASES:
            self.assertIn(phase.upper(), text)

    def test_a_cause_and_fix_and_see_line_are_all_rendered(self):
        text = render_text(rows(), discovery(), colour=False)
        self.assertIn("fix: f", text)
        self.assertIn("see: ", text)


class TestExitCode(unittest.TestCase):
    def test_a_failure_exits_one(self):
        self.assertEqual(exit_code(rows()), 1)

    def test_warnings_alone_do_not_fail_unless_strict(self):
        warned = [("static", "x", "", Result.warn("w", cause="c"))]
        self.assertEqual(exit_code(warned), 0)
        self.assertEqual(exit_code(warned, strict=True), 1)

    def test_a_broken_check_exits_two(self):
        broken = [("static", "x", "", Result(Status.ERROR, "boom", cause="c"))]
        self.assertEqual(exit_code(broken), 2)


if __name__ == "__main__":
    unittest.main()
