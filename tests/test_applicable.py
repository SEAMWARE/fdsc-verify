"""Not applicable is not the same as could not answer.

SKIP used to mean both, and on a deployment with no fdsc-edc that produced
seventeen rows nobody read: "no EDC connector lane in this namespace" repeated
until the two rows that were real gaps were invisible among them.

The line is about who owes what. *Not applicable* - no connector here, no vault,
one transport asked for - means the question does not arise and the tool owes
nothing, so the row is summarised on the header's `scope` line instead of taking
a line of its own. *Skip* means the question does arise and the tool failed to
settle it; that is a coverage gap and it stays visible, because an operator who
cannot see that the tool went quiet cannot know to go and look themselves.

Both stay SKIP: neither is a finding and neither may be reported as a pass. The
whole distinction therefore has to survive in --json and under -v, or it becomes
a way of hiding things rather than of ordering them.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fdsc_verify.model import Result, Status  # noqa: E402
from fdsc_verify.report import exit_code, render_json, render_text, tally  # noqa: E402
import json  # noqa: E402

DISCOVERY = {"context": "ctx", "namespace": "ns"}
NO_LANE = "no EDC connector lane in this namespace, and this check reads a lane's config"


def rows(*specs):
    return [("preflight", check_id, "", result) for check_id, result in specs]


BOTH = rows(("controlplane-image", Result.na("t", cause=NO_LANE)),
            ("sts-secret-aliases", Result.na("t", cause=NO_LANE)),
            ("did-document", Result.ok("resolves")),
            ("credential-freshness", Result.skip("t", cause="needs cluster access")))


class TestTheResultItself(unittest.TestCase):
    def test_na_is_a_skip_that_knows_it_is_not_owed(self):
        self.assertIs(Result.na("t").status, Status.SKIP)
        self.assertFalse(Result.na("t").applicable)

    def test_every_other_result_is_applicable(self):
        for made in (Result.ok("t"), Result.warn("t"), Result.fail("t"),
                     Result.skip("t")):
            self.assertTrue(made.applicable, made)

    def test_it_cannot_move_the_exit_code(self):
        # SKIP has never affected it and N/A must not start: only ERROR, FAIL and
        # --strict WARN decide whether a run failed
        self.assertEqual(exit_code(BOTH), 0)
        self.assertEqual(exit_code(BOTH, strict=True), 0)


class TestTheTextReport(unittest.TestCase):
    def test_not_applicable_rows_are_not_printed(self):
        text = render_text(BOTH, DISCOVERY, colour=False)
        self.assertNotIn("controlplane-image", text)
        self.assertNotIn("sts-secret-aliases", text)

    def test_but_a_real_gap_still_is(self):
        text = render_text(BOTH, DISCOVERY, colour=False)
        self.assertIn("credential-freshness", text)
        self.assertIn("needs cluster access", text)

    def test_the_header_says_how_many_and_why(self):
        text = render_text(BOTH, DISCOVERY, colour=False)
        self.assertIn("scope", text)
        self.assertIn("no EDC lane", text)
        self.assertIn("2 check(s) not applicable", text)
        self.assertIn("no EDC lane: 2", text)

    def test_the_tally_separates_the_two(self):
        # 1 OK, 1 genuine skip, 2 not applicable - and they add up to every row
        text = render_text(BOTH, DISCOVERY, colour=False)
        self.assertIn("OK=1", text)
        self.assertIn("SKIP=1", text)
        self.assertIn("N/A=2", text)

    def test_verbose_prints_everything(self):
        # -v is what makes the filter safe to trust: nothing is only ever hidden
        text = render_text(BOTH, DISCOVERY, verbose=True, colour=False)
        self.assertIn("controlplane-image", text)
        self.assertIn("sts-secret-aliases", text)

    def test_a_phase_with_nothing_applicable_keeps_its_heading(self):
        """An absent heading reads as a phase that was never planned."""
        text = render_text(rows(("controlplane-image", Result.na("t", cause=NO_LANE))),
                           DISCOVERY, colour=False)
        self.assertIn("PREFLIGHT", text)
        self.assertIn("nothing here applies", text)


class TestTheJsonContract(unittest.TestCase):
    def test_every_row_survives_and_carries_the_flag(self):
        out = json.loads(render_json(BOTH, DISCOVERY))
        self.assertEqual(len(out["results"]), 4)
        flags = {r["check"]: r["applicable"] for r in out["results"]}
        self.assertFalse(flags["controlplane-image"])
        self.assertTrue(flags["credential-freshness"])

    def test_the_summary_still_counts_them_as_skips(self):
        """So a consumer diffing two runs sees no phantom change."""
        out = json.loads(render_json(BOTH, DISCOVERY))
        self.assertEqual(out["summary"]["SKIP"], 3)
        self.assertEqual(tally(BOTH)[Status.SKIP], 3)


if __name__ == "__main__":
    unittest.main()
