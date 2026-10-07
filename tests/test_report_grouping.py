"""Grouping repeated SKIPs must never lose a row.

Nine copies of "no EDC connector lane in this namespace" is a wall that buries
the rows that did have something to say, so identical skip reasons collapse into
one line. The danger is the cure: the whole reason those rows exist is that an
absent row reads exactly like a check that ran and found nothing, and a first
attempt at this suppressed every row sharing a reason - including pairs that were
never collapsed, which made verifier-jwks-matches-key vanish from the report while
still being counted in the tally.

So the invariant is not "collapse looks tidy", it is **every check appears
somewhere**, either as its own row or named inside a group.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fdsc_verify.model import Result  # noqa: E402
from fdsc_verify.report import render_text  # noqa: E402

DISCOVERY = {"context": "ctx", "namespace": "ns"}
NO_LANE = "no EDC connector lane in this namespace"


def rows(*specs):
    return [("preflight", check_id, lane, result) for check_id, lane, result in specs]


def render(built):
    return render_text(built, DISCOVERY, colour=False)


class TestEveryCheckAppearsSomewhere(unittest.TestCase):
    def test_a_reason_shared_by_two_rows_is_not_collapsed(self):
        # the regression: collapsing a pair costs a line and saves none, and the
        # first implementation removed both rows without printing a group
        built = rows(("verifier-jwks-matches-key", "dcp", Result.skip("no jwksAddress")),
                     ("verifier-jwks-matches-key", "oid4vc", Result.skip("no jwksAddress")),
                     ("dsp-route", "dcp", Result.ok("dsp 200")))
        text = render(built)
        self.assertIn("verifier-jwks-matches-key (dcp)", text)
        self.assertIn("verifier-jwks-matches-key (oid4vc)", text)
        self.assertNotIn("check(s) skipped", text)

    def test_three_rows_collapse_but_all_are_named(self):
        built = rows(("a", None, Result.skip("x", cause=NO_LANE)),
                     ("b", None, Result.skip("x", cause=NO_LANE)),
                     ("c", None, Result.skip("x", cause=NO_LANE)))
        text = render(built)
        self.assertIn("3 check(s) skipped: %s" % NO_LANE, text)
        for check_id in ("a", "b", "c"):
            self.assertIn(check_id, text)
        # collapsed to a single group line, not three
        self.assertEqual(text.count("check(s) skipped"), 1)

    def test_rows_with_other_reasons_keep_their_own_line(self):
        built = rows(("a", None, Result.skip("x", cause=NO_LANE)),
                     ("b", None, Result.skip("x", cause=NO_LANE)),
                     ("c", None, Result.skip("x", cause=NO_LANE)),
                     ("d", None, Result.skip("needs --peer")),
                     ("e", None, Result.fail("broken", cause="why")))
        text = render(built)
        self.assertIn("needs --peer", text)
        self.assertIn("[FAIL]", text)
        self.assertIn("broken", text)

    def test_two_different_reasons_group_independently(self):
        built = rows(("a", None, Result.skip("x", cause=NO_LANE)),
                     ("b", None, Result.skip("x", cause=NO_LANE)),
                     ("c", None, Result.skip("x", cause=NO_LANE)),
                     ("d", None, Result.skip("y", cause="--transport native")),
                     ("e", None, Result.skip("y", cause="--transport native")),
                     ("f", None, Result.skip("y", cause="--transport native")))
        text = render(built)
        self.assertEqual(text.count("check(s) skipped"), 2)
        for check_id in "abcdef":
            self.assertIn(check_id, text)

    def test_verbose_prints_every_row_separately(self):
        # -v is the escape hatch: it must not hide anything behind a group
        built = rows(("a", None, Result.skip("x", cause=NO_LANE)),
                     ("b", None, Result.skip("x", cause=NO_LANE)),
                     ("c", None, Result.skip("x", cause=NO_LANE)))
        text = render_text(built, DISCOVERY, verbose=True, colour=False)
        self.assertNotIn("check(s) skipped", text)
        self.assertEqual(text.count(NO_LANE), 3)

    def test_the_tally_counts_rows_not_printed_lines(self):
        built = rows(("a", None, Result.skip("x", cause=NO_LANE)),
                     ("b", None, Result.skip("x", cause=NO_LANE)),
                     ("c", None, Result.skip("x", cause=NO_LANE)),
                     ("d", None, Result.ok("fine")))
        self.assertIn("SKIP=3", render(built))


if __name__ == "__main__":
    unittest.main()
