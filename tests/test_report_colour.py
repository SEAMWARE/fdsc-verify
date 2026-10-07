"""The header's colour, and the rule that it has to mean something.

The header was eight lines of undifferentiated grey that nobody read. Alignment
fixed the shape; colour is what makes a value findable without reading the line
it is on. The rule is that a colour carries meaning or it does not get used:

- the DID in cyan, because it is the most copied and most mistyped value in the
  whole system and half of troubleshooting.md is one character of it wrong;
- a release that is not `deployed`, and values the tool could not read from the
  cluster, in the warning colour, because in both cases every static verdict is
  about something other than what is running;
- the `scope` line in the warning colour, because a partial report that does not
  announce itself is how somebody concludes "all green" from a run that skipped
  the half they cared about.

An absence is not a problem, so `EDC  not deployed` stays dim. And everything
goes through the `colour` flag - a hard-coded escape would break every text
assertion in test_report.py, which renders with colour=False.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fdsc_verify.model import Result  # noqa: E402
from fdsc_verify.report import render_text  # noqa: E402

ESC = "\033"
CYAN = "\033[36m"
ALERT = "\033[33m"
DIM = "\033[2m"
DID = "did:web:did.remote-mkt.example.org:did"


def rows():
    return [("preflight", "a", "", Result.ok("fine"))]


def discovery(**extra):
    base = {
        "context": "ctx", "namespace": "ns",
        "primaryRelease": {"name": "r", "revision": 21, "chart": "c", "status": "deployed"},
        "participant": {"did": DID, "from": "verifier"},
        "values": {"trust": "effective", "keys": 1902},
        "lanes": {"dcp": {}}, "notes": [],
    }
    base.update(extra)
    return base


def render(**extra):
    return render_text(rows(), discovery(**extra), colour=True)


class TestWhatEarnsColour(unittest.TestCase):
    def test_the_did_is_highlighted(self):
        self.assertIn(CYAN + DID, render())

    def test_a_release_that_is_not_deployed_is_flagged(self):
        text = render(primaryRelease={"name": "r", "revision": 21, "chart": "c",
                                      "status": "pending-upgrade"})
        self.assertIn(ALERT + "status: pending-upgrade", text)

    def test_a_deployed_release_says_nothing_about_its_status(self):
        # the common case must not be decorated, or the flag stops meaning anything
        self.assertNotIn("status:", render())

    def test_values_the_cluster_did_not_give_us_are_flagged(self):
        self.assertIn(ALERT + "user", render(values={"trust": "user", "keys": 12}))

    def test_values_read_from_the_release_are_not(self):
        self.assertNotIn(ALERT + "effective", render())

    def test_a_partial_report_announces_itself(self):
        text = render_text(
            rows() + [("preflight", "b", "", Result.na("t", cause="no EDC connector lane"))],
            discovery(), colour=True)
        self.assertIn(ALERT + "1 check(s) not applicable", text)

    def test_an_absent_connector_is_dim_rather_than_alarming(self):
        # not deployed is a shape, not a fault
        text = render(lanes={})
        self.assertIn(DIM + "not deployed", text)
        self.assertNotIn(ALERT + "not deployed", text)


class TestNothingLeaksWhenColourIsOff(unittest.TestCase):
    def test_no_escape_survives(self):
        """Pinned because nothing asserted it before.

        Every other text assertion in the suite renders with colour=False, so a
        hard-coded escape anywhere in the header would surface as a pile of
        confusing string mismatches rather than as this one clear failure.
        """
        text = render_text(
            rows() + [("preflight", "b", "", Result.na("t", cause="no EDC connector lane"))],
            discovery(lanes={}, values={"trust": "user", "keys": 1},
                      notes=["a caveat"]),
            colour=False)
        self.assertNotIn(ESC, text)


if __name__ == "__main__":
    unittest.main()
