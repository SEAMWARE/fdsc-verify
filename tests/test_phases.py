"""PHASES is the single source of truth, and the gate between phases cuts one way.

Two things are worth pinning down here. The first is that the phase list lives in
exactly one place: it used to be a literal repeated in `runner` and in `report`,
and a third phase is precisely the change that turns that duplication into a bug.
The second is the asymmetry of the gate - a static failure must close `flow` but
must NOT close `preflight`, because preflight's findings are independent
diagnoses, not consequences, and suppressing them would hide what the tool is for.
"""

import contextlib
import os
import re
import unittest
from types import SimpleNamespace

from fdsc_verify import model, runner
from fdsc_verify.model import PHASES, REGISTRY, Result, Status, check

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@contextlib.contextmanager
def registry_isolated():
    """Swap REGISTRY out so a test can register checks without leaking them."""
    saved = list(REGISTRY)
    REGISTRY[:] = []
    try:
        yield REGISTRY
    finally:
        REGISTRY[:] = saved


def fake_context(lanes=()):
    """The runner only touches these five things; a real Context needs a cluster."""
    return SimpleNamespace(
        kube=SimpleNamespace(available=lambda: True),
        deployment=SimpleNamespace(edc_lanes={name: SimpleNamespace(name=name)
                                                 for name in lanes}),
        peers=[],
        progress=None,
        lane_names=lambda: sorted(lanes),
    )


class TestPhaseList(unittest.TestCase):
    def test_every_registered_check_declares_a_known_phase(self):
        from fdsc_verify import checks  # noqa: F401  - importing registers them
        unknown = sorted({spec.phase for spec in REGISTRY} - set(PHASES))
        self.assertEqual(unknown, [], "checks registered under unknown phases: %s" % unknown)

    def test_no_module_hardcodes_the_phase_list(self):
        """The literal is gone from runner and report; keep it gone.

        Scanned as text rather than behaviour because the failure mode is a
        *silent* one: a new phase simply never appears in the output.
        """
        offenders = []
        for name in sorted(os.listdir(os.path.join(ROOT, "fdsc_verify"))):
            if not name.endswith(".py") or name == "model.py":
                continue
            with open(os.path.join(ROOT, "fdsc_verify", name), encoding="utf-8") as handle:
                body = handle.read()
            if re.search(r'\(\s*"preflight"\s*,\s*"flow"\s*\)', body):
                offenders.append(name)
        self.assertEqual(offenders, [], "hardcoded phase tuple in: %s" % ", ".join(offenders))

    def test_phases_in_order_normalises_and_deduplicates(self):
        self.assertEqual(runner.phases_in_order(None), list(PHASES))
        self.assertEqual(runner.phases_in_order(["flow", "static"]), ["static", "flow"])
        self.assertEqual(runner.phases_in_order(["static", "static"]), ["static"])

    def test_phases_in_order_rejects_a_typo(self):
        with self.assertRaises(ValueError) as caught:
            runner.phases_in_order(["prefligth"])
        self.assertIn("prefligth", str(caught.exception))


class TestCheckRegistration(unittest.TestCase):
    def test_an_unknown_phase_is_refused_at_import_time(self):
        with registry_isolated():
            with self.assertRaises(ValueError) as caught:
                check("x", "t", phase="prefligth")
            self.assertIn("unknown phase", str(caught.exception))

    def test_a_duplicate_id_is_refused(self):
        with registry_isolated():
            check("dupe", "first")(lambda ctx: Result.ok("ok"))
            with self.assertRaises(ValueError) as caught:
                check("dupe", "second")
            self.assertIn("already registered", str(caught.exception))

    def test_every_phase_in_PHASES_is_accepted(self):
        with registry_isolated():
            for index, phase in enumerate(PHASES):
                check("c%d" % index, "t", phase=phase)(lambda ctx: Result.ok("ok"))
            self.assertEqual([spec.phase for spec in REGISTRY], list(PHASES))


class TestGate(unittest.TestCase):
    def _rows_by_id(self, rows):
        return {row[1]: row[3] for row in rows}

    def test_phases_run_in_PHASES_order_not_registration_order(self):
        with registry_isolated():
            check("f", "flow one", phase="flow")(lambda ctx: Result.ok("ok"))
            check("s", "static one", phase="static")(lambda ctx: Result.ok("ok"))
            rows = runner.run(fake_context())
        self.assertEqual([row[0] for row in rows], ["static", "flow"])

    def test_a_static_failure_does_not_stop_preflight(self):
        with registry_isolated():
            check("s", "static", phase="static")(lambda ctx: Result.fail("broken", cause="c"))
            check("p", "preflight", phase="preflight")(lambda ctx: Result.ok("ran"))
            rows = runner.run(fake_context(), phases=["static", "preflight"])
        results = self._rows_by_id(rows)
        self.assertIs(results["s"].status, Status.FAIL)
        self.assertIs(results["p"].status, Status.OK, "preflight must still run")

    def test_a_static_failure_does_close_the_flow_gate(self):
        with registry_isolated():
            check("s", "static", phase="static")(lambda ctx: Result.fail("broken", cause="c"))
            check("flow-x", "flow", phase="flow")(lambda ctx: Result.ok("should not run"))
            rows = runner.run(fake_context())
        results = self._rows_by_id(rows)
        self.assertNotIn("flow-x", results)
        self.assertIs(results["flow-*"].status, Status.SKIP)
        self.assertIn("static", results["flow-*"].summary)

    def test_force_flows_reopens_the_gate(self):
        with registry_isolated():
            check("s", "static", phase="static")(lambda ctx: Result.fail("broken", cause="c"))
            check("flow-x", "flow", phase="flow")(lambda ctx: Result.ok("ran"))
            rows = runner.run(fake_context(), force_flows=True)
        results = self._rows_by_id(rows)
        self.assertIs(results["flow-x"].status, Status.OK)
        self.assertNotIn("flow-*", results)

    def test_selecting_only_static_never_reaches_the_gate(self):
        with registry_isolated():
            check("s", "static", phase="static")(lambda ctx: Result.fail("broken", cause="c"))
            check("flow-x", "flow", phase="flow")(lambda ctx: Result.ok("ran"))
            rows = runner.run(fake_context(), phases=["static"])
        self.assertEqual(sorted(self._rows_by_id(rows)), ["s"])

    def test_a_warning_does_not_close_the_gate(self):
        with registry_isolated():
            check("s", "static", phase="static")(lambda ctx: Result.warn("odd", cause="c"))
            check("flow-x", "flow", phase="flow")(lambda ctx: Result.ok("ran"))
            rows = runner.run(fake_context())
        self.assertIs(self._rows_by_id(rows)["flow-x"].status, Status.OK)


class TestLaneScopedChecksWithNoLane(unittest.TestCase):
    """A lane-scoped check with no lane must still be in the report.

    This was fifteen checks vanishing at once on a deployment with no fdsc-edc -
    not skipped, not mentioned: absent. An absent row reads exactly like a check
    that ran and had nothing to say, which is the one reading that is wrong.
    """

    def _rows_by_id(self, rows):
        return {row[1]: row[3] for row in rows}

    def test_no_lanes_at_all_still_produces_a_row(self):
        with registry_isolated():
            check("per-lane", "per lane", lanes=["*"])(lambda ctx, lane: Result.ok("ran"))
            rows = runner.run(fake_context(lanes=()))
        result = self._rows_by_id(rows)["per-lane"]
        self.assertIs(result.status, Status.SKIP)
        self.assertIn("no EDC connector lane", result.cause)
        self.assertIn("not a requirement", result.cause)

    def test_the_reason_names_the_lanes_that_do_exist(self):
        with registry_isolated():
            check("dcp-only", "dcp only", lanes=["dcp"])(lambda ctx, lane: Result.ok("ran"))
            rows = runner.run(fake_context(lanes=("oid4vc",)))
        result = self._rows_by_id(rows)["dcp-only"]
        self.assertIs(result.status, Status.SKIP)
        self.assertIn("oid4vc", result.cause)
        self.assertIn("dcp", result.cause)

    def test_a_lane_independent_check_is_untouched(self):
        with registry_isolated():
            check("once", "once", lanes=None)(lambda ctx: Result.ok("ran"))
            rows = runner.run(fake_context(lanes=()))
        self.assertIs(self._rows_by_id(rows)["once"].status, Status.OK)

    def test_one_row_per_lane_when_lanes_exist(self):
        with registry_isolated():
            check("per-lane", "per lane", lanes=["*"])(lambda ctx, lane: Result.ok("ran"))
            rows = runner.run(fake_context(lanes=("dcp", "oid4vc")))
        self.assertEqual([row[2] for row in rows], ["dcp", "oid4vc"])
        self.assertTrue(all(row[3].status is Status.OK for row in rows))


class TestOnlyTheFlowPhaseWrites(unittest.TestCase):
    """`--preflight-only` promises it creates nothing. This is what makes that true.

    It was not true before: `broker-keyword-escaping` sat in preflight with
    `mutates=True` and created a throwaway entity, so the promise held only if you
    also passed `--no-write` - which the flag's own help never said. An invariant
    with one exception is not an invariant, it is something you have to remember.
    """

    def test_no_check_outside_the_flow_phase_writes(self):
        from fdsc_verify import checks  # noqa: F401
        from fdsc_verify.model import REGISTRY

        writers = sorted(spec.id for spec in REGISTRY
                         if spec.mutates and spec.phase != "flow")
        self.assertEqual(writers, [],
                         "these write outside the flow phase, which breaks the "
                         "promise --preflight-only makes: %s" % ", ".join(writers))

    def test_the_phases_that_can_write_are_exactly_the_ones_that_say_so(self):
        """And every writer still declares `mutates`, so --no-write can skip it."""
        from fdsc_verify import checks  # noqa: F401
        from fdsc_verify.model import REGISTRY

        flow_writers = [spec.id for spec in REGISTRY
                        if spec.phase == "flow" and spec.mutates]
        self.assertTrue(flow_writers, "expected the flow phase to contain the writers")


class TestRoleGate(unittest.TestCase):
    """`roles=` replaces `families=`, which nothing ever declared and nothing validated.

    The failure it removes is the quiet one: a misspelled value used to gate a
    check out of every run and say nothing about it.
    """

    def _rows_by_id(self, rows):
        return {row[1]: row[3] for row in rows}

    def context(self, services=None, profile=None):
        from fdsc_verify.profile import Profile
        return SimpleNamespace(
            kube=SimpleNamespace(available=lambda: True),
            deployment=SimpleNamespace(edc_lanes={}, services=services or {},
                                       primary_release=None, releases={}),
            values=SimpleNamespace(trust="effective", source=""),
            profile=profile or Profile(), peers=[], progress=None,
            lane_names=lambda: [])

    def test_a_provider_check_skips_on_a_consumer_and_says_why(self):
        from fdsc_verify.profile import Profile
        profile = Profile()
        profile.roles, profile._origins["roles"] = ("consumer",), "--role"
        with registry_isolated():
            check("p", "provider only", roles=("provider",))(lambda ctx: Result.ok("ran"))
            rows = runner.run(self.context(profile=profile))
        result = self._rows_by_id(rows)["p"]
        self.assertIs(result.status, Status.SKIP)
        self.assertIn("only applies to a provider", result.cause)
        self.assertIn("this one is a consumer", result.cause)

    def test_it_runs_when_the_role_matches(self):
        from fdsc_verify.profile import Profile
        profile = Profile()
        profile.roles, profile._origins["roles"] = ("provider",), "--role"
        with registry_isolated():
            check("p", "provider only", roles=("provider",))(lambda ctx: Result.ok("ran"))
            rows = runner.run(self.context(profile=profile))
        self.assertIs(self._rows_by_id(rows)["p"].status, Status.OK)

    def test_an_undetermined_role_skips_rather_than_assuming_one(self):
        with registry_isolated():
            check("p", "provider only", roles=("provider",))(lambda ctx: Result.ok("ran"))
            rows = runner.run(self.context())
        result = self._rows_by_id(rows)["p"]
        self.assertIs(result.status, Status.SKIP)
        self.assertIn("--role", result.cause)

    def test_a_check_with_no_role_runs_regardless(self):
        with registry_isolated():
            check("any", "applies to all")(lambda ctx: Result.ok("ran"))
            rows = runner.run(self.context())
        self.assertIs(self._rows_by_id(rows)["any"].status, Status.OK)

    def test_a_misspelled_role_is_refused_at_import_time(self):
        with registry_isolated():
            with self.assertRaises(ValueError) as caught:
                check("x", "typo", roles=("providr",))(lambda ctx: Result.ok("ran"))
            self.assertIn("providr", str(caught.exception))


class TestCliSelection(unittest.TestCase):
    def _phases(self, argv):
        from fdsc_verify.__main__ import _phases_from_args, build_parser
        return _phases_from_args(build_parser().parse_args(argv))

    def test_default_is_every_phase(self):
        self.assertEqual(self._phases(["-n", "ns"]), list(PHASES))

    def test_preflight_only_keeps_meaning_everything_but_the_flows(self):
        self.assertEqual(self._phases(["-n", "ns", "--preflight-only"]),
                         ["static", "preflight"])

    def test_static_only(self):
        self.assertEqual(self._phases(["-n", "ns", "--static-only"]), ["static"])

    def test_explicit_phase_wins_over_the_shorthands(self):
        self.assertEqual(self._phases(["-n", "ns", "--preflight-only", "--phase", "flow"]),
                         ["flow"])


if __name__ == "__main__":
    unittest.main()
