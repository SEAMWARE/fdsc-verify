"""Rendering. The cause and the fix are the product; OK/FAIL is the packaging."""

from __future__ import annotations

import json
import os
import sys
from typing import Dict, List, Optional, Tuple

from .model import PHASES, Result, Status

_COLOURS = {
    Status.OK: "\033[32m",
    Status.WARN: "\033[33m",
    Status.FAIL: "\033[31m",
    Status.SKIP: "\033[90m",
    Status.ERROR: "\033[35m",
}
_RESET = "\033[0m"
# Not status colours: emphasis. `_colour` is keyed on Status and cannot express
# "dim" or "bold", and the header has no status to key on - it is context, not
# verdicts. Dim labels and plain values give the eye a column to run down without
# turning the report into a christmas tree.
_DIM = "\033[2m"
_BOLD = "\033[1m"
_CYAN = "\033[36m"
_LABEL_W = 9

# Colour in the header carries meaning or it is not worth the ink. Four things earn it:
# the DID, because it is the most copied and most mistyped value in the whole system and
# half the failures in troubleshooting.md are one character of it; a release that is not
# `deployed`, because then everything the values say describes something that is not
# running; values the tool could not read from the cluster, because every static verdict
# is then only as good as the file it was handed; and a `scope` line, because a partial
# report that does not announce itself is how somebody concludes "all green" from a run
# that skipped the half they cared about.
_ALERT = _COLOURS[Status.WARN]

# Where the diagnoses are written up: docs/troubleshooting.md, shipped with this
# repo so the reference resolves wherever the tool is run from. Printed as an
# absolute path when the file is actually on disk (an operator reading a red line
# wants to open it, not to go looking for it) and as the relative path otherwise,
# which is what a wheel install or a `curl`ed copy of the package will see.
# Override with FDSC_VERIFY_DOC_BASE when a deployment keeps its own copy.
_REL_DOC = "docs/troubleshooting.md"


def _default_doc_base() -> str:
    local = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), _REL_DOC)
    return local if os.path.exists(local) else _REL_DOC


DOC_BASE = os.environ.get("FDSC_VERIFY_DOC_BASE") or _default_doc_base()


def _colour(status: Status, text: str, enabled: bool) -> str:
    if not enabled:
        return text
    return "%s%s%s" % (_COLOURS.get(status, ""), text, _RESET)


def _style(sgr: str, text: str, enabled: bool) -> str:
    """Emphasis rather than a verdict. Same discipline as `_colour`."""
    if not enabled:
        return text
    return "%s%s%s" % (sgr, text, _RESET)


def _head(label: str, value: str, enabled: bool, indent: str = "") -> str:
    """One header line: dim label in a fixed column, value in the normal colour.

    The padding is computed on the raw label and the escape codes wrapped around
    the result, or `len()` counts the escape bytes and every column after the
    first goes crooked - the same trap the row renderer avoids.
    """
    padded = "%-*s" % (_LABEL_W - len(indent), label)
    return "%s%s %s" % (indent, _style(_DIM, padded, enabled), value)


def render_text(rows: List[Tuple[str, str, str, Result]], discovery: Dict[str, object],
                verbose: bool = False, colour: bool = None) -> str:
    """rows: (phase, check_id, lane_or_empty, result)"""
    if colour is None:
        # NO_COLOR is the cross-tool convention (no-color.org): set at all, even
        # empty, means no escapes. Checked here because this is the only place the
        # decision is made.
        colour = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
    out: List[str] = []

    # The header answers "what am I looking at" before "what is wrong with it".
    # It used to lead with `lanes: none found`, which on a deployment that
    # legitimately has no EDC connector - most of them - announced an absence as
    # the headline and buried the role, the identity and the release below it.
    out.append("%s %s / %s" % (
        _style(_BOLD, "FDSC", colour),
        discovery.get("context") or "current-context", discovery.get("namespace")))
    out.append("")

    declared = discovery.get("declared") or {}

    roles = discovery.get("roles") or []
    if roles:
        out.append(_head("role", "%s  %s" % (
            "+".join(roles),
            _style(_DIM, "(%s)" % (discovery.get("roleSource") or "inferred"), colour)),
            colour))
    else:
        out.append(_head("role", "%s  %s" % (
            _style(_ALERT, "undetermined", colour),
            _style(_DIM, "(pass --role to say what this is meant to be)", colour)), colour))

    primary = discovery.get("primaryRelease") or {}
    if primary:
        line = "%s  rev %s  %s" % (
            primary.get("name"), primary.get("revision"),
            _style(_DIM, "chart %s" % primary.get("chart"), colour))
        status = primary.get("status")
        if status and status != "deployed":
            line += "  " + _style(_ALERT, "status: %s" % status, colour)
        out.append(_head("release", line, colour))
    elif discovery.get("release"):
        out.append(_head("release", str(discovery["release"]), colour))
    others = discovery.get("otherReleases") or []
    if others:
        # "also" only reads right when one of them was actually picked
        label = "also here" if primary else "candidates"
        out.append(_head(label, ", ".join(others), colour, indent="  "))

    who = discovery.get("participant") or {}
    if who.get("did"):
        aside = "(from %s)" % (who.get("from") or "?")
        if who.get("documentServer") and who["documentServer"] != "unknown":
            aside += ", document served by %s" % who["documentServer"]
        out.append(_head("identity", "%s  %s" % (
            _style(_CYAN, who["did"], colour),
            _style(_DIM, aside, colour)), colour))
        if who.get("identitySecret"):
            out.append(_head("key", "secret %s" % who["identitySecret"], colour,
                             indent="  "))
    elif discovery.get("identitySecret"):
        out.append(_head("identity", "secret %s" % discovery["identitySecret"], colour))

    values = discovery.get("values") or {}
    if values:
        trust = values.get("trust")
        # `effective` is the release as the cluster holds it; anything else means the
        # static verdicts rest on a file somebody handed us, or on nothing at all
        painted = trust if trust == "effective" else _style(_ALERT, str(trust), colour)
        out.append(_head("values", "%s  %s" % (
            painted,
            _style(_DIM, "(%d keys)" % (values.get("keys") or 0), colour)), colour))

    # ALWAYS, which is the change: an absence has to be asserted, not left to be
    # inferred from missing rows. The lane checks no longer print a row each when
    # there is no connector, so this line is the only place the report says whether
    # fdsc-edc is part of this deployment - and if discovery got it wrong, a false
    # sentence in the header is something an operator can catch, which sixteen
    # skipped rows nobody reads were not.
    lanes = sorted(discovery.get("lanes") or {})
    if lanes:
        out.append(_head("EDC", "%d lane(s): %s" % (len(lanes), ", ".join(lanes)), colour))
    else:
        edc = declared.get("edc") or {}
        how = ("declared %s" % edc.get("from")) if edc else "inferred"
        out.append(_head("EDC", "%s  %s" % (
            _style(_DIM, "not deployed", colour),
            _style(_DIM, "(%s)" % how, colour)), colour))

    if declared:
        out.append(_head("declared", ", ".join(
            "%s=%s" % (name, _flat(item.get("value")))
            for name, item in sorted(declared.items())), colour))

    ruled_out = _not_applicable(rows)
    if ruled_out:
        out.append(_head("scope", "%s  %s" % (
            _style(_ALERT, "%d check(s) not applicable"
                   % sum(count for _, count in ruled_out), colour),
            _style(_DIM, "(%s)" % "; ".join(
                "%s: %d" % (label, count) for label, count in ruled_out), colour)), colour))

    for note in discovery.get("notes") or []:
        out.append(_head("note", _style(_ALERT, note, colour), colour, indent="  "))
    out.append("")

    for phase in PHASES:
        all_rows = [r for r in rows if r[0] == phase]
        if not all_rows:
            continue
        # Not applicable = the question does not arise here, so the tool owes no
        # answer and the row is not news. It is counted in the tally, summarised on
        # the `scope` line above, kept in --json and printed under -v; what it does
        # not do is take a line each. `-v` is the escape hatch, and it shows
        # everything precisely so that nothing depends on trusting this filter.
        phase_rows = all_rows if verbose else [r for r in all_rows if r[3].applicable]
        out.append(phase.upper())
        if not phase_rows:
            # not "to this deployment": the reason may be the invocation - no
            # --peer, one transport asked for - and the scope line has it
            out.append("  (nothing here applies; see `scope` above for why)")
            out.append("")
            continue
        # Several checks skipped for the SAME reason collapse into one line. Every row
        # still exists - the JSON is untouched and `-v` prints them - but nine copies of
        # "no EDC connector lane in this namespace" is a wall that buries the rows that
        # did have something to say. The rule deliberately does NOT drop them: an absent
        # row reads exactly like a check that ran and found nothing, which is the failure
        # this reporting rule was written to avoid in the first place.
        grouped = _skip_groups(phase_rows) if not verbose else {}
        emitted = set()
        for _, check_id, lane, result in phase_rows:
            reason = _skip_reason_text(result)
            if reason is not None and reason in grouped:
                # print the group once, in the position of its first member, and
                # suppress ONLY the rows it names
                if reason in emitted:
                    continue
                emitted.add(reason)
                members = grouped[reason]
                out.append("  %s %d check(s) skipped: %s" % (
                    _colour(Status.SKIP, "%-7s" % "[SKIP]", colour), len(members), reason))
                out.append("          %s" % ", ".join(members))
                continue
            tag = "[%s]" % result.status.value
            label = check_id if not lane else "%s (%s)" % (check_id, lane)
            out.append("  %s %-46s %s" % (
                _colour(result.status, "%-7s" % tag, colour), label, result.summary))
            # a FAIL without a cause is an incomplete check; show whatever we have
            if result.cause:
                for line in _wrap(result.cause, 88):
                    out.append("          %s" % line)
            if result.fix:
                out.append("          fix: %s" % result.fix)
            if result.doc:
                out.append("          see: %s#%s" % (DOC_BASE, result.doc))
            if verbose and result.detail:
                out.append("          detail: %s" % json.dumps(result.detail, default=str))
        out.append("")

    # Counted from the ROWS, never from what was printed. A count that follows the
    # rendering is how a suppressed row becomes invisible twice over, which is the
    # regression tests/test_report_grouping.py exists to prevent. N/A is broken out
    # rather than folded into SKIP so the arithmetic is checkable by eye: the two
    # add up to every row that did not run.
    counts = tally(rows)
    na = sum(1 for _, _, _, result in rows if not result.applicable)
    parts = ["%s=%d" % (status.value, counts[status] - (na if status is Status.SKIP else 0))
             for status in (Status.OK, Status.WARN, Status.FAIL, Status.SKIP, Status.ERROR)
             if counts[status] - (na if status is Status.SKIP else 0)]
    if na:
        parts.append("N/A=%d" % na)
    out.append("  ".join(parts))
    return "\n".join(out)


def _not_applicable(rows) -> List[Tuple[str, int]]:
    """Why rows were left out of the text, as (label, count), commonest first.

    The label is a short stand-in for the reason rather than the reason itself -
    the full sentence stays in --json and under -v. Header space is the scarcest
    in the report, and "no EDC lane" is the whole story for an operator wondering
    where the connector checks went.
    """
    labels = (("no EDC connector lane", "no EDC lane"),
              ("--transport", "one transport asked for"),
              ("only applies to a", "role does not match"),
              ("needs --peer", "no --peer given"),
              ("--no-write", "--no-write given"))
    counts: Dict[str, int] = {}
    for _, _, _, result in rows:
        if result.applicable:
            continue
        why = result.cause or result.summary or ""
        label = next((short for needle, short in labels if needle in why),
                     "not part of this deployment")
        counts[label] = counts.get(label, 0) + 1
    return sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))


def _skip_reason_text(result) -> Optional[str]:
    """The reason a SKIP gives, or None when the row is not a groupable skip."""
    if result.status is not Status.SKIP:
        return None
    return result.cause or result.summary


def _skip_groups(phase_rows) -> Dict[str, List[str]]:
    """Skip reasons shared by more than two rows, mapped to the checks that gave them.

    Two is left alone on purpose: collapsing a pair costs a line and saves none, and
    the check names stay where the eye expects them.
    """
    seen: Dict[str, List[str]] = {}
    for _, check_id, lane, result in phase_rows:
        reason = _skip_reason_text(result)
        if reason is None:
            continue
        label = check_id if not lane else "%s (%s)" % (check_id, lane)
        seen.setdefault(reason, []).append(label)
    return {reason: members for reason, members in seen.items() if len(members) > 2}


def _flat(value) -> str:
    if isinstance(value, list):
        return "+".join(str(v) for v in value)
    if isinstance(value, dict):
        return ",".join("%s=%s" % (k, "on" if v else "off") for k, v in sorted(value.items()))
    return str(value)


def _wrap(text: str, width: int) -> List[str]:
    words, lines, current = text.split(), [], ""
    for word in words:
        if len(current) + len(word) + 1 > width:
            lines.append(current)
            current = word
        else:
            current = "%s %s" % (current, word) if current else word
    if current:
        lines.append(current)
    return lines


def render_json(rows: List[Tuple[str, str, str, Result]], discovery: Dict[str, object]) -> str:
    counts = tally(rows)
    return json.dumps({
        "discovery": discovery,
        "summary": {status.value: counts[status] for status in Status},
        "results": [
            {
                "phase": phase,
                "check": check_id,
                "lane": lane or None,
                "status": result.status.value,
                # SKIP either way, so `summary` keeps counting them together and a
                # consumer diffing two runs sees no phantom change; this says which
                # KIND of skip it was. Fields may be added here, never renamed or
                # removed.
                "applicable": result.applicable,
                "summary": result.summary,
                "cause": result.cause,
                "fix": result.fix,
                "doc": ("%s#%s" % (DOC_BASE, result.doc)) if result.doc else None,
                "detail": result.detail or None,
            }
            for phase, check_id, lane, result in rows
        ],
    }, indent=2, default=str)


def tally(rows) -> Dict[Status, int]:
    counts = {status: 0 for status in Status}
    for _, _, _, result in rows:
        counts[result.status] += 1
    return counts


def exit_code(rows, strict: bool = False) -> int:
    """0 clean, 1 something failed, 2 the tool itself broke.

    WARNs do not fail the run unless --strict: they exist to be read, and a
    permanently red build gets ignored.
    """
    counts = tally(rows)
    if counts[Status.ERROR]:
        return 2
    if counts[Status.FAIL]:
        return 1
    if strict and counts[Status.WARN]:
        return 1
    return 0
