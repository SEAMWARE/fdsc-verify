"""Run the registered checks and decide what to skip.

The rule that shapes this: if an earlier phase found something broken, do not run
the flows. A failed flow only says "it does not work", which the operator already
knows; the earlier failure is the answer.

Note that this cuts one way only. A `static` failure closes the gate on `flow`,
because "a required component is missing" is already the diagnosis - but it does
*not* stop `preflight`, whose findings (a stale JWKS, a DID copied from a
neighbour) are independent diagnoses rather than consequences. Suppressing them
would hide exactly what this tool exists to find.
"""

from __future__ import annotations

import traceback
from typing import Dict, List, Optional, Sequence, Tuple

from .context import Context
from .model import PHASES, REGISTRY, Check, Result, Status
from .progress import null

Row = Tuple[str, str, str, Result]


def phases_in_order(phases: Optional[Sequence[str]] = None) -> List[str]:
    """Normalise a phase selection to PHASES order, deduplicated.

    Callers pass a set the operator chose, in whatever order they typed it; the
    run order is the tool's to decide, not theirs.
    """
    if phases is None:
        return list(PHASES)
    wanted = set(phases)
    unknown = sorted(wanted - set(PHASES))
    if unknown:
        raise ValueError("unknown phase(s): %s (expected any of %s)"
                         % (", ".join(unknown), ", ".join(PHASES)))
    return [phase for phase in PHASES if phase in wanted]


def run(ctx: Context, lanes: Optional[List[str]] = None, only: Optional[List[str]] = None,
        phases: Optional[Sequence[str]] = None, allow_writes: bool = True,
        force_flows: bool = False, transports: Optional[Sequence[str]] = None,
        progress=None) -> List[Row]:
    selected_phases = phases_in_order(phases)
    selected_lanes = lanes if lanes is not None else ctx.lane_names()
    rows: List[Row] = []
    progress = progress or null()
    ctx.progress = progress          # checks report their own sub-steps through this

    progress.start("checking cluster access")
    cluster = ctx.kube.available()
    progress.finish()

    for phase in selected_phases:
        if phase == "flow" and not force_flows:
            failures = [r for r in rows if r[3].status is Status.FAIL]
            if failures:
                earlier = [p for p in selected_phases if p != "flow"]
                rows.append((
                    "flow", "flow-*", "",
                    Result.skip(
                        "not run: %d failure(s) in %s"
                        % (len(failures), "/".join(earlier) or "an earlier phase"),
                        cause="a flow would only confirm that it does not work; the "
                              "failures above are the diagnosis. Use --force-flows to "
                              "run anyway"),
                ))
                continue

        # planned up front so the counter has a denominator: "[preflight 7/23]" is
        # the difference between "it is working" and "it is stuck on number 7"
        plan: List[Tuple[Check, Optional[str]]] = []
        for spec in REGISTRY:
            if spec.phase != phase or (only and spec.id not in only):
                continue
            targets = _lanes_for(spec, selected_lanes)
            if targets:
                plan.extend((spec, target) for target in targets)
            else:
                # lane-scoped, with no lane to run it on. It still gets a row - a
                # check that silently disappears is indistinguishable from one that
                # passed, and on a deployment without fdsc-edc that was fifteen of
                # them at once - but the row says whether the absence is the
                # deployment's shape or a gap, and the text report shows it
                # accordingly.
                plan.append((spec, None))
        for index, (spec, lane_name) in enumerate(plan, start=1):
            label = spec.id if not lane_name else "%s (%s)" % (spec.id, lane_name)
            progress.start("[%s %d/%d] %s" % (phase, index, len(plan), label))
            if lane_name is None:
                reason, applicable = _no_lane_reason(spec, selected_lanes, ctx)
                make = Result.skip if applicable else Result.na
                rows.append((spec.phase, spec.id, "",
                             make(spec.title, cause=reason)))
            else:
                rows.append(_run_one(ctx, spec, lane_name, cluster, allow_writes,
                                     transports))
            progress.finish()
    return rows


def _no_lane_reason(spec: Check, selected: List[str], ctx: Context) -> Tuple[str, bool]:
    """Why a lane-scoped check had nothing to run on. Returns (reason, applicable).

    The precision this function already carried now decides how the row is shown:
    "this deployment has no EDC lane" is a fact about the deployment and usually
    the expected answer, so it is not applicable; "the lane you asked for is not
    one this check covers" is a fact about the invocation and stays visible,
    because the operator asked for something they did not get.
    """
    if not ctx.deployment.edc_lanes:
        return ("no EDC connector lane in this namespace, and this check reads a "
                "lane's configuration. fdsc-edc is one way to deploy a DSC, not a "
                "requirement - the checks that do not need a lane still ran"), False
    if spec.lanes != ["*"]:
        return ("none of the lanes here (%s) is one this check covers (%s)"
                % (", ".join(selected) or "none selected",
                   ", ".join(spec.lanes or [])), True)
    return "no lane was selected to run it on", True


def _lanes_for(spec: Check, selected: List[str]) -> List[str]:
    """A check either runs once, or once per selected lane."""
    if spec.lanes is None:
        return [""]
    if spec.lanes == ["*"]:
        return selected
    return [lane for lane in selected if lane in spec.lanes]


def _run_one(ctx: Context, spec: Check, lane_name: str, cluster: bool,
             allow_writes: bool,
             selected_transports: Optional[Sequence[str]] = None) -> Row:
    reason, applicable = _skip_reason(ctx, spec, lane_name, cluster, allow_writes,
                                      selected_transports)
    if reason:
        make = Result.skip if applicable else Result.na
        return (spec.phase, spec.id, lane_name, make(spec.title, cause=reason))
    try:
        if lane_name:
            result = spec.fn(ctx, ctx.deployment.edc_lanes[lane_name])
        else:
            result = spec.fn(ctx)
    except Exception as exc:  # noqa: BLE001 - a broken check must not stop the run
        result = Result(Status.ERROR, "the check itself failed",
                        cause="%s: %s" % (type(exc).__name__, exc),
                        detail={"traceback": traceback.format_exc(limit=3)})
    return (spec.phase, spec.id, lane_name, result)


def _skip_reason(ctx: Context, spec: Check, lane_name: str, cluster: bool,
                 allow_writes: bool,
                 selected_transports: Optional[Sequence[str]] = None) -> Tuple[Optional[str], bool]:
    """The one place the skip policy lives. Returns (reason, applicable).

    Every branch returns a reason the operator can act on, and now says which KIND
    of reason it is - a distinction this docstring drew in prose long before the
    report could act on it. "needs cluster access" is a fact about the invocation
    and the tool still owes an answer, so the row stays visible. "only applies to a
    provider" and "no EDC connector lane here" are facts about the deployment or
    about the scope asked for: nothing is owed, so the row is summarised in the
    header instead of printed. Neither is a finding, and neither may be reported as
    a pass.
    """
    if spec.needs_cluster and not cluster:
        return "needs cluster access (kubectl unavailable or cluster unreachable)", True
    if spec.needs_values and ctx.values.trust == "none":
        return ("needs the release values (%s)"
                % (ctx.values.source or "none were resolved"), True)
    if spec.needs_release and not ctx.deployment.primary_release:
        return ("needs to know which release to look at; %s"
                % _release_hint(ctx), True)
    if spec.roles:
        from . import components as components_mod

        roles, how = components_mod.roles_for(ctx.deployment, ctx.profile)
        if not roles:
            # undetermined, not inapplicable: the tool could not tell which it is,
            # and that is a gap the operator can close with --role
            return ("only applies to a %s, and the role of this deployment could not "
                    "be determined (%s). Pass --role to settle it"
                    % (" or ".join(spec.roles), how), True)
        if not set(spec.roles) & set(roles):
            return ("only applies to a %s; this one is a %s (%s)"
                    % (" or ".join(spec.roles), "+".join(roles), how), False)
    if spec.needs_peer and not ctx.peers:
        return "needs --peer", False
    if spec.mutates and not allow_writes:
        return "--no-write given and this check creates objects", False
    # A check runs when ANY path it can break was asked for. Intersection rather than
    # equality because `transports` is a set: verifier-jwks-matches-key breaks both, so it
    # has to survive `--transport fiware` as well as `--transport edc`.
    if spec.transports and selected_transports and not set(spec.transports) & set(selected_transports):
        return ("--transport %s was asked for; a failure here breaks the %s path"
                % ("/".join(selected_transports), "/".join(sorted(spec.transports))), False)
    if lane_name and lane_name not in ctx.deployment.edc_lanes:
        return "lane %s not deployed" % lane_name, False
    return None, True


def _release_hint(ctx: Context) -> str:
    candidates = sorted(ctx.deployment.releases)
    if not candidates:
        return ("no Helm release for a DSC was readable here. A GitOps install renders "
                "with `helm template` and leaves none behind, in which case pass "
                "--values <the file it was deployed from>")
    return "pass --release (candidates: %s)" % ", ".join(candidates)
