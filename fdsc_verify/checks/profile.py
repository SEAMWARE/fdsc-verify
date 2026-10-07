"""What you said this deployment is, against what is actually there.

The first thing the report should answer is "what am I looking at, and how do I
know". Everything downstream changes verdict on it: which components are
required, whether the lane checks apply, which DID the identity checks compare
against.

So this check does two jobs, and the second is the one that earns it a place in
the registry rather than a line in the header:

1. It makes the resolution visible. Every structural fact is either declared or
   inferred, and an operator reading a screenful of SKIPs deserves to know which
   - "no EDC lane" reads very differently when you said `--no-edc` than when the
   tool merely failed to find one.
2. It **contradicts**. A declaration is an assertion: saying `--edc` where no
   lane exists means either the flag is wrong or the connector never deployed,
   and both are worth a FAIL. This is the cheapest check in the tool and the only
   one that can catch "you are pointing at the wrong namespace", which is a
   mistake every operator makes at least once.

It never fails for want of a declaration: a run with no flags at all is the
normal case, and then this check is pure information.
"""

from __future__ import annotations

from typing import List

from ..model import Result, check


@check("deployment-profile", "The deployment matches what was declared about it",
       phase="static")
def deployment_profile(ctx) -> Result:
    profile = ctx.profile
    declared = profile.declared()
    lanes = sorted(ctx.deployment.edc_lanes)
    # Every contradiction below compares a declaration against something discovery
    # read from the cluster, so all of them need discovery to have actually looked.
    # Without that, "no lane was found" means "nobody looked", and reporting it as a
    # contradiction is the tool blaming the operator for its own lack of access.
    inspected = ctx.kube.available()
    detail = {"declared": declared, "lanesFound": lanes, "clusterInspected": inspected,
              "releaseFound": ctx.deployment.primary_release}

    contradictions: List[str] = []
    if not inspected:
        if not declared:
            return Result.ok("nothing declared, and no cluster to compare against",
                             **detail)
        return Result.skip(
            "%d declaration(s) recorded, none verified" % len(declared),
            cause="the cluster could not be read, so there is nothing to contradict "
                  "them with. They still apply: %s"
                  % "; ".join("%s from %s" % (name, item["from"])
                              for name, item in sorted(declared.items())))

    # --edc / --no-edc against the lanes discovery actually found
    if profile.edc is True and not lanes:
        contradictions.append(
            "%s says there is an EDC connector, but no fdsc-edc lane was found in %s"
            % (profile.origin("edc"), ctx.deployment.namespace))
    if profile.edc is False and lanes:
        contradictions.append(
            "%s says there is no EDC connector, but %d lane(s) were found: %s"
            % (profile.origin("edc"), len(lanes), ", ".join(lanes)))

    # --edc-protocol against what the lanes say they speak
    if profile.edc_protocol and lanes:
        speaking = {name: ctx.deployment.edc_lanes[name].identity for name in lanes}
        known = {value for value in speaking.values() if value != "unknown"}
        if known and profile.edc_protocol not in known:
            contradictions.append(
                "%s says %s, but the deployed lane(s) are configured for %s (%s)"
                % (profile.origin("edc_protocol"), profile.edc_protocol,
                   " and ".join(sorted(known)),
                   ", ".join("%s=%s" % pair for pair in sorted(speaking.items()))))

    # --did against the DID the lanes carry, which is a different source
    lane_dids = {lane.participant_id for lane in ctx.deployment.edc_lanes.values()
                 if lane.participant_id}
    if profile.did and lane_dids and profile.did not in lane_dids:
        contradictions.append(
            "%s says %s, but the lane configuration carries %s"
            % (profile.origin("did"), profile.did, ", ".join(sorted(lane_dids))))

    # --release against what is in the namespace
    if profile.release and ctx.deployment.releases and \
            profile.release not in ctx.deployment.releases:
        contradictions.append(
            "%s names a release that is not in this namespace; found: %s"
            % (profile.origin("release"), ", ".join(sorted(ctx.deployment.releases))))

    if contradictions:
        return Result.fail(
            "%d declaration(s) do not match the deployment" % len(contradictions),
            cause="%s. Either the flags describe a different deployment - the wrong "
                  "namespace or the wrong context is the usual reason - or the "
                  "deployment is not what you believe it is. Both are worth knowing "
                  "before reading the rest of this report."
                  % "; ".join(contradictions),
            fix="check -n/--context first, then drop the flag that is wrong",
            contradictions=contradictions, **detail)

    if not declared:
        return Result.ok("nothing declared; everything below is inferred",
                         **detail)
    return Result.ok(
        "%d declaration(s), all consistent with what was found: %s"
        % (len(declared), "; ".join("%s from %s" % (name, item["from"])
                                    for name, item in sorted(declared.items()))),
        **detail)
