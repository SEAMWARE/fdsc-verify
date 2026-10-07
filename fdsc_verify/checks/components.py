"""Is this deployment built like the role it plays?

Three checks, and the first is the one everything else hangs off: a report that
lists what is missing without saying what the deployment is *for* has no way to
tell a correctly built Consumer from a Provider with half its stack gone. Both
look like "no verifier here".

The rule these follow is the tool's second authority. **Presence is the cluster's
to answer** - a Service that exists is a component that is there, whoever
installed it, because in one environment the did-helper is a subchart and in
another a sibling release and both are correct. **Intent and the fix are the
values' to answer**, so a finding names the key somebody will edit.

The failure mode to avoid here is over-reporting, and it is not hypothetical: an
earlier version of discovery listed every participant component as missing in a
trust-anchor namespace, all correctly absent. That note was deleted rather than
fixed, with a comment deferring it to this matrix.
"""

from __future__ import annotations

from typing import List

from .. import components as matrix
from ..model import Result, check

DOC_INVENTORY = "a-role-is-missing-a-component-it-requires"
DOC_CONSISTENCY = "components-that-cannot-work-without-each-other"


@check("deployment-role", "What this deployment is, and how we know",
       phase="static")
def deployment_role(ctx) -> Result:
    """Never a failure. It is `values-source` for roles: it makes the basis visible.

    A role that cannot be determined is reported as exactly that, because every
    role-gated check below will then skip and a screenful of unexplained skips
    reads as a broken tool rather than as a deployment nobody described.
    """
    roles, how = matrix.roles_for(ctx.deployment, ctx.profile)
    detail = {"roles": list(roles), "from": how,
              "services": sorted(ctx.deployment.services)}
    if not roles:
        return Result.skip(
            "the role of this deployment could not be determined",
            cause="%s. Pass --role consumer|provider|consumer+provider to say what it "
                  "is meant to be; without it the component checks have no row of the "
                  "matrix to measure against" % how)
    # The one deployment shape worth naming here rather than leaving as an
    # absence: a provider with no marketplace of its own looks under-deployed
    # until you know it publishes through a central one.
    central = (ctx.values.get("contract-management.enableCentralMarketplace") is True
               and ctx.deployment.service("contractmanagement")
               and not ctx.deployment.service("marketplace"))
    detail["centralMarketplace"] = bool(central)
    summary = "%s (%s)" % ("+".join(roles), how)
    if central:
        summary += ", publishing through a central marketplace"
    return Result.ok(summary, **detail)


@check("component-inventory", "Every component this role requires is deployed",
       phase="static")
def component_inventory(ctx) -> Result:
    roles, how = matrix.roles_for(ctx.deployment, ctx.profile)
    if not roles:
        return Result.skip("no role to measure against",
                           cause="%s; see deployment-role" % how)

    missing, wanted_but_absent, unknown, present, extra = [], [], [], [], []
    for component in matrix.MATRIX:
        requirement = component.requirement(roles)
        state = matrix.presence(ctx.deployment, ctx.values, ctx.profile, component.key)
        if state.present:
            present.append(component.label)
            if requirement == matrix.NOT_APPLICABLE:
                extra.append("%s (%s)" % (component.label, state.why))
            continue
        if state.unknown:
            if requirement == matrix.REQUIRED:
                unknown.append("%s: %s" % (component.label, state.why))
            continue
        # Present=False. Whether that is a fault depends on the row, and on
        # whether anybody asked for it.
        if requirement == matrix.REQUIRED:
            missing.append("%s (%s, %s)" % (component.label, component.values_path,
                                            state.why))
        elif state.wanted:
            wanted_but_absent.append("%s (%s is on, but nothing is running)"
                                     % (component.label, component.values_path))

    detail = {"roles": list(roles), "present": present, "missing": missing,
              "enabledButAbsent": wanted_but_absent, "undetermined": unknown,
              "beyondTheRole": extra}

    if missing:
        return Result.fail(
            "%d component(s) this role requires are not deployed" % len(missing),
            cause="a %s needs them: %s. The canonical matrix is in "
                  "data-space-connector/doc/deployment-integration/roles/README.md"
                  % ("+".join(roles), "; ".join(missing)),
            fix="enable them in the values, or correct --role if this deployment is "
                "not meant to be a %s" % "+".join(roles),
            doc=DOC_INVENTORY, **detail)
    if wanted_but_absent:
        return Result.fail(
            "%d component(s) are enabled but not running" % len(wanted_but_absent),
            cause="%s. The values ask for them, so this is not a deployment that "
                  "chose to go without: something failed to come up, or the release "
                  "was never applied." % "; ".join(wanted_but_absent),
            fix="check the release status and the workloads of those components",
            doc=DOC_INVENTORY, **detail)
    summary = "%d component(s) present, all %s requirements met" % (
        len(present), "+".join(roles))
    if unknown:
        return Result.warn(summary + ", %d undetermined" % len(unknown),
                           cause="; ".join(unknown), **detail)
    return Result.ok(summary, **detail)


@check("component-consistency", "Components that need each other are deployed together",
       phase="static")
def component_consistency(ctx) -> Result:
    """Pairs that have to travel together, and the one that is an either/or.

    These are real dependencies rather than tidiness: a verifier without the
    credentials-config-service has nothing to tell it which credentials a service
    demands, so every login it handles produces a request object with no
    presentation definition - which a wallet reports as "could not process the
    information request", naming none of it.
    """
    problems: List[str] = []
    checked: List[str] = []

    for key, needs, why in matrix.IMPLIES:
        state = matrix.presence(ctx.deployment, ctx.values, ctx.profile, key)
        if not state.present:
            continue
        label = matrix.BY_KEY[key].label
        for needed in needs:
            other = matrix.presence(ctx.deployment, ctx.values, ctx.profile, needed)
            if other.unknown:
                continue
            checked.append("%s -> %s" % (key, needed))
            if not other.present:
                problems.append("%s is deployed but %s is not: %s"
                                % (label, matrix.BY_KEY[needed].label, why))

    # did-helper XOR identityhub. Two document servers is the ambiguous case
    # worth reporting: a counterparty resolves whichever one answers the did:web
    # URL, and which that is depends on the ingress rather than on intent.
    # Deliberately the raw services, not `presence`: the DID requirement is
    # *satisfied by* the IdentityHub, so asking `presence("did")` on a DCP
    # deployment answers "yes, via the IdentityHub" and this would then report
    # both servers deployed on every single one of them.
    did = bool(ctx.deployment.services.get("did"))
    hub = bool(ctx.deployment.services.get("identityhub"))
    if did and hub:
        problems.append(
            "both the did-helper and the IdentityHub are deployed, and both serve a "
            "DID document: a counterparty gets whichever one the ingress routes to, "
            "which is not a decision anybody made")
    elif not did and not hub:
        problems.append(
            "neither the did-helper nor the IdentityHub is deployed, so nothing "
            "serves this participant's DID document and no counterparty can "
            "resolve it")
    else:
        checked.append("did-helper xor identityhub")

    detail = {"checked": checked, "documentServer": ctx.participant.document_server}
    if problems:
        return Result.fail("%d component(s) are deployed without what they need"
                           % len(problems),
                           cause="; ".join(problems),
                           fix="deploy the missing half, or disable the one that "
                               "cannot work without it",
                           doc=DOC_CONSISTENCY, **detail)
    if not checked:
        return Result.skip("nothing to compare",
                           cause="none of the paired components could be located")
    return Result.ok("%d relationship(s) hold" % len(checked), **detail)


@check("deployment-drift", "What Helm rendered is what is running",
       needs_cluster=True, needs_release=True, phase="preflight")
def deployment_drift(ctx) -> Result:
    """Objects the release rendered that are not in the cluster, and the reverse.

    The values say what was asked for and the cluster says what is there; this is
    the seam between them, and things really do slip through it. In one deployment
    here the dashboard's ConfigMap is applied by hand, the trust-anchor volume was
    swapped with `kubectl patch` and an STS alias was tried with `kubectl set env` -
    none of which any values file knows about, and all of which survive until
    somebody upgrades and silently loses them.

    Scoped by *kind* rather than by component: Deployments, StatefulSets and
    Services are the objects that are supposed to stay put, and one `kubectl get`
    per kind covers the whole namespace however many there are. Jobs are
    deliberately excluded - Helm deletes the ones carrying `hook-succeeded`, so
    their absence proves nothing - and so is everything else, because a ConfigMap
    that Helm rendered and somebody replaced in place still exists under the same
    name and would look fine here anyway.
    """
    release = ctx.values.release
    if release is None or not release.manifest:
        return Result.skip("no rendered manifest to compare against",
                           cause="the release could not be read, or was installed by "
                                 "something that renders with `helm template` and keeps "
                                 "no record")

    # Only the kinds that stay put. Jobs are deliberately absent: Helm deletes the
    # ones carrying hook-succeeded, so their absence proves nothing at all.
    wanted_kinds = ("Deployment", "StatefulSet", "Service")
    rendered = [obj for obj in release.manifest_index()
                if obj.kind in wanted_kinds and obj.name]
    if not rendered:
        return Result.skip("the manifest declares none of %s" % ", ".join(wanted_kinds))

    live_cache, missing, compared = {}, [], []
    for obj in rendered:
        kind = obj.kind.lower()
        if kind not in live_cache:
            data = ctx.kube.get_json(kind, namespace=ctx.deployment.namespace,
                                     check=False) or {}
            live_cache[kind] = {(item.get("metadata") or {}).get("name")
                                for item in data.get("items", [])}
        compared.append("%s/%s" % (obj.kind, obj.name))
        if obj.name not in live_cache[kind]:
            missing.append("%s/%s (from %s)" % (obj.kind, obj.name, obj.source))

    detail = {"compared": len(compared), "missing": missing}
    if missing:
        return Result.fail(
            "%d rendered object(s) are not in the cluster" % len(missing),
            cause="%s. Helm produced them at the last revision, so either something "
                  "removed them outside Helm or the release was never fully applied - "
                  "and an upgrade will put them back without warning." % "; ".join(missing),
            fix="`helm get manifest` and compare, then re-apply or accept the drift "
                "deliberately by taking it out of the values",
            **detail)
    return Result.ok("%d rendered object(s) all present" % len(compared), **detail)
