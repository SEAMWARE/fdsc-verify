"""Checks that read the deployment as it was *declared*, not as it is behaving.

These come first in the report on purpose. When a deployment is misconfigured,
the runtime symptoms are downstream and generic - a 401, a negotiation stuck in
REQUESTED, an empty catalog - while the declaration says plainly what is wrong and
where to fix it. Answering "is this built right" before "is it working" is what
turns half an afternoon of bisection into one line of output.

Everything here reads `ctx.values`, which is Helm's own record of the release. Two
consequences worth stating: a check may never conclude anything from
`ctx.values.tri(...)` coming back unknown - it SKIPs with the reason - and no
check here needs a cluster beyond the one read discovery already did.
"""

from __future__ import annotations

from typing import Dict, List, Tuple

from ..model import Result, check

DOC_VALUES_SOURCE = "reading-the-values-of-a-release"
DOC_RELEASE_STATUS = "a-release-that-is-not-deployed"
DOC_HOOKS = "a-post-install-only-registration-job-stops-registering-on-upgrade"
DOC_UNKNOWN_KEYS = "values-keys-that-no-chart-key-consumes"

HOOK_KEY = "helm.sh/hook"
DELETE_POLICY_KEY = "helm.sh/hook-delete-policy"

# Adding post-upgrade is only half the repair, and the other half bites on the
# first failure rather than at once. The vcverifier chart's default policy is
# `hook-succeeded`, which leaves a *failed* Job in place; the next upgrade then
# tries to create a hook Job of the same name and dies with `jobs.batch
# "<name>-job" already exists`, which reads like a Helm problem rather than
# like a job that failed weeks ago. `before-hook-creation` deletes the previous
# one first and is what the DSC already uses elsewhere - identityhub-bootstrap
# runs `post-install,post-upgrade` with it in the same releases.
DELETE_POLICY_FIX = "%s=before-hook-creation" % DELETE_POLICY_KEY


@check("values-source", "The Helm values of this release can be read",
       phase="static")
def values_source(ctx) -> Result:
    """Make the confidence model visible instead of letting it act silently.

    Every other static check degrades to SKIP when the values are thin, and a
    screenful of SKIPs with no explanation reads like the tool is broken. This
    one line says which source was used and what it can support.
    """
    values = ctx.values
    if values.trust == "effective":
        return Result.ok("%s, %d keys" % (values.source, values.count()),
                         trust=values.trust, keys=values.count())
    if values.trust == "user":
        return Result.warn(
            "user-supplied values only, %d keys" % values.count(),
            cause="%s. A key nobody set has no answer here, and the role matrix "
                  "disagrees with the chart defaults often enough - "
                  "credentials-config-service is Required for a provider and "
                  "defaults to false - that guessing would be worse than skipping."
                  % values.source,
            fix="no release could be read in this namespace, so `helm get values` "
                "has nothing to ask either: a GitOps install renders with `helm "
                "template` and stores none, which is the case this message is "
                "almost always about. Take the defaults from the chart instead - "
                "`helm show values <chart> --version <v>` - deep-merge this file "
                "over them and pass the result as --effective-values; the doc has "
                "the snippet, including the wrapper-chart case where the DSC is a "
                "dependency. If a release does exist and only this tool failed to "
                "decode it, --effective-values $(helm get values <rel> -n <ns> "
                "--all -o json) is the shorter route",
            doc=DOC_VALUES_SOURCE, trust=values.trust)
    return Result.skip("no values could be read", cause=values.source)


@check("release-status", "The release is in a settled state",
       phase="static", needs_values=True, needs_release=True)
def release_status(ctx) -> Result:
    """A release that is not `deployed` explains a whole class of confusion.

    `pending-upgrade` and `failed` mean the cluster is running something other
    than what the values say, which makes every other static check a statement
    about an intention rather than about reality.
    """
    release = ctx.values.release
    if release is None:
        return Result.skip("no primary release")
    if release.status == "deployed":
        return Result.ok("%s rev %d, deployed" % (release.name, release.revision),
                         chart=release.chart, revision=release.revision)
    return Result.warn(
        "%s rev %d is %s" % (release.name, release.revision, release.status),
        cause='helm reports status "%s". The manifests in the cluster are not '
              "necessarily the ones these values describe, so every other static "
              "check below is a statement about what was asked for, not about what "
              "is running." % release.status,
        fix="helm history %s -n %s, then either complete or roll back the release"
            % (release.name, ctx.deployment.namespace),
        doc=DOC_RELEASE_STATUS, status=release.status)


def _hook_annotations(tree, path: Tuple[str, ...] = ()
                      ) -> List[Tuple[Tuple[str, ...], List[str]]]:
    """Every `annotations` block in the values that declares a Helm hook.

    Walks the values rather than matching job names. Names are per-release and
    per-chart-version (`verifier-job` here, `provider-til-registration-job`
    there), while the annotation block is where the hook is actually declared and
    therefore where the fix goes.
    """
    out: List[Tuple[Tuple[str, ...], List[str]]] = []
    if not isinstance(tree, dict):
        return out
    for key, value in tree.items():
        here = path + (str(key),)
        if key == "annotations" and isinstance(value, dict) and HOOK_KEY in value:
            events = [event.strip()
                      for event in str(value.get(HOOK_KEY) or "").split(",")
                      if event.strip()]
            out.append((here, events))
        out.extend(_hook_annotations(value, here))
    return out


def _job_is_enabled(values, path: Tuple[str, ...]) -> bool:
    """Does the job this annotation block belongs to actually render?

    An inert block is not a finding, and this is not hypothetical: demo's producer
    carries `tm-forum-api.registration.annotations` with a `post-install`-only
    hook while `tm-forum-api.registration.enabled` is false, so nothing renders
    from it and reporting it would be a false positive - exactly the kind this
    tool cannot afford.

    The `enabled` flag is not always the annotations block's immediate sibling
    (`...vcverifier.registration.job.annotations` is governed by
    `...vcverifier.registration.enabled`), so the whole ancestry is walked. **Every**
    `enabled` on the way up has to be true, not just the nearest one - stopping at
    the nearest is what this used to do, and provider-central is the deployment that
    exposed it: `tm-forum-api.enabled` is false while the chart's own default leaves
    `tm-forum-api.registration.enabled` true, so the walk stopped one level short and
    reported a job that Helm never renders. Helm disables a subchart wholesale; no
    flag inside it can switch it back on.

    No ancestor declaring `enabled` means "cannot tell", which is treated as enabled:
    the block exists, so something meant to render it.
    """
    for depth in range(len(path) - 1, 0, -1):
        ancestor = list(path[:depth])
        found, value = values._dig(values.effective, ancestor + ["enabled"])
        if found and value is False:
            return False
    return True


@check("registration-job-hooks", "Registration jobs re-run when the release is upgraded",
       phase="static", needs_values=True, needs_release=True)
def registration_job_hooks(ctx) -> Result:
    """A `post-install`-only hook stops taking effect the moment you upgrade.

    This is one rule rather than a list of known-broken jobs, and it earns that
    generality: the same defect has shipped under several names across chart
    versions, and the release itself carries both halves of the evidence - what
    the hook declared, and how many times the release has been upgraded since.
    """
    release = ctx.values.release
    if release is None:
        return Result.skip("no primary release")

    declared = _hook_annotations(ctx.values.effective)
    if not declared:
        return Result.skip("this release declares no hook annotations in its values")

    post_install_only = [(path, events) for path, events in declared
                         if "post-install" in events and "post-upgrade" not in events]
    stale = [(".".join(path), events) for path, events in post_install_only
             if _job_is_enabled(ctx.values, path)]
    inert = [".".join(path) for path, _ in post_install_only
             if not _job_is_enabled(ctx.values, path)]
    revision = release.revision

    if not stale:
        return Result.ok("all %d enabled hook(s) re-run on upgrade" % len(declared),
                         hooks={".".join(path): events for path, events in declared},
                         inert=inert)

    listed = "; ".join("%s = %s" % (path, ",".join(events)) for path, events in stale)
    # corroborate from the rendered hooks, which name the actual Jobs
    rendered = [name for name, events in release.hook_events()
                if "post-install" in events and "post-upgrade" not in events]
    detail = {"paths": [path for path, _ in stale], "renderedHooks": rendered,
              "revision": revision,
              # kept visible rather than dropped: an inert block today becomes a
              # live one the moment somebody enables that job
              "inertPostInstallOnly": inert}

    if revision <= 1:
        return Result.warn(
            "%d hook(s) are post-install only" % len(stale),
            cause="%s. The release is still at revision 1, so nothing has been "
                  "missed yet - but the first `helm upgrade` will skip %s and "
                  "whatever they registered will silently go stale."
                  % (listed, " and ".join(rendered) or "them"),
            fix='add post-upgrade AND make the hook replaceable: --set '
                '"%s.%s=post-install\\,post-upgrade" --set "%s.%s=before-hook-creation". '
                'Without the second, the default hook-delete-policy (hook-succeeded) '
                'leaves a failed Job behind and the next upgrade fails with "already exists"'
                % (stale[0][0], HOOK_KEY.replace(".", "\\."),
                   stale[0][0], DELETE_POLICY_KEY.replace(".", "\\.")),
            doc=DOC_HOOKS, **detail)

    subject = " and ".join(rendered) if rendered else "the job"
    plural = len(rendered) > 1
    # WARN rather than FAIL, deliberately. The declaration proves the hook *cannot*
    # have re-run; it does not prove anything is missing as a result - that depends
    # on whether the registration changed since install. `registration-services-present`
    # answers that against the live config repo. Asserting the consequence from here
    # has already sent an operator hunting for a service that was registered fine.
    return Result.warn(
        "%d registration hook(s) cannot have re-run since the first install" % len(stale),
        cause="%s. This release is at revision %d, so %s ran once at install and "
              "%s been skipped by all %d upgrades since. Anything added to the "
              "registration after install was therefore never applied: a service "
              "missing from the verifier's config repo comes back as a request "
              "object with no presentation_definition, which a wallet reports as "
              "\"Could not process the information request\". Whether that has "
              "actually happened here is what registration-services-present answers."
              % (listed, revision, subject, "have" if plural else "has",
                 revision - 1),
        fix="set both annotations on the hook - %s=post-install,post-upgrade and "
            "%s=before-hook-creation - then helm upgrade %s -n %s --reuse-values to "
            "re-run it. The delete policy is not optional: the chart default "
            "(hook-succeeded) keeps a failed Job, and the next upgrade then dies with "
            "'jobs.batch \"%s\" already exists'. identityhub-bootstrap in this same "
            "release is already configured that way. To repair without an upgrade, "
            "delete the Job and recreate it from the -registration ConfigMap by hand"
            % (HOOK_KEY, DELETE_POLICY_KEY, release.name, ctx.deployment.namespace,
               rendered[0] if rendered else "<name>-job"),
        doc=DOC_HOOKS, **detail)


@check("values-unknown-keys", "Every supplied value is consumed by the chart",
       phase="static", needs_values=True, needs_release=True)
def values_unknown_keys(ctx) -> Result:
    """A top-level key the chart never reads is silently ignored by Helm.

    Top level only, and that is a measured limit rather than laziness. The stored
    release carries the umbrella's own `values.yaml` but not its subcharts', so a
    recursive comparison reports every subchart key the umbrella does not itself
    override: 51 hits on a real deployment, of which none were real. At the top
    level the same deployment yields four, three of them genuine leftovers from
    an older chart.
    """
    values = ctx.values
    release = values.release
    if release is None:
        return Result.skip("no primary release")
    if not values.defaults:
        return Result.skip("the release carries no chart defaults to compare against")

    known = set(values.defaults)
    for dep in release.dependencies:
        known.add(dep.key)
        known.add(dep.name)
        if dep.condition:
            known.add(dep.condition.split(".")[0])

    orphans = sorted(key for key in values.user
                     # `x-` prefixed keys are the conventional home for YAML
                     # anchors, which exist to be referenced, not consumed
                     if key not in known and not str(key).startswith("x-"))
    if not orphans:
        return Result.ok("all %d top-level key(s) are consumed" % len(values.user))

    if len(orphans) == 1:
        subject = "no `%s` key" % orphans[0]
        where, pronoun = "that key", "it"
    else:
        subject = "none of them"
        where, pronoun = "those keys", "them"
    return Result.warn(
        "%d top-level value(s) the chart does not read: %s"
        % (len(orphans), ", ".join(orphans)),
        cause="the chart %s declares %s, and no dependency is configured under %s "
              "either, so Helm silently ignored %s. A key left over from an older "
              "chart version looks exactly like a setting that is in effect."
              % (release.chart, subject, where, pronoun),
        fix="remove them from the values file, or check them against the chart's "
            "README for the key they were renamed to",
        doc=DOC_UNKNOWN_KEYS, keys=orphans)
