"""CLI entry point.

    fdsc-verify -n <ns>                              # everything that is deployed
    fdsc-verify -n <ns> --edc-lane dcp               # one EDC lane
    fdsc-verify -n <ns> --peer peers/example.yaml    # interop against a real peer
    fdsc-verify -n <ns> --preflight-only             # read-only, no objects created
    fdsc-verify -n <ns> --static-only                # configuration only
    fdsc-verify -n <ns> --json                       # machine readable, for CI
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import List, Optional

from . import checks  # noqa: F401  - importing registers the checks
from . import http
from .context import Context
from .discovery import discover, load_peers, summarise
from .kube import Kube
from .model import PHASES, REGISTRY, TRANSPORTS
from .profile import Profile, ProfileError
from .progress import Progress
from .report import exit_code, render_json, render_text
from .runner import phases_in_order, run


def _load_document(path: str) -> dict:
    """Load YAML if PyYAML is available, otherwise JSON.

    The tool has no hard dependency on PyYAML: a JSON peer file works everywhere,
    and YAML is accepted when the library happens to be installed.
    """
    text = Path(path).read_text()
    try:
        import yaml  # type: ignore

        return yaml.safe_load(text) or {}
    except ImportError:
        try:
            return json.loads(text)
        except ValueError:
            raise SystemExit(
                "%s: install PyYAML to read YAML, or provide the file as JSON" % path)


def _render_declared(value) -> str:
    if isinstance(value, list):
        return "+".join(str(v) for v in value)
    if isinstance(value, dict):
        return ",".join("%s=%s" % (k, "on" if v else "off") for k, v in sorted(value.items()))
    return str(value)


def _phases_from_args(args) -> List[str]:
    """Work out which phases to run from the three ways of asking.

    The two older flags are kept because scripts use them: `--preflight-only`
    means "everything except the flows", which is what it has always meant, and
    it gains the new `static` phase for free - that is the point.
    """
    if args.phase:
        selected = [name.strip() for name in args.phase.split(",") if name.strip()]
    elif args.static_only:
        selected = ["static"]
    elif args.preflight_only:
        selected = ["static", "preflight"]
    else:
        selected = None
    return phases_in_order(selected)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fdsc-verify",
        description="Verify that a deployed FDSC's EDC flows actually work, and say "
                    "why when they do not.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Protocol conformance is not this tool's job - that is run-tck.sh in the "
               "fdsc-edc repo. This checks one real deployment.",
    )
    # not `required`: --list-checks is useful without a cluster or a namespace
    parser.add_argument("-n", "--namespace", help="namespace of the FDSC")
    parser.add_argument("--context", help="kube context (default: current)")
    parser.add_argument("--edc-lane", "--lane", dest="edc_lane", default="both",
                        help="EDC lane to test: a name, a comma-separated list, or "
                             "'both' for everything discovered (default). --lane is "
                             "kept as an alias so existing scripts and the runbook "
                             "keep working")
    parser.add_argument("--peer", metavar="FILE",
                        help="the counterparty to run the EDC flows against. Only "
                             "participantId is required. Without it those flows are "
                             "not applicable: there is no loopback, because one "
                             "participant cannot be both sides of a negotiation")
    parser.add_argument("--peer-name", help="pick one peer from a multi-peer file")
    parser.add_argument("--config", metavar="FILE",
                        help="override anything discovery got wrong")
    parser.add_argument("--values", metavar="FILE", action="append",
                        help="a values file to check instead of the release's own user "
                             "values; chart defaults still come from the live release "
                             "when one is reachable. Repeatable")
    parser.add_argument("--effective-values", metavar="FILE",
                        help="already-merged values, for full precision with no "
                             "cluster at all. From a live release that is $(helm get "
                             "values <rel> --all -o json); where Helm stores none - a "
                             "GitOps install - merge your file over `helm show values "
                             "<chart> --version <v>` instead")
    parser.add_argument("--release", metavar="NAME",
                        help="which Helm release to verify, when the namespace holds "
                             "more than one")

    declared = parser.add_argument_group(
        "declaring the deployment",
        "The tool points at a DSC somebody already deployed, and you know what it is "
        "meant to be. Anything declared here beats inference, and is also checked "
        "against what is really there - see the deployment-profile check. Each one is "
        "shorthand for the same key in --config.")
    declared.add_argument("--role", metavar="ROLE",
                          help="consumer, provider, or consumer+provider (comma-separated "
                               "is accepted)")
    edc_group = declared.add_mutually_exclusive_group()
    edc_group.add_argument("--edc", dest="edc", action="store_true", default=None,
                           help="this deployment has an EDC connector")
    edc_group.add_argument("--no-edc", dest="edc", action="store_false", default=None,
                           help="it has none: the lane checks report 'not applicable' "
                                "instead of 'not found'")
    declared.add_argument("--edc-protocol", metavar="P",
                          help="dcp or oid4vc (oid4vp accepted), when the lane's own "
                               "config cannot be trusted to say")
    declared.add_argument("--did", metavar="DID",
                          help="the participant's DID, e.g. did:web:example.org")
    declared.add_argument("--identity-secret", metavar="NAME",
                          help="the TLS secret holding the identity key, when it cannot "
                               "be resolved by type")
    declared.add_argument("--values-root", metavar="PATH",
                          help="where the data-space-connector values start when it is "
                               "deployed as a dependency of a wrapper chart (e.g. 'dsc'). "
                               "Detected from the release; declare it when it cannot be")
    declared.add_argument("--component", metavar="NAME=ON|OFF", action="append",
                          help="declare a component present or absent. Repeatable")
    parser.add_argument("--only", help="comma-separated check ids to run")
    parser.add_argument("--phase", default=None,
                        help="comma-separated phases to run: %s (default: all)"
                             % ", ".join(PHASES))
    parser.add_argument("--transport", choices=TRANSPORTS + ("all",), default="all",
                        help="which data path to report on: %s, or all (default). A "
                             "deployment can run both at once, and they fail "
                             "independently; asking for one leaves the other's checks "
                             "out as not applicable" % ", ".join(TRANSPORTS))
    parser.add_argument("--static-only", action="store_true",
                        help="configuration checks only; needs no cluster access beyond "
                             "reading the release")
    parser.add_argument("--preflight-only", action="store_true",
                        help="everything except the flows, and it creates nothing: no "
                             "check outside the flow phase writes. Alias of "
                             "--phase static,preflight")
    parser.add_argument("--no-write", action="store_true",
                        help="skip every check that creates objects, including the "
                             "broker probe")
    parser.add_argument("--force-flows", action="store_true",
                        help="run the flows even if preflight failed")
    parser.add_argument("--keep", action="store_true",
                        help="leave the objects the flows created, for inspection")
    parser.add_argument("--insecure", action="store_true",
                        help="do not verify TLS when calling public endpoints")
    parser.add_argument("--strict", action="store_true", help="treat WARN as failure")
    parser.add_argument("--json", action="store_true", dest="as_json")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="no progress on stderr; the report is unaffected")
    parser.add_argument("--list-checks", action="store_true", help="print the checks and exit")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    if args.list_checks:
        for spec in sorted(REGISTRY, key=lambda s: PHASES.index(s.phase)):
            scope = "per-lane" if spec.lanes else "once"
            needs = ",".join(filter(None, [
                "cluster" if spec.needs_cluster else "",
                "values" if spec.needs_values else "",
                "release" if spec.needs_release else "",
                "peer" if spec.needs_peer else "",
                "writes" if spec.mutates else "",
                "/".join(spec.roles) if spec.roles else "",
                "/".join(spec.transports),
            ])) or "http-only"
            print("%-9s %-30s %-9s %-30s %s"
                  % (spec.phase, spec.id, scope, needs, spec.title))
        return 0

    # resolved before the namespace check so a bad --phase is reported as the usage
    # error it is, rather than after half a minute of discovery
    try:
        phases = _phases_from_args(args)
    except ValueError as exc:
        raise SystemExit("%s" % exc)

    # `choices` does the validating, so a retired spelling is an argparse usage error
    # naming the replacements rather than a silent no-op. With two transports `all` says
    # everything a comma list could, so there is no list to split.
    transports = None if args.transport == "all" else [args.transport]

    if not args.namespace:
        raise SystemExit("-n/--namespace is required (or use --list-checks)")

    config = _load_document(args.config) if args.config else {}
    # Declarations are validated before anything slow happens: a bad --role is a
    # usage error, and finding that out after half a minute of discovery is rude.
    try:
        profile = Profile.from_args(args, config)
    except ProfileError as exc:
        raise SystemExit("%s" % exc)

    overrides = profile.raw
    overrides.setdefault("keep", args.keep)
    overrides.setdefault("noWrite", args.no_write)
    if args.values:
        overrides["values"] = args.values
    if args.effective_values:
        overrides["effectiveValues"] = args.effective_values

    # Before anything slow: discovery alone is half a dozen kubectl calls, and a run
    # can take minutes before the report appears. Silence here reads as a hang.
    progress = Progress(enabled=not args.quiet)
    try:
        return _run(args, profile, progress, phases, transports)
    finally:
        # the transient line must be gone before anything else is printed, on every
        # path out of here - including ^C, which an operator will use on a slow flow
        progress.close()


def _run(args, profile: Profile, progress: Progress,
         phases: Optional[List[str]] = None,
         transports: Optional[List[str]] = None) -> int:
    started = time.monotonic()
    overrides = profile.raw
    progress.note("fdsc-verify: %s / %s%s"
                  % (args.context or "current context", args.namespace,
                     "" if not args.peer else "  peer: %s" % args.peer))
    if not profile.is_empty():
        progress.note("  declared: %s" % ", ".join(
            "%s=%s" % (name, _render_declared(item["value"]))
            for name, item in sorted(profile.declared().items())))

    # Before discovery, not after: a run can take minutes, and an interpreter that
    # cannot do TLS 1.3 makes every host-facing check lie. Better to say it while
    # the operator is still watching than to bury it under the report.
    tls_warning = http.tls_capability_warning()
    if tls_warning:
        progress.note("  WARNING: %s" % tls_warning)

    kube = Kube(context=args.context, namespace=args.namespace)
    deployment = discover(kube, args.namespace, overrides, progress=progress,
                          load_document=_load_document)
    if tls_warning:
        # also in the report header, so it travels with pasted output
        deployment.notes.insert(0, tls_warning)
    primary = deployment.primary
    progress.note("  found: release %s, lanes %s"
                  % (("%s rev %d (%s)" % (primary.name, primary.revision, primary.chart))
                     if primary else (deployment.release or "unknown"),
                     ", ".join(sorted(deployment.edc_lanes)) or "none"))

    peers = []
    if args.peer:
        try:
            peers = load_peers(_load_document(args.peer))
        except ValueError as exc:
            raise SystemExit("%s: %s" % (args.peer, exc))
        if args.peer_name:
            peers = [p for p in peers if p.name == args.peer_name]
            if not peers:
                raise SystemExit("no peer named %s in %s" % (args.peer_name, args.peer))

    ctx = Context(kube, deployment, peers=peers, config=overrides, insecure=args.insecure,
                  profile=profile)

    lanes = None
    if args.edc_lane and args.edc_lane != "both":
        lanes = [name.strip() for name in args.edc_lane.split(",") if name.strip()]
        unknown = [name for name in lanes if name not in deployment.edc_lanes]
        if unknown:
            known = ", ".join(sorted(deployment.edc_lanes)) or "none"
            raise SystemExit("lane(s) %s not deployed in %s (found: %s)"
                             % (", ".join(unknown), args.namespace, known))

    only = [c.strip() for c in args.only.split(",")] if args.only else None
    if only:
        known = {spec.id for spec in REGISTRY}
        unknown = [c for c in only if c not in known]
        if unknown:
            raise SystemExit("unknown check(s): %s (see --list-checks)" % ", ".join(unknown))

    rows = run(ctx, lanes=lanes, only=only, phases=phases,
               allow_writes=not args.no_write, force_flows=args.force_flows,
               transports=transports, progress=progress)
    progress.close()
    progress.note("  %d checks in %ds" % (len(rows), time.monotonic() - started))

    discovery = summarise(deployment, profile=profile, participant=ctx.participant)
    if args.as_json:
        print(render_json(rows, discovery))
    else:
        print(render_text(rows, discovery, verbose=args.verbose))
    return exit_code(rows, strict=args.strict)


if __name__ == "__main__":
    sys.exit(main())
