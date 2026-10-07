"""Work out what is deployed, without being told.

The whole point of the tool is `fdsc-verify -n <ns>` and nothing else, so this
module has to be right. Two findings shape it, both verified across three
independent deployments (`provider-edc-2`, `provider-edc` and `consumer-edc`):

1. Each EDC instance has a ConfigMap `<release>-fdsc-edc-<lane>` carrying
   `dataspaceconnector-configuration.properties` with ~86 keys: participant id,
   hostname, every web.http port and path, the STS alias, the holder kid, the
   TIL address, the TMForum API URLs. Almost the entire preflight surface comes
   from there, with no HTTP call and no pod exec.

2. The shared components have *fixed* service names in all three deployments
   (`identityhub-service`, `verifier`, `trusted-issuers-list`,
   `data-service-scorpio`, `tm-forum-api-svc`), while the per-release ones are
   `<release>-<component>`.

The one thing that is NOT stable is the identity certificate secret name
(`connector-example-es-tls` in one deployment, `did-provider.example.org-tls` in
another), so it is resolved by looking at which secret is mounted on the path the
config itself declares - never by name.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

from . import values as values_mod
from .kube import Kube, KubeError, KubeUnavailable, parse_properties
from .model import Deployment, EdcLane, Peer
from .progress import null

EDC_CONFIG_KEY = "dataspaceconnector-configuration.properties"

# ConfigMaps that match *-fdsc-edc-* but are not a lane's main config
_NOT_A_LANE = ("-additional-contexts", "-scope-mappings", "-logging")

# component -> the fixed service name the charts use. Every one of these carries a
# `fullnameOverride` in the deployments inspected, which is why the name is stable.
FIXED_SERVICES = {
    "identityhub": "identityhub-service",
    "verifier": "verifier",
    "til": "trusted-issuers-list",
    "broker": "data-service-scorpio",
    "tmforum": "tm-forum-api-svc",
    "odrlpap": "odrl-pap",
    "contractmanagement": "contract-management",
}

# component -> service name tails, for the ones that carry the release name in
# front (`provider-keycloak`, `edc-dashboard-data-dashboard`). Matched as an exact
# name or as a `-<tail>` suffix, first match in sorted order winning. A deployment
# that names one of these differently can still declare it under `services` in
# --config; nothing here is load-bearing enough to guess at.
SUFFIX_SERVICES = {
    "apisix": ("apisix-gateway",),
    "vault": ("vault",),
    "dashboard": ("data-dashboard", "fdsc-dashboard"),
    "keycloak": ("keycloak",),
    "did": ("did", "did-helper"),
    "ccs": ("credentials-config-service",),
    # The BAE ships several services and needs more than one of them to work. The
    # logic proxy is the front door - it is what authenticates a user and what the
    # login client id belongs to - and the charging backend is what turns an order
    # into something billable. A marketplace missing either is not a marketplace,
    # so they are separate keys and `IMPLIES` ties them together.
    "marketplace": ("biz-ecosystem-logic-proxy", "business-api-ecosystem"),
    "marketplacecharging": ("biz-ecosystem-charging-backend",),
}

_LANE_RE = re.compile(r"^(?P<release>.+)-fdsc-edc-(?P<lane>[a-z0-9]+)$")


def discover(kube: Kube, namespace: str, overrides: Optional[dict] = None,
             progress=None, load_document=None) -> Deployment:
    """Build a Deployment from the cluster, then let `overrides` have the last word.

    Order matters twice over. Releases are read before the lanes because a
    deployment may have no lanes at all and still be perfectly real - a consumer
    with fdsc-edc off, or the trust anchor. Values are resolved *after* the lanes,
    because when a namespace holds several DSC releases (one measured holds four)
    the release that owns the lanes is the tie-breaker for which one this run is
    about.
    """
    dep = Deployment(context=kube.context, namespace=namespace, release=None)
    progress = progress or null()

    progress.start("discovering %s" % namespace, "contacting the cluster")
    try:
        reachable = kube.available()
    except KubeUnavailable as exc:
        dep.notes.append("cluster unreachable (%s): only HTTP-only checks will run" % exc)
        reachable = False
    else:
        if not reachable:
            dep.notes.append("cluster unreachable: only HTTP-only checks will run")

    if not reachable:
        progress.finish()
        dep = _apply_overrides(dep, overrides)
        dep.values = values_mod.resolve(None, namespace, {}, None, overrides, load_document)
        # The values notes matter most on exactly this path: with no cluster, a
        # --values file is all there is, and "the DSC lives under `dsc`" is the
        # difference between a real report and one that calls everything absent.
        dep.notes.extend(dep.values.notes)
        return dep

    progress.detail("listing helm releases")
    dep.releases, release_notes = values_mod.discover_releases(kube, namespace, progress)
    dep.notes.extend(release_notes)

    progress.detail("reading the lane configmaps")
    _discover_lanes(kube, namespace, dep, progress)
    progress.detail("listing services")
    _discover_services(kube, namespace, dep)
    progress.finish()

    dep = _apply_overrides(dep, overrides)
    dep.primary_release, primary_notes = values_mod.choose_primary(
        dep.releases, preferred=(overrides or {}).get("release"), lane_release=dep.release)
    dep.notes.extend(primary_notes)
    dep.values = values_mod.resolve(kube, namespace, dep.releases, dep.primary_release,
                                    overrides, load_document)
    dep.notes.extend(dep.values.notes)

    # After the values on purpose: without a lane the only pointer to the identity
    # secret is the did-helper's own host, which lives in them.
    progress.start("resolving the identity secret")
    _discover_identity_secret(kube, namespace, dep)
    progress.finish()
    dep = _apply_overrides(dep, overrides)
    if not dep.releases and not dep.edc_lanes:
        dep.notes.append(
            "no data-space-connector or trust-anchor release and no fdsc-edc lane in %s; "
            "checks will skip with a reason rather than report a healthy deployment"
            % namespace)
    return dep


def _discover_lanes(kube: Kube, namespace: str, dep: Deployment, progress=None) -> None:
    """Find the lanes rather than assuming dcp/oid4vc.

    A deployment may run one lane, both, or something named differently; the
    ConfigMap list is the ground truth. This is also what lets `--lane both`
    mean "everything that is actually deployed".
    """
    names = kube.list_names("configmap", namespace=namespace)
    for name in sorted(names):
        if "-fdsc-edc-" not in name or any(name.endswith(s) for s in _NOT_A_LANE):
            continue
        match = _LANE_RE.match(name)
        if not match:
            continue
        release, lane_name = match.group("release"), match.group("lane")
        if progress:
            progress.detail("reading configmap %s" % name)
        data = kube.configmap(name, namespace=namespace)
        props = parse_properties(data.get(EDC_CONFIG_KEY, ""))
        if not props:
            dep.notes.append("configmap %s has no %s, skipped" % (name, EDC_CONFIG_KEY))
            continue
        dep.edc_lanes[lane_name] = EdcLane(
            name=lane_name,
            release=release,
            deployment=name,     # the chart names deployment, service and cm alike
            service=name,
            configmap=name,
            props=props,
        )
        dep.release = dep.release or release


def _discover_services(kube: Kube, namespace: str, dep: Deployment) -> None:
    present = set(kube.list_names("service", namespace=namespace))
    for component, service in FIXED_SERVICES.items():
        if service in present:
            dep.services[component] = service
    # The release-prefixed ones. The loop is over COMPONENTS, and within each one the
    # tails are tried in the order they are declared - that order is the preference.
    #
    # It used to loop over the service names instead, sorted, and let the first
    # component that matched claim each one. That made alphabetical order of the
    # *names* decide, which is not a preference at all: `marketplace` resolved to
    # `*-biz-ecosystem-charging-backend` on both demo deployments, because it sorts
    # before `*-biz-ecosystem-logic-proxy` - while the comment beside the table said,
    # correctly, that the logic proxy is the front door. Anything port-forwarding to
    # `service("marketplace")` was talking to the wrong component.
    #
    # `taken` keeps the old invariant that one service name serves one component, so
    # a short tail cannot quietly claim a name another component already owns.
    taken = set(dep.services.values())
    names = sorted(present)
    for component, tails in sorted(SUFFIX_SERVICES.items()):
        if component in dep.services:
            continue
        for tail in tails:
            match = next((name for name in names
                          if name not in taken
                          and (name == tail or name.endswith("-" + tail))), None)
            if match:
                dep.services[component] = match
                taken.add(match)
                break
    # Deliberately no "components not found" note here any more. It was written
    # for a participant namespace, and in a trust-anchor one it listed every
    # participant component as missing - all correctly absent. Which components
    # ought to be present is a question about the role, so the component
    # inventory answers it with the matrix; discovery just records what it saw.


def _discover_identity_secret(kube: Kube, namespace: str, dep: Deployment) -> None:
    """Resolve the identity certificate secret, never by name.

    The secret name is the one thing that is not stable between deployments
    (`connector-example-es-tls` here, `did-provider.example.org-tls` there), so it
    is found by *type*: among the secret-backed volumes of the EDC pod, the one
    of type `kubernetes.io/tls`. Verified to hold in both deployments.

    Note that `oid4vp.holder.key.path` cannot be used to locate it: the charts
    convert the key in an initContainer and expose the result on an emptyDir, so
    that path points at the converted copy, not at the secret. The raw secret is
    only referenced by the initContainer's own mount.

    The type is the *first* discriminator, not the only one. A deployment that
    keeps the identity key in a SealedSecret often ends up with `type: Opaque`,
    because the type lives in the SealedSecret's `spec.template` and is easy to
    leave at the default - so a second pass accepts an Opaque secret that carries
    both `tls.crt` and `tls.key`. That pair is what makes it an identity key
    regardless of the label Kubernetes has on it.
    """
    fallback: Optional[Tuple[str, Optional[EdcLane]]] = None
    for workload, lane in _identity_workloads(dep):
        data = kube.get_json("deployment", workload, namespace=namespace, check=False)
        if not data:
            continue
        spec = data.get("spec", {}).get("template", {}).get("spec", {})
        candidates = []
        for volume in spec.get("volumes", []) or []:
            secret = (volume.get("secret") or {}).get("secretName")
            if secret:
                candidates.append(secret)
        for secret in candidates:
            meta = kube.get_json("secret", secret, namespace=namespace, check=False)
            if not meta:
                continue
            if meta.get("type") == "kubernetes.io/tls":
                _adopt_identity_secret(dep, lane, secret)
                return
            if fallback is None and _looks_like_tls_keypair(meta):
                fallback = (secret, lane)

    if fallback is not None:
        secret, lane = fallback
        _adopt_identity_secret(dep, lane, secret)
        dep.notes.append(
            "identity key secret %s resolved by content (it carries tls.crt and "
            "tls.key) because no mounted secret is typed kubernetes.io/tls; "
            "consider setting that type so it is unambiguous" % secret)
        return

    # Last resort, and only on a name cert-manager itself chose: the ingress that
    # publishes the DID document asks for `<host>-tls`, so the host the document
    # is served from names the secret holding the key that signs for it.
    guessed = _identity_secret_by_convention(kube, namespace, dep)
    if guessed:
        _adopt_identity_secret(dep, None, guessed)
        dep.notes.append(
            "identity key secret %s resolved by the cert-manager naming convention "
            "(<did host>-tls); nothing mounts it where this tool could see it" % guessed)
        return

    if not dep.identity_secret:
        dep.notes.append(
            "identity key secret not resolvable; set identity.secret in --config (or "
            "--identity-secret) to enable the key-consistency checks")


def _identity_workloads(dep: Deployment) -> List[Tuple[str, Optional[EdcLane]]]:
    """Workloads that mount the identity key, most authoritative first.

    The EDC controlplane when there is one - that is where this started - and then
    whatever serves the DID document, because a deployment without a connector
    still signs with a key and still publishes it. The did-helper mounts the very
    certificate it derives the document from, which makes it the right place to
    look and the reason this is not lane-only any more.
    """
    out: List[Tuple[str, Optional[EdcLane]]] = [
        (lane.deployment, lane)
        for lane in sorted(dep.edc_lanes.values(), key=lambda l: l.name)
        if lane.deployment]
    for component in ("did", "identityhub"):
        service = dep.service(component)
        if service:
            # the charts name Deployment and Service alike
            out.append((service, None))
    return out


def _identity_secret_by_convention(kube: Kube, namespace: str,
                                   dep: Deployment) -> Optional[str]:
    """`<did host>-tls`, confirmed to exist and to be a TLS secret before adopting.

    Never a bare guess: the name is derived from the host this deployment says it
    serves its DID document from, and the secret has to be there and carry both
    halves. A miss returns None and the caller says so.
    """
    values = dep.values
    host = None
    if values is not None and values.trust != "none":
        url = values.get("did.config.server.hostUrl")
        if url and not values_mod.has_placeholder(url):
            host = str(url).split("://")[-1].split("/")[0].split(":")[0]
    if not host:
        return None
    name = "%s-tls" % host
    meta = kube.get_json("secret", name, namespace=namespace, check=False)
    if not meta:
        return None
    if meta.get("type") == "kubernetes.io/tls" or _looks_like_tls_keypair(meta):
        return name
    return None


def _looks_like_tls_keypair(meta: dict) -> bool:
    """Both halves present. One alone is a CA bundle or a bare key, not identity."""
    data = meta.get("data") or {}
    return "tls.crt" in data and "tls.key" in data


def _adopt_identity_secret(dep: Deployment, lane: Optional[EdcLane], secret: str) -> None:
    dep.identity_secret = secret
    # The lane knows where the converted key lands; without one, a cert-manager
    # secret carries the standard pair and `tls.key` is the right half.
    key_path = (lane.prop("oid4vp.holder.key.path") if lane else None) or "/signing-key/tls.key"
    dep.identity_secret_key = key_path.rsplit("/", 1)[1]


def _apply_overrides(dep: Deployment, overrides: Optional[dict]) -> Deployment:
    """Discovery fills in, the config file wins.

    Kept deliberately shallow: only the fields a non-standard deployment would
    actually need to correct. Anything deeper belongs in the cluster, not here.
    """
    if not overrides:
        return dep
    dep.release = overrides.get("release", dep.release)
    identity = overrides.get("identity") or {}
    dep.identity_secret = identity.get("secret", dep.identity_secret)
    dep.identity_secret_key = identity.get("key", dep.identity_secret_key)
    for name, service in (overrides.get("services") or {}).items():
        dep.services[name] = service
    for lane_name, lane_over in (overrides.get("lanes") or {}).items():
        lane = dep.edc_lanes.get(lane_name)
        if lane is None:
            lane = EdcLane(name=lane_name, release=dep.release or "", deployment="", service="",
                        configmap="", props={})
            dep.edc_lanes[lane_name] = lane
        lane.props.update(lane_over.get("props") or {})
        for attr in ("deployment", "service", "configmap"):
            if attr in lane_over:
                setattr(lane, attr, lane_over[attr])
        dep.notes.append("lane %s: %d value(s) overridden from --config"
                         % (lane_name, len(lane_over.get("props") or {})))
    return dep


def load_peers(raw: dict) -> List[Peer]:
    """Parse a --peer YAML/JSON document into Peer objects.

    Accepts either a single peer mapping or {peers: [...]} so a file can describe
    a whole dataspace and the operator picks with --peer-name.
    """
    entries = raw.get("peers") if isinstance(raw, dict) and "peers" in raw else [raw]
    peers = []
    for entry in entries:
        if not entry.get("participantId"):
            raise ValueError("peer entry is missing participantId")
        protocol_url = entry.get("protocolUrl")
        peers.append(Peer(
            name=entry.get("name") or entry["participantId"],
            participant_id=entry["participantId"],
            protocol_url=protocol_url.rstrip("/") if protocol_url else None,
            context=entry.get("context"),
            namespace=entry.get("namespace"),
            lane=entry.get("lane"),
        ))
    return peers


def summarise(dep: Deployment, profile=None, participant=None) -> Dict[str, object]:
    """Compact, machine-readable view of what discovery found.

    Printed by --json and by -v, and it is the fastest way to spot that the tool
    latched onto the wrong thing.

    The role and the participant are passed in rather than recomputed: the run
    already resolved both, and the report has to show the *same* answer the
    checks used - a header that disagrees with the rows below it is worse than no
    header.
    """
    primary = dep.primary
    roles: Tuple[str, ...] = ()
    role_source = ""
    if profile is not None:
        from . import components as components_mod

        roles, role_source = components_mod.roles_for(dep, profile)
    return {
        "context": dep.context,
        "namespace": dep.namespace,
        "release": dep.release,
        "family": dep.family,
        "roles": list(roles),
        "roleSource": role_source,
        "participant": participant.to_json() if participant is not None else None,
        "declared": profile.declared() if profile is not None else {},
        "primaryRelease": primary.to_json() if primary else None,
        "otherReleases": sorted(name for name in dep.releases
                                if name != dep.primary_release),
        "values": dep.values.to_json() if dep.values else None,
        "identitySecret": dep.identity_secret,
        "services": dep.services,
        "lanes": {
            name: {
                "participantId": lane.participant_id,
                "hostname": lane.hostname,
                "protocolUrl": lane.protocol_url,
                "managementUrl": lane.management_url,
                "holderKid": lane.prop("oid4vp.holder.kid"),
                "stsAlias": lane.prop("edc.iam.sts.oauth.client.secret.alias"),
                "tilAddress": lane.prop("ebsiTir.tilAddress"),
                "trustAnchorsFolder": lane.prop("oid4vp.trustAnchorsFolder"),
                "props": len(lane.props),
            }
            for name, lane in sorted(dep.edc_lanes.items())
        },
        "notes": dep.notes,
    }
