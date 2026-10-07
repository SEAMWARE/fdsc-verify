"""Who this deployment is, resolved from every place that claims to know.

The identity used to hang off the EDC lane: `edc.participant.id` in the lane's
ConfigMap was the only source of the participant's DID in the whole tool, so a
deployment without fdsc-edc had no identity at all and every identity check
skipped. But the DID is not an EDC fact - a Consumer with nothing but Keycloak
and a did-helper still has one, and the canonical role matrix makes FDSC-EDC
optional for all three participant roles.

So the DID is resolved from whatever is there, in order of how directly each
source states it, and **every source that answered is kept**. There are three
tiers - the EDC lanes, the values, and the cluster - and the third exists because
a GitOps install has only that one: Argo renders with `helm template` and leaves
no release Secret, so the values are unreadable and the first two answer nothing.
The cluster is consulted last for *picking* and always for *recording*, so it can
fill a gap without moving a deployment that already had an answer. That second part is
the point: the DID is written down in six independent places in a DSC's values,
nobody re-reads them all after a rename, and a disagreement between them is a
real failure with a generic symptom. `identity-did-consistency` is the check that
reads this.

Two traps, both met in real values files:

- **`keycloak.issuerDid` is usually the literal `${DID}`**, substituted from an
  environment variable at runtime, and `registration.issuer[].did` with it. A
  comparison that does not ask `values.has_placeholder()` first reports a
  mismatch that is not there.
- **`did.config.server.hostUrl` is a URL, not a DID**, and the path segments
  matter: `https://did.example.org` is `did:web:did.example.org` while
  `https://did.example.org/did` is `did:web:did.example.org:did`. Both forms are
  in use in this dataspace. This is the exact inverse of `did_to_url`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .values import has_placeholder

# Where a DSC writes its own DID, most directly stated first. The verifier and
# contract-management carry a resolved DID; the did-helper carries the URL it is
# derived from. `keycloak.issuerDid` is kept for a chart that uses it, but a
# recursive sweep of the full values of every deployment reachable from here
# found no key of that shape at all: what Keycloak really carries is a literal
# `DID` environment variable on its pod, which is the cluster source below.
_DID_PATHS = (
    ("decentralizedIam.vcAuthentication.vcverifier.deployment.verifier.did", "verifier"),
    ("decentralizedIam.vcAuthentication.vcverifier.verifier.did", "verifier"),
    ("contract-management.did", "contract-management"),
    ("keycloak.issuerDid", "keycloak"),
)
_DID_HOST_PATH = "did.config.server.hostUrl"
_TIL_PATHS = (
    "decentralizedIam.vcAuthentication.vcverifier.deployment.verifier.tirAddress",
    "decentralizedIam.vcAuthentication.vcverifier.verifier.tirAddress",
)

# The cluster states the DID too, and unlike the values it states what the pods
# are running with. Both sources below were verified present and correct on all
# five deployments reachable from here - two clusters, charts 9.0.5 and 10.4.12,
# and both did:web shapes (with and without a path suffix).
_VERIFIER_CONFIGMAP = "verifier"
_VERIFIER_CONFIG_KEY = "server.yaml"
_DID_HELPER_HOST_ENV = "HOST_URL"
# Keycloak's pod carries the participant's DID outright, and it is the only place
# it appears: `keycloak.issuerDid` is in no deployment's values.
_KEYCLOAK_DID_ENV = "DID"


def verifier_server_yaml(kube, namespace: str) -> dict:
    """The verifier's own server.yaml, parsed, exactly as the pod mounts it.

    It carries four things the tool otherwise has to get from the values, and a
    GitOps install has no values: `verifier.did`, `verifier.tirAddress`,
    `verifier.clientIdentification` and `server.host`. One read, one parse, and
    `Context.verifier_config` caches it for the checks that want the other two.

    PyYAML is optional in this tool, so its absence costs this source and nothing
    else: every caller falls back to the values, which is what happened before this
    source existed. Never a false pass.
    """
    body = (kube.configmap(_VERIFIER_CONFIGMAP, namespace=namespace)
            or {}).get(_VERIFIER_CONFIG_KEY)
    if not body:
        return {}
    try:
        import yaml  # type: ignore
        parsed = yaml.safe_load(body)
    except Exception:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _verifier_config(kube, namespace: str) -> dict:
    """Just the `verifier` block, which is what identity resolution needs."""
    block = verifier_server_yaml(kube, namespace).get("verifier")
    return block if isinstance(block, dict) else {}


def workload_pod_spec(kube, namespace: str, service: str) -> dict:
    """The pod spec of the workload behind a Service, found by its **selector**.

    By selector rather than by name because the two do not always agree and one
    namespace here runs two did-helpers: only the one discovery identified as this
    deployment's may be read. Returns `{}` rather than raising, because every
    caller treats an unreadable workload as "this source did not answer".

    Shared by the identity sources, which want an environment variable, and by
    `keycloak-signing-key`, which wants the init containers and the volumes.
    """
    svc = kube.get_json("service", service, namespace=namespace, check=False) or {}
    selector = (svc.get("spec") or {}).get("selector") or {}
    if not selector:
        return {}
    expr = ",".join("%s=%s" % kv for kv in sorted(selector.items()))
    pods = kube.get_json("pod", namespace=namespace, check=False,
                         selector=expr) or {}
    for pod in (pods.get("items") or [])[:1]:
        return (pod.get("spec") or {}) if isinstance(pod.get("spec"), dict) else {}
    return {}


def _workload_env_value(kube, namespace: str, service: str,
                        name: str) -> Optional[str]:
    """One environment variable of the workload behind a Service, reference or not.

    `HOST_URL` on the did-helper is a `configMapKeyRef` in every deployment
    inspected, never a literal, so `Context.workload_env` cannot see it - that
    helper leaves `valueFrom` alone on purpose, because it exists to read things
    like client ids and must not splice a secret's contents into a report. A
    ConfigMap key is not a secret, so this one follows that reference; a
    `secretKeyRef` is still left alone.

    The workload is found through the Service's selector rather than by name: one
    namespace here runs two did-helpers and only the one discovery identified as
    this deployment's may be read.
    """
    spec = workload_pod_spec(kube, namespace, service)
    for container in (spec.get("containers") or []):
        for entry in container.get("env") or []:
            if entry.get("name") != name:
                continue
            if entry.get("value"):
                return str(entry["value"])
            ref = (entry.get("valueFrom") or {}).get("configMapKeyRef") or {}
            if ref.get("name") and ref.get("key"):
                return (kube.configmap(ref["name"], namespace=namespace)
                        or {}).get(ref["key"])
    return None


def did_from_host_url(url: Optional[str]) -> Optional[str]:
    """`https://host/a/b` -> `did:web:host:a:b`. The inverse of `did_to_url`.

    The did-helper is configured with the URL its document is served from, so
    this is how a deployment with no EDC states its identity.
    """
    if not url or not isinstance(url, str):
        return None
    without_scheme = url.split("://", 1)[-1].strip("/")
    if not without_scheme:
        return None
    parts = [part for part in without_scheme.split("/") if part]
    return "did:web:" + ":".join(parts)


@dataclass
class Participant:
    """The identity of the deployment under test, and where each part came from."""

    did: Optional[str] = None
    did_sources: Dict[str, str] = field(default_factory=dict)  # source -> DID it claims
    origin: Optional[str] = None            # which source the chosen DID came from
    identity_secret: Optional[str] = None
    secret_key: Optional[str] = None
    document_server: str = "unknown"        # did-helper | identityhub | unknown
    hosts: Tuple[str, ...] = ()
    til_address: Optional[str] = None
    placeholders: Tuple[str, ...] = ()      # sources that hold an unresolved ${DID}

    def disagreements(self) -> List[Tuple[str, str]]:
        """(source, DID) for every source that names something other than ours."""
        if not self.did:
            return []
        return sorted((source, value) for source, value in self.did_sources.items()
                      if value != self.did)

    def to_json(self) -> dict:
        return {
            "did": self.did,
            "from": self.origin,
            "sources": dict(self.did_sources),
            "placeholders": list(self.placeholders),
            "documentServer": self.document_server,
            "identitySecret": self.identity_secret,
            "tilAddress": self.til_address,
            "hosts": list(self.hosts),
        }


def resolve(deployment, profile, values, kube=None) -> Participant:
    """Build the Participant from the profile, the lanes and the values.

    Precedence for the DID follows the tool's one rule - declared beats inferred -
    and then prefers the sources that state a DID outright over the one that has
    to be derived from a URL. Every source is recorded either way, because the
    comparison between them is itself a diagnosis.
    """
    participant = Participant()
    sources: Dict[str, str] = {}
    placeholders: List[str] = []

    # 1. the lanes, when there are any
    for lane in sorted(getattr(deployment, "edc_lanes", {}).values(), key=lambda l: l.name):
        if lane.participant_id:
            sources.setdefault("lane %s" % lane.name, lane.participant_id)

    # 2. the values, which is the only source a deployment without EDC has
    if values is not None and values.trust != "none":
        for path, label in _DID_PATHS:
            value = values.get(path)
            if not value:
                continue
            if has_placeholder(value):
                placeholders.append(label)
                continue
            sources.setdefault(label, str(value))
        host_url = values.get(_DID_HOST_PATH)
        if host_url and not has_placeholder(host_url):
            derived = did_from_host_url(host_url)
            if derived:
                sources.setdefault("did-helper", derived)
        for path in _TIL_PATHS:
            til = values.get(path)
            if til and not has_placeholder(til):
                participant.til_address = str(til)
                break

    # 3. the cluster. This is the only source a GitOps install has: Argo renders
    # with `helm template` and leaves no release Secret, so `values.trust` is
    # "none" and step 2 answers nothing - dev's provider had a did-helper, a
    # verifier and a TIL all running and still reported "no source states a DID",
    # which skipped five identity checks on a deployment that could answer all of
    # them. It is recorded even when the values did answer, because it is what the
    # pods are running with and a disagreement with the values is precisely what
    # `identity-did-consistency` exists to name.
    cluster_til: Optional[str] = None
    if kube is not None:
        if deployment.service("verifier"):
            config = _verifier_config(kube, deployment.namespace)
            did = config.get("did")
            if did and not has_placeholder(did):
                sources.setdefault("verifier (cluster)", str(did))
            tir = config.get("tirAddress")
            cluster_til = str(tir) if tir else None
        did_service = deployment.service("did")
        if did_service:
            derived = did_from_host_url(_workload_env_value(
                kube, deployment.namespace, did_service, _DID_HELPER_HOST_ENV))
            if derived:
                sources.setdefault("did-helper (cluster)", derived)
        keycloak_service = deployment.service("keycloak")
        if keycloak_service:
            issuer = _workload_env_value(kube, deployment.namespace,
                                         keycloak_service, _KEYCLOAK_DID_ENV)
            if issuer and not has_placeholder(issuer):
                sources.setdefault("keycloak (cluster)", str(issuer))

    participant.did_sources = sources
    participant.placeholders = tuple(sorted(set(placeholders)))

    # 3. pick one. Declared wins outright; then the lane, because that is the
    # configuration the connector is actually running with and it is what
    # `any_participant_id` has always returned - changing that would move
    # verdicts on every EDC deployment. Then the values, most direct first.
    if profile is not None and getattr(profile, "did", None):
        participant.did = profile.did
        participant.origin = profile.origin("did") or "declared"
    else:
        lane_labels = sorted(label for label in sources if label.startswith("lane "))
        # cluster sources come last on purpose: every deployment that already had
        # an answer keeps the one it had, and this only fills a gap.
        for label in lane_labels + ["verifier", "contract-management", "did-helper",
                                    "keycloak", "verifier (cluster)",
                                    "did-helper (cluster)", "keycloak (cluster)"]:
            if label in sources:
                participant.did, participant.origin = sources[label], label
                break

    participant.identity_secret = deployment.identity_secret
    participant.secret_key = deployment.identity_secret_key
    participant.document_server = _document_server(deployment, values)
    participant.hosts = _hosts(deployment, participant)
    if participant.til_address is None:
        participant.til_address = _til_from_lanes(deployment)
    if participant.til_address is None:
        participant.til_address = cluster_til
    return participant


def _document_server(deployment, values) -> str:
    """Who serves did.json here. The two are mutually exclusive by design.

    `did.enabled` and `identityhub.enabled` are an either/or in every deployment
    inspected: the DCP lane brings an IdentityHub that serves the document, and a
    deployment without it runs the static did-helper instead. Which one it is
    decides where a wrong DID has to be fixed.
    """
    if deployment.service("identityhub"):
        return "identityhub"
    if deployment.service("did"):
        return "did-helper"
    if values is not None and values.trust != "none":
        if values.tri("identityhub.enabled").is_true:
            return "identityhub"
        if values.tri("did.enabled").is_true:
            return "did-helper"
    return "unknown"


def _hosts(deployment, participant: Participant) -> Tuple[str, ...]:
    """Public hostnames worth looking at a certificate for."""
    hosts: List[str] = []
    for lane in deployment.edc_lanes.values():
        for key in ("edc.hostname", "fdscTransfer.oid4vc.verifierHost",
                    "fdscTransfer.transferHost", "fdscTransfer.dcp.oid.host"):
            value = lane.prop(key)
            if value:
                hosts.append(str(value).split("://")[-1].split("/")[0])
    if participant.did and participant.did.startswith("did:web:"):
        hosts.append(participant.did[len("did:web:"):].split(":")[0].replace("%3A", ":"))
    seen, out = set(), []
    for host in hosts:
        if host and host not in seen:
            seen.add(host)
            out.append(host)
    return tuple(out)


def _til_from_lanes(deployment) -> Optional[str]:
    for lane in sorted(deployment.edc_lanes.values(), key=lambda l: l.name):
        if lane.prop("ebsiTir.enabled", "true").lower() != "true":
            continue
        address = lane.prop("ebsiTir.tilAddress")
        if address:
            return address
    return None
