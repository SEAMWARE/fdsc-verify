"""The context a check receives: cached access to everything it might need.

Checks are meant to be short and to read like the diagnosis they encode, so all
the awkward plumbing - port-forwards, the identityhub's unusual API token, base64
DIDs - lives here and is memoised, because several checks want the same DID
document or the same credential list.
"""

from __future__ import annotations

import base64
import json
from typing import Dict, List, Optional, Tuple

from . import http
from .kube import Kube, KubeError, PortForward
from . import participant as participant_mod
from .model import Deployment, EdcLane, Peer
from .participant import Participant
from .profile import Profile
from .progress import null
from .values import Values


def did_b64(did: str) -> str:
    """The identityhub addresses participants by base64url of the DID, unpadded.

    Both path parameters want this - including `{did}` on the endpoints route,
    where passing the raw DID fails with "Illegal base64 character 3a" and
    surfaces as a bare 400.
    """
    return base64.urlsafe_b64encode(did.encode()).decode().rstrip("=")


class Context:
    def __init__(self, kube: Kube, deployment: Deployment, peers: Optional[List[Peer]] = None,
                 config: Optional[dict] = None, insecure: bool = False,
                 profile: Optional["Profile"] = None):
        self.kube = kube
        self.deployment = deployment
        self.peers = peers or []
        self.config = config or {}
        self.insecure = insecure
        # What the operator declared. Never None, so a check can read
        # `ctx.profile.edc` without guarding; an undeclared field is None, which
        # means "ask discovery", never "false".
        self.profile = profile if profile is not None else Profile(self.config)
        self._cache: Dict[str, object] = {}
        # flow steps hand results to each other (catalog -> negotiation -> transfer)
        self._memo: Dict[str, object] = {}
        # everything created during a run, so cleanup can find it again
        self.tracked: Dict[str, List] = {}
        self.identityhub_error: Optional[str] = None
        # 90s was too tight and produced a WARN on a negotiation that was
        # working: measured end to end on demo, INITIAL -> FINALIZED took 103s,
        # most of it the EDC state machine's own tick intervals (11s to leave
        # INITIAL, 43s waiting for the provider's ContractAgreementMessage).
        # The cost of waiting longer is a slower run; the cost of waiting less
        # is telling an operator their deployment is broken when it is not.
        self.timeouts = {"negotiation": 180, "transfer": 120}
        self.timeouts.update((config or {}).get("timeouts") or {})
        # the runner replaces this; a check that says what it is waiting on turns a
        # 40-second silence into "port-forward to identityhub-service"
        self.progress = null()

    # ------------------------------------------------------------- run-scoped state

    def remember(self, key: str, value) -> None:
        self._memo[key] = value

    def recall(self, key: str):
        """Fetch a value a previous step stored.

        `agreement:<lane>` is resolved from the tracked objects so the transfer
        step does not need the negotiation step to have handed it over explicitly.
        """
        if key in self._memo:
            return self._memo[key]
        if key.startswith("agreement:"):
            lane_name = key.split(":", 1)[1]
            for identifier, lane in self.tracked.get("agreement", []):
                if lane.name == lane_name:
                    return identifier
        return None

    def track(self, kind: str, identifier: str, lane) -> None:
        self.tracked.setdefault(kind, []).append((identifier, lane))

    def tracked_summary(self) -> Dict[str, List[str]]:
        return {kind: [i for i, _ in entries] for kind, entries in self.tracked.items()}

    # ------------------------------------------------------------------ values

    @property
    def values(self) -> Values:
        """The release's values, never None.

        Deliberately never None so a check cannot write `if ctx.values:` and get a
        silent pass on a deployment nobody could read. When there is nothing to
        read this is a `Values` with `trust="none"`, and every `tri()` on it comes
        back unknown carrying the reason - which the check turns into a SKIP.
        """
        if self.deployment.values is None:
            self.deployment.values = Values.empty(
                "values were never resolved for this deployment")
        return self.deployment.values

    # ------------------------------------------------------------------ basics

    @property
    def participant(self) -> Participant:
        """Who this deployment is, from every source that claims to know.

        Memoised per run: it reads the lanes and the values, both already in
        memory, but several checks want it and the disagreement list is the kind
        of thing that should be computed once.
        """
        if "participant" not in self._cache:
            self._cache["participant"] = participant_mod.resolve(
                self.deployment, self.profile, self.values, self.kube)
        return self._cache["participant"]  # type: ignore[return-value]

    def verifier_config(self) -> dict:
        """The verifier's server.yaml from the cluster, cached for the run.

        The cluster is the fallback for everything the values would have said, and
        on a GitOps install it is the only source: Argo renders with `helm
        template` and stores no release. `participant.resolve` already reads this
        ConfigMap for the DID and the TIL address; this is the same read, memoised,
        for the checks that want `clientIdentification` and the public host.
        """
        if "verifier_config" not in self._cache:
            self._cache["verifier_config"] = participant_mod.verifier_server_yaml(
                self.kube, self.deployment.namespace)
        return self._cache["verifier_config"]  # type: ignore[return-value]

    def any_participant_id(self) -> Optional[str]:
        """The participant's DID, wherever it is written down.

        Used to read the lanes and nothing else, which left a deployment without
        fdsc-edc with no identity at all. It now goes through `participant`, which
        keeps the lane first so no EDC deployment changes verdict, and falls back
        to the values - the only source a Consumer has. `identity.participantId`
        is the older spelling of `--did` in a --config file and stays supported.
        """
        return self.participant.did or (self.config.get("identity") or {}).get(
            "participantId")

    def lane_names(self) -> List[str]:
        return sorted(self.deployment.edc_lanes)

    def peer_for(self, lane: str) -> Optional[Peer]:
        for peer in self.peers:
            if peer.lane in (None, lane):
                return peer
        return None

    # -------------------------------------------------------------- identityhub

    def _identityhub_token(self) -> Optional[str]:
        """`base64(super-user).<secret>` - the shape the seeding extension expects.

        Deployments differ in what they *store*, not in whether they work: some
        keep only the secret half and the prefix has to be added, others store the
        whole composed token. Prefixing an already-composed token yields
        `base64(super-user).base64(super-user).<secret>`, which the API answers
        with a 401 that reads exactly like a credential of "a different shape" -
        so the shape is detected here rather than assumed, and the operator is not
        asked to hand over a token the tool could derive.
        """
        override = (self.config.get("identityhub") or {}).get("token")
        if override:
            return override
        secret = self.kube.secret("identityhub-secret")
        if not secret or "superuser" not in secret:
            return None
        stored = secret["superuser"].decode().strip()
        prefix = base64.b64encode(b"super-user").decode()
        # Only that exact prefix counts as "already composed". The secret half is
        # base64 as well, so a bare "." test would misfire on a stored secret that
        # happens to contain one.
        if stored.startswith(prefix + "."):
            return stored
        return "%s.%s" % (prefix, stored)

    def _identityhub_get(self, path: str) -> Tuple[Optional[object], Optional[str]]:
        cache_key = "ih:%s" % path
        if cache_key in self._cache:
            return self._cache[cache_key]  # type: ignore[return-value]

        service = self.deployment.service("identityhub")
        if not service:
            result = (None, "identityhub service not found in this namespace")
        else:
            token = self._identityhub_token()
            if not token:
                result = (None, "no identityhub API token; set identityhub.token in --config")
            else:
                identity_port = int((self.config.get("identityhub") or {}).get("port", 8082))
                self.progress.detail("port-forward to %s, then GET %s" % (service, path))
                try:
                    with PortForward(self.kube, service, identity_port,
                                     namespace=self.deployment.namespace) as pf:
                        resp = http.get("%s/api/identity/v1alpha%s" % (pf.base_url, path),
                                        headers={"x-api-key": token})
                except KubeError as exc:
                    result = (None, "%s" % exc)
                else:
                    if resp.status == 401:
                        result = (None, "identityhub API rejected the token (401); this "
                                        "deployment's superuser credential has a different "
                                        "shape - set identityhub.token in --config")
                    elif not resp.ok:
                        result = (None, "identityhub API returned HTTP %d" % resp.status)
                    else:
                        result = (resp.json(), None)
        self._cache[cache_key] = result
        return result

    def identityhub_participant_key(self, did: str) -> Optional[dict]:
        """The publicKeyJwk the identityhub holds for the participant."""
        body, err = self._identityhub_get("/participants/%s/keypairs" % did_b64(did))
        if err or not isinstance(body, list):
            return None
        for entry in body:
            serialized = entry.get("serializedPublicKey")
            if not serialized:
                continue
            try:
                jwk = json.loads(serialized)
            except (ValueError, TypeError):
                continue
            if entry.get("keyId", "").startswith(did):
                return jwk
        return None

    # ----------------------------------------------------------------- verifier

    def verifier_services(self) -> Tuple[Optional[List[dict]], Optional[str]]:
        """The services the verifier's config repo actually holds.

        This is the only way to tell whether the registration job ever took
        effect. The declaration in the values says what *should* be registered;
        Helm's revision counter says how many upgrades could have re-run the job.
        Neither says what the verifier will serve when a wallet arrives, and a
        service that is absent here comes back as a request object with no
        presentation definition.

        The config repo is embedded in the verifier and listens on its own port
        (8090 next to 3000), not through the ingress.
        """
        cache_key = "verifier:services"
        if cache_key in self._cache:
            return self._cache[cache_key]  # type: ignore[return-value]

        service = self.deployment.service("verifier")
        if not service:
            result = (None, "verifier service not found in this namespace")
        else:
            port = int((self.config.get("verifier") or {}).get("configPort", 8090))
            self.progress.detail("port-forward to %s, then GET /service" % service)
            try:
                with PortForward(self.kube, service, port,
                                 namespace=self.deployment.namespace) as pf:
                    resp = http.get("%s/service" % pf.base_url)
            except KubeError as exc:
                result = (None, "%s" % exc)
            else:
                if not resp.ok:
                    result = (None, "config repo returned HTTP %d on port %d"
                                    % (resp.status, port))
                else:
                    body = resp.json()
                    # the endpoint has returned both a bare list and a paged
                    # envelope across versions
                    if isinstance(body, dict):
                        body = body.get("services") or body.get("content") or []
                    if not isinstance(body, list):
                        result = (None, "unexpected response shape from the config repo")
                    else:
                        result = (body, None)
        self._cache[cache_key] = result
        return result

    def identityhub_credentials(self, did: str) -> Optional[List[dict]]:
        """Credentials in the store, or None when the store could not be read.

        The reason is kept in `identityhub_error` so a check can report *why* it
        skipped: "could not read the store" is not actionable, "the API rejected
        the token, set identityhub.token" is.
        """
        body, err = self._identityhub_get("/participants/%s/credentials" % did_b64(did))
        if err or not isinstance(body, list):
            self.identityhub_error = err or "unexpected response shape"
            return None
        return body

    # ------------------------------------------------------------- credentials

    def credential_file_jwt(self) -> Optional[str]:
        """The JWT in the OID4VP credentials folder, read from a running pod.

        `kubectl exec cat` rather than anything cleverer: the folder is usually an
        emptyDir filled by an init container, so there is no secret to read.
        """
        if "credential_file" in self._cache:
            return self._cache["credential_file"]  # type: ignore[return-value]
        result = None
        for lane in sorted(self.deployment.edc_lanes.values(), key=lambda l: l.name):
            folder = lane.prop("oid4vp.credentialsFolder")
            if not folder:
                continue
            self.progress.detail("reading %s from %s" % (folder, lane.deployment))
            try:
                listing = self.kube.run(
                    "exec", "deploy/%s" % lane.deployment, "-c", "dsp-controlplane",
                    "--", "sh", "-c", "ls %s" % folder, check=False)
                name = next((n for n in listing.split() if n.endswith(".jwt")), None)
                if not name:
                    continue
                body = self.kube.run(
                    "exec", "deploy/%s" % lane.deployment, "-c", "dsp-controlplane",
                    "--", "cat", "%s/%s" % (folder, name), check=False)
                if body and body.count(".") == 2:
                    result = body.strip()
                    break
            except KubeError:
                continue
        self._cache["credential_file"] = result
        return result

    def credential_folder_listing(self, lane: EdcLane) -> Optional[List[str]]:
        folder = lane.prop("oid4vp.credentialsFolder")
        if not folder:
            return None
        try:
            out = self.kube.run("exec", "deploy/%s" % lane.deployment, "-c", "dsp-controlplane",
                                "--", "sh", "-c", "ls -1 %s" % folder, check=False)
        except KubeError:
            return None
        return [line for line in out.split() if line] if out else []

    # ------------------------------------------------------------------ dashboard

    def dashboard_connectors(self) -> Tuple[Optional[List[dict]], Optional[str]]:
        """What the dashboard actually serves at /config/edc-connector-config.json.

        Served, not declared: the ConfigMap is only half the story. The image
        deep-merges `application.yaml` over its own `application.default.yaml` and
        skips null overrides, so a default entry cannot be removed - only shadowed -
        and the mount uses `subPath`, which kubelet does not auto-update. Both mean
        the file on disk and the list the operator sees can differ, and the list
        the operator sees is the one that picks a counterparty.
        """
        if "dashboard" in self._cache:
            return self._cache["dashboard"]  # type: ignore[return-value]

        service = self.deployment.service("dashboard")
        if not service:
            result = (None, "no connector dashboard service in this namespace")
        else:
            port = self._service_port(service, 8080)
            self.progress.detail("reading the connector list from %s" % service)
            try:
                with PortForward(self.kube, service, port,
                                 namespace=self.deployment.namespace) as pf:
                    resp = http.get("%s/config/edc-connector-config.json" % pf.base_url)
            except KubeError as exc:
                result = (None, "%s" % exc)
            else:
                if resp.error:
                    result = (None, resp.error)
                elif not resp.ok:
                    result = (None, "the dashboard returned HTTP %d for "
                                    "/config/edc-connector-config.json" % resp.status)
                else:
                    body = resp.json()
                    if not isinstance(body, list):
                        result = (None, "the dashboard served %s, not the expected list "
                                        "of connectors" % type(body).__name__)
                    else:
                        result = (body, None)
        self._cache["dashboard"] = result
        return result

    def _service_port(self, service: str, default: int) -> int:
        """The service's first declared port. Never guessed when it can be read."""
        data = self.kube.get_json("service", service,
                                  namespace=self.deployment.namespace, check=False)
        ports = ((data or {}).get("spec") or {}).get("ports") or []
        if ports and isinstance(ports[0].get("port"), int):
            return ports[0]["port"]
        return default

    # -------------------------------------------------------------------- images

    def image_of(self, *fragments: str) -> Tuple[Optional[str], Optional[str]]:
        """(workload, image) for the first Deployment whose image matches a fragment.

        Matched on the image rather than on the workload name, because the name is
        the operator's to choose - `producer-tm-forum-api-all-in-one` in one
        namespace, `central-mk-tm-forum-api-all-in-one` in another - while the
        image repository is the chart's. Listed once and cached: several checks
        want a version and none of them should pay for it twice.
        """
        if "images" not in self._cache:
            data = self.kube.get_json("deployment", namespace=self.deployment.namespace,
                                      check=False) or {}
            pairs = []
            for item in data.get("items", []) or []:
                name = (item.get("metadata") or {}).get("name") or ""
                containers = (((item.get("spec") or {}).get("template") or {})
                              .get("spec") or {}).get("containers") or []
                for container in containers:
                    image = container.get("image")
                    if image:
                        pairs.append((name, image))
            self._cache["images"] = pairs
        for name, image in self._cache["images"]:  # type: ignore[union-attr]
            if any(fragment in image for fragment in fragments):
                return name, image
        return None, None

    def workload_env(self, service: str) -> Dict[str, str]:
        """The environment of the workload behind a Service, by its selector.

        Two things this does not do, both learned from the deployments in front of
        it. It does not assume a Deployment: the BAE's logic proxy is a
        **StatefulSet**, and `kubectl get deploy <name>` answers NotFound for it. And
        it does not guess the workload's name from the Service's - those agree often
        enough to be tempting and not always, so the Service's selector is what
        decides, which is the same thing kube-proxy uses.

        Only literal `value` entries come back. A `valueFrom` (secretKeyRef,
        fieldRef) is deliberately left out rather than resolved: a check reading a
        client id wants what is configured, and silently substituting a secret's
        contents into a report is not something this tool should do.
        """
        cache_key = "env:%s" % service
        if cache_key in self._cache:
            return self._cache[cache_key]  # type: ignore[return-value]

        env: Dict[str, str] = {}
        svc = self.kube.get_json("service", service,
                                 namespace=self.deployment.namespace, check=False) or {}
        selector = ((svc.get("spec") or {}).get("selector") or {})
        if selector:
            expr = ",".join("%s=%s" % kv for kv in sorted(selector.items()))
            pods = self.kube.get_json("pod", namespace=self.deployment.namespace,
                                      check=False, selector=expr) or {}
            for pod in (pods.get("items") or [])[:1]:
                for container in ((pod.get("spec") or {}).get("containers") or []):
                    for entry in container.get("env") or []:
                        name, value = entry.get("name"), entry.get("value")
                        if name and value is not None:
                            env.setdefault(name, value)
        self._cache[cache_key] = env
        return env

    # ------------------------------------------------------------------- gateway

    def gateway_hosts(self) -> Tuple[List[str], Optional[str]]:
        """Public hostnames whose Ingress routes to the APISIX gateway.

        Read from the Ingress objects rather than from the values, because the
        values are not reliable here: one deployment inspected carries the chart's
        placeholder `apisix.local` while its real hosts are four entries on a live
        Ingress. The cluster is the authority for what is published, which is the
        same rule the component matrix follows.

        The DSP hosts are filtered out. In a deployment running both transports the
        one gateway fronts both - `dsp-producer` and `mp-data-service` are the same
        APISIX - and the DSP routes are `dsp-route`'s to probe.
        """
        if "gateway_hosts" in self._cache:
            return self._cache["gateway_hosts"]  # type: ignore[return-value]

        gateway = self.deployment.service("apisix")
        if not gateway:
            result: Tuple[List[str], Optional[str]] = (
                [], "no APISIX gateway service in this namespace")
        else:
            data = self.kube.get_json("ingress", namespace=self.deployment.namespace,
                                      check=False)
            if data is None:
                result = ([], "the Ingress objects could not be listed")
            else:
                dsp_hosts = {lane.hostname for lane in self.deployment.edc_lanes.values()
                             if lane.hostname}
                hosts: List[str] = []
                for item in data.get("items", []) or []:
                    for rule in (item.get("spec") or {}).get("rules") or []:
                        host = rule.get("host")
                        if not host or host in dsp_hosts or host in hosts:
                            continue
                        paths = ((rule.get("http") or {}).get("paths") or [])
                        backends = {((path.get("backend") or {}).get("service") or {})
                                    .get("name") for path in paths}
                        if gateway in backends:
                            hosts.append(host)
                result = (sorted(hosts), None)
        self._cache["gateway_hosts"] = result
        return result

    # -------------------------------------------------------- EDC management API

    def edc_request(self, lane: EdcLane, method: str, path: str, body=None):
        """Call a lane's management API through a port-forward.

        The management API is never exposed publicly - and must not be - so every
        flow step goes through a tunnel. Ports and base path come from the lane's
        own config, so a deployment that moves them still works.
        """
        service = lane.service or lane.deployment
        port = int(lane.port("management", "8085"))
        base_path = lane.path("management", "/api/v1/management")
        self.progress.detail("%s %s on %s" % (method, path, service))
        try:
            with PortForward(self.kube, service, port,
                             namespace=self.deployment.namespace) as pf:
                return http.request(method, "%s%s%s" % (pf.base_url, base_path, path),
                                    body=body), None
        except KubeError as exc:
            return None, "%s" % exc

    def edc_catalog(self, lane: EdcLane, peer: Peer):
        """Request the peer's catalog. Returns (body, error)."""
        if not peer.protocol_url:
            return None, ("peer %s declares no protocolUrl, so there is no DSP "
                          "endpoint to ask" % peer.name)
        request = {
            "@context": {"@vocab": "https://w3id.org/edc/v0.0.1/ns/"},
            "@type": "CatalogRequest",
            "counterPartyAddress": peer.protocol_url,
            "counterPartyId": peer.participant_id,
            "protocol": self.dsp_protocol(peer),
        }
        resp, err = self.edc_request(lane, "POST", "/v3/catalog/request", request)
        if err:
            return None, err
        if resp.error:
            return None, resp.error
        if not resp.ok:
            return None, "management API returned HTTP %d: %s" % (resp.status, resp.text(240))
        return resp.json(), None

    @staticmethod
    def dsp_protocol(peer: Peer) -> str:
        """Derive the protocol id from the peer's URL, defaulting to 2025-1.

        A peer that advertises its version in the path (".../api/dsp/2025-1") tells
        us which binding to ask for; otherwise the current default is right.
        """
        if not peer.protocol_url:
            return "dataspace-protocol-http:2025-1"
        tail = peer.protocol_url.rstrip("/").rsplit("/", 1)[-1]
        if tail and tail[0].isdigit():
            return "dataspace-protocol-http:%s" % tail
        return "dataspace-protocol-http:2025-1"

    # ---------------------------------------------------------------------- TIL

    def til_issuer(self, til_address: str, did: str) -> Tuple[Optional[dict], Optional[str]]:
        """Query the EBSI TIR-shaped issuer endpoint the EDC itself uses.

        The configured address is an in-cluster URL, so it is reached through a
        port-forward to whichever service it names.
        """
        cache_key = "til:%s:%s" % (til_address, did)
        if cache_key in self._cache:
            return self._cache[cache_key]  # type: ignore[return-value]

        self.progress.detail("asking the trusted issuers list about %s" % did)
        service, port = _service_from_url(til_address)
        if service is None:
            resp = http.get("%s/v4/issuers/%s" % (til_address.rstrip("/"), did),
                            insecure=self.insecure)
            result = _til_response(resp)
        else:
            local = self.deployment.service("til") or service
            try:
                with PortForward(self.kube, local, port,
                                 namespace=self.deployment.namespace) as pf:
                    resp = http.get("%s/v4/issuers/%s" % (pf.base_url, did))
                    result = _til_response(resp)
            except KubeError as exc:
                result = (None, "%s" % exc)
        self._cache[cache_key] = result
        return result

    @staticmethod
    def til_credential_types(issuer_body: dict) -> List[str]:
        """Decode the base64 attribute bodies to get the credential types."""
        types = []
        for attribute in issuer_body.get("attributes") or []:
            raw = attribute.get("body")
            if not raw:
                continue
            try:
                decoded = json.loads(base64.b64decode(raw + "=" * (-len(raw) % 4)))
            except (ValueError, TypeError):
                continue
            kind = decoded.get("credentialsType")
            if kind:
                types.append(kind)
        return types


def _til_response(resp: http.Response) -> Tuple[Optional[dict], Optional[str]]:
    if resp.error:
        return None, resp.error
    if resp.status == 404:
        return None, None  # a clean "not registered", not an error
    if not resp.ok:
        return None, "TIL returned HTTP %d" % resp.status
    return resp.json(), None


def _service_from_url(url: str) -> Tuple[Optional[str], int]:
    """Split an in-cluster URL into (service, port); (None, 0) when it is public."""
    without_scheme = url.split("://", 1)[-1]
    host_port = without_scheme.split("/", 1)[0]
    host, _, port = host_port.partition(":")
    if ".svc" not in host and "." in host and not host.endswith(".local"):
        return None, 0  # looks like a public hostname, reach it directly
    return host.split(".")[0], int(port or 80)
