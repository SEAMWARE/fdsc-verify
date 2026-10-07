"""Infrastructure and configuration checks.

These are the cheap ones - most read nothing but the lane's ConfigMap - and they
catch the failures that are least visible at runtime.
"""

from __future__ import annotations

from typing import List, Optional

from .. import http
from ..model import Result, check

DOC_IMAGE = "the-dcp-instance-needs-the-dcp-controlplane-image"
DOC_STS = "the-dcp-lane-needs-an-sts-client-secret-that-dev-mode-vault-loses"
DOC_ANCHORS = "oid4vp-trust-anchors-use-the-images-public-root-store"
DOC_CRED_REPO = "credential-repo-must-project-a-single-key"
DOC_DNS = "working-around-the-broken-atdih-record"
DOC_EDR = "the-edr-token-lives-5-minutes-and-cannot-be-refreshed"


@check("controlplane-image", "Each lane runs the controlplane build for its identity",
       needs_cluster=True, lanes=["*"], transport="edc")
def controlplane_image(ctx, lane) -> Result:
    """The chart's `common` default image is the OID4VC build.

    A `deployment.<name>` instance that overrides only the tag therefore runs the
    OID4VC build under the name `dcp`, which is not a DCP connector: it signs
    outbound DSP requests with a verifier token instead of a self-issued one and
    the counterparty cannot resolve its kid. Seen from the receiving side the
    stack trace names `OID4VPParticipantIdExtractionFunction`, which identifies
    the image - `controlplane-dcp` does not depend on `oid4vc-extension` at all.
    """
    # A lane declared in --config carries no Deployment name, and an empty name
    # turns this into `kubectl get deployment -o json`: a List, which has no
    # `spec` and used to crash the check instead of skipping it.
    if not lane.deployment:
        return Result.skip("lane %s has no Deployment name (declared in --config?), "
                           "so its image cannot be read" % lane.name)
    data = ctx.kube.get_json("deployment", lane.deployment, check=False)
    if not data or data.get("kind") != "Deployment":
        return Result.skip("deployment %s not found" % lane.deployment)
    containers = (data.get("spec", {}).get("template", {})
                  .get("spec", {}).get("containers") or [])
    if not containers:
        return Result.skip("deployment %s declares no containers" % lane.deployment)
    image = containers[0].get("image") or ""
    speaks_dcp = lane.speaks_dcp

    if speaks_dcp and "controlplane-oid4vc" in image:
        return Result.fail(
            "a DCP lane is running the OID4VC controlplane build",
            cause="image %s: OID4VPExtension registers OID4VPIdentityService, so "
                  "outbound DSP requests carry a verifier-signed token instead of a "
                  "DCP self-issued one and the peer cannot resolve the kid" % image,
            fix="pin repository to .../fdsc-edc-controlplane-dcp for this instance; "
                "overriding only the tag inherits the common default",
            doc=DOC_IMAGE,
            image=image)
    if not speaks_dcp and "controlplane-dcp" in image:
        return Result.warn(
            "an OID4VC lane is running the DCP controlplane build",
            cause="image %s does not carry oid4vc-extension" % image,
            fix="pin the oid4vc repository for this instance",
            doc=DOC_IMAGE,
            image=image)

    # corroborate with the extensions the process actually loaded
    logs = ctx.kube.logs("deploy/%s" % lane.deployment, since="24h", tail=3000)
    if logs:
        loaded_dcp = "IdentityAndTrust" in logs
        obtaining_oid4vp = "Try to obtain credential via OID4VP." in logs
        if speaks_dcp and obtaining_oid4vp and not loaded_dcp:
            return Result.fail(
                "the DCP lane is using the OID4VP identity stack at runtime",
                cause="the log shows 'Try to obtain credential via OID4VP.' and no "
                      "IdentityAndTrustExtension, regardless of the image name",
                fix="check the image and that dcp.enabled is set for this instance",
                doc=DOC_IMAGE,
                image=image)
    return Result.ok("%s" % image.rsplit("/", 1)[-1], image=image)


@check("sts-secret-aliases", "The STS client secret exists under both alias encodings",
       needs_cluster=True, lanes=["*"], transport="edc")
def sts_secret_aliases(ctx, lane) -> Result:
    """EDC double-encodes the alias, so the working deployments hold two keys.

    The vault client URL-encodes the alias and the HTTP layer then encodes the
    `%`, so a lookup for `did:web:x-...` resolves a key literally named
    `did%3Aweb%3Ax-...`. Only checking one form gives a false pass.
    """
    if not lane.speaks_dcp:
        return Result.na("only a DCP lane uses the identityhub STS")
    alias = lane.prop("edc.iam.sts.oauth.client.secret.alias")
    if not alias:
        return Result.skip("no STS client secret alias configured")

    vault_url = lane.prop("edc.vault.hashicorp.url")
    token = lane.prop("edc.vault.hashicorp.token")
    secret_path = lane.prop("edc.vault.hashicorp.api.secret.path", "/v1/secret")
    if not vault_url or not token:
        return Result.skip("vault address or token not in the lane config")

    service, port = _service_and_port(vault_url)
    if not service:
        return Result.skip("vault address %s is not an in-cluster service" % vault_url)

    variants = [alias, alias.replace(":", "%253A")]
    from ..kube import KubeError, PortForward

    found, missing = [], []
    try:
        with PortForward(ctx.kube, service, port, namespace=ctx.deployment.namespace) as pf:
            for variant in variants:
                resp = http.get("%s%s/data/%s" % (pf.base_url, secret_path, variant),
                                headers={"X-Vault-Token": token})
                (found if resp.ok else missing).append(variant)
    except KubeError as exc:
        return Result.skip("could not reach vault: %s" % exc)

    if not found:
        return Result.fail(
            "the STS client secret is absent from vault",
            cause="neither %s nor its percent-encoded form resolves; the lane fails "
                  "with 'Failed to fetch client secret from the vault with alias'" % alias,
            fix="re-run the identityhub bootstrap job; it must write the secret "
                "unconditionally, because a 409 on participant creation means the "
                "generated secret is gone forever",
            doc=DOC_STS)
    if missing:
        return Result.warn(
            "the STS secret exists under only one alias encoding",
            cause="present: %s; absent: %s. EDC's vault client encodes the alias, so "
                  "the percent form is the one it actually looks up" % (found, missing),
            fix="write both key names, as the working deployments do",
            doc=DOC_STS)
    return Result.ok("present under both alias encodings")


@check("vault-mode", "Vault persistence", needs_cluster=True, lanes=None)
def vault_mode(ctx) -> Result:
    """Dev-mode vault is in-memory, so a restart silently empties it."""
    service = ctx.deployment.service("vault")
    if not service:
        return Result.na("no vault service in this namespace")
    pods = ctx.kube.get_json("pod", check=False)
    dev = False
    for pod in (pods or {}).get("items", []):
        for container in pod["spec"].get("containers", []):
            joined = " ".join(container.get("args") or []) + " " + " ".join(container.get("command") or [])
            if "-dev" in joined.split() or "server -dev" in joined:
                dev = True
    if not dev:
        return Result.ok("not running in dev mode")
    return Result.warn(
        "vault is running in dev mode (in-memory)",
        cause="every restart wipes the signing key, the super-user credential and "
              "the STS secret; anything that provisions them must re-run afterwards",
        fix="ensure the bootstrap job is a post-install,post-upgrade hook, or move "
            "vault to persistent storage",
        doc=DOC_STS)


@check("trust-anchors-folder", "OID4VP trust anchors are configured and loadable",
       lanes=["*"], transport="edc")
def trust_anchors_folder(ctx, lane) -> Result:
    """An empty setting silently falls back to the JVM truststore *with* revocation.

    That fails with "Could not determine revocation status", which reads like a
    network problem rather than a configuration one.
    """
    if lane.prop("oid4vp.enabled", "false").lower() != "true":
        return Result.skip("oid4vp is not enabled on this lane")
    folder = lane.prop("oid4vp.trustAnchorsFolder")
    if not folder:
        return Result.fail(
            "oid4vp.trustAnchorsFolder is empty",
            cause="OID4VPExtension only builds X509SanDnsClientResolver(trustAnchors, "
                  "false) when anchors are configured; unset, it uses the JVM default "
                  "truststore with revocation checking and fails with 'Could not "
                  "determine revocation status'",
            fix="point it at the image's own root store (/etc/ssl/certs)",
            doc=DOC_ANCHORS)

    if not ctx.kube.available():
        return Result.ok("configured: %s (contents not verified)" % folder)

    # loadCertificatesFromFolder throws on any file it cannot parse as X.509,
    # so one stray file in the folder breaks startup.
    listing = ctx.kube.run("exec", "deploy/%s" % lane.deployment, "-c", "dsp-controlplane",
                           "--", "sh", "-c",
                           "ls -1 %s 2>/dev/null | head -400" % folder, check=False)
    if not listing:
        return Result.warn("could not list %s" % folder, cause="exec into the pod failed")
    names = [n for n in listing.split() if n]
    strays = [n for n in names
              if not (n.endswith(".pem") or n.endswith(".crt") or n.endswith(".0")
                      or n.endswith(".1") or n == "ca-certificates.crt")]
    if strays:
        return Result.fail(
            "%d file(s) in the trust anchor folder are not certificates" % len(strays),
            cause="loadCertificatesFromFolder does a flat listing and throws on "
                  "anything it cannot parse: %s" % strays[:6],
            fix="remove them, or copy the store into an emptyDir and point the "
                "setting there",
            doc=DOC_ANCHORS,
            strays=strays[:20])
    return Result.ok("%s, %d entries" % (folder, len(names)))


@check("credential-repo-single-key", "The credentials folder holds exactly one usable file",
       needs_cluster=True, lanes=["*"], transport="edc")
def credential_repo_single_key(ctx, lane) -> Result:
    """FileSystemCredentialsRepository infers the format from each file extension.

    Mounting the whole vc-operator Secret creates one file per key and it aborts
    on the extensionless `format` file.
    """
    if lane.prop("oid4vp.enabled", "false").lower() != "true":
        return Result.skip("oid4vp is not enabled on this lane")
    listing = ctx.credential_folder_listing(lane)
    if listing is None:
        return Result.skip("credentialsFolder not configured or pod unreachable")
    if not listing:
        return Result.fail(
            "the credentials folder is empty",
            cause="the OID4VP lane has no credential to present",
            fix="check the credential secret and the init container that fills the folder",
            doc=DOC_CRED_REPO)
    bad = [n for n in listing if "." not in n]
    if bad:
        return Result.fail(
            "the credentials folder holds file(s) without an extension",
            cause="FileSystemCredentialsRepository derives the format from the "
                  "extension and dies with 'Unsupported file extension' on %s" % bad,
            fix="project only the credential key from the Secret, named *.jwt",
            doc=DOC_CRED_REPO,
            files=listing)
    return Result.ok("%d file(s): %s" % (len(listing), ", ".join(listing)))


@check("dsp-route", "The lane's public DSP endpoint answers", lanes=["*"],
       transport="edc")
def dsp_route(ctx, lane) -> Result:
    """The EDC half of what used to be one check.

    A host that resolves elsewhere returns a plausible 404 from a foreign server,
    so telling "guarded, as designed" (401) from "you reached someone else" (404)
    is the whole point.
    """
    protocol_url = lane.protocol_url
    if not protocol_url:
        return Result.skip("this lane publishes no protocol URL")
    version_path = "%s/.well-known/dspace-version" % protocol_url.rstrip("/")
    resp = http.get(version_path, insecure=ctx.insecure)
    if resp.error:
        return Result.fail("the DSP endpoint could not be reached",
                           cause="%s: %s" % (version_path, resp.error),
                           fix="fix the A record, or advertise the service on a host "
                               "that already resolves and route it in the gateway",
                           doc=DOC_DNS)
    if resp.status == 404:
        return Result.fail(
            "the DSP endpoint answers 404",
            cause="%s -> 404. The route is missing, or DNS points at a host that is "
                  "not this cluster and answered for us" % version_path,
            fix="fix the A record, or add the route in the gateway",
            doc=DOC_DNS)
    return Result.ok("dsp %d" % resp.status, endpoint=version_path)


@check("credential-service-route", "The published CredentialService answers",
       lanes=None)
def credential_service_route(ctx) -> Result:
    """The generic half: any participant that publishes one has to serve it.

    Split out of `dns-and-routes` because it needs no EDC lane - the endpoint is
    published in the DID document, which every participant has - and because it is
    the half that caught a real fault: a CredentialService pointing at a stale A
    record blocked every DCP test until somebody noticed the 404 came from a
    foreign server rather than from us.
    """
    did = ctx.participant.did or ""
    if not did.startswith("did:web:"):
        return Result.skip("no did:web participant id to resolve")
    from .identity import fetch_did_document

    doc, err = fetch_did_document(did, ctx.insecure)
    if not doc:
        return Result.skip("the DID document could not be read", cause=err)
    endpoints = [service.get("serviceEndpoint") or ""
                 for service in (doc.get("service") or [])
                 if str(service.get("serviceEndpoint") or "").startswith("http")]
    if not endpoints:
        return Result.ok("the DID document publishes no CredentialService to probe",
                         did=did)

    checks, problems = [], []
    for endpoint in endpoints:
        resp = http.post("%s/presentations/query" % endpoint.rstrip("/"),
                         body={}, insecure=ctx.insecure)
        if resp.error:
            problems.append("%s: %s" % (endpoint, resp.error))
        elif resp.status == 404:
            problems.append("%s answers 404 - DNS most likely resolves to a foreign "
                            "host" % endpoint)
        else:
            checks.append("%s -> %d" % (endpoint, resp.status))
    if problems:
        return Result.fail("%d published endpoint(s) do not answer" % len(problems),
                           cause="; ".join(problems),
                           fix="fix the A record, or advertise the service on a host "
                               "that already resolves and route it in the gateway",
                           doc=DOC_DNS, did=did)
    return Result.ok(", ".join(checks), did=did)


@check("edr-token-lifetime", "The data-plane token lifetime is workable", lanes=["*"],
       transport="edc")
def edr_token_lifetime(ctx, lane) -> Result:
    """Informational, but it is the reason a manual transfer "randomly" 401s.

    The EDR token is minted when the data flow starts, lives 300 s in the current
    build, and cannot be refreshed: the management API has no auto_refresh and the
    EDR carries no refresh material. Knowing this up front turns a confusing 401
    into an expected one.
    """
    if lane.prop("fdscTransfer.enabled", "false").lower() != "true":
        return Result.na("fdscTransfer is not enabled on this lane")
    return Result.warn(
        "the EDR token is short-lived and cannot be refreshed",
        cause="EXPIRATION_MS is hard-coded to 300_000 in "
              "FDSCDcpEndpointDataReferenceService and the token is minted when the "
              "data flow starts, not when you fetch the EDR; /dataaddress returns "
              "the same stored token",
        fix="use the EDR immediately - script the chain - and check the remaining "
            "lifetime before spending it",
        doc=DOC_EDR)


def _service_and_port(url: str):
    without_scheme = url.split("://", 1)[-1]
    host_port = without_scheme.split("/", 1)[0]
    host, _, port = host_port.partition(":")
    if ".svc" not in host and "." in host and not host.endswith(".local"):
        return None, 0
    return host.split(".")[0], int(port or 8200)
