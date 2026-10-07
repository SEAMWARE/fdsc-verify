"""Certificate and gateway-token checks."""

from __future__ import annotations

import datetime
import re
import subprocess
from typing import Dict, List, Optional, Tuple

from .. import http, jose
from .. import values as values_mod
from ..context import _service_from_url
from ..kube import KubeError, PortForward
from ..model import Result, check

DOC_APISIX_JWKS = "apisix-caches-the-verifiers-jwks-and-the-kid-never-changes"
DOC_CLIENT_ID = "the-wildcard-certificate-cannot-be-an-x509_san_dns-client-id"
DOC_CLIENT_ID_SCHEME = "the-client-id-scheme-and-the-request-object-have-to-agree"

# Where the verifier's own client identification lives. Global to the release,
# not per lane: one verifier serves every lane. The `deployment` level is the one
# the chart actually uses; the shorter form is tried too rather than assumed
# away, because the block is addressed both ways across chart versions.
CLIENT_ID_PATHS = (
    "decentralizedIam.vcAuthentication.vcverifier.deployment.verifier.clientIdentification",
    "decentralizedIam.vcAuthentication.vcverifier.verifier.clientIdentification",
)

# OID4VP client identifier prefixes. `did` was renamed to
# `decentralized_identifier` in OID4VP 1.0; both appear in the wild, and a bare
# `did:web:...` carries no prefix at all yet is unambiguous.
_PREFIXES = ("x509_san_dns", "x509_san_uri", "redirect_uri", "verifier_attestation",
             "decentralized_identifier", "did", "https", "web-origin")


def _cluster_verifier(ctx) -> dict:
    """The verifier's live server.yaml, or {} when it cannot be read.

    Tolerates a Context that does not have the accessor, because several test
    contexts are plain namespaces and this is only ever a fallback.
    """
    read = getattr(ctx, "verifier_config", None)
    if not callable(read):
        return {}
    try:
        config = read()
    except Exception:
        return {}
    return config if isinstance(config, dict) else {}


def _client_identification(ctx) -> dict:
    """The verifier's clientIdentification block, wherever the chart put it.

    The chart declares every field with a null default, so a key being present
    says nothing - only a non-null value does.

    The values answer first, and the running verifier's own ConfigMap is the
    fallback - a GitOps install has no release to read values from, and this block
    decides both `client-id-scheme` and `cert-san-vs-client-id`, which used to skip
    there for want of a source while the answer sat in a ConfigMap the tool was
    already opening for the DID.
    """
    for path in CLIENT_ID_PATHS:
        block = ctx.values.get_at(path.split("."))
        if isinstance(block, dict) and any(v is not None for v in block.values()):
            return block
    block = (_cluster_verifier(ctx).get("verifier") or {}).get("clientIdentification")
    if isinstance(block, dict) and any(v is not None for v in block.values()):
        return block
    return {}


def _client_id_scheme(ctx) -> Tuple[str, Optional[str]]:
    """The configured client id and which identifier prefix it uses.

    A bare value with no recognised prefix is a pre-registered client id, which
    is a legitimate scheme rather than a mistake - so it is named, not rejected.
    """
    client_id = _client_identification(ctx).get("id")
    if not client_id or not isinstance(client_id, str):
        return "unknown", None
    head = client_id.split(":", 1)[0]
    if head == "did":
        # `did:web:host` is a DID, not the (obsolete) `did:` prefix around one
        return "did", client_id
    if head in _PREFIXES:
        return head, client_id
    return "pre-registered", client_id


def _openssl_text(der: bytes) -> str:
    proc = subprocess.run(
        ["openssl", "x509", "-inform", "DER", "-noout", "-text", "-subject", "-enddate"],
        input=der, capture_output=True)
    return proc.stdout.decode("utf-8", "replace") if proc.returncode == 0 else ""


def _parse_cert(der: bytes) -> Dict[str, object]:
    text = _openssl_text(der)
    subject = ""
    match = re.search(r"^subject=\s*(.+)$", text, re.M)
    if match:
        subject = match.group(1).strip()
    cn = ""
    cn_match = re.search(r"CN\s*=\s*([^,/\n]+)", subject or text)
    if cn_match:
        cn = cn_match.group(1).strip()
    sans: List[str] = []
    san_match = re.search(r"Subject Alternative Name:\s*\n\s*(.+)", text)
    if san_match:
        sans = [s.strip().replace("DNS:", "") for s in san_match.group(1).split(",")
                if s.strip().startswith("DNS:")]
    not_after = None
    end_match = re.search(r"^notAfter=(.+)$", text, re.M)
    if end_match:
        try:
            not_after = datetime.datetime.strptime(end_match.group(1).strip(),
                                                   "%b %d %H:%M:%S %Y %Z")
        except ValueError:
            not_after = None
    return {"cn": cn, "sans": sans, "notAfter": not_after}


def _hosts_of_interest(ctx) -> List[str]:
    """Every public host this participant answers on.

    The lanes used to be the only source, so a deployment without fdsc-edc had no
    hosts and this skipped - while still having a did:web host whose certificate
    expiring breaks every counterparty's ability to resolve it. `participant.hosts`
    collects both, and the verifier's own host from the values, which is the one a
    Provider without EDC still has to serve.
    """
    hosts = set(ctx.participant.hosts)
    verifier_host = ctx.values.get(
        "decentralizedIam.vcAuthentication.vcverifier.deployment.verifier.host")
    for value in (verifier_host, _values_host(ctx)):
        if value:
            hosts.add(str(value).split("://")[-1].split("/")[0])
    return sorted(host.split(":")[0] for host in hosts
                  if host and "." in host and "svc" not in host)


def _values_host(ctx) -> Optional[str]:
    """The did-helper's own host, which is where the DID document is served."""
    url = ctx.values.get("did.config.server.hostUrl")
    if url and not values_mod.has_placeholder(url):
        return str(url)
    return None


@check("cert-expiry", "Every public host serves a valid certificate", lanes=None)
def cert_expiry(ctx) -> Result:
    """Which certificate each host actually serves, and for how long.

    Traefik aggregates every Ingress certificate into one store and picks by SNI,
    so the certificate a host serves is not necessarily the one its own Ingress
    names. Reporting what is really on the wire is the only way to see that.
    """
    hosts = _hosts_of_interest(ctx)
    if not hosts:
        return Result.skip("no public hostnames discovered")

    served: Dict[str, Dict[str, object]] = {}
    problems, unreachable = [], []
    now = datetime.datetime.utcnow()
    for host in hosts:
        der, err = http.peer_cert(host)
        if err or not der:
            unreachable.append("%s (%s)" % (host, err or "no certificate"))
            continue
        info = _parse_cert(der)
        served[host] = {"cn": info["cn"],
                        "notAfter": info["notAfter"].isoformat() if info["notAfter"] else None}
        if info["notAfter"]:
            days = (info["notAfter"] - now).days
            served[host]["daysLeft"] = days
            if days < 0:
                problems.append("%s: EXPIRED %d days ago" % (host, -days))
            elif days < 15:
                problems.append("%s: expires in %d days" % (host, days))

    if problems:
        return Result.fail("certificate problems on %d host(s)" % len(problems),
                           cause="; ".join(problems),
                           fix="renew and, if the key changes, run the whole rotation "
                               "runbook - not just the secret swap",
                           served=served)
    if not served:
        return Result.warn("no host could be reached over TLS",
                           cause="; ".join(unreachable), served=served)
    summary = "%d host(s) valid" % len(served)
    if unreachable:
        return Result.warn(summary + ", %d unreachable" % len(unreachable),
                           cause="; ".join(unreachable), served=served)
    return Result.ok(summary, served=served)


def _verifier_host(ctx, client_id: str) -> Optional[str]:
    """Where the verifier answers, without needing an EDC lane to say so.

    `x509_san_dns:<name>` carries the name it claims, which is the host whose
    certificate has to carry it; the ingress and the lane are fallbacks for a
    deployment that identifies some other way.
    """
    if client_id and client_id.startswith("x509_san_dns:"):
        return client_id.split(":", 1)[1].split("/")[0].split(":")[0]
    hosts = ctx.values.get(
        "decentralizedIam.vcAuthentication.vcverifier.ingress.hosts") or []
    for entry in hosts:
        if isinstance(entry, dict) and entry.get("host"):
            return str(entry["host"])
    for lane in ctx.deployment.edc_lanes.values():
        value = lane.prop("fdscTransfer.oid4vc.verifierHost")
        if value:
            return value.split("://")[-1].split("/")[0].split(":")[0]
    # Last: what the running verifier publishes as its own address. All three
    # sources above are values or lane, so a GitOps install with no EDC had none
    # of them and `flow-fiware-discovery` skipped on a deployment whose host was
    # sitting in `server.host` of the ConfigMap next door.
    host = (_cluster_verifier(ctx).get("server") or {}).get("host")
    if host:
        return str(host).split("://")[-1].split("/")[0].split(":")[0]
    return None


@check("cert-san-vs-client-id", "The x509_san_dns client id appears in a SAN",
       lanes=None, roles=("provider",))
def cert_san_vs_client_id(ctx) -> Result:
    """The counterparty compares the client id to the SAN entries as plain strings.

    There is no wildcard matching, so a wildcard certificate cannot back a
    spec-compliant `x509_san_dns` client id. Failure surfaces at the peer as
    "The client is not contain in the SAN of the x5c" - note that is a different
    line from chain validation, and mistaking the two costs an afternoon.

    All of which only applies when the verifier actually identifies by
    certificate. The scheme is read from `clientIdentification.id` rather than
    assumed: a deployment identifying by DID or by `redirect_uri` has no x5c for
    a peer to compare, and asserting a certificate problem there sends the
    operator after a certificate nobody uses.
    """
    scheme, client_id = _client_id_scheme(ctx)
    if client_id is None:
        return Result.skip("no verifier clientIdentification.id could be read, "
                           "so the client id scheme is unknown")
    if scheme != "x509_san_dns":
        return Result.skip("this deployment identifies by %s, not x509_san_dns" % scheme,
                           cause="clientIdentification.id = %s" % client_id)

    # The host is in the client id itself - `x509_san_dns:<dns name>` names the
    # very SAN it claims - so this needs no lane. One verifier serves every lane
    # anyway, which is why it used to produce two identical rows.
    host = _verifier_host(ctx, client_id)
    if not host:
        return Result.skip("no verifier host could be resolved from the client id, "
                           "the values or the verifier's own ConfigMap")

    der, err = http.peer_cert(host)
    if err or not der:
        return Result.skip("could not fetch the certificate of %s (%s)" % (host, err))
    info = _parse_cert(der)
    sans = info["sans"] or []

    if host in sans:
        return Result.ok("%s is a literal SAN entry" % host, sans=sans)
    wildcards = [s for s in sans if s.startswith("*.")]
    if wildcards:
        return Result.fail(
            "the verifier host is only covered by a wildcard SAN",
            cause="client id x509_san_dns:%s must appear literally in a SAN; the "
                  "certificate offers %s and the resolver does no wildcard matching. "
                  "Using the wildcard name as the client id works but is not "
                  "spec-compliant." % (host, sans),
            fix="issue a certificate carrying DNS:%s and set "
                "clientIdentification.id to x509_san_dns:%s" % (host, host),
            doc=DOC_CLIENT_ID,
            sans=sans)
    return Result.fail(
        "the verifier host is absent from the certificate SANs",
        cause="serving CN=%s with SANs %s, but the client id needs %s"
              % (info["cn"], sans, host),
        fix="issue a certificate that covers %s" % host,
        doc=DOC_CLIENT_ID,
        sans=sans)


@check("client-id-scheme", "The client id scheme matches how the request object is signed",
       phase="static", roles=("provider",))
def client_id_scheme(ctx) -> Result:
    """Each identifier prefix carries obligations, and the verifier honours none.

    VCVerifier treats `clientIdentification.id` as an opaque string: it has no
    `client_id_scheme` logic, it always signs the request object, and it never
    emits `client_metadata`. So whether the wallet accepts what we send depends
    entirely on which prefix was configured, and the mismatch is invisible from
    our side - the verifier logs a healthy 200 and the wallet reports something
    generic like "could not process the information request".

    Three combinations are worth naming, all three learned the hard way:

    - `redirect_uri` requires `client_metadata` and forbids signing the request.
      We do the opposite of both.
    - `x509_san_dns` requires an x5c header, which needs `certificatePath`; the
      chain is omitted silently when it is unset.
    - a DID needs a `kid` naming a verification method in the DID document. The
      bare DID is not one, and the fallback when `kid` is unset is the bare id.
    """
    scheme, client_id = _client_id_scheme(ctx)
    if client_id is None:
        return Result.skip(
            "no verifier clientIdentification.id could be read",
            cause="neither the release values nor the verifier's own ConfigMap "
                  "states one, so which scheme it identifies by is unknown")

    ident = _client_identification(ctx)
    signing_key = ident.get("keyPath")
    cert_path = ident.get("certificatePath")
    kid = ident.get("kid")
    detail = {"scheme": scheme, "clientId": client_id, "kid": kid,
              "keyPath": signing_key, "certificatePath": cert_path}

    if scheme == "redirect_uri" and signing_key:
        return Result.warn(
            "the redirect_uri scheme is used with a signed request object",
            cause="clientIdentification.id = %s, and keyPath = %s means the request "
                  "object is signed. OID4VP says of this prefix: \"Requires "
                  "client_metadata. MUST NOT be signed.\" VCVerifier always signs and "
                  "never emits client_metadata, so a wallet enforcing the scheme will "
                  "reject the request; a lenient one ignores the signature, which "
                  "leaves the request unauthenticated." % (client_id, signing_key),
            fix="either identify by DID (id + kid pointing at a verification method in "
                "the DID document) or x509_san_dns with a certificatePath - or accept "
                "the non-conformance deliberately and record which wallets were tested",
            doc=DOC_CLIENT_ID_SCHEME, **detail)

    if scheme in ("x509_san_dns", "x509_san_uri") and not cert_path:
        return Result.warn(
            "the %s scheme is used without a certificate to embed" % scheme,
            cause="clientIdentification.id = %s, but certificatePath is unset, so no "
                  "x5c header is added - the verifier logs \"No certificate chain for "
                  "client identity\" at debug and signs with the kid alone. The peer "
                  "has nothing to compare the client id against." % client_id,
            fix="set clientIdentification.certificatePath to the certificate whose SAN "
                "carries %s" % client_id.split(":", 1)[-1],
            doc=DOC_CLIENT_ID_SCHEME, **detail)

    if scheme in ("did", "decentralized_identifier"):
        effective_kid = kid or client_id
        if "#" not in effective_kid:
            return Result.warn(
                "the DID client id has no verification method to resolve",
                cause="kid resolves to %s, which is the bare DID. A DID document "
                      "publishes keys as <did>#<fragment>, so the wallet has no "
                      "verification method to check the request signature against%s."
                      % (effective_kid,
                         "" if kid else " (kid is unset, and the verifier falls back "
                                        "to id)"),
                fix="set clientIdentification.kid to <did>#<fragment published in the "
                    "DID document>",
                doc=DOC_CLIENT_ID_SCHEME, **detail)

    return Result.ok("%s, consistent with how the request is signed" % scheme, **detail)


def _jwks_address(lane):
    """The VERIFIER's JWKS, which is the one that has to match our identity key.

    `jwksAddress` is present and empty in every deployment inspected, so this check
    has never actually run - worth knowing, and worth fixing at the source rather
    than here.

    It is tempting to fall back to `fdscTransfer.<proto>.oid.*`, which is where the
    gateway fetches keys for EDR tokens. Do not: that is the controlplane's own
    RS256 EDR-signing key (`kid=sig`), a different key from the participant's EC
    identity key on purpose, and comparing them reports a FAIL on a healthy
    deployment. Measured: secret b44b027528d9c971 against a JWKS advertising
    296d8a28f91a22ae, neither of which is wrong. A separate check could compare
    what APISIX holds against that EDR JWKS; this one is not it.
    """
    return (lane.prop("jwksAddress") or "").strip() or None


# Both paths, and this is the check the whole set exists for. It is lane-scoped -
# `jwksAddress` is read from the lane config - so it looks like an fdsc-edc check,
# but what it measures is APISIX holding a stale key from OUR verifier, and APISIX
# guards the FIWARE data services too. Gating it to `edc` would have hidden it from
# exactly the run that asks about the gateway.
@check("verifier-jwks-matches-key", "The verifier publishes the key it signs with",
       needs_cluster=True, lanes=["*"], transport=("edc", "fiware"))
def verifier_jwks_matches_key(ctx, lane) -> Result:
    """The failure that looks exactly like a counterparty problem.

    **It was called `apisix-jwks-staleness`, and that was a promise it could not
    keep.** It reads nothing from APISIX. APISIX keeps its JWKS in an internal lua
    dictionary; the admin API exposes route configuration, not cache contents, so
    no check can see what the gateway is holding. What this compares is what the
    verifier *publishes* against what the signing secret *contains* - which
    catches the verifier failing to pick up a rotated key, the upstream half of
    the same story. Whether a gateway then cached the old document is only
    discoverable by presenting it a token, which is the flow phase's job.


    The /api/dsp routes are guarded by openid-connect with use_jwks against our
    own verifier. `clientIdentification.kid` is a fixed literal, so after a key
    rotation the verifier republishes the new key under the same kid: a kid miss
    would force a refetch, a kid hit with the wrong key just fails forever. The
    catalog still works (it does not traverse that route), the verifier still
    issues tokens, and the negotiation even gets a correlationId - so everything
    looks healthy while callbacks 401.
    """
    jwks_url = _jwks_address(lane)
    if not jwks_url:
        return Result.na(
            "jwksAddress is not set on this lane, so there is no verifier "
            "JWKS to compare our signing key against")

    # The connector advertises its JWKS by its in-cluster name, which does not
    # resolve from wherever this is being run, so reach it the way ctx.til_issuer
    # reaches the trusted issuers list: through a port-forward to the service the
    # URL names. Without this the check swapped one skip for another.
    service, port = _service_from_url(jwks_url)
    path = "/" + jwks_url.split("://", 1)[-1].split("/", 1)[-1] if "/" in \
        jwks_url.split("://", 1)[-1] else "/"
    if service is None:
        resp = http.get(jwks_url, insecure=ctx.insecure)
    else:
        try:
            with PortForward(ctx.kube, service, port,
                             namespace=ctx.deployment.namespace) as pf:
                resp = http.get("%s%s" % (pf.base_url, path))
        except KubeError as exc:
            return Result.skip("could not reach %s (%s)" % (jwks_url, exc))
    if resp.error or not resp.ok:
        return Result.skip("could not fetch %s (%s)" % (jwks_url, resp.error or resp.status))
    keys = (resp.json() or {}).get("keys") or []
    if not keys:
        return Result.warn("the verifier publishes no JWKS keys", jwks=jwks_url)

    published = {jose.jwk_fingerprint(k): k.get("kid") for k in keys}

    if not ctx.deployment.identity_secret:
        return Result.warn(
            "cannot compare the published JWKS with the signing key",
            cause="identity secret not resolved; set identity.secret in --config",
            kids=[k.get("kid") for k in keys])

    secret = ctx.kube.secret(ctx.deployment.identity_secret)
    key_name = ctx.deployment.identity_secret_key or "tls.key"
    if key_name not in secret:
        return Result.skip("secret %s has no %s" % (ctx.deployment.identity_secret, key_name))
    try:
        current = jose.jwk_fingerprint(jose.public_jwk_from_pem(secret[key_name]))
    except Exception as exc:  # noqa: BLE001
        return Result.skip("could not derive the public key: %s" % exc)

    if current not in published:
        return Result.fail(
            "the verifier publishes a JWKS that does not match the signing key",
            cause="the secret holds %s, the JWKS advertises %s - the verifier has "
                  "not picked up the current key" % (current, sorted(published)),
            fix="rollout restart the verifier",
            doc=DOC_APISIX_JWKS,
            published=list(published.values()))

    # the key is right; now ask whether the gateway could still be caching the old one
    gateway = ctx.deployment.service("apisix")
    if not gateway:
        return Result.ok("the published JWKS matches the signing key (no apisix here)")

    secret_age = _resource_age(ctx, "secret", ctx.deployment.identity_secret)
    gateway_age = _resource_age(ctx, "pod", None, selector="app.kubernetes.io/name=apisix")
    detail = {"kid": published[current], "secretAgeMin": secret_age, "gatewayAgeMin": gateway_age}
    if secret_age is not None and gateway_age is not None and gateway_age > secret_age:
        return Result.fail(
            "the gateway predates the identity secret and may be caching the old JWKS",
            cause="the apisix pod started %d min ago, the secret changed %d min ago. "
                  "Because the kid never changes, apisix will not refetch: inbound "
                  "callbacks 401 with 'jwt signature verification failed' while "
                  "everything else looks healthy."
                  % (gateway_age, secret_age),
            fix="kubectl -n %s rollout restart deploy/%s"
                % (ctx.deployment.namespace, gateway),
            doc=DOC_APISIX_JWKS,
            **detail)
    return Result.ok("the published JWKS matches the signing key", **detail)


def _resource_age(ctx, kind: str, name: Optional[str], selector: str = None) -> Optional[int]:
    """Age in minutes of a resource, or of the newest match for a selector."""
    args = ["get", kind]
    if name:
        args.append(name)
    if selector:
        args += ["-l", selector]
    args += ["-o", "json"]
    try:
        data = ctx.kube.run(*args, check=False)
    except Exception:  # noqa: BLE001
        return None
    if not data:
        return None
    import json as _json

    try:
        parsed = _json.loads(data)
    except ValueError:
        return None
    items = parsed.get("items", [parsed]) if "items" in parsed else [parsed]
    stamps = []
    for item in items:
        stamp = (item.get("metadata") or {}).get("creationTimestamp")
        if stamp:
            try:
                stamps.append(datetime.datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ"))
            except ValueError:
                continue
    if not stamps:
        return None
    newest = max(stamps)
    return int((datetime.datetime.utcnow() - newest).total_seconds() // 60)
