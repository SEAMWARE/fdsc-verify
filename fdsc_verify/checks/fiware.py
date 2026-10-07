"""The FIWARE DSC data path, probed without a credential.

A dataspace participant can move data two ways, and a deployment with both
deployed runs both: the Dataspace Protocol through fdsc-edc, and the native
FIWARE path - a Verifiable Credential presented to the verifier, exchanged for a
token, and spent at the APISIX gateway, which asks OPA whether the ODRL policy
allows it. They fail independently, which is why they are separate transports
here and why `--transport` can ask for one at a time.

**These two checks do not present a credential.** Doing that properly means being
a wallet: getting a VC out of Keycloak over OID4VCI, minting a key, building and
signing a Verifiable Presentation. That is a separate piece of work and it needs a
test user somebody has to provision - which would break the promise that
`--no-write` creates nothing.

What is left without one is still worth having, because it separates *the door is
hung wrong* from *my credential was refused*, and those get confused constantly:

- the gateway **demands** a credential rather than serving the data to anyone, and
  is reachable at all on the hosts it publishes;
- the verifier **publishes what the gateway needs** to validate one - an OIDC
  discovery document per registered service, and a JWKS behind it.

Neither proves a real credential is accepted. Both prove that when one is refused,
the refusal means something.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from .. import http
from ..model import Result, check
from .certs import _client_id_scheme, _verifier_host
from .identity import DOC_REGISTRATION

# What a properly guarded APISIX route answers, and what each one means. 403 counts:
# the gateway authenticated the request and OPA denied it, which is still a gate.
_GUARDED = {401: "unauthenticated", 403: "denied by policy"}


def _auth_redirect(resp) -> Optional[str]:
    """A 3xx to an OAuth2 authorization request is a refusal, not an answer.

    APISIX guards API routes with `bearer_only: true`, which refuses with the 401
    everyone expects. Browser-facing routes use `bearer_only: false`, which refuses
    by *redirecting* to the IdP - and a probe that follows redirects lands on a
    login page and reads 200, i.e. "this host serves data to anybody". That false
    positive was reported on demo's edc-dashboard, which is correctly guarded.

    Recognised by the OAuth2 authorization-request shape (`response_type` plus
    `client_id`) rather than by any provider's URL, so it holds for something other
    than Keycloak.
    """
    if resp.status not in (301, 302, 303, 307, 308):
        return None
    location = resp.header("location") or ""
    if "response_type=" in location and "client_id=" in location:
        return location.split("?", 1)[0]
    return None


@check("flow-fiware-gate", "The gateway demands a credential for the data it fronts",
       phase="flow", needs_cluster=True, roles=("provider",), transport="fiware")
def flow_native_gate(ctx) -> Result:
    """Every host the gateway publishes, asked for data with no token at all.

    The interesting answer is `401` with a `WWW-Authenticate` header - that is the
    gate doing its job, and the header names the realm the operator will search
    for. A published host that answers nothing at all is the finding: an Ingress
    exists for it, so somebody meant it to be reachable.

    The DSP hosts are not probed here even though the same APISIX fronts them;
    `dsp-route` owns those, and in a deployment running both transports one
    gateway serves `dsp-producer` and `mp-data-service` alike.
    """
    hosts, err = ctx.gateway_hosts()
    if err:
        return Result.skip("the gateway's published hosts could not be listed",
                           cause=err)
    if not hosts:
        return Result.skip(
            "no published host routes to the gateway",
            cause="either nothing is exposed through it yet, or every Ingress that "
                  "does belongs to the DSP transport, which dsp-route probes")

    guarded: List[str] = []
    open_hosts: List[str] = []
    unreachable: List[str] = []
    other: List[str] = []
    detail: Dict[str, object] = {}
    for host in hosts:
        resp = http.get("https://%s/" % host, insecure=ctx.insecure,
                        follow_redirects=False)
        if resp.error:
            unreachable.append("%s: %s" % (host, resp.error))
            continue
        idp = _auth_redirect(resp)
        if idp:
            guarded.append("%s -> %d (redirected to %s)" % (host, resp.status, idp))
        elif resp.status in _GUARDED:
            challenge = resp.header("www-authenticate")
            guarded.append("%s -> %d%s" % (host, resp.status,
                                           " (%s)" % challenge if challenge else ""))
        elif resp.ok:
            open_hosts.append("%s -> %d" % (host, resp.status))
        else:
            other.append("%s -> %d" % (host, resp.status))
    detail = {"guarded": guarded, "answeredWithoutCredential": open_hosts,
              "unreachable": unreachable, "other": other}

    if unreachable:
        return Result.fail(
            "%d published host(s) do not answer at all" % len(unreachable),
            cause="%s. An Ingress publishes them, so somebody meant them to be "
                  "reachable; nothing behind the gateway can be consumed until they "
                  "are." % "; ".join(unreachable),
            fix="check the gateway's own pods and the DNS for those hosts",
            **detail)
    if open_hosts:
        return Result.warn(
            "%d published host(s) answered without a credential" % len(open_hosts),
            cause="%s. That may be a public landing path rather than the data itself - "
                  "this probe asks for `/` and not for a protected resource - but on a "
                  "gateway whose whole job is to demand a credential it is worth one "
                  "look." % "; ".join(open_hosts),
            fix="request the actual data path with no token and confirm it is refused",
            **detail)
    if not guarded:
        return Result.warn(
            "no published host refused the request the way a gate would",
            cause="; ".join(other) or "nothing answered 401 or 403",
            **detail)
    summary = "%d of %d published host(s) demand a credential: %s" % (
        len(guarded), len(hosts), "; ".join(guarded))
    if other:
        # 404 on `/` is the ambiguous one: APISIX routes by path, so a host with no
        # route for the root answers the same way a host pointing at somebody else
        # would. Reported, not judged.
        return Result.ok(summary, note="%s answered something else: %s. On `/` that is "
                                       "usually just no route for the root path"
                                       % (len(other), "; ".join(other)), **detail)
    return Result.ok(summary, **detail)


@check("flow-fiware-discovery", "The verifier publishes what the gateway validates with",
       phase="flow", needs_cluster=True, roles=("provider",), transport="fiware")
def flow_native_discovery(ctx) -> Result:
    """One OIDC discovery document per registered service, and a JWKS behind it.

    This is exactly what APISIX consumes: its `openid-connect` plugin is pointed at
    `/services/<id>/.well-known/openid-configuration` and follows the `jwks_uri` it
    finds there. A service registered in the verifier's config repo but with no
    discovery document is a login that cannot be validated no matter how good the
    credential is - and the wallet reports it as the same generic "could not
    process the information request" that a dozen other faults produce.
    """
    services, err = ctx.verifier_services()
    if err or services is None:
        return Result.skip("the verifier's config repo could not be read", cause=err)
    ids = [s.get("id") for s in services if isinstance(s, dict) and s.get("id")]
    if not ids:
        return Result.skip("the verifier has no registered service to look up")

    _, client_id = _client_id_scheme(ctx)
    host = _verifier_host(ctx, client_id or "")
    if not host:
        return Result.skip("the verifier's public host could not be resolved")

    served: Dict[str, str] = {}
    missing: List[str] = []
    jwks_uris: List[str] = []
    for service_id in ids:
        url = "https://%s/services/%s/.well-known/openid-configuration" % (host, service_id)
        resp = http.get(url, insecure=ctx.insecure)
        if resp.error:
            missing.append("%s: %s" % (service_id, resp.error))
            continue
        if not resp.ok:
            missing.append("%s: HTTP %d" % (service_id, resp.status))
            continue
        body = resp.json() or {}
        jwks_uri = body.get("jwks_uri")
        if not jwks_uri:
            missing.append("%s: the document carries no jwks_uri" % service_id)
            continue
        served[service_id] = jwks_uri
        if jwks_uri not in jwks_uris:
            jwks_uris.append(jwks_uri)

    keys_by_uri: Dict[str, int] = {}
    for uri in jwks_uris:
        resp = http.get(uri, insecure=ctx.insecure)
        keys = len(((resp.json() or {}).get("keys") or [])) if resp.ok else 0
        keys_by_uri[uri] = keys

    detail = {"host": host, "served": served, "missing": missing, "jwks": keys_by_uri}
    if missing:
        return Result.fail(
            "%d registered service(s) publish no usable discovery document"
            % len(missing),
            cause="%s. The gateway's openid-connect plugin reads exactly this "
                  "document and follows its jwks_uri, so a login against one of these "
                  "cannot be validated however good the credential is - and the wallet "
                  "reports it as 'could not process the information request', naming "
                  "none of it." % "; ".join(missing),
            fix="re-run the verifier registration (see registration-job-hooks) so the "
                "service is served as well as stored",
            doc=DOC_REGISTRATION, **detail)
    empty = [uri for uri, keys in keys_by_uri.items() if not keys]
    if empty:
        return Result.fail(
            "the verifier advertises a JWKS with no keys in it",
            cause="%s served no key. Every token it issues would be unverifiable by "
                  "the gateway." % ", ".join(empty),
            fix="rollout restart the verifier and check its signing key is mounted",
            **detail)
    return Result.ok(
        "%d service(s) served, %s" % (
            len(served),
            ", ".join("%s: %d key(s)" % (uri.rsplit("/", 1)[-1], keys)
                      for uri, keys in keys_by_uri.items())),
        **detail)
