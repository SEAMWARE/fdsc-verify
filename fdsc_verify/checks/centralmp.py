"""A provider that publishes through somebody else's marketplace.

A provider need not run a marketplace. It can publish through a **central** one,
and then two things matter that nothing checked: the central marketplace has to be
able to reach our contract-management, and the integrations contract-management
declares have to exist.

The tool knew this shape only as an absence - four marketplace checks go quiet
with "a provider may use a central one instead", and
`contract-management-subscriptions` warns saying in its own words that from
outside it cannot tell the two shapes apart. These two checks give that absence a
positive reading.

**The shape is not the flag.** `contract-management.enableCentralMarketplace` is
true on deployments that run their own marketplace as well - measured on three of
four - so detecting the shape by it sweeps in a provider that has its own. The
shape is *contract-management deployed and no local marketplace*; the flag is then
one of the things to check rather than the thing to detect by.

**Where a route goes is only in the values.** Every published host points at the
APISIX Service on its Ingress and they answer an identical `401`, so neither the
Ingress nor a probe from outside says which one reaches contract-management. The
upstream is in `decentralizedIam.odrlAuthorization.apisix.routes`, which is also
where the fix goes - and there are no APISIX CRDs here to read instead.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from ..model import Result, check

DOC_ROUTE = "the-central-marketplace-cannot-reach-contract-management"
DOC_WIRING = "contract-management-is-wired-to-something-that-is-not-deployed"

ROUTES_PATH = "decentralizedIam.odrlAuthorization.apisix.routes"
CM_SERVICE_PREFIX = "contract-management"
CENTRAL_MP_FLAG = "contract-management.enableCentralMarketplace"

# Which `enable*` flag turns each configured endpoint on. A URL is only held
# against the deployment when its integration is switched on: `services.rainbow`
# is configured on every deployment here and `enableRainbow` is false on all of
# them, so checking the URL alone would report a fault on every one.
SERVICE_FLAGS: Dict[str, str] = {
    "party": "enableTmForum",
    "product-catalog": "enableTmForum",
    "product-order": "enableTmForum",
    "service-catalog": "enableTmForum",
    "tmforum-agreement-api": "enableTmForum",
    "quote": "enableTmForum",
    "trusted-issuers-list": "enableTrustedIssuersList",
    "odrl": "enableOdrlPap",
    "rainbow": "enableRainbow",
}


def _central_marketplace(ctx) -> Optional[Result]:
    """The N/A both checks here share, and the definition of the shape.

    Three conditions, and all three are needed. The two Service lookups are the
    cluster's to answer, as presence always is. The flag is the third because the
    first two alone are not the shape: a **consumer** that runs contract-management
    and no marketplace matches them exactly, and gets swept in - measured, it was
    reported as a provider with a broken central-marketplace route.

    The flag is not enough on its own either, which is the other half of the same
    point: it is true on deployments that run their own marketplace as well, on
    three of the four measured.
    """
    if not ctx.deployment.service("contractmanagement"):
        return Result.na(
            "no contract-management in this namespace",
            cause="integration with a central marketplace is contract-management's "
                  "job; without it this deployment publishes through nobody and "
                  "there is no integration to check")
    if ctx.deployment.service("marketplace"):
        return Result.na(
            "this provider runs its own marketplace",
            cause="a local marketplace is deployed here, so the catalogue is driven "
                  "from inside this namespace and the `marketplace-*` checks are the "
                  "ones that apply")
    if ctx.values.get(CENTRAL_MP_FLAG) is not True:
        return Result.na(
            "this deployment does not declare a central marketplace",
            cause="there is no local marketplace and `%s` is not set, so nothing "
                  "says a central one drives this catalogue. If one does, setting "
                  "that flag is what turns these checks on - and "
                  "contract-management-subscriptions is what reports a provider "
                  "whose catalogue nothing drives at all" % CENTRAL_MP_FLAG)
    return None


def _routes(ctx) -> list:
    declared = ctx.values.get(ROUTES_PATH)
    return [route for route in declared if isinstance(route, dict)] \
        if isinstance(declared, list) else []


def _upstream_services(route: dict) -> List[str]:
    """The service names a route forwards to.

    `upstream.nodes` is a mapping of `host:port` to weight, not a list, and the
    service name is what precedes the colon in each **key**.
    """
    nodes = (route.get("upstream") or {}).get("nodes") or {}
    names = nodes if isinstance(nodes, dict) else {}
    return [str(node).rsplit(":", 1)[0] for node in names]


@check("central-mp-contract-management-route",
       "The central marketplace can reach contract-management",
       needs_cluster=True, lanes=None, roles=("provider",), transport="fiware")
def central_mp_contract_management_route(ctx) -> Result:
    """The way in, from a marketplace that lives somewhere else.

    A central marketplace drives this provider's catalogue by calling its
    contract-management. That call arrives through our own APISIX, so a route has
    to exist, its host has to be published, it has to refuse the way a machine
    expects, and the client it authenticates as has to be one the verifier knows.

    Each of those fails differently and none of them is visible from inside: the
    marketplace simply never manages to publish anything here, and nothing in this
    namespace logs a reason.
    """
    absent = _central_marketplace(ctx)
    if absent:
        return absent

    routes = _routes(ctx)
    if not routes:
        return Result.skip(
            "the gateway's routes could not be read",
            cause="`%s` is absent from the values, so which host reaches "
                  "contract-management cannot be told - the Ingress only says every "
                  "host goes to APISIX, and they all answer the same 401"
                  % ROUTES_PATH)

    matching = [route for route in routes
                if any(name == CM_SERVICE_PREFIX or name.endswith("-" + CM_SERVICE_PREFIX)
                       for name in _upstream_services(route))]
    if not matching:
        return Result.fail(
            "no gateway route forwards to contract-management",
            cause="%d route(s) are declared in `%s` and none has contract-management "
                  "as its upstream, so a central marketplace has no way in. It will "
                  "fail to publish anything here and nothing in this namespace will "
                  "say why" % (len(routes), ROUTES_PATH),
            fix="add a route whose upstream is `contract-management:8080`, guarded "
                "by openid-connect with bearer_only, and publish its host",
            doc=DOC_ROUTE, routes=len(routes))

    hosts, err = ctx.gateway_hosts()
    published = set(hosts or [])
    services, services_err = ctx.verifier_services()
    registered = {s.get("id") for s in services or [] if isinstance(s, dict)}

    unpublished: List[str] = []
    interactive: List[str] = []
    unregistered: List[str] = []
    good: List[str] = []
    for route in matching:
        host = str(route.get("host") or "")
        plugins = route.get("plugins") or {}
        oidc = plugins.get("openid-connect") or {}
        client_id = oidc.get("client_id")
        if err is None and host and host not in published:
            unpublished.append(host)
            continue
        if oidc and oidc.get("bearer_only") is not True:
            interactive.append(host or "?")
            continue
        if services is not None and client_id and client_id not in registered:
            unregistered.append("%s (client `%s`)" % (host or "?", client_id))
            continue
        good.append(host or "?")

    detail = {"hosts": [r.get("host") for r in matching], "published": sorted(published),
              "unpublished": unpublished, "interactive": interactive,
              "unregistered": unregistered}

    if unpublished:
        return Result.fail(
            "the route to contract-management is not published",
            cause="%s is routed in the gateway and no Ingress publishes it, so the "
                  "route exists and nothing outside can reach it. Published here: %s"
                  % (", ".join(unpublished), ", ".join(sorted(published)) or "nothing"),
            fix="publish the host on the gateway's Ingress and point its DNS record "
                "at this cluster",
            doc=DOC_ROUTE, **detail)
    if unregistered:
        return Result.fail(
            "contract-management's route authenticates as a client the verifier "
            "does not know",
            cause="%s, and the verifier's config repo holds %s. APISIX will ask for "
                  "a token against a discovery document that does not exist, so "
                  "every call the central marketplace makes is refused"
                  % ("; ".join(unregistered), sorted(registered) or "nothing"),
            fix="register that client id as a service on the verifier's config port, "
                "or point the route at one that is registered",
            doc=DOC_ROUTE, **detail)
    if interactive:
        return Result.warn(
            "contract-management's route refuses by redirecting, not by 401",
            cause="%s is guarded with `bearer_only` off, so an unauthenticated call "
                  "is answered with a redirect to the IdP. That is right for a "
                  "browser and useless for the central marketplace, which calls "
                  "machine to machine and has no session to establish"
                  % ", ".join(interactive),
            fix="set bearer_only: true on that route's openid-connect plugin",
            doc=DOC_ROUTE, **detail)

    summary = "contract-management is reachable at %s" % ", ".join(good)
    if err:
        summary += " (published hosts could not be listed)"
    if services_err:
        summary += " (the verifier's config repo could not be read)"
    return Result.ok(summary, **detail)


@check("central-mp-contract-management-wiring",
       "What contract-management is configured to call is deployed",
       needs_cluster=True, lanes=None, roles=("provider",), transport="fiware")
def central_mp_contract_management_wiring(ctx) -> Result:
    """Configured to call something that is not there.

    contract-management reaches a handful of APIs, each switched on by its own
    `enable*` flag and addressed by a URL. Where the flag is on and the URL names
    an in-cluster service that does not exist, every call down that path fails
    against a host that does not resolve - and the deployment looks complete.

    The flags matter as much as the URLs: `services.rainbow` is configured on every
    deployment inspected and `enableRainbow` is false on all of them, so holding
    the URL against the deployment on its own reports a fault on every one.
    """
    absent = _central_marketplace(ctx)
    if absent:
        return absent

    block = ctx.values.get("contract-management")
    if not isinstance(block, dict) or not block:
        return Result.skip(
            "contract-management's configuration could not be read",
            cause="`contract-management` is absent from the values, so which "
                  "integrations it declares is unknown")

    configured = block.get("services") or {}
    absent: Dict[str, dict] = {}
    checked = 0
    for key, entry in sorted(configured.items()):
        flag = SERVICE_FLAGS.get(key)
        if flag and block.get(flag) is not True:
            continue
        url = (entry or {}).get("url") if isinstance(entry, dict) else None
        if not url:
            continue
        host = str(url).split("://")[-1].split("/")[0].split(":")[0]
        # only in-cluster names are ours to confirm; an external URL is somebody
        # else's deployment and resolving it is not this check's business
        if "." in host or not host:
            continue
        checked += 1
        if not ctx.kube.get_json("service", host,
                                 namespace=ctx.deployment.namespace, check=False):
            absent.setdefault(host, {"flags": set(), "keys": []})
            absent[host]["flags"].add(flag or "no flag")
            absent[host]["keys"].append(key)

    # Aggregated by host, because one missing service is reached through six
    # endpoint keys and naming each of them turns one fault into six lines of the
    # same sentence.
    missing = ["`%s`, reached by %d endpoint(s) (%s)"
               % (host, len(info["keys"]), ", ".join(sorted(info["flags"])))
               for host, info in sorted(absent.items())]
    detail = {"checked": checked, "missing": missing,
              "endpoints": {h: sorted(i["keys"]) for h, i in sorted(absent.items())}}

    if missing:
        return Result.warn(
            "%d configured service(s) are not deployed here" % len(absent),
            cause="%s. The flag says the integration is on and no Service of that "
                  "name exists in this namespace, so every call down that path goes "
                  "to a host that does not resolve - while the deployment looks "
                  "complete. `-v`, or `endpoints` in `--json`, lists which keys "
                  "point at each" % "; ".join(missing),
            fix="deploy what the flag turns on, point the URL at wherever it really "
                "runs, or switch the flag off",
            doc=DOC_WIRING, **detail)

    return Result.ok("%d configured integration(s) are deployed" % checked, **detail)
