"""The local Marketplace: can anyone log in, and is there anything to find.

The tool knew the marketplace existed and nothing else. These three ask what
makes a provider's own MP worth deploying: that the client id it authenticates
with is registered in the verifier, that it protects more than its own front
door, and that something is published in a state a counterparty can discover.

Four things about the two marketplaces in this dataspace shaped every line here,
and each one breaks the obvious implementation:

* **The logic proxy is a StatefulSet.** `kubectl get deploy <name>` answers
  NotFound for it, so the environment is read through the Service's selector
  rather than off a workload kind that was assumed.
* **`service("marketplace")` used to resolve to the charging backend**, because
  discovery let alphabetical order of service names decide. Fixed in
  `discovery.py`; mentioned here because every probe below depends on talking to
  the right one.
* **The two deployments use different auth stacks.** demo's `producer` runs OIDC
  and carries the client id in `BAE_LP_OAUTH2_CLIENT_ID`; `central-mk` runs SIOP
  and carries it in `BAE_LP_SIOP_CLIENT_ID`, with the other variable absent
  entirely. Reading one fixed name reports a false negative on one of the two.
* **The lifecycle vocabularies disagree.** producer says `Launched`/`Retired`,
  central-mk says `Active`/`In design`/`Launched`, and producer has a catalog
  whose `lifecycleStatus` is absent altogether - which a `== "Launched"` filter
  drops in silence.
"""

from __future__ import annotations

import json
from typing import Dict, List, Optional, Tuple

from .. import http
from ..kube import KubeError, PortForward
from ..model import Result, check

DOC_LOGIN = "the-marketplace-cannot-log-anyone-in"
DOC_OFFERINGS = "nothing-in-the-catalogue-is-discoverable"
DOC_COMPLETENESS = "an-offering-is-published-and-nothing-downstream-happens"

# Which env var carries the login client id depends on which stack is switched on.
# In declaration order: the flag that turns the mode on, and the id it then uses.
AUTH_MODES = (("oidc", "BAE_LP_OIDC_ENABLED", "BAE_LP_OAUTH2_CLIENT_ID"),
              ("siop", "BAE_LP_SIOP_ENABLED", "BAE_LP_SIOP_CLIENT_ID"))

# A state a counterparty can actually find the thing in. Two vocabularies, because
# the charts differ and pinning one misfires on the other; kept as data so a third
# is a line here rather than a new branch.
DISCOVERABLE = ("launched", "active")

# Where the values declare the passthrough environment of the logic proxy.
VALUES_ENV = "marketplace.bizEcosystemLogicProxy.additionalEnvVars"


def _no_marketplace(ctx) -> Optional[Result]:
    """The N/A every check here shares: a provider may use a central MP instead."""
    if not ctx.deployment.service("marketplace"):
        return Result.na(
            "no marketplace in this namespace",
            cause="a local marketplace is Optional for a provider - one integrated "
                  "with a central marketplace has none, and that is a deployment "
                  "shape rather than something missing")
    return None


def _login_client_id(ctx) -> Tuple[Optional[str], Optional[str], Dict[str, str]]:
    """(mode, client id, env) for whichever auth stack the logic proxy has on."""
    env = ctx.workload_env(ctx.deployment.service("marketplace"))
    for mode, flag, id_var in AUTH_MODES:
        if (env.get(flag) or "").strip().lower() == "true":
            return mode, (env.get(id_var) or "").strip() or None, env
    return None, None, env


def _declared_env(ctx) -> Dict[str, str]:
    """The same variables as the values declare them, for the drift comparison."""
    declared = ctx.values.get(VALUES_ENV) or []
    out: Dict[str, str] = {}
    for entry in declared:
        if isinstance(entry, dict) and entry.get("name"):
            out[entry["name"]] = str(entry.get("value"))
    return out


@check("marketplace-login-service",
       "The marketplace's login client is registered in the verifier",
       needs_cluster=True, roles=("provider",), transport="fiware")
def marketplace_login_service(ctx) -> Result:
    """Nobody gets into the MP unless the verifier knows the client it presents.

    The failure is total and silent from the outside: the login page redirects,
    the verifier answers a request object with no presentation definition, and the
    wallet says "could not process the information request" - the same generic
    sentence a dozen other faults produce.
    """
    absent = _no_marketplace(ctx)
    if absent:
        return absent

    mode, client_id, env = _login_client_id(ctx)
    if mode is None:
        return Result.skip(
            "neither auth stack is switched on in the logic proxy",
            cause="BAE_LP_OIDC_ENABLED and BAE_LP_SIOP_ENABLED are both off or "
                  "absent, so there is no login client id to check. Read %d "
                  "variable(s) from %s" % (len(env), ctx.deployment.service("marketplace")))
    if not client_id:
        return Result.fail(
            "%s login is on but no client id is configured" % mode,
            cause="the logic proxy has %s enabled and the variable that carries the "
                  "client id for that mode is empty or absent" % mode,
            fix="set the client id for the %s stack on the logic proxy" % mode,
            doc=DOC_LOGIN, mode=mode)

    services, err = ctx.verifier_services()
    if services is None:
        return Result.skip("could not read the verifier's config repo", cause=err)
    registered = [s.get("id") for s in services if isinstance(s, dict)]

    detail = {"mode": mode, "clientId": client_id, "registered": sorted(
        i for i in registered if i)}
    # A placeholder that reached the registry verbatim. Found on demo's producer
    # and consumer: the registration script single-quotes the JSON body, so a
    # `${DID}` in the values is stored literally while the job's own log line
    # prints the resolved DID - the log actively misleads.
    placeholders = sorted(i for i in registered if i and "${" in i)

    if client_id not in registered:
        return Result.fail(
            "the marketplace's login client is not registered in the verifier",
            cause="the logic proxy authenticates as `%s` (%s mode) and the "
                  "verifier's config repo holds %s. A login attempt resolves to a "
                  "request object with no presentation_definition, which the wallet "
                  "reports as \"could not process the information request\""
                  % (client_id, mode, sorted(i for i in registered if i)),
            fix="register that id as a service on the verifier's config port, or "
                "correct the client id the logic proxy uses - they have to be the "
                "same string, path suffix included",
            doc=DOC_LOGIN, **detail)

    declared = _declared_env(ctx)
    _, _, id_var = next(m for m in AUTH_MODES if m[0] == mode)
    stated = (declared.get(id_var) or "").strip()
    if stated and stated != client_id:
        return Result.warn(
            "the values declare a different login client id than the pod uses",
            cause="the running logic proxy authenticates as `%s`, which is "
                  "registered; `%s` in the values says `%s`. The pod is what runs, "
                  "so this is drift rather than the fault - but a redeploy would "
                  "switch the MP to an id nobody registered"
                  % (client_id, id_var, stated),
            fix="align %s in the values with what the pod uses, or redeploy" % id_var,
            doc=DOC_LOGIN, declared=stated, **detail)

    if placeholders:
        return Result.warn(
            "%d registered service id(s) are unexpanded placeholders" % len(placeholders),
            cause="%s. The registration script passes the JSON body as a "
                  "single-quoted shell argument, so a `${VAR}` in the values reaches "
                  "the verifier verbatim - while the job logs the resolved value, so "
                  "its own log says the registration succeeded under a name that was "
                  "never used. Login works because the real id is registered too"
                  % ", ".join(placeholders),
            fix="delete the placeholder services from the verifier's config port and "
                "put the literal value in registration.services[].id",
            doc=DOC_LOGIN, placeholders=placeholders, **detail)

    return Result.ok("`%s` is registered (%s login)" % (client_id, mode), **detail)


@check("marketplace-services-beyond-login",
       "The verifier protects something besides the marketplace's own front door",
       needs_cluster=True, roles=("provider",), transport="fiware")
def marketplace_services_beyond_login(ctx) -> Result:
    """Logging in is not the point; reaching data behind the gateway is.

    A verifier whose only registered service is the marketplace's login client can
    authenticate a user and then has nothing to let them into. It is the shape a
    fresh install has before anybody registers a data service, which is exactly
    when saying so is useful.
    """
    absent = _no_marketplace(ctx)
    if absent:
        return absent

    _, client_id, _ = _login_client_id(ctx)
    services, err = ctx.verifier_services()
    if services is None:
        return Result.skip("could not read the verifier's config repo", cause=err)
    registered = sorted(s.get("id") for s in services
                        if isinstance(s, dict) and s.get("id"))
    others = [i for i in registered if i != client_id]

    if not others:
        return Result.warn(
            "the only registered service is the marketplace's login client",
            cause="`%s` is the one service in the verifier's config repo, so a user "
                  "can authenticate and there is nothing behind the gateway for them "
                  "to reach. Nothing is broken; nothing is offered either"
                  % (client_id or "the login client"),
            fix="register a service for each data API the gateway should protect, "
                "under registration.services in the values",
            doc=DOC_LOGIN, registered=registered)
    return Result.ok("%d service(s) besides the login client" % len(others),
                     registered=registered)


def _catalogue(ctx, resource: str) -> Tuple[Optional[list], Optional[str]]:
    """List a TMForum productCatalogManagement resource through a port-forward.

    `limit=1000` because the default page size is 100 and a truncated list would
    make this check lie in exactly one direction - the reassuring one.
    """
    service = ctx.deployment.service("tmforum")
    if not service:
        return None, "no tm-forum-api service in this namespace"
    cache_key = "catalogue:%s" % resource
    if cache_key in ctx._cache:
        return ctx._cache[cache_key]
    try:
        with PortForward(ctx.kube, service, 8080,
                         namespace=ctx.deployment.namespace) as pf:
            resp = http.get("%s/tmf-api/productCatalogManagement/v4/%s?limit=1000"
                            % (pf.base_url, resource))
    except KubeError as exc:
        return None, "could not reach tm-forum-api: %s" % exc
    if not resp.ok:
        result = (None, "HTTP %d from /%s" % (resp.status, resource))
    else:
        body = resp.json()
        result = (body, None) if isinstance(body, list) else (None, "unexpected body")
    ctx._cache[cache_key] = result
    return result


def _status(item) -> str:
    return str((item or {}).get("lifecycleStatus") or "").strip()


@check("marketplace-offerings", "The catalogue has something discoverable in it",
       needs_cluster=True, roles=("provider",), transport="fiware")
def marketplace_offerings(ctx) -> Result:
    """A provider with nothing published is not offering anything to anybody.

    WARN rather than FAIL: a freshly installed deployment legitimately has no
    offerings yet, and turning every first report red over something that is not
    broken is how a tool teaches people to ignore it. Offerings that exist but are
    all retired is a different sentence, because that is almost always a mistake.
    """
    absent = _no_marketplace(ctx)
    if absent:
        return absent

    offerings, err = _catalogue(ctx, "productOffering")
    if offerings is None:
        return Result.skip("could not read the product catalogue", cause=err)
    catalogs, _ = _catalogue(ctx, "catalog")

    live = [o for o in offerings if _status(o).lower() in DISCOVERABLE]
    states: Dict[str, int] = {}
    for offering in offerings:
        states[_status(offering) or "(none)"] = states.get(_status(offering) or "(none)", 0) + 1
    # A catalog with no lifecycleStatus at all is the case a naive filter drops; it
    # is worth naming wherever it turns up, not only when the verdict is bad.
    stateless = [c.get("name") for c in (catalogs or []) if not _status(c)]
    detail = {"offerings": len(offerings), "discoverable": len(live),
              "states": states, "catalogsWithoutStatus": stateless}

    if not offerings:
        return Result.warn(
            "the catalogue is empty",
            cause="no productOffering at all, so there is nothing for a counterparty "
                  "to discover. On a deployment that was just installed this is "
                  "expected; on one that is meant to be serving data it is not",
            fix="publish an offering and move it to a discoverable state (%s)"
                % ", ".join(DISCOVERABLE),
            doc=DOC_OFFERINGS, **detail)
    if not live:
        return Result.warn(
            "%d offering(s), none of them discoverable" % len(offerings),
            cause="the states present are %s, and none is one a counterparty can "
                  "find (%s). Offerings that exist and are all retired is usually "
                  "somebody retiring the last one by accident"
                  % (states, ", ".join(DISCOVERABLE)),
            fix="move an offering back to a discoverable state",
            doc=DOC_OFFERINGS, **detail)

    summary = "%d of %d offering(s) discoverable" % (len(live), len(offerings))
    if stateless:
        summary += " (%d catalog(s) carry no lifecycleStatus)" % len(stateless)
    return Result.ok(summary, **detail)


# The characteristic that tells the verifier what credential to demand is spelled
# two ways in the same catalogue on demo - one offering says `credentialsConfig`
# and three say `credentialsConfiguration`. Both work; accepting only one accuses
# an offering of missing something it has, which a first cut of this check did.
CREDENTIALS_KEYS = ("credentialsConfig", "credentialsConfiguration")
POLICY_KEY = "authorizationPolicy"
# Present on an offering meant to be negotiated over DSP and absent on one served
# only through the gateway. Reported, never judged: demo has one of each and there
# is no evidence that either is wrong.
TRANSPORT_KEYS = ("endpointUrl", "upstreamAddress", "transferType", "transferPath")


def _shortfall(total: int, no_policy: int, no_credentials: int) -> str:
    """How the unusable offerings fall short, **aggregated**.

    On a real catalogue they nearly all fall short the same way, and spelling the
    same two clauses out once per offering is what made this check's cause
    unreadable: ten offerings produced fifteen lines saying one thing. The
    per-offering breakdown is still in `unusable`, which `-v` and `--json` print.
    """
    if no_policy == total and no_credentials == total:
        return ("every one of them lacks both an `%s` and a credentials "
                "characteristic" % POLICY_KEY)
    parts = []
    if no_policy:
        parts.append("%d lack `%s`, so nothing authorises access"
                     % (no_policy, POLICY_KEY))
    if no_credentials:
        parts.append("%d lack a credentials characteristic, so the verifier is "
                     "never told what to demand" % no_credentials)
    return "; ".join(parts)


def _named(names: List[str], cap: int = 5) -> str:
    """List them while the list is short enough to read, then stop counting."""
    if len(names) <= cap:
        return ", ".join(names)
    return "%s and %d more" % (", ".join(names[:cap]), len(names) - cap)


def _characteristics(spec) -> set:
    return {c.get("valueType") for c in ((spec or {}).get("productSpecCharacteristic") or [])}


@check("marketplace-offering-completeness",
       "Published offerings carry what the chain needs to act on them",
       needs_cluster=True, roles=("provider",), transport="fiware")
def marketplace_offering_completeness(ctx) -> Result:
    """An offering a counterparty can find and can never use.

    Publishing is not enough on its own. contract-management turns an offering's
    `authorizationPolicy` into the Rego that OPA evaluates at the gateway, and its
    credentials characteristic into the service entry that decides which
    credential a caller must present. An offering carrying neither is discoverable
    and inert: selectable in the catalogue, impossible to obtain anything through,
    and silent about why.

    **Only discoverable offerings are judged.** A retired one missing everything is
    not a fault, because nobody will find it - demo has two of those and flagging
    them would be noise.

    **Severity follows what the deployment can still do.** An offering is published
    *content*, not deployed *configuration*, and the exit code of this tool is a
    statement about the deployment - so a catalogue with junk in it next to
    something that works is a WARN, and only a catalogue where *nothing*
    discoverable is obtainable is a FAIL, because that is a Provider that provides
    nothing. The rule is deliberately not "at least one is fine, so downgrade":
    that would let an unrelated offering decide how bad this one is, which is the
    mistake `til-registration` made once and was corrected for. A dangling
    specification stays a FAIL either way - that is a broken reference, not an
    incomplete one.

    The complete ones are **named in every verdict**, because the common case is
    somebody adding one good offering to a catalogue full of samples and wanting to
    know whether theirs counts. Reporting only the failures made the answer to that
    invisible.

    This is where the tool stops, deliberately. Whether the policy is *correct*, or
    whether any issuer actually grants the credential it demands, needs Rego
    evaluation and a conversation with Keycloak as a wallet - which is the line in
    the README. What is checked is that the ingredients are there, not that the
    recipe works.
    """
    absent = _no_marketplace(ctx)
    if absent:
        return absent

    offerings, err = _catalogue(ctx, "productOffering")
    if offerings is None:
        return Result.skip("could not read the product catalogue", cause=err)
    specs, err = _catalogue(ctx, "productSpecification")
    if specs is None:
        return Result.skip("could not read the product specifications", cause=err)
    by_id = {s.get("id"): s for s in specs if isinstance(s, dict)}

    live = [o for o in offerings if _status(o).lower() in DISCOVERABLE]
    if not live:
        return Result.na(
            "no discoverable offering to check",
            cause="marketplace-offerings answers whether that is expected; there is "
                  "nothing here whose completeness could matter")

    unusable: List[str] = []
    complete: List[str] = []
    dangling: List[str] = []
    spellings: set = set()
    without_transport: List[str] = []
    no_policy = no_credentials = 0

    for offering in live:
        name = str(offering.get("name") or offering.get("id"))
        ref = (offering.get("productSpecification") or {}).get("id")
        spec = by_id.get(ref)
        if spec is None:
            dangling.append("%s -> %s" % (name, ref))
            continue
        present = _characteristics(spec)
        spellings |= present & set(CREDENTIALS_KEYS)
        missing = []
        if POLICY_KEY not in present:
            no_policy += 1
            missing.append("no %s, so nothing authorises access" % POLICY_KEY)
        if not (present & set(CREDENTIALS_KEYS)):
            no_credentials += 1
            missing.append("no credentials characteristic, so the verifier is never "
                           "told what to demand")
        if missing:
            unusable.append("%s: %s" % (name, "; ".join(missing)))
        else:
            complete.append(name)
        if not (present & set(TRANSPORT_KEYS)):
            without_transport.append(name)

    detail: Dict[str, object] = {
        "discoverable": len(live), "unusable": unusable, "complete": complete,
        "dangling": dangling,
        "credentialsSpellings": sorted(spellings),
        "withoutTransportCharacteristics": without_transport}

    if dangling:
        return Result.fail(
            "%d discoverable offering(s) point at a specification that is not there"
            % len(dangling),
            cause="%s. There is nothing describing what is on offer, so nothing "
                  "downstream can be built from it" % "; ".join(dangling),
            fix="restore the specification or retire the offering",
            doc=DOC_COMPLETENESS, **detail)
    if unusable:
        shortfall = _shortfall(len(unusable), no_policy, no_credentials)
        inert = ("They are discoverable and inert: a counterparty selects one in the "
                 "catalogue and obtains nothing, with no error anywhere to say why")
        where = "`-v`, or `unusable` in `--json`, names them one by one"
        repair = ("add the missing characteristics to the product specification, or "
                  "retire the offering until it is complete")
        if not complete:
            return Result.fail(
                "none of the %d discoverable offering(s) can be used" % len(live),
                cause="%s. %s. Nothing published here is obtainable at all, so this "
                      "is a catalogue with no way through it. %s"
                      % (shortfall.capitalize(), inert, where),
                fix=repair, doc=DOC_COMPLETENESS, **detail)
        return Result.warn(
            "only %d of %d discoverable offering(s) can be used: %s"
            % (len(complete), len(live), _named(complete)),
            cause="Of the other %d, %s. %s. The chain itself works, so this is the "
                  "state of the catalogue rather than of the deployment - which is "
                  "why it is a WARN; `--strict` fails the run on it. %s"
                  % (len(unusable), shortfall, inert, where),
            fix=repair, doc=DOC_COMPLETENESS, **detail)

    summary = "%d discoverable offering(s), all complete" % len(live)
    if len(spellings) > 1:
        return Result.warn(
            summary + "; the credentials characteristic is spelled two ways",
            cause="this catalogue uses %s. Both are accepted, so nothing is broken - "
                  "but whoever writes the next offering will copy whichever one they "
                  "happen to look at, and a checker that knows only one of them "
                  "reports a complete offering as missing its credentials"
                  % " and ".join(sorted(spellings)),
            fix="settle on one spelling across the catalogue",
            doc=DOC_COMPLETENESS, **detail)
    if without_transport:
        summary += " (%d carry no transport characteristics)" % len(without_transport)
    return Result.ok(summary, **detail)
