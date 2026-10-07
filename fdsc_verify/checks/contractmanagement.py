"""contract-management: is it listening to what happens in the marketplace.

An offering published in the marketplace only becomes something a counterparty
can negotiate for because contract-management hears the event and turns it into a
policy and a registered service. If it is not subscribed, the marketplace looks
healthy, the catalogue fills up, and nothing downstream ever appears - with no
error anywhere to explain it.

**The subscription itself cannot be read**, and that shapes this whole check.
TMForum's `/hub` answers `405` on both deployments here: the implementation
supports POST to register and DELETE to remove, and offers no listing. So there is
no way to ask "is it subscribed, and how many times". Nor do the logs say: 24
hours of contract-management logs on a live provider contain no registration line
at all, and the startup logs are long since rotated away.

What this check does, therefore, is say which part is which - the same separation
that `registration-job-hooks` (the declaration) has from
`registration-services-present` (the outcome). The declaration is verifiable. The
outcome is inferable from traffic. The subscription itself is not observable, and
the check says so instead of implying it checked.

One thing that would change that, and needs no code: the Micronaut health
aggregator **already computes a `Subscription Health` indicator** - it shows up in
contract-management's own DEBUG logs. It is suppressed because
`endpoints.health.details-visible` defaults to `AUTHENTICATED`. Setting
`ENDPOINTS_HEALTH_DETAILS_VISIBLE=ANONYMOUS` - one entry under
`contract-management.additionalEnvVars` - turns the weakest part of this check
into a direct reading. Nothing else is needed: the endpoint is on 9090, which the
Service does not publish, which is exactly why `_health` addresses the pod.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from .. import http
from ..kube import KubeError, PortForward
from ..model import Result, check

DOC = "contract-management-is-not-listening-to-the-marketplace"

# The entity types whose events drive the chain. Absent ones are named rather than
# assumed harmless: a deployment that hears about offerings but not orders looks
# healthy right up to the first purchase.
EXPECTED_ENTITIES = ("ProductOffering", "ProductOrder", "Catalog", "Quote")

HEALTH_PORT = 9090

# Declared intent, and the one thing that tells a provider publishing through a
# central marketplace from one whose catalogue nothing drives at all.
CENTRAL_MP_FLAG = "contract-management.enableCentralMarketplace"


def _notification(ctx) -> Tuple[Optional[dict], Optional[str]]:
    """The `notification` block of contract-management's own application.yaml."""
    name = ctx.deployment.service("contractmanagement")
    if not name:
        return None, "no contract-management service in this namespace"
    data = ctx.kube.configmap("contract-management") or {}
    body = data.get("application.yaml")
    if not body:
        return None, "the contract-management ConfigMap carries no application.yaml"
    try:
        import yaml  # type: ignore

        parsed = yaml.safe_load(body) or {}
    except ImportError:
        return None, ("PyYAML is not installed, so the notification block cannot be "
                      "parsed; install it or pass the config as JSON")
    return (parsed.get("notification") or {}), None


def _health(ctx) -> Tuple[Optional[dict], Optional[str]]:
    """Read the management health endpoint, which is on the POD, not the Service.

    The container listens on 9090 and the Service publishes 8080 only, so this is
    unreachable through the Service however right the name is.
    """
    selector = "app.kubernetes.io/name=contract-management"
    pods = ctx.kube.get_json("pod", namespace=ctx.deployment.namespace,
                             check=False, selector=selector) or {}
    items = pods.get("items") or []
    if not items:
        return None, "no contract-management pod matched %s" % selector
    pod = (items[0].get("metadata") or {}).get("name")
    try:
        with PortForward(ctx.kube, pod, HEALTH_PORT,
                         namespace=ctx.deployment.namespace, kind="pod") as pf:
            resp = http.get("%s/health" % pf.base_url)
    except KubeError as exc:
        return None, "could not reach the pod's health port: %s" % exc
    if not resp.ok:
        return None, "HTTP %d from /health on port %d" % (resp.status, HEALTH_PORT)
    body = resp.json()
    return (body if isinstance(body, dict) else None,
            None if isinstance(body, dict) else "unexpected body from /health")


@check("contract-management-subscriptions",
       "contract-management is subscribed to the marketplace's events",
       needs_cluster=True, roles=("provider",), transport="fiware")
def contract_management_subscriptions(ctx) -> Result:
    if not ctx.deployment.service("contractmanagement"):
        return Result.na(
            "no contract-management in this namespace",
            cause="it is Optional for a provider; without it nothing turns a "
                  "published offering into something negotiable, which is a "
                  "deployment shape rather than a fault")

    notification, err = _notification(ctx)
    if notification is None:
        return Result.skip("could not read the notification configuration", cause=err)

    if not notification.get("enabled"):
        # Whether this is a fault depends on whether there is a marketplace here to
        # listen to. With a local one it is unambiguous. Without one - a provider
        # integrated with a central marketplace - it may well be deliberate, and the
        # tool has no way to tell from the outside, so it says so rather than
        # inventing a verdict - unless the deployment declares a central
        # marketplace, which settles it.
        if ctx.deployment.service("marketplace"):
            return Result.fail(
                "contract-management is not subscribed to anything",
                cause="`notification.enabled` is off while a marketplace is deployed "
                      "in this namespace, so no event from it reaches "
                      "contract-management. Offerings can be published all day and "
                      "nothing downstream - no policy, no registered service - will "
                      "ever appear, with no error to explain it",
                fix="set notification.enabled and the entities to subscribe to in "
                    "the contract-management values",
                doc=DOC)
        # This used to be one WARN saying, in its own words, that from outside
        # there was no way to tell the two shapes apart. There is: a deployment
        # that declares a central marketplace has said which one it is, and
        # subscribing to its own catalogue is not its job.
        if ctx.values.get(CENTRAL_MP_FLAG) is True:
            return Result.na(
                "a central marketplace drives this catalogue",
                cause="`notification.enabled` is off, there is no local marketplace, "
                      "and `%s` says a central one drives the chain. Nothing here "
                      "has a local catalogue to react to, so the subscription is not "
                      "expected - `central-mp-*` check that the central marketplace "
                      "can reach this deployment" % CENTRAL_MP_FLAG)
        return Result.warn(
            "nothing drives this provider's catalogue",
            cause="`notification.enabled` is off, no marketplace is deployed here, "
                  "and `%s` is not set either - so neither a local marketplace nor a "
                  "central one turns a published offering into something negotiable. "
                  "An offering can be published and nothing downstream will ever act "
                  "on it" % CENTRAL_MP_FLAG,
            fix="if this provider is meant to react to its own catalogue, enable "
                "notification and declare the entities; if a central marketplace "
                "owns that, set %s so it is stated rather than guessed" % CENTRAL_MP_FLAG,
            doc=DOC)

    declared = [str((e or {}).get("entityType")) for e in notification.get("entities") or []]
    missing = [e for e in EXPECTED_ENTITIES if e not in declared]
    detail: Dict[str, object] = {"declared": declared, "missing": missing}

    # The outcome, as far as it can be seen. A health indicator for the
    # subscriptions exists but is suppressed by Micronaut's default.
    health, health_err = _health(ctx)
    indicator = None
    if isinstance(health, dict):
        details = health.get("details") or {}
        indicator = next((v for k, v in details.items() if "subscription" in k.lower()),
                         None)
        detail["health"] = health.get("status")
        detail["healthDetailsVisible"] = bool(details)
    else:
        detail["healthError"] = health_err

    if missing:
        return Result.warn(
            "%d event type(s) nobody is subscribed to: %s" % (len(missing),
                                                              ", ".join(missing)),
            cause="the notification block declares %s. A deployment that hears about "
                  "offerings but not orders looks healthy until the first purchase, "
                  "and then nothing happens" % (declared or "nothing"),
            fix="add the missing entityTypes to notification.entities",
            doc=DOC, **detail)

    if indicator is not None:
        status = (indicator or {}).get("status") if isinstance(indicator, dict) else indicator
        if str(status).upper() != "UP":
            return Result.fail(
                "the subscription health indicator is %s" % status,
                cause="contract-management's own health endpoint reports its "
                      "subscriptions as %s. This is the one direct reading available "
                      "and it says they are not working" % status,
                fix="check contract-management's logs for what it could not "
                    "subscribe to, and that the TMForum APIs it names are reachable",
                doc=DOC, **detail)
        return Result.ok("subscribed to %d event type(s); health reports the "
                         "subscriptions UP" % len(declared), **detail)

    return Result.warn(
        "subscribed to %d event type(s) by declaration; the subscription itself "
        "cannot be read" % len(declared),
        cause="all %d expected entity types are declared and notification is "
              "enabled, which is as far as configuration goes. Whether the hubs were "
              "ever registered is not observable: TMForum's /hub answers 405 (POST "
              "and DELETE only, no listing) and contract-management logs nothing "
              "about registering. Its health endpoint does compute a subscription "
              "indicator, but Micronaut hides the per-indicator detail unless asked"
              % len(declared),
        fix="set ENDPOINTS_HEALTH_DETAILS_VISIBLE=ANONYMOUS on contract-management "
            "- one entry under contract-management.additionalEnvVars; the "
            "indicator it already computes then becomes readable and this check "
            "stops guessing. Port %d needs no change: it is not on the Service, "
            "which is why this reads the pod directly" % HEALTH_PORT,
        doc=DOC, **detail)
