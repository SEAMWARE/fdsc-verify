"""The connector dashboard's list of counterparties.

This is the proactive half of a diagnosis the tool could previously only make
after the fact, from a failed catalog request. The Catalog view uses exactly two
fields of the selected entry - `did` becomes `counterPartyId` and `protocolUrl`
becomes `counterPartyAddress` - so an entry that pairs a peer's URL with the
wrong DID makes the connector mint a token whose `aud` names the wrong
participant, and the peer answers:

    Unauthorized: Token audience claim (aud -> [did:web:did-provider.example.org:did])
      did not contain expected audience: did:web:connector.example.es

The reason it is worth a check of its own is that it only bites in one
direction. Responding to a negotiation *we* started works, because then the
identifier comes from the incoming message - so a working negotiation is not
evidence that the entry is right, and the fault surfaces later, on the peer's
first attempt, looking like their problem.

What is read is what the dashboard *serves*, never the ConfigMap: the image
deep-merges `application.yaml` over its own defaults and skips null overrides, so
a default entry cannot be deleted - only shadowed - and the mount uses `subPath`,
which kubelet does not auto-update.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from ..model import Result, check

DOC_AUD = "wrong-aud-the-counterpartys-dashboard-carries-the-wrong-did"
DOC_DEFAULTS = "image-defaults-leak-into-the-connector-list"

# A protocol URL a counterparty can never reach. The image ships
# connectors.consumer -> http://localhost:8084/protocol, so this is the literal
# signature of a default that was shadowed by nothing.
_UNREACHABLE_HOSTS = ("localhost", "127.0.0.1", "0.0.0.0")


def _host(url) -> str:
    """The hostname of a served URL.

    Tolerates the *declared* shape as well as the served one: the ConfigMap writes
    `protocolUrl: {url, proxy}` and the dashboard flattens it to a string. Nothing
    should ever hand this the declared form - the check reads what is served - but
    getting a dict here must degrade to "unknown host", not to a crashed check.
    """
    if isinstance(url, dict):
        url = url.get("url")
    if not url or not isinstance(url, str):
        return ""
    return url.split("://")[-1].split("/")[0].split(":")[0].lower()


def _label(entry: dict) -> str:
    return str(entry.get("id") or entry.get("connectorName") or entry.get("name") or "?")


def _our_hosts(ctx) -> Dict[str, str]:
    """host -> lane name, for every lane's public DSP endpoint."""
    hosts = {}
    for lane in ctx.deployment.edc_lanes.values():
        if lane.hostname:
            hosts[lane.hostname.lower()] = lane.name
    return hosts


def _our_services(ctx) -> Dict[str, str]:
    """management-API service name -> lane name.

    The second way to recognise our own entry, and the one that keeps this check
    honest: `edc.hostname` is the public DSP host, and a deployment is free to put
    something else in the dashboard's `protocolUrl` - a gateway alias, an internal
    name. Without this fallback such an entry looks like a counterparty carrying
    our DID, which is the exact fault the check reports. A false FAIL there would
    send an operator to rewrite a perfectly good ConfigMap.
    """
    services = {}
    for lane in ctx.deployment.edc_lanes.values():
        for name in (lane.service, lane.deployment):
            if name:
                services[name.lower()] = lane.name
    return services


def _ours(entry: dict, our_hosts: Dict[str, str], our_services: Dict[str, str]) -> Optional[str]:
    """The lane this entry points at, or None if it points somewhere else."""
    host = _host(entry.get("protocolUrl"))
    if host in our_hosts:
        return our_hosts[host]
    management = (entry.get("managementUrl") or "")
    management = management if isinstance(management, str) else ""
    for service, lane_name in our_services.items():
        if service and service in management.lower():
            return lane_name
    return None


@check("dashboard-config", "The dashboard's connector list carries the right DIDs",
       needs_cluster=True, lanes=None)
def dashboard_config(ctx) -> Result:
    entries, err = ctx.dashboard_connectors()
    if err:
        if not ctx.deployment.service("dashboard"):
            return Result.na("no connector dashboard in this namespace",
                             cause="there is no list to get wrong; this check exists "
                                   "for the deployments that serve one")
        return Result.skip("the dashboard's connector list could not be read",
                           cause=err)
    if not entries:
        return Result.warn("the dashboard serves an empty connector list",
                           cause="nothing can be selected as a counterparty, so the "
                                 "Catalog view has nothing to call",
                           doc=DOC_DEFAULTS)

    our_did = ctx.any_participant_id()
    our_hosts, our_services = _our_hosts(ctx), _our_services(ctx)
    # a peer declared without a protocolUrl has no host to match an entry by;
    # it is still a peer, just not one this check can place in the list
    peers_by_host = {_host(p.protocol_url): p for p in ctx.peers if p.protocol_url}
    # With no lane to compare against there is no way to tell our own entries from
    # a counterparty's, and "this entry carries our DID" is only a fault for the
    # second kind. The rest of the check still applies.
    can_tell_ours = bool(our_hosts or our_services)

    wrong_own: List[str] = []       # our endpoint, not our DID
    wrong_peer: List[str] = []      # someone else's endpoint, our DID
    wrong_named_peer: List[str] = []  # a --peer's endpoint, not that peer's DID
    unreachable: List[str] = []
    for entry in entries:
        label, did = _label(entry), entry.get("did")
        host = _host(entry.get("protocolUrl"))
        if host in _UNREACHABLE_HOSTS:
            unreachable.append("%s -> %s" % (label, entry.get("protocolUrl")))
            continue
        if not did or not host:
            continue
        lane_name = _ours(entry, our_hosts, our_services)
        if lane_name:
            if our_did and did != our_did:
                wrong_own.append("%s (lane %s) carries %s" % (label, lane_name, did))
            continue
        # not one of ours: it is a counterparty entry
        if our_did and did == our_did and can_tell_ours:
            wrong_peer.append("%s -> %s carries our own DID" % (label, host))
        peer = peers_by_host.get(host)
        if peer and did != peer.participant_id:
            wrong_named_peer.append("%s -> %s carries %s, but %s identifies as %s"
                                    % (label, host, did, peer.name, peer.participant_id))

    detail = {"entries": [_label(e) for e in entries], "ourDid": our_did,
              "ourHosts": sorted(our_hosts), "ourLanes": sorted(set(our_services.values()))}
    problems = wrong_peer + wrong_named_peer + wrong_own
    if problems:
        return Result.fail(
            "%d dashboard entr%s name the wrong participant"
            % (len(problems), "y" if len(problems) == 1 else "ies"),
            cause="%s. The Catalog view sends the entry's `did` as counterPartyId, so "
                  "selecting it mints a token whose `aud` names that participant and "
                  "the peer rejects it with \"Token audience claim (aud -> [...]) did "
                  "not contain expected audience\". It only fails in that direction: a "
                  "negotiation the peer starts works, so this survives a green test."
                  % "; ".join(problems),
            fix="set each counterparty entry's `did` to that participant's own "
                "edc.participant.id (mind the did:web path suffix - ours is %s), then "
                "`kubectl rollout restart` the dashboard: the ConfigMap is mounted with "
                "subPath and kubelet does not refresh it" % (our_did or "unset"),
            doc=DOC_AUD, wrong=problems, **detail)

    if unreachable:
        return Result.fail(
            "%d connector(s) in the list cannot be reached by anyone"
            % len(unreachable),
            cause="%s. That is the image's own application.default.yaml showing "
                  "through: the dashboard deep-merges the ConfigMap over it and skips "
                  "null overrides, so a default entry cannot be removed - only "
                  "shadowed by an entry reusing the same key."
                  % "; ".join(unreachable),
            fix="reuse the default keys (`consumer`, `provider`) for your own entries "
                "instead of renaming them, then rollout restart the dashboard",
            doc=DOC_DEFAULTS, unreachable=unreachable, **detail)

    if not our_did:
        return Result.skip("no participant id discovered, so the entries cannot be "
                           "checked against our own DID",
                           cause="%d entries were read and none is obviously broken"
                                 % len(entries))
    if not can_tell_ours:
        return Result.skip("no lane to compare the %d entries against" % len(entries),
                           cause="this deployment has no EDC lane, so an entry carrying "
                                 "our own DID cannot be told apart from our own "
                                 "connector's entry. Only unreachable entries and "
                                 "--peer mismatches were checked")
    return Result.ok("%d connector(s), each naming the right participant" % len(entries),
                     **detail)
