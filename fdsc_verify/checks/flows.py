"""The flows: catalog, negotiation, transfer, data access.

**An EDC flow needs a counterparty. There is no loopback.**

There used to be: a lane acting as consumer against its own public DSP endpoint,
self-contained and needing nobody. It cannot work on this stack, and the failure
is expensive rather than obvious. The TMF-backed store keeps a negotiation as one
Quote with both roles in `relatedParty`, and rebuilds it by finding the party
whose DID is *not* ours - which is how it recovers `counterPartyId`,
`counterPartyAddress` and `protocol`, the three fields
`ContractNegotiation.Builder.build()` requires. With one participant on both
sides that party does not exist, the fields stay null, and every read throws a
NullPointerException. The state machine then retries every two seconds for ever,
and the only cure is deleting the Quote by hand.

EDC itself permits it - its builder checks only that the three fields are
present, never that the counterparty differs from us - so this is a limit of the
TMF store, and one that is not going to be lifted. Offering loopback anyway would
mean handing someone a run that poisons their environment.

So the EDC flow checks are **not applicable without `--peer`**, and say so.
`dsp-route` still proves our own DSP endpoint answers, which is what loopback was
really confirming most of the time.

Everything created is tagged with a run id and removed at the end unless --keep.
"""

from __future__ import annotations

import time
import uuid
from typing import Dict, List, Optional, Tuple

from .. import http, jose
from ..model import Peer, Result, check
from .peers import _classify_catalog_failure, _datasets

DOC_EDR = "the-edr-token-lives-5-minutes-and-cannot-be-refreshed"

# On the consumer side FINALIZED is the only state that means the provider is done:
# VERIFIED says "I sent my verification", and the agreement is not in our store yet.
# Treating VERIFIED as settled made flow-negotiation report success and flow-transfer
# post immediately, which the EDC answered - correctly - with `Contract agreement
# <id> not found`. Measured on demo/consumer: the same negotiation read FINALIZED a
# moment later, with that exact agreement id resolvable at
# GET /v3/contractagreements/<id>. So VERIFIED is a state worth *waiting through*,
# not a terminal one.
NEGOTIATION_DONE = {"FINALIZED"}
# How long to wait for the EDR after a transfer reads STARTED. It arrives
# asynchronously, and the token it carries lives ~5 minutes, so waiting is
# cheap and fetching once was wrong.
EDR_WAIT = 30
TERMINAL_OK = {"FINALIZED", "VERIFIED"}   # transfers still accept either
TERMINAL_BAD = {"TERMINATED", "TERMINATING"}


NO_PEER = (
    "an EDC flow needs a counterparty, and none is configured for lane %s",
    "there is no loopback: the TMF-backed store keeps a negotiation as one Quote "
    "with both roles in relatedParty and rebuilds counterPartyId from the party "
    "whose DID is not ours, so one participant on both sides leaves it null and "
    "every read throws. EDC permits it; this store cannot represent it")


def _why_refused(challenge) -> str:
    """Turn the gateway's own words into the next thing to look at."""
    text = (challenge or "").lower()
    if "key" in text and "not found" in text:
        return ("Compare `tokenKid` and `tokenIss` in this row's detail (-v or --json) "
                "with the JWKS the counterparty's route points at - that is the "
                "comparison nobody can make after the fact, because the route is "
                "deleted on terminate and the token is never stored. "
                "The token is a well-formed JWT and the gateway resolved its `kid`; "
                "what it could not do is find that key in the JWKS it holds. Note "
                "*whose* gateway: the data endpoint belongs to the COUNTERPARTY, so "
                "this is their APISIX holding a JWKS without that key - nothing on "
                "our side is wrong and nothing on our side will fix it. `not found` "
                "rather than a failed signature means the cached document has no "
                "such kid at all, which is what a copy fetched before the connector "
                "published it looks like. Their cache is not readable from outside "
                "(APISIX keeps it in an internal dictionary), so verifier-jwks-"
                "matches-key cannot see it either and a JWKS fetched now looks "
                "healthy")
    if "expired" in text:
        return ("Accepted as ours and refused as too old. The EDR is minted when the "
                "data flow starts, not when you fetch it, so a slow run spends a "
                "token that was already half gone")
    if "error_description" not in text:
        return ("No error_description, so no usable token reached the gateway at all, "
                "as opposed to one it rejected. Check the EDR field names: "
                "FDSCDcpEndpointDataReferenceService writes `authorization` and "
                "`authType`, so a consumer reading `token`/`tokenType` finds nothing "
                "and sends no bearer at all")
    return "The gateway rejected the token it was given; its own words are above"


def _target_peer(ctx, lane):
    """The counterparty for this lane, or None. See the module docstring."""
    return ctx.peer_for(lane.name)


def _no_peer(lane) -> Result:
    return Result.na(NO_PEER[0] % lane.name,
                     cause="%s. Pass --peer <file> to run the EDC flows" % NO_PEER[1])


@check("flow-catalog", "A catalog request returns datasets", phase="flow", lanes=["*"],
       needs_cluster=True, transport="edc")
def flow_catalog(ctx, lane) -> Result:
    peer = _target_peer(ctx, lane)
    if not peer:
        return _no_peer(lane)

    body, err = ctx.edc_catalog(lane, peer)
    if err:
        return _classify_catalog_failure(ctx, lane, peer, err)
    datasets = _datasets(body) if isinstance(body, dict) else []
    ctx.remember("catalog:%s" % lane.name, datasets)
    if not datasets:
        return Result.fail(
            "the catalog is empty",
            cause="the handshake succeeded, so identity is fine, but no dataset was "
                  "offered. Either nothing is published, or the access policy "
                  "evaluates to deny - a policy the odrl-pap cannot map yields an "
                  "empty catalog rather than an error",
            fix="publish an offering with a permissive access policy and check the "
                "odrl-pap mapped it",
            peer=peer.name)
    return Result.ok("%d dataset(s) via %s" % (len(datasets), peer.name),
                     peer=peer.name,
                     datasets=[d.get("@id") for d in datasets][:5])


@check("flow-negotiation", "A contract negotiation reaches FINALIZED", phase="flow",
       lanes=["*"], needs_cluster=True, mutates=True, transport="edc")
def flow_negotiation(ctx, lane) -> Result:
    peer = _target_peer(ctx, lane)
    if not peer:
        return _no_peer(lane)
    if not peer:
        return Result.skip("no target for this lane")
    datasets = ctx.recall("catalog:%s" % lane.name)
    if not datasets:
        return Result.skip("no dataset from flow-catalog to negotiate on")

    dataset = datasets[0]
    offer = _first_policy(dataset)
    if not offer:
        return Result.skip("the dataset carries no odrl policy")

    request = {
        "@context": {"@vocab": "https://w3id.org/edc/v0.0.1/ns/",
                     "odrl": "http://www.w3.org/ns/odrl/2/"},
        "@type": "ContractRequest",
        "counterPartyAddress": peer.protocol_url,
        "protocol": ctx.dsp_protocol(peer),
        "policy": {
            "@context": "http://www.w3.org/ns/odrl.jsonld",
            "@id": offer.get("@id"),
            "@type": "Offer",
            "assigner": offer.get("assigner") or peer.participant_id,
            "target": dataset.get("@id"),
            "permission": offer.get("permission") or offer.get("odrl:permission") or [],
        },
    }
    resp, err = ctx.edc_request(lane, "POST", "/v3/contractnegotiations", request)
    if err or resp is None:
        return Result.fail("could not start the negotiation", cause=err)
    if not resp.ok:
        return Result.fail("the negotiation was rejected on submission",
                           cause="HTTP %d: %s" % (resp.status, resp.text(240)))
    negotiation_id = (resp.json() or {}).get("@id")
    if not negotiation_id:
        return Result.fail("no negotiation id returned", cause=resp.text(240))
    ctx.track("negotiation", negotiation_id, lane)

    state, last, timeline = _poll(
        ctx, lane, "/v3/contractnegotiations/%s" % negotiation_id,
        timeout=ctx.timeouts["negotiation"], wanted=NEGOTIATION_DONE)
    detail = {"id": negotiation_id, "peer": peer.name, "state": state,
              "timeline": timeline}
    if state in NEGOTIATION_DONE:
        agreement = (last or {}).get("contractAgreementId")
        if agreement:
            ctx.track("agreement", agreement, lane)
            detail["agreementId"] = agreement
        return Result.ok("%s via %s" % (state, peer.name), **detail)
    if state == "VERIFIED":
        # Not a stall to classify: the state machine is moving and the provider
        # simply has not finalized inside our window. Saying which state it reached
        # is the whole difference between "raise the timeout" and "go read logs".
        return Result.warn(
            "the negotiation reached VERIFIED but not FINALIZED in %ds"
            % ctx.timeouts["negotiation"],
            cause="it was moving the whole time (%s); VERIFIED means we sent our "
                  "verification and the provider finalizes after it. The contract "
                  "agreement is only registered on our side at FINALIZED, so a "
                  "transfer started now is refused with `Contract agreement <id> not "
                  "found`" % ", ".join(timeline),
            fix="raise timeouts.negotiation in the --config file, or re-run: the "
                "negotiation usually finalizes seconds later and nothing is lost",
            **detail)
    return _classify_negotiation_stall(ctx, lane, peer, state, last, detail)


@check("flow-transfer", "A transfer starts and the EDR grants access to the data",
       phase="flow", lanes=["*"], needs_cluster=True, mutates=True, transport="edc")
def flow_transfer(ctx, lane) -> Result:
    peer = _target_peer(ctx, lane)
    if not peer:
        return _no_peer(lane)
    agreement = ctx.recall("agreement:%s" % lane.name)
    if not agreement:
        return Result.skip("no agreement from flow-negotiation")

    datasets = ctx.recall("catalog:%s" % lane.name) or []
    dataset_id = datasets[0].get("@id") if datasets else None
    request = {
        "@context": {"@vocab": "https://w3id.org/edc/v0.0.1/ns/"},
        "@type": "TransferRequest",
        "counterPartyAddress": peer.protocol_url,
        "protocol": ctx.dsp_protocol(peer),
        "contractId": agreement,
        "assetId": dataset_id,
        "transferType": "HttpData-PULL",
    }
    resp, err = ctx.edc_request(lane, "POST", "/v3/transferprocesses", request)
    if err or resp is None:
        return Result.fail("could not start the transfer", cause=err)
    if not resp.ok:
        return Result.fail("the transfer was rejected on submission",
                           cause="HTTP %d: %s" % (resp.status, resp.text(240)))
    transfer_id = (resp.json() or {}).get("@id")
    if not transfer_id:
        return Result.fail("no transfer id returned", cause=resp.text(240))
    ctx.track("transfer", transfer_id, lane)

    state, _, timeline = _poll(
        ctx, lane, "/v3/transferprocesses/%s" % transfer_id,
        timeout=ctx.timeouts["transfer"], wanted={"STARTED"} | TERMINAL_OK)
    if state not in ({"STARTED"} | TERMINAL_OK):
        return Result.fail("the transfer did not start (state %s)" % state,
                           cause="the agreement exists, so this is the data plane or "
                                 "the provider's transfer configuration",
                           id=transfer_id, peer=peer.name)

    # The EDR does not appear the instant the transfer reads STARTED. The provider
    # sends it in the TransferStartMessage, the controlplane raises a
    # TransferProcessStarted event, and the EDR store receiver persists it - all
    # asynchronous. Fetching once gave a 404 on a transfer that was perfectly
    # healthy, and cleanup then terminated it, which deletes the EDR and erases the
    # evidence. Measured on demo: STARTED at 14:14:05.098, the single fetch failed,
    # cleanup terminated at 14:14:07.926.
    #
    # The token lives ~5 minutes from the data flow starting, so a few seconds spent
    # waiting costs almost nothing and the remaining lifetime is reported either way.
    edr, err, deadline = None, None, time.time() + EDR_WAIT
    while time.time() < deadline:
        edr, err = ctx.edc_request(lane, "GET", "/v3/edrs/%s/dataaddress" % transfer_id)
        if edr is not None and edr.ok:
            break
        ctx.progress.detail("waiting for the EDR of %s (%ds left)"
                            % (transfer_id[:8], max(int(deadline - time.time()), 0)))
        time.sleep(2)
    if err or edr is None or not edr.ok:
        return Result.fail(
            "the EDR never reached our cache",
            cause="%s after %ds. The transfer is STARTED, so the provider sent the "
                  "TransferStartMessage; what did not happen is our own controlplane "
                  "persisting the DataAddress it carried. That is the EDR store "
                  "receiver's job"
                  % (err or "HTTP %s" % (edr.status if edr else "?"), EDR_WAIT),
            fix="check that the controlplane logs `Endpoint Data Reference Store "
                "Receiver Extension` at boot, and look for an error handling the "
                "TransferProcessStarted event",
            id=transfer_id)
    address = edr.json() or {}
    endpoint = address.get("endpoint")
    token = address.get("token") or address.get("authorization")
    if not endpoint:
        return Result.fail("the EDR carries no endpoint", cause=str(address)[:200],
                           id=transfer_id)

    detail = {"id": transfer_id, "endpoint": endpoint}
    if token:
        # The `kid` and `iss` the token carries, reported whatever happens. When the
        # gateway answers `key with id <x> not found`, the one thing nobody can work
        # out afterwards is which key it was asked for and who claims to have signed
        # it - the route is deleted on terminate and the token is never stored. Two
        # fields here turn a second run into the answer instead of another
        # bisection.
        try:
            decoded = jose.decode_jwt(token)
            header, claims = decoded["header"], decoded["payload"]
            detail["tokenKid"] = header.get("kid")
            detail["tokenAlg"] = header.get("alg")
            detail["tokenIss"] = claims.get("iss")
            detail["tokenAud"] = claims.get("aud")
        except Exception:  # noqa: BLE001 - never lose the real verdict to this
            pass
        try:
            life = jose.token_lifetime(token)
            detail["tokenTtl"] = life["ttl"]
            detail["tokenRemaining"] = life["remaining"]
            if life["remaining"] is not None and life["remaining"] <= 0:
                return Result.fail(
                    "the EDR token was already expired when handed to us",
                    cause="ttl %ss, expired %ss ago. It is minted when the data flow "
                          "starts, not when the EDR is fetched, and there is no "
                          "refresh path" % (life["ttl"], -life["remaining"]),
                    fix="reduce the delay between starting the transfer and using "
                        "the EDR, or make the lifetime configurable",
                    doc=DOC_EDR, **detail)
        except jose.MalformedToken:
            detail["tokenTtl"] = None

    if not token:
        # By design on the OID4VC path. FDSCOid4VpEndpointDataReferenceService puts
        # only `endpoint` and `endpointType` in the EDR - "token handling happens at
        # the OID4VC level", as its own revoke method says - because the consumer is
        # meant to earn a token by presenting a credential to the verifier, which
        # the route's `discovery` points at. Doing that means being a wallet
        # (OID4VCI from Keycloak, a key, a signed VP, a provisioned test user), the
        # same line flow-fiware-gate declines to cross and for the same reason.
        #
        # So this is where the check stops, and it says so rather than reporting a
        # missing token as a fault. What it still proves is worth having: the EDR
        # was issued and the endpoint it names refuses an anonymous request.
        anonymous = http.get(endpoint, insecure=ctx.insecure)
        detail["dataStatus"] = anonymous.status
        detail["tokenInEdr"] = False
        if anonymous.status in (401, 403):
            return Result.ok(
                "EDR issued and its endpoint is guarded (HTTP %d); no token to spend "
                "on this path" % anonymous.status,
                **detail)
        if anonymous.ok:
            return Result.fail(
                "the data endpoint served the data with no credential at all",
                cause="the EDR carries no token - correct for OID4VC, where the "
                      "consumer earns one from the verifier - but `%s` answered %d "
                      "to a request with no Authorization header. The gate is open"
                      % (endpoint, anonymous.status),
                fix="check the route's openid-connect plugin: bearer_only and the "
                    "discovery address it validates against",
                **detail)
        return Result.skip(
            "the EDR carries no token and the endpoint answered %d" % anonymous.status,
            cause="no token is expected on the OID4VC path, so all that could be "
                  "checked is whether the endpoint refuses an anonymous request - "
                  "and it answered something other than a refusal or a success")

    headers = {"Authorization": token if str(token).lower().startswith("bearer")
               else "Bearer %s" % token}
    data = http.get(endpoint, headers=headers, insecure=ctx.insecure)
    detail["dataStatus"] = data.status

    # The EDR's endpoint is a base URL with no trailing slash; the gateway route
    # fdsc-edc registers for it is `/<dataFlowId>/*`, which cannot match it. The
    # request therefore falls through to some other route, whose JWKS has no such
    # key, and the gateway blames the token. Measured on demo: the same token on
    # the same endpoint is 401 `RSA key with id sig not found` bare and 404 - i.e.
    # authenticated, upstream empty at the root - with one slash appended.
    #
    # Probing both is not papering over it. A consumer following the EDR verbatim
    # gets the misleading 401, so this is a real fault and reported as one; what
    # the retry buys is being able to say WHICH fault, instead of accusing the
    # token.
    if data.status == 401 and not endpoint.endswith("/"):
        slashed = http.get(endpoint + "/", headers=headers, insecure=ctx.insecure)
        detail["dataStatusWithSlash"] = slashed.status
        if slashed.status != 401:
            return Result.fail(
                "the EDR endpoint is not fetchable as handed over",
                cause="`%s` answers 401 (%s), and the same token on `%s/` answers "
                      "%d - so the token is fine and the URL is not. fdsc-edc builds "
                      "the EDR endpoint without a trailing slash while registering "
                      "the gateway route as `/<dataFlowId>/*`, which cannot match it; "
                      "the request lands on another route whose JWKS has no such key "
                      "and the gateway blames the token"
                      % (endpoint, (data.header("www-authenticate") or "")[:80],
                         endpoint, slashed.status),
                fix="in fdsc-edc, make FDSCEndpoints.buildEndpoint and the route "
                    "registered by TransferMapper.toDcpServiceRoute agree on the "
                    "trailing slash. Until then a consumer must append one to the "
                    "EDR's endpoint before using it",
                **detail)
    if data.ok:
        return Result.ok("data retrieved (%d bytes) via %s"
                         % (len(data.body), peer.name), **detail)
    if data.status == 401:
        auth = data.header("www-authenticate") or ""
        if "expired" in auth.lower():
            return Result.fail(
                "the data endpoint rejected the token as expired",
                cause="www-authenticate: %s - the 300s lifetime elapsed between the "
                      "transfer starting and this request" % auth,
                fix="use the EDR immediately", doc=DOC_EDR, **detail)
        return Result.fail(
            "the data endpoint rejected the request as unauthenticated",
            # Read the challenge rather than assert one shape of failure. The canned
            # text claimed "no error_description means no usable token" even when the
            # header carried one - on demo it said `RSA key with id sig not found`,
            # which is the opposite problem: a well-formed token whose signing key
            # the gateway could not resolve.
            cause="www-authenticate: %s. %s" % (auth or "(absent)", _why_refused(auth)),
            fix="if the key could not be resolved, ask the counterparty to restart "
                "their gateway - that drops the cached JWKS and it refetches - and "
                "confirm their connector publishes the kid the token carries; "
                "otherwise send the EDR's token verbatim as a bearer",
            doc="the-dashboard-never-sends-the-edr-token", **detail)
    if data.status == 404:
        return Result.warn(
            "authenticated, but the endpoint has no data at its root",
            cause="HTTP 404 with a valid token: the base URL alone may not be "
                  "fetchable and the consumer has to append a path",
            **detail)
    return Result.fail("the data request failed with HTTP %d" % data.status,
                       cause=data.text(200), **detail)


# ------------------------------------------------------------------- internals


def _first_policy(dataset: dict) -> Optional[dict]:
    policy = dataset.get("odrl:hasPolicy") or dataset.get("hasPolicy")
    if isinstance(policy, list):
        return policy[0] if policy else None
    return policy


def _poll(ctx, lane, path: str, timeout: int,
          wanted=None) -> Tuple[str, Optional[dict], List[str]]:
    """Poll a state machine until it settles.

    Returns (state, last body, timeline) where the timeline names each state as it
    was first seen and how long in. A bare "it did not finish" says nothing about
    whether the thing was moving; "REQUESTED 11s, AGREED 47s, VERIFIED 68s" is the
    difference between raising a timeout and going to read logs.
    """
    wanted = wanted or TERMINAL_OK
    started = time.time()
    deadline = started + timeout
    state, body = "UNKNOWN", None
    timeline: List[str] = []

    def read():
        nonlocal state, body
        resp, err = ctx.edc_request(lane, "GET", path)
        if err or resp is None or not resp.ok:
            return False
        body = resp.json() or {}
        seen = body.get("state") or "UNKNOWN"
        if seen != state:
            timeline.append("%s %ds" % (seen, int(time.time() - started)))
        state = seen
        return state in wanted or state in TERMINAL_BAD

    while time.time() < deadline:
        if read():
            return state, body, timeline
        # shown during the sleep, so the state is on screen rather than the GET:
        # a REQUESTED that never moves is the failure this tool exists to explain,
        # and watching it sit there is how the operator recognises it
        _report_state(ctx, path, state, deadline)
        time.sleep(2)

    # One last read past the deadline. The loop sleeps 2s between reads, so the
    # window can expire on a state machine that settled a moment earlier - and a run
    # that reports "not finished" about something that finished is the worst of both
    # outcomes. It costs one request.
    ctx.progress.detail("%s: deadline reached, reading once more" % path.strip("/"))
    read()
    return state, body, timeline


def _report_state(ctx, path: str, state: str, deadline: float) -> None:
    ctx.progress.detail("%s is %s, %ds before giving up"
                        % (path.strip("/"), state, max(int(deadline - time.time()), 0)))


def _classify_negotiation_stall(ctx, lane, peer, state, last, detail) -> Result:
    """A stalled negotiation is the symptom; the logs carry the cause.

    These four signatures cover every stall seen so far, and each points at a
    different side of the wire, which is exactly what is expensive to work out by
    hand.
    """
    logs = ctx.kube.logs("deploy/%s" % lane.deployment, since="5m")
    gateway = ctx.deployment.service("apisix")
    gateway_logs = ctx.kube.logs("deploy/%s" % gateway, since="5m") if gateway else ""

    if "Was not able to read negotiation" in logs:
        # Same symptom, two causes, and the tool used to assert the wrong one. The
        # store keeps a negotiation as a TMForum quote and rebuilds it on every read;
        # anything that stops it rebuilding spins the state machine forever, every
        # two seconds, until somebody deletes the quote by hand. WHICH cause it is
        # has to be read off the stack, not assumed - the keyword answer was stated
        # unconditionally while `tmforum-reserved-words` in the same report said the
        # escape could not be lost on this deployment.
        if "TMFEdcMapper" in logs and "NullPointerException" in logs:
            return Result.fail(
                "the negotiation record cannot be rebuilt (stuck in %s)" % state,
                cause="a NullPointerException in TMFEdcMapper.toContractNegotiation, "
                      "from ContractNegotiation.Builder.build(): counterPartyId, "
                      "counterPartyAddress and protocol are required, and the mapper "
                      "only sets them for a related party whose DID is NOT ours. A "
                      "loopback negotiation has us as both Provider and Consumer, so "
                      "that branch never runs and the field stays null. EDC itself "
                      "does not forbid this - its builder only requires the three "
                      "fields - so it is the TMF-backed store that cannot represent "
                      "a negotiation with one participant on both sides",
                fix="delete the quote holding this negotiation (it is the record "
                    "itself) to stop the retry loop, and negotiate against a real "
                    "counterparty with --peer instead of loopback",
                doc="scorpio-6-strips-json-ld-keywords", **detail)
        return Result.fail(
            "the negotiation record cannot be read back (stuck in %s)" % state,
            cause="'Was not able to read negotiation ... from quotes' in a loop: the "
                  "state is stored as a TMForum quote and the stored policy no longer "
                  "parses. The state machine then spins forever. If the broker dropped "
                  "the JSON-LD keywords this is why - check what "
                  "tmforum-reserved-words said above before assuming it, because on a "
                  "deployment where the escape cannot be lost the cause is elsewhere",
            fix="read the stack in the controlplane log to see what failed to parse, "
                "then delete the damaged quote, which is the negotiation record "
                "itself. tmforum-reserved-words says whether this build can lose the "
                "keywords at all",
            doc="scorpio-6-strips-json-ld-keywords", **detail)
    if "did not contain expected audience" in logs:
        return Result.fail(
            "the counterparty's token had the wrong audience (stuck in %s)" % state,
            cause="aud names the sender instead of us, so whoever initiated took the "
                  "counterparty id from the wrong place",
            fix="fix the peer's participant id in its dashboard entry or peer file",
            doc="wrong-aud-the-counterpartys-dashboard-carries-the-wrong-did", **detail)
    if "jwt signature verification failed" in gateway_logs:
        return Result.fail(
            "the gateway rejected the inbound callback (stuck in %s)" % state,
            cause="apisix reports 'jwt signature verification failed' on /api/dsp: it "
                  "is validating the callback against a cached JWKS. Because the kid "
                  "never changes, a rotated key is never refetched",
            fix="rollout restart the apisix deployment",
            doc="apisix-caches-the-verifiers-jwks-and-the-kid-never-changes", **detail)
    if "Token verification failed" in logs:
        return Result.fail(
            "signature verification failed (stuck in %s)" % state,
            cause="that message means exactly 'the signature does not validate against "
                  "the key resolved from the kid'. Not a rule failure - those name the "
                  "claim. Look for a credential signed before a key rotation",
            fix="run credential-freshness on both sides",
            doc="a-stale-credential-in-the-identityhub-outlives-a-key-rotation", **detail)

    inbound = [line for line in gateway_logs.splitlines()
               if "/api/dsp" in line and " 401 " in line]
    if inbound:
        return Result.fail(
            "inbound callbacks are being rejected (stuck in %s)" % state,
            cause="the gateway logged %d 401(s) on /api/dsp during the attempt, so the "
                  "counterparty is reaching us and being turned away" % len(inbound),
            fix="check the gateway's token validation before suspecting the peer",
            doc="apisix-caches-the-verifiers-jwks-and-the-kid-never-changes", **detail)

    return Result.fail(
        "the negotiation did not finalise (stuck in %s)" % state,
        cause="no known signature matched. %s" % (
            "The counterparty acknowledged the request (correlationId is set), so it "
            "is the callback or the peer's own state machine."
            if (last or {}).get("correlationId") else
            "No correlationId, so the request never got through."),
        fix="check both connectors' logs around the attempt, and the gateway access log",
        **detail)


@check("flow-cleanup", "Test data created by this run is removed", phase="flow",
       lanes=None, needs_cluster=True, mutates=True, transport="edc")
def flow_cleanup(ctx) -> Result:
    """Leave nothing behind.

    Negotiations and agreements are not deletable through the management API, so
    what can be removed is removed and what cannot is listed - silently leaving
    state around in someone else's environment is worse than saying so.
    """
    if ctx.config.get("keep"):
        tracked = ctx.tracked_summary()
        return Result.warn("--keep given, %d object(s) left in place" % sum(
            len(v) for v in tracked.values()), cause=str(tracked))

    removed, left = [], []
    for kind, entries in ctx.tracked.items():
        for identifier, lane in entries:
            if kind == "transfer":
                # Terminate first, THEN drop the EDR. Deleting only the EDR left the
                # transfer process STARTED for ever - the cache entry goes and the
                # state machine does not, so the provider keeps a data flow
                # provisioned for a consumer that has gone away. Two were found
                # sitting on demo, one per lane, from runs whose cleanup reported
                # success.
                ok = False
                resp, _ = ctx.edc_request(
                    lane, "POST", "/v3/transferprocesses/%s/terminate" % identifier,
                    {"@context": {"@vocab": "https://w3id.org/edc/v0.0.1/ns/"},
                     "reason": "fdsc-verify cleanup"})
                ok = resp is not None and resp.ok
                edr, _ = ctx.edc_request(lane, "DELETE", "/v3/edrs/%s" % identifier)
                (removed if ok else left).append("%s/%s" % (kind, identifier))
            else:
                left.append("%s/%s" % (kind, identifier))
    if not removed and not left:
        return Result.ok("nothing to clean up")
    if left:
        return Result.warn(
            "%d object(s) removed, %d not removable" % (len(removed), len(left)),
            cause="the management API cannot delete %s; they are inert but will show "
                  "up in listings" % ", ".join(sorted({l.split("/")[0] for l in left})),
            removed=removed, left=left)
    return Result.ok("%d object(s) removed" % len(removed), removed=removed)
