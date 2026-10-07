"""Checks that need a counterparty.

Loopback catches almost every self-inflicted misconfiguration, but three classes
of failure only appear with a real peer, and every one of them cost hours: a trust
anchor missing on the other side, an `aud` built from the wrong DID, and a
credential on the peer that no longer verifies. These run only with --peer.
"""

from __future__ import annotations

from typing import Optional

from .. import http, jose
from ..model import Result, check
from .identity import fetch_did_document

DOC_AUD = "wrong-aud-the-counterpartys-dashboard-carries-the-wrong-did"
DOC_STALE = "a-stale-credential-in-the-identityhub-outlives-a-key-rotation"
DOC_ANCHORS = "peer-side-the-harica-anchor-is-missing-for-callbacks-to-us"


@check("peer-reachable", "The peer's DSP endpoint answers", needs_peer=True,
       lanes=["*"], transport="edc")
def peer_reachable(ctx, lane) -> Result:
    peer = ctx.peer_for(lane.name)
    if not peer:
        return Result.skip("no peer configured for this lane")

    # the version document is the one DSP endpoint that is usually unguarded
    if not peer.protocol_url:
        return Result.skip(
            "peer %s declares no DSP endpoint" % peer.name,
            cause="`protocolUrl` is optional in the peer file, and without one there "
                  "is no Dataspace Protocol endpoint to probe. The identity checks "
                  "still run against this peer")
    url = "%s/.well-known/dspace-version" % peer.protocol_url.rstrip("/")
    resp = http.get(url, insecure=ctx.insecure)
    if resp.error:
        return Result.fail("the peer's DSP endpoint is unreachable",
                           cause="%s: %s" % (url, resp.error),
                           peer=peer.name)
    if resp.status == 404:
        # the base path may carry the version, in which case the well-known sits above it
        parent = peer.protocol_url.rstrip("/").rsplit("/", 1)[0]
        alt = http.get("%s/.well-known/dspace-version" % parent, insecure=ctx.insecure)
        if alt.ok:
            versions = [v.get("version") for v in (alt.json() or {}).get("protocolVersions", [])]
            return Result.ok("reachable, versions %s (well-known lives at %s)"
                             % (versions, parent), peer=peer.name)
        return Result.fail(
            "the peer's DSP endpoint answers 404",
            cause="neither %s nor %s/.well-known/dspace-version exists; the "
                  "protocolUrl in the peer file is probably wrong" % (url, parent),
            fix="check the peer's base path - some deployments serve /api/dsp "
                "unversioned and advertise /2025-1 in the version document",
            peer=peer.name)
    if resp.ok:
        versions = [v.get("version") for v in (resp.json() or {}).get("protocolVersions", [])]
        return Result.ok("reachable, versions %s" % versions, peer=peer.name)
    return Result.ok("reachable (HTTP %d, guarded as expected)" % resp.status, peer=peer.name)


@check("peer-did-resolves", "The peer's DID document resolves and matches its participant id",
       needs_peer=True, lanes=None)
def peer_did_resolves(ctx) -> Result:
    peer = ctx.peers[0] if ctx.peers else None
    if not peer:
        return Result.skip("no peer configured")
    doc, err = fetch_did_document(peer.participant_id, ctx.insecure)
    if err:
        return Result.fail(
            "the peer's DID document does not resolve",
            cause=err,
            fix="without it we cannot verify anything the peer signs; check the "
                "participantId in the peer file, including whether it carries a "
                "':did' path suffix - deployments differ on this",
            peer=peer.name)
    keys = jose.did_document_keys(doc)
    if doc.get("id") != peer.participant_id:
        return Result.fail(
            "the peer's DID document declares a different id",
            cause="the file says %s, the document says %s" % (peer.participant_id, doc.get("id")),
            fix="align the peer file with the document",
            peer=peer.name)
    # A single verification method used to WARN, on the grounds that several of the
    # peer's components sign as the same DID and only one of them could then be
    # verifiable. It was dropped: one key is the *normal* shape - the demo's producer
    # serves one and its identityhub, its identity secret and both lanes' holder kid
    # all agree on it - and from outside there is no way to tell that case from the
    # broken one, because the peer's secrets are not ours to read. A warning nobody
    # can act on is noise, and the real fault is not invisible: it is caught on the
    # side that owns the deployment, where the evidence is, by
    # identity-key-consistency (secret vs published key vs identityhub) and, per lane,
    # by holder-kid-fragment (the kid names a published method). Run the tool on both
    # sides - that is the standing advice for dashboard-config too.
    return Result.ok("resolves, %d key(s)" % len(keys), peer=peer.name, methods=sorted(keys))


@check("peer-trusts-us", "The peer's trusted issuers list contains our DID",
       needs_peer=True, needs_cluster=True, lanes=None)
def peer_trusts_us(ctx) -> Result:
    """Only possible when we happen to have cluster access to the peer.

    Worth it: the credential we present is self-issued, so unless the peer trusts
    our DID as an issuer the exchange dies at the credential layer - after every
    signature check has passed, which makes it look like a signing problem.
    """
    peer = next((p for p in ctx.peers if p.namespace), None)
    if not peer:
        return Result.skip("no peer with cluster access configured (needs context/namespace)")
    our_did = ctx.any_participant_id()
    if not our_did:
        return Result.skip("our participant id is unknown")

    from ..kube import Kube
    from ..discovery import discover

    peer_kube = Kube(context=peer.context, namespace=peer.namespace)
    if not peer_kube.available():
        return Result.skip("the peer's cluster is unreachable from here")
    peer_dep = discover(peer_kube, peer.namespace)

    from ..context import Context
    peer_ctx = Context(peer_kube, peer_dep, insecure=ctx.insecure)
    lane = next(iter(sorted(peer_dep.edc_lanes.values(), key=lambda l: l.name)), None)
    if not lane:
        return Result.skip("no lanes discovered on the peer")
    til = lane.prop("ebsiTir.tilAddress")
    if not til:
        return Result.skip("the peer has no TIL configured")

    body, err = peer_ctx.til_issuer(til, our_did)
    if err:
        return Result.skip("could not query the peer's TIL: %s" % err)
    if body is None:
        return Result.fail(
            "the peer does not trust our DID as an issuer",
            cause="%s is absent from the peer's trusted issuers list; our credential "
                  "is self-issued, so the exchange fails at the credential layer "
                  "after the signatures verify" % our_did,
            fix="register our DID with the credential types the peer's lanes require",
            peer=peer.name)
    types = peer_ctx.til_credential_types(body)
    return Result.ok("registered for %s" % (", ".join(sorted(types)) or "no type"),
                     peer=peer.name, types=sorted(types))


@check("peer-credential-valid", "The peer's stored credential still verifies",
       needs_peer=True, needs_cluster=True, lanes=None)
def peer_credential_valid(ctx) -> Result:
    """The failure that presents as our own connector being broken.

    A peer whose identityhub holds a credential signed with a pre-rotation key
    makes *our* connector report a generic verification failure, which sends the
    investigation to the wrong side of the wire.
    """
    peer = next((p for p in ctx.peers if p.namespace), None)
    if not peer:
        return Result.skip("no peer with cluster access configured")

    from ..kube import Kube
    from ..discovery import discover
    from ..context import Context

    peer_kube = Kube(context=peer.context, namespace=peer.namespace)
    if not peer_kube.available():
        return Result.skip("the peer's cluster is unreachable from here")
    peer_ctx = Context(peer_kube, discover(peer_kube, peer.namespace), insecure=ctx.insecure)

    stored = peer_ctx.identityhub_credentials(peer.participant_id)
    if stored is None:
        return Result.skip("could not read the peer's credential store")
    doc, err = fetch_did_document(peer.participant_id, ctx.insecure)
    if err:
        return Result.skip("the peer's DID document does not resolve: %s" % err)
    keys = jose.did_document_keys(doc)

    bad = []
    for entry in stored:
        raw = (entry.get("verifiableCredential") or {}).get("rawVc") or entry.get("rawVc")
        if not raw or raw.count(".") != 2:
            continue
        try:
            kid = jose.decode_jwt(raw)["header"].get("kid")
            jwk = keys.get(kid) or (sorted(keys.values(), key=str)[0] if keys else None)
            if jwk and not jose.verify_jwt(raw, jwk):
                bad.append(entry.get("id") or "<unnamed>")
        except (jose.MalformedToken, jose.CryptoUnavailable):
            continue

    if bad:
        return Result.fail(
            "the peer's stored credential does not verify against its own DID document",
            cause="credential(s) %s on %s were signed with a key the peer no longer "
                  "publishes. Our connector will report a generic verification "
                  "failure, which looks like our problem and is not." % (bad, peer.name),
            fix="the peer must re-issue the credential into its identityhub store; "
                "refreshing only the credential file fixes OID4VC and leaves DCP broken",
            doc=DOC_STALE,
            peer=peer.name)
    return Result.ok("%d credential(s) verify" % len(stored), peer=peer.name)


@check("peer-catalog", "The peer serves us a catalog", needs_peer=True, lanes=["*"],
       phase="flow", transport="edc")
def peer_catalog(ctx, lane) -> Result:
    """The first flow step, and the cheapest interop signal there is.

    It exercises our token, the peer's verification of it, and its trust decision
    in one request - without creating anything on either side.
    """
    peer = ctx.peer_for(lane.name)
    if not peer:
        return Result.skip("no peer configured for this lane")
    body, err = ctx.edc_catalog(lane, peer)
    if err:
        return _classify_catalog_failure(ctx, lane, peer, err)
    datasets = body if isinstance(body, list) else _datasets(body)
    return Result.ok("%d dataset(s) offered" % len(datasets),
                     peer=peer.name, datasets=[d.get("@id") for d in datasets][:5])


def _datasets(catalog: dict):
    raw = catalog.get("dcat:dataset") or catalog.get("dataset") or []
    return raw if isinstance(raw, list) else [raw]


def _classify_catalog_failure(ctx, lane, peer, err: str) -> Result:
    """Turn a failed catalog request into the actual diagnosis.

    The management API's error is generic, so the useful signal is in our own
    connector's log in the seconds around the attempt. These are the four
    signatures worth recognising.
    """
    logs = ctx.kube.logs("deploy/%s" % lane.deployment, since="3m") if ctx.kube.available() else ""

    if "did not contain expected audience" in logs:
        return Result.fail(
            "the peer rejected our token: wrong audience",
            cause="our token's aud does not name the peer. The initiating side takes "
                  "the counterparty id from its own configuration, so this is almost "
                  "always the wrong DID in a dashboard entry or peer file - note our "
                  "DID may or may not carry a ':did' suffix",
            fix="set the peer's participantId to its real edc.participant.id",
            doc=DOC_AUD, peer=peer.name, error=err)
    if "Token verification failed" in logs:
        return Result.fail(
            "signature verification failed on one side",
            cause="that message means exactly 'the signature does not validate "
                  "against the key resolved from the kid' - never a rule failure, "
                  "which would name the claim. Look at keys, not at claims: most "
                  "often a credential signed before a rotation",
            fix="run credential-freshness on both sides",
            doc=DOC_STALE, peer=peer.name, error=err)
    if "Was not able to extract the issuer" in logs:
        return Result.fail(
            "the lanes are crossed",
            cause="OID4VPParticipantIdExtractionFunction on the receiving side means a "
                  "DCP token reached an OID4VC connector. controlplane-dcp does not "
                  "even depend on oid4vc-extension, so that class name identifies the "
                  "image the peer is running",
            fix="pair like with like: a DCP lane must target the peer's DCP endpoint",
            peer=peer.name, error=err)
    if "Was not able to validate the x5c" in logs:
        return Result.fail(
            "the peer does not trust our verifier's certificate chain",
            cause="the peer's OID4VP trust anchors do not include our chain's root",
            fix="point the peer's trustAnchorsFolder at its own public root store",
            doc=DOC_ANCHORS, peer=peer.name, error=err)
    return Result.fail("the catalog request failed", cause=err, peer=peer.name)
