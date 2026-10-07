"""Identity checks: the DID document, the keys behind it, and the credentials.

Every check here comes from a failure that cost hours and produced either a
generic 401 or a negotiation stuck in REQUESTED. They are ordered so that the
cheapest, most-explanatory one runs first.
"""

from __future__ import annotations

from typing import Dict, Optional

from .. import components, http, jose
from .. import values as values_mod
from ..model import Result, check

DOC_KEY_CONSISTENCY = "apisix-caches-the-verifiers-jwks-and-the-kid-never-changes"
DOC_STALE_CREDENTIAL = "a-stale-credential-in-the-identityhub-outlives-a-key-rotation"
# IssuerKeyIdValidationRule is documented in the token-failure table, not in the
# controlplane-image entry - the kid problem is its own thing
DOC_HOLDER_KID = "reading-edcs-dcp-token-failures"
DOC_DID_CONSISTENCY = "the-did-is-written-down-in-several-places-and-they-drift"
DOC_REGISTRATION = "a-post-install-only-registration-job-stops-registering-on-upgrade"


def did_to_url(did: str) -> Optional[str]:
    """did:web -> the URL its document is served from.

    The path form matters: `did:web:host` resolves to /.well-known/did.json while
    `did:web:host:a:b` resolves to /a/b/did.json. Deployments in this dataspace
    use both (one has the `:did` suffix, another does not), and assuming either
    one is a recurring source of confusion.
    """
    if not did or not did.startswith("did:web:"):
        return None
    rest = did[len("did:web:"):]
    parts = rest.split(":")
    host = parts[0].replace("%3A", ":")
    if len(parts) == 1:
        return "https://%s/.well-known/did.json" % host
    return "https://%s/%s/did.json" % (host, "/".join(parts[1:]))


def fetch_did_document(did: str, insecure: bool = False) -> (Optional[dict],
                                                              Optional[str]):
    """The DID document a did:web resolves to.

    `insecure` has to be threaded through from the caller's `ctx` because this
    takes a DID and not a context, and for a long time it was not: `--insecure`
    reached fourteen other `http.get` calls and not this one, so on a deployment
    with a self-signed certificate - a local k3s on nip.io, say - the flag
    silently did nothing here and four checks failed on TLS that the operator had
    explicitly said to ignore.
    """
    url = did_to_url(did)
    if not url:
        return None, "not a did:web identifier: %s" % did
    resp = http.get(url, insecure=insecure)
    if resp.error:
        return None, "%s: %s" % (url, resp.error)
    if not resp.ok:
        return None, "%s returned HTTP %d" % (url, resp.status)
    doc = resp.json()
    if doc is None:
        return None, "%s did not return JSON" % url
    return doc, None


@check("identity-did-consistency", "Every place that names our DID names the same one",
       phase="static", lanes=None)
def identity_did_consistency(ctx) -> Result:
    """The generic sibling of identity-key-consistency, for the declared half.

    A DSC writes its own DID down in several independent places - the verifier,
    contract-management, the did-helper's hostUrl, the lanes, Keycloak - and
    nothing re-reads them all after a domain change. One left behind produces a
    symptom that names neither the key nor the file: a counterparty rejects a
    token whose `aud` or `iss` is a participant it has never heard of, and the
    component that minted it looks healthy from every angle.

    Unlike `identity-key-consistency` this needs no cluster and no EDC lane: it
    compares what the deployment *declares* about itself, which is exactly what a
    Consumer has and nothing else.
    """
    who = ctx.participant
    sources = who.did_sources
    detail = {"did": who.did, "from": who.origin, "sources": dict(sources),
              "placeholders": list(who.placeholders)}

    if not sources:
        return Result.skip(
            "no source states a DID",
            cause="neither a lane nor the values name one%s. Pass --did to say what "
                  "this participant is called"
                  % ("" if ctx.values.trust != "none"
                     else ", and the values could not be read (%s)" % ctx.values.source))
    if len(sources) == 1:
        name = next(iter(sources))
        return Result.ok("one source, %s: %s" % (name, who.did), **detail)

    distinct = set(sources.values())
    if len(distinct) > 1:
        # Point at the odd one out rather than at whatever `participant` happened
        # to pick: when two sources agree and one does not, the one that does not
        # is the finding, and naming the majority instead sends the operator to
        # change the wrong file.
        counts = {value: sum(1 for v in sources.values() if v == value)
                  for value in distinct}
        best = max(counts.values())
        majority = [value for value, n in counts.items() if n == best]
        agreed = majority[0] if len(majority) == 1 else None
        odd = sorted((source, value) for source, value in sources.items()
                     if agreed is None or value != agreed)
        if agreed:
            summary = ("%d of %d places name a different participant"
                       % (len(odd), len(sources)))
            lead = "%d source(s) say %s, but %s" % (
                best, agreed, "; ".join("%s says %s" % pair for pair in odd))
        else:
            summary = "%d places name %d different participants" % (len(sources),
                                                                    len(distinct))
            lead = "; ".join("%s says %s" % pair for pair in odd)
        return Result.fail(
            summary,
            cause="%s. Whoever signs with the odd one out mints tokens a counterparty "
                  "rejects as coming from someone it does not know, and the component "
                  "itself looks healthy - the failure surfaces on the other side of "
                  "the wire." % lead,
            fix="settle on one and update the others: the verifier's "
                "`deployment.verifier.did`, `contract-management.did`, the did-helper's "
                "`config.server.hostUrl`, and the lane's `edc.participant.id`",
            doc=DOC_DID_CONSISTENCY, **detail)

    note = ""
    if who.placeholders:
        # `${DID}` is correct, not broken: an init container substitutes it. Saying
        # so keeps the next reader from "fixing" it.
        note = " (%s hold an unresolved placeholder, which is how they are meant to "
        note = (note % ", ".join(who.placeholders)) + "look)"
    return Result.ok("%d sources agree on %s%s" % (len(sources), who.did, note), **detail)


@check("did-document", "The DID document resolves and is well formed",
       lanes=None)
def did_document(ctx) -> Result:
    did = ctx.any_participant_id()
    if not did:
        return Result.skip("no participant id discovered")
    doc, err = fetch_did_document(did, ctx.insecure)
    if err:
        return Result.fail(
            "the DID document does not resolve",
            cause=err,
            fix="check the did:web host's DNS and ingress; a counterparty cannot "
                "authenticate us at all without this",
        )

    problems = []
    methods = doc.get("verificationMethod") or []
    if not methods:
        problems.append("no verificationMethod")
    ids = [m.get("id") for m in methods]
    if len(ids) != len(set(ids)):
        problems.append("duplicate verificationMethod ids: %s" % ids)

    services = [s for s in (doc.get("service") or [])]
    credential_services = [s for s in services if s.get("type") == "CredentialService"]
    service_ids = [s.get("id") for s in services]
    if len(service_ids) != len(set(service_ids)):
        problems.append("duplicate service ids: %s" % service_ids)
    if len(credential_services) > 1:
        problems.append("%d CredentialService entries; a peer will use the first"
                        % len(credential_services))

    detail = {"did": did, "verificationMethods": ids,
              "credentialService": [s.get("serviceEndpoint") for s in credential_services]}
    if problems:
        return Result.fail(
            "the DID document is malformed",
            cause="; ".join(problems),
            fix="PATCH on the endpoints API appends instead of replacing - use "
                "DELETE ?serviceId=<id> then POST",
            doc="the-did-endpoints-api-patch-appends-it-does-not-replace",
            **detail)
    if not credential_services:
        # Only DCP reads it. A deployment with no DCP lane has no use for one, and
        # warning there tells a correctly built Consumer that something is wrong
        # with it - which is how an operator learns to stop reading the output.
        speaks_dcp = any(lane.speaks_dcp for lane in ctx.deployment.edc_lanes.values())
        if not speaks_dcp:
            return Result.ok(
                "resolves, %d key(s); no CredentialService, which only DCP needs"
                % len(ids), **detail)
        return Result.warn(
            "resolves, but publishes no CredentialService",
            cause="the DCP lane needs it: a counterparty reads it to fetch our presentation",
            **detail)
    return Result.ok("resolves, %d key(s), CredentialService present" % len(ids), **detail)


@check("identity-key-consistency", "Every copy of the identity key agrees",
       needs_cluster=True, lanes=None)
def identity_key_consistency(ctx) -> Result:
    """The check that would have saved the most time.

    Four copies of the same key have to agree, and a mismatch is completely
    silent until a counterparty rejects a signature: the private key in the
    secret, the public key in the published DID document, the participant's
    publicKeyJwk in the identityhub, and whatever actually signed the stored
    credential.
    """
    did = ctx.any_participant_id()
    if not did:
        return Result.skip("no participant id discovered")
    if not ctx.deployment.identity_secret:
        return Result.skip("identity secret not resolved; set identity.secret in --config")

    fingerprints: Dict[str, str] = {}

    secret = ctx.kube.secret(ctx.deployment.identity_secret)
    key_name = ctx.deployment.identity_secret_key or "tls.key"
    if key_name not in secret:
        return Result.skip("secret %s has no key %s" % (ctx.deployment.identity_secret, key_name))
    try:
        fingerprints["secret"] = jose.jwk_fingerprint(jose.public_jwk_from_pem(secret[key_name]))
    except Exception as exc:  # noqa: BLE001
        return Result.fail("could not read the private key",
                          cause="%s: %s" % (ctx.deployment.identity_secret, exc))

    doc, err = fetch_did_document(did, ctx.insecure)
    if err:
        return Result.fail("cannot compare: the DID document does not resolve", cause=err)
    keys = jose.did_document_keys(doc)
    if not keys:
        return Result.fail("the DID document publishes no JWK to compare against")
    # Match each local copy against EVERY published method. This used to take
    # `sorted(keys.items())[0]` and compare against that one alone, which is right
    # only while a document carries a single method - the shape of every deployment
    # inspected so far, which is why it never misfired. A document is free to publish
    # one method per component signing as this DID, and against such a document the
    # old form compared the secret with an arbitrary key and failed, naming two
    # fingerprints that were never meant to be equal. What actually has to hold is
    # that each copy is published *somewhere*: an unpublished key is what makes a
    # signature unverifiable, not a key that differs from its neighbour.
    published = {vm: jose.jwk_fingerprint(jwk) for vm, jwk in keys.items()}

    ih_jwk = ctx.identityhub_participant_key(did)
    if ih_jwk:
        fingerprints["identityhub"] = jose.jwk_fingerprint(ih_jwk)
    else:
        ctx.identityhub_credentials(did)  # records why, for the message below

    def method_for(fingerprint):
        return next((vm for vm, fp in sorted(published.items()) if fp == fingerprint), None)

    matched = {source: method_for(fp) for source, fp in fingerprints.items()}
    unpublished = sorted(source for source, vm in matched.items() if vm is None)
    detail = {"fingerprints": fingerprints, "published": published, "matched": matched,
              # kept under its old name: it is what the JSON has always called the
              # method the signing key resolves to
              "verificationMethod": matched.get("secret")}
    if not unpublished:
        # name the sources compared: "2 copies agree" would read as all-clear even
        # when the identityhub copy could not be read at all
        summary = "%s published as %s (%s)" % (
            " + ".join(sorted(fingerprints)),
            ", ".join(sorted(set(vm for vm in matched.values() if vm))),
            fingerprints["secret"])
        if "identityhub" not in fingerprints:
            # No identityhub at all is not a gap: it comes with a DCP lane, and a
            # deployment without one keeps its key in two places rather than
            # three. Warning there tells a correctly built provider that something
            # is missing from it.
            if not ctx.deployment.service("identityhub"):
                return Result.ok(
                    "%s (no identityhub here, so there is no third copy)" % summary,
                    **detail)
            return Result.warn(
                summary,
                cause="the identityhub's own copy could not be read (%s), so a "
                      "mismatch there would not show up here"
                      % (ctx.identityhub_error or "reason unknown"),
                **detail)
        return Result.ok(summary, **detail)
    return Result.fail(
        "%s: the identity key is not published in the DID document"
        % " and ".join(unpublished),
        cause="%s - the document publishes %s, so whatever signs with an "
              "unpublished key is rejected by every counterparty, and the rejection "
              "names a signature rather than a key that was never distributed"
              % ("; ".join("%s=%s" % (s, fingerprints[s]) for s in unpublished),
                 ", ".join("%s=%s" % (vm, fp) for vm, fp in sorted(published.items()))),
        fix="re-run the rotation runbook end to end; note the participant's "
            "publicKeyJwk is NOT updated by a re-run of the bootstrap job (it 409s)",
        doc=DOC_KEY_CONSISTENCY,
        **detail)


@check("credential-freshness", "The stored credential verifies against the published key",
       needs_cluster=True, lanes=None)
def credential_freshness(ctx) -> Result:
    """Catches the credential that survives a key rotation.

    It is signed with the previous key, nothing expires it, and it breaks only
    the DCP lane - which makes it look like a DCP problem. Verifying the
    signature is the only way to see it.
    """
    did = ctx.any_participant_id()
    if not did:
        return Result.skip("no participant id discovered")

    stored = ctx.identityhub_credentials(did)
    if stored is None:
        if not ctx.deployment.service("identityhub"):
            return Result.na("no identityhub in this namespace",
                             cause="the credential store it checks comes with a DCP "
                                   "lane; there is nothing here to go stale")
        return Result.skip("could not read the identityhub credential store",
                           cause=ctx.identityhub_error)
    if not stored:
        return Result.fail(
            "the identityhub holds no credential",
            cause="the DCP lane builds its presentation from this store; with no "
                  "credential a counterparty gets nothing to verify",
            fix="POST the credential to /participants/<didB64>/credentials",
            doc=DOC_STALE_CREDENTIAL)

    doc, err = fetch_did_document(did, ctx.insecure)
    if err:
        return Result.fail("cannot verify: the DID document does not resolve", cause=err)
    keys = jose.did_document_keys(doc)

    bad, checked, unverifiable = [], 0, []
    for entry in stored:
        raw = ((entry.get("verifiableCredential") or {}).get("rawVc")
               or entry.get("rawVc"))
        if not raw or raw.count(".") != 2:
            continue
        try:
            header = jose.decode_jwt(raw)["header"]
        except jose.MalformedToken:
            continue
        kid = header.get("kid")
        jwk = keys.get(kid) or (sorted(keys.values(), key=str)[0] if keys else None)
        if not jwk:
            continue
        checked += 1
        try:
            if not jose.verify_jwt(raw, jwk):
                bad.append(entry.get("id") or "<unnamed>")
        except jose.CryptoUnavailable as exc:
            unverifiable.append("%s (%s)" % (entry.get("id"), exc))

    if bad:
        return Result.fail(
            "%d stored credential(s) do not verify against the published key" % len(bad),
            cause="credential(s) %s were signed with a different key - the classic "
                  "symptom is a peer reporting 'Token verification failed', which "
                  "means exactly 'the signature does not validate', never a rule failure"
                  % ", ".join(bad),
            fix="re-issue the credential and PUT it into the store; the JSON key is "
                "verifiableCredentialContainer, not credential",
            doc=DOC_STALE_CREDENTIAL,
            failing=bad)
    if unverifiable:
        return Result.warn("could not verify %d credential(s)" % len(unverifiable),
                           cause="; ".join(unverifiable),
                           fix="pip install cryptography")
    if not checked:
        return Result.warn("no verifiable credential found in the store",
                           cause="%d entries, none with a JWT we could match to a "
                                 "published key" % len(stored))
    return Result.ok("%d credential(s) verify against the published key" % checked)


@check("credential-two-copies", "The file and the identityhub hold the same credential",
       needs_cluster=True, lanes=None)
def credential_two_copies(ctx) -> Result:
    """The OID4VC lane reads a file, the DCP lane reads the database.

    A rotation typically refreshes only the file, so one lane keeps working and
    the other breaks - which sends you looking at the wrong lane.
    """
    did = ctx.any_participant_id()
    stored = ctx.identityhub_credentials(did) if did else None
    file_jwt = ctx.credential_file_jwt()

    if stored is None and file_jwt is None:
        if not ctx.deployment.service("identityhub"):
            return Result.na("no identityhub in this namespace",
                             cause="there is only ever one copy without a DCP lane, "
                                   "so there is nothing to compare")
        return Result.skip("neither copy could be read", cause=ctx.identityhub_error)
    if stored is None:
        return Result.skip("could not read the identityhub store",
                           cause=ctx.identityhub_error)
    if file_jwt is None:
        return Result.skip("could not read the credential file from the pod")
    if not stored:
        return Result.skip("the identityhub store is empty (see credential-freshness)")

    raws = {(e.get("verifiableCredential") or {}).get("rawVc") or e.get("rawVc")
            for e in stored}
    if file_jwt in raws:
        return Result.ok("both copies hold the same credential")
    return Result.warn(
        "the file and the identityhub hold different credentials",
        cause="the OID4VC lane presents the file, the DCP lane presents the stored "
              "row; when they differ, exactly one lane works and it looks "
              "lane-specific",
        fix="update the identityhub store with the JWT that is in the file",
        doc=DOC_STALE_CREDENTIAL)


@check("holder-kid-fragment", "oid4vp.holder.kid names a real verification method",
       lanes=["*"], transport="edc")
def holder_kid_fragment(ctx, lane) -> Result:
    """A bare-DID kid is rejected by the DCP validator.

    `IssuerKeyIdValidationRule` requires the kid to match `<iss>#...`, so a kid
    equal to the participant id fails with "kid header expected to correlate to
    iss". The OID4VP path is more tolerant, which is why this is a FAIL for a
    lane that speaks DCP and a WARN otherwise.
    """
    kid = lane.prop("oid4vp.holder.kid")
    participant = lane.participant_id
    if not kid or not participant:
        return Result.skip("oid4vp.holder.kid or edc.participant.id not set")

    speaks_dcp = lane.speaks_dcp
    has_fragment = kid.startswith(participant + "#")

    if not has_fragment:
        problem = ("kid is the bare DID (%s), so it does not correlate to iss" % kid
                   if kid == participant else
                   "kid %s is not <participantId>#<fragment>" % kid)
        maker = Result.fail if speaks_dcp else Result.warn
        return maker(
            "holder kid does not name a verification method",
            cause=problem + (" - the DCP validator rejects this" if speaks_dcp
                             else " - tolerated on the OID4VP path, but it will "
                                  "break the moment this lane speaks DCP"),
            fix="set oid4vp.holder.kid to %s#<fragment published in the DID document>"
                % participant,
            doc=DOC_HOLDER_KID,
            kid=kid)

    doc, err = fetch_did_document(participant, ctx.insecure)
    if err:
        return Result.warn("kid is well formed but could not be confirmed",
                           cause=err, kid=kid)
    published = set(jose.did_document_keys(doc))
    if kid not in published:
        return Result.fail(
            "holder kid is not published in the DID document",
            cause="kid %s is absent from the document, which publishes %s; every "
                  "signature we make will be unverifiable" % (kid, sorted(published)),
            fix="align oid4vp.holder.kid with a published verificationMethod, or "
                "publish that method",
            doc=DOC_HOLDER_KID,
            kid=kid)
    return Result.ok("kid %s is published" % kid)


def _til_addresses(ctx) -> list:
    """Every trusted-issuers-list this deployment points at.

    A set rather than one, because the address is a per-lane property and two
    lanes are free to name different lists - and a participant with no lane at
    all still has one, configured on the verifier as `tirAddress`. Collapsing to
    a single check would have silently stopped testing the second list.
    """
    addresses = []
    for lane in sorted(ctx.deployment.edc_lanes.values(), key=lambda l: l.name):
        if lane.prop("ebsiTir.enabled", "true").lower() != "true":
            continue
        address = lane.prop("ebsiTir.tilAddress")
        if address and address not in addresses:
            addresses.append(address)
    if not addresses and ctx.participant.til_address:
        addresses.append(ctx.participant.til_address)
    return addresses


@check("til-registration", "The DIDs that must be trusted are in the issuers list",
       needs_cluster=True, lanes=None)
def til_registration(ctx) -> Result:
    """Runs once per participant, not once per lane.

    Whether our DID is trusted is a fact about the participant and its issuers
    list, not about a transport: the two lanes of an EDC deployment produced two
    identical rows, and a deployment with no lane produced none at all while
    still having a verifier that consults a list.
    """
    addresses = _til_addresses(ctx)
    if not addresses:
        return Result.skip("no trusted issuers list is configured",
                           cause="neither a lane's ebsiTir.tilAddress nor the verifier's "
                                 "tirAddress names one")

    did = ctx.participant.did
    if not did:
        return Result.skip("no participant id discovered")
    peer = ctx.peers[0] if ctx.peers else None
    wanted = [("self", did)]
    if peer:
        wanted.append(("peer", peer.participant_id))

    missing, registered = [], {}
    for address in addresses:
        for role, subject in wanted:
            body, err = ctx.til_issuer(address, subject)
            if err:
                return Result.warn("could not query the TIL", cause=err, til=address)
            if body is None:
                if (role, subject) not in missing:
                    missing.append((role, subject))
            else:
                registered[subject] = sorted(ctx.til_credential_types(body))

    if missing:
        # This list decides who cannot be believed, not who cannot believe us. The
        # TIL a participant runs is consulted by *its own* verifier, so a DID
        # missing from ours only ever breaks something coming **in**. Which is why
        # the two halves of `missing` are not the same finding at all.
        peer_missing = [s for role, s in missing if role == "peer"]
        self_missing = [s for role, s in missing if role == "self"]

        if peer_missing:
            return Result.fail(
                "a peer's DID is absent from our issuers list",
                cause="%s not registered here. Our verifier asks this list whether the "
                      "issuer of an incoming credential is trusted, so every "
                      "presentation from that peer is refused at the credential layer "
                      "- after every signature check has passed, which reads like a "
                      "signing problem and is not." % ", ".join(peer_missing),
                fix="register it via the TIL API or the chart's registration job",
                til=addresses, missing=peer_missing)

        # Only our own. Never a failure: nothing we do *outwards* depends on it,
        # because the list that decides whether a provider accepts us is theirs.
        roles, _ = components.roles_for(ctx.deployment, ctx.profile)
        breaks = []
        if ctx.deployment.edc_lanes:
            breaks.append("a loopback DSP flow, which negotiates against our own "
                          "endpoint and therefore verifies a credential we issued")
        if "provider" in roles:
            breaks.append("our own users reaching our own gateway-protected services "
                          "with a credential our Keycloak issued")
        breaks.append("any counterparty presenting a credential we issued to them")

        return Result.warn(
            "our own DID is absent from our own issuers list",
            cause="%s not registered. Nothing we do outwards depends on this - the "
                  "list that decides whether a provider accepts us is theirs, not "
                  "ours - so access to a central marketplace or to any other "
                  "participant is unaffected. What it does stop is anything arriving "
                  "with us as the issuer: %s."
                  % (", ".join(self_missing), "; ".join(breaks)),
            fix="register it via the TIL API or the chart's registration job, if any "
                "of the above is something this deployment is meant to do",
            til=addresses, missing=self_missing)

    return Result.ok(
        "; ".join("%s: %s" % (subject, ", ".join(types) or "no type")
                  for subject, types in registered.items()),
        registered=registered, til=addresses)


@check("registration-services-present",
       "The verifier's config repo holds every registered service",
       needs_cluster=True, needs_values=True, roles=("provider",))
def registration_services_present(ctx) -> Result:
    """Whether the registration job's declaration ever reached the verifier.

    The declaration and the outcome are different facts, and only this one
    matters to a wallet. `registration-job-hooks` can prove the job cannot have
    re-run since install, but not that anything is missing as a result - that
    depends on whether the values changed afterwards. Conversely, the config repo
    can be complete while the hook is still misconfigured, which is exactly the
    state a domain migration leaves behind once somebody re-registered by hand.

    A service declared but absent here is served as a request object with no
    presentation definition, which a wallet reports as "could not process the
    information request" - the same generic message a dozen other faults produce.
    """
    declared = ctx.values.get(
        "decentralizedIam.vcAuthentication.vcverifier.registration.services")
    if not declared:
        return Result.skip("this release declares no verifier services to register")
    wanted, deferred = [], []
    for service in declared:
        if not isinstance(service, dict) or not service.get("id"):
            continue
        # `${DID}` is a *shell* variable in the registration script, and whether
        # it survives to the config repo depends on the chart the job ran under.
        # Up to vcverifier 4.12.1 the body went out through an unquoted heredoc
        # and the shell expanded it, so the repo holds the resolved DID; the
        # refactor in 4.12.5 passes the body as a single-quoted argument, which
        # does not expand, so the repo holds the literal `${DID}`. Both are live
        # in demo: dso-infra registered `did:web:did.central.example.org` and
        # consumer registered the string `${DID}`. The job is post-install only,
        # so what is in the repo reflects the chart at *first install*, not the
        # one deployed now - which means the values cannot tell us which form to
        # look for, and comparing either literally reports a false verdict on
        # the other. Hence: not compared, and said out loud.
        if values_mod.has_placeholder(service["id"]):
            deferred.append(service["id"])
        else:
            wanted.append(service["id"])
    if not wanted:
        if deferred:
            return Result.skip(
                "every declared service id is a placeholder (%s)" % ", ".join(deferred),
                cause="a placeholder is expanded by the registration script only on "
                      "chart versions up to vcverifier 4.12.1; from 4.12.5 it reaches "
                      "the config repo verbatim. Since the job is post-install only, "
                      "which of the two is registered depends on the chart at first "
                      "install, so there is nothing here that can be compared without "
                      "guessing. Read the ids with GET :8090/service to see which "
                      "form this deployment has")
        return Result.skip("the declared services carry no ids")

    services, err = ctx.verifier_services()
    if err or services is None:
        return Result.skip("could not read the verifier's config repo", cause=err)

    present = {s.get("id") for s in services if isinstance(s, dict)}
    missing = [sid for sid in wanted if sid not in present]
    if missing:
        return Result.fail(
            "%d declared service(s) are absent from the verifier's config repo"
            % len(missing),
            cause="declared %s, registered %s. A login against %s resolves to a "
                  "request object with no presentation_definition, which the wallet "
                  "reports as \"could not process the information request\"."
                  % (wanted, sorted(present), missing[0]),
            fix="re-run the registration job (see registration-job-hooks), or POST "
                "the service to the config repo on port 8090",
            doc=DOC_REGISTRATION, declared=wanted, registered=sorted(present),
            missing=missing)
    extra = sorted(present - set(wanted))
    summary = "all %d declared service(s) are registered" % len(wanted)
    if deferred:
        summary += (" (%d placeholder id(s) not comparable: the script expands "
                    "them only up to chart 4.12.1)" % len(deferred))
    return Result.ok(summary, declared=wanted, unmanaged=extra, placeholders=deferred)
