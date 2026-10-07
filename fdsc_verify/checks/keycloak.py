"""Keycloak: how long a credential lives, and in what format it is issued.

Keycloak is Required for every participant role and the tool read nothing from
it. It is the issuer for the whole deployment, so two of its decisions decide
whether the FIWARE path works at all - how long an issued credential is valid,
and which format it comes out in - and both are one line in the realm that
nobody looks at twice.

Four things about the realm shaped every line here, all measured before any of
this was written:

* **`verifiable_credential_type` is not the block name.** The block
  `membership-credential` declares `verifiable_credential_type:
  MembershipCredential`. Comparing block names against what the verifier asks
  for reports a disagreement that is not there.
* **On older charts that attribute is absent altogether**, and then the type
  cannot be determined at all. Two deployments here are in that state. Those
  blocks are named and skipped rather than guessed at from the block name.
* **Four format spellings live in one dataspace** - `dc+sd-jwt`, `vc+sd-jwt`,
  `jwt_vc_json`, `jwt_vc` - and they are not interchangeable. Nothing here
  normalises them.
* **The attribute keys contain dots** (`credential_build_config.sd_jwt.visible_claims`),
  so they are read out of the attributes mapping directly. `values.get("a.b.c")`
  splits on the dots and finds nothing.
"""

from __future__ import annotations

import json
from typing import Dict, List, Optional, Set, Tuple

from .. import jose
from .. import values as values_mod
from ..model import Result, check
from ..participant import workload_pod_spec
from .identity import fetch_did_document

DOC_LIFETIME = "a-credential-expires-in-a-week-and-the-ui-says-a-year"
DOC_FORMATS = "the-verifier-asks-for-a-format-keycloak-does-not-issue"
DOC_SIGNING_KEY = "keycloak-signs-with-a-key-the-did-document-does-not-publish"

VC_PATH = "keycloak.realm.verifiableCredentials"

# Keycloak's own default when `refresh_interval_in_seconds` is not set. It is the
# number that lands in the credential's `exp`, so it is the one that matters.
KEYCLOAK_DEFAULT_REFRESH = 604800

# The chart writes these without a prefix and the Admin API shows them with one.
# Both spellings are accepted so the check reads a realm whichever way it arrived.
EXPIRY_KEYS = ("expiry_in_seconds", "vc.expiry_in_seconds")
REFRESH_KEYS = ("refresh_interval_in_seconds", "vc.refresh_interval_in_seconds")
TYPE_KEYS = ("verifiable_credential_type", "vc.verifiable_credential_type")
FORMAT_KEYS = ("format", "vc.format")


def _attr(attributes: dict, names) -> Optional[str]:
    """One attribute under any of its spellings, as the string Keycloak stores.

    Read straight out of the mapping rather than through `values.get`: these keys
    contain dots and a dotted lookup would split them into a path that does not
    exist.
    """
    for name in names:
        value = attributes.get(name)
        if value is not None and str(value).strip():
            return str(value).strip()
    return None


def _credential_blocks(ctx) -> Dict[str, dict]:
    block = ctx.values.get(VC_PATH)
    return block if isinstance(block, dict) else {}


@check("keycloak-credential-lifetime",
       "An issued credential lives as long as the realm says it does",
       phase="static", needs_values=True)
def keycloak_credential_lifetime(ctx) -> Result:
    """The admin UI reports one number and the credential carries another.

    Two attributes govern this and only one of them reaches the credential:

    | attribute | what it does |
    |---|---|
    | `expiry_in_seconds` | what the admin UI displays |
    | `refresh_interval_in_seconds` | what lands in the credential's `exp`; **unset means Keycloak defaults it to 604800** |

    Measured on a real credential: `nbf` and `exp` exactly 604800 s apart while
    the UI said a year. Raising `expiry_in_seconds` alone changed nothing;
    raising the refresh interval moved `exp`. Neither was set by the deployment -
    both were Keycloak defaults.

    It is also the real cause of an identityhub credential copy going stale every
    week, which read for a long time as a design decision and was this default.

    WARN rather than FAIL in both branches: credentials are issued and they work.
    What is wrong is that they stop working sooner than anybody was told, which
    is a clock running rather than an outage. `--strict` still fails the run.
    """
    blocks = _credential_blocks(ctx)
    if not blocks:
        return Result.na(
            "no verifiableCredentials block in this realm",
            cause="`%s` is absent, so this deployment declares no credential for "
                  "Keycloak to issue and there is no lifetime to check" % VC_PATH)

    unset: List[str] = []
    mismatched: List[str] = []
    agreed: List[str] = []
    for name, body in sorted(blocks.items()):
        attributes = (body or {}).get("attributes") or {}
        expiry = _attr(attributes, EXPIRY_KEYS)
        refresh = _attr(attributes, REFRESH_KEYS)
        if refresh is None:
            unset.append("%s (the UI will show %s)"
                         % (name, expiry or "Keycloak's own default"))
        elif expiry is not None and expiry != refresh:
            mismatched.append("%s (UI %s, credential %s)" % (name, expiry, refresh))
        else:
            agreed.append(name)

    detail = {"unset": unset, "mismatched": mismatched, "agreed": agreed}
    fix = ("set both attributes to the same value on every credential - moving "
           "expiry_in_seconds alone changes nothing. Realm attributes only take "
           "effect on an import, so on a realm that already exists they have to be "
           "updated through the Admin API instead of the chart")

    if unset:
        return Result.warn(
            "%d credential type(s) expire in %d s, not what the UI reports"
            % (len(unset), KEYCLOAK_DEFAULT_REFRESH),
            cause="`refresh_interval_in_seconds` is unset on %s, so Keycloak "
                  "defaults it to %d - seven days - and that is the number that "
                  "lands in the credential's `exp`. The admin UI shows "
                  "`expiry_in_seconds` instead, so nothing on screen says the "
                  "credential is about to expire. Anything holding a copy, the "
                  "identityhub included, goes stale on the same clock"
                  % ("; ".join(unset), KEYCLOAK_DEFAULT_REFRESH),
            fix=fix, doc=DOC_LIFETIME, **detail)
    if mismatched:
        return Result.warn(
            "%d credential type(s) report one lifetime and issue another"
            % len(mismatched),
            cause="%s. `expiry_in_seconds` is what the admin UI displays and "
                  "`refresh_interval_in_seconds` is what reaches the credential's "
                  "`exp`, so the shorter one is what actually happens and the "
                  "longer one is what everybody believes" % "; ".join(mismatched),
            fix=fix, doc=DOC_LIFETIME, **detail)
    return Result.ok("%d credential type(s) expire when the UI says they do"
                     % len(agreed), **detail)


def _issued(ctx) -> Tuple[Dict[str, str], List[str]]:
    """`{credential type: format}` for what this Keycloak issues.

    A block whose `verifiable_credential_type` is absent is returned separately
    rather than keyed by its own name: `membership-credential` issues
    `MembershipCredential`, so the block name is not the type and guessing from
    it invents a disagreement.
    """
    issued: Dict[str, str] = {}
    undetermined: List[str] = []
    for name, body in sorted(_credential_blocks(ctx).items()):
        attributes = (body or {}).get("attributes") or {}
        vc_type = _attr(attributes, TYPE_KEYS)
        fmt = _attr(attributes, FORMAT_KEYS)
        if not vc_type or not fmt:
            undetermined.append(name)
            continue
        issued[vc_type] = fmt
    return issued, undetermined


def _accepted(services) -> List[Tuple[str, str, Dict[str, Set[str]]]]:
    """(service id, scope, {credential type: formats that scope accepts}).

    The formats a scope will take are spread over three places and a scope may
    carry any subset of them: `presentationDefinition.format`, the same key on
    each `input_descriptors` entry, and a `format` on each `dcql.credentials`
    entry. The dcql entries are the precise ones - each names a format *and* the
    type it applies to - while the presentation definition's formats apply to
    whatever `credentials[].type` the scope lists.
    """
    out: List[Tuple[str, str, Dict[str, Set[str]]]] = []
    for service in services or []:
        if not isinstance(service, dict):
            continue
        for scope, body in (service.get("oidcScopes") or {}).items():
            if not isinstance(body, dict):
                continue
            definition = body.get("presentationDefinition") or {}
            shared = set(definition.get("format") or {})
            for descriptor in definition.get("input_descriptors") or []:
                shared |= set((descriptor or {}).get("format") or {})

            per_type: Dict[str, Set[str]] = {}
            for entry in body.get("credentials") or []:
                vc_type = (entry or {}).get("type")
                if vc_type:
                    per_type.setdefault(vc_type, set()).update(shared)
            for entry in (body.get("dcql") or {}).get("credentials") or []:
                fmt = (entry or {}).get("format")
                meta = (entry or {}).get("meta") or {}
                # two spellings across versions, and `type_values` nests one level
                types = list(meta.get("vct_values") or [])
                for value in meta.get("type_values") or []:
                    types.extend(value if isinstance(value, list) else [value])
                for vc_type in types:
                    if vc_type and fmt:
                        per_type.setdefault(vc_type, set()).add(fmt)
            if per_type:
                out.append((str(service.get("id") or "?"), str(scope), per_type))
    return out


@check("keycloak-verifier-formats",
       "The verifier accepts the format Keycloak issues",
       needs_cluster=True, transport="fiware")
def keycloak_verifier_formats(ctx) -> Result:
    """A credential nobody can present, and nothing says so.

    Keycloak issues a credential in one format; the verifier asks for a format in
    its presentation definition and its DCQL query. When they do not intersect, a
    wallet holding a perfectly valid credential has nothing that satisfies the
    request, and reports it as the same generic "could not process the
    information request" that a dozen other faults produce.

    **Only the intersection with ourselves is judged.** A type the verifier asks
    for and this Keycloak does not issue is not a finding: in a working dataspace
    a counterparty issues it, and flagging it would put a permanent complaint in
    every report. What can be settled from here is our own users against our own
    services, and that is what this measures.

    **A scope that states no format at all is not a disagreement.** Nine services
    on one real deployment declare a credential type with neither a presentation
    definition format nor a dcql entry - leftovers from past transfers - and
    treating an empty set as a mismatch reported nine faults on a healthy
    deployment. An empty set means the scope was never told a format, which is a
    different sentence and not this check's.
    """
    # The realm is a values-only source, and this check is not gated on them
    # because its other half is a live read. So an unreadable release has to say
    # so rather than assert an empty realm: that is the difference between "the
    # question does not arise" and "the tool could not settle it".
    if getattr(ctx.values, "trust", "none") == "none":
        return Result.skip("the realm could not be read",
                           cause=getattr(ctx.values, "source", None) or
                           "no values were readable, so what this Keycloak issues "
                           "is unknown. Pass --values or --effective-values")

    issued, undetermined = _issued(ctx)
    if not issued:
        if undetermined:
            return Result.na(
                "no credential type could be determined from the realm",
                cause="%s declare no `verifiable_credential_type`, which older "
                      "charts leave out entirely. The block name is not the type - "
                      "`membership-credential` issues `MembershipCredential` - so "
                      "there is nothing here that can be compared without guessing"
                      % ", ".join(undetermined))
        return Result.na(
            "this realm issues no credential",
            cause="`%s` is absent or empty, so there is no format to compare "
                  "against what the verifier asks for" % VC_PATH)

    if not ctx.deployment.service("verifier"):
        return Result.na(
            "no verifier in this namespace",
            cause="the verifier is what states the formats it will accept; without "
                  "one there is nothing to compare Keycloak against")

    services, err = ctx.verifier_services()
    if services is None:
        return Result.skip("the verifier's config repo could not be read", cause=err)

    disagreements: List[str] = []
    formatless: List[str] = []
    compared = 0
    for service_id, scope, per_type in _accepted(services):
        for vc_type, fmt in issued.items():
            if vc_type not in per_type:
                continue
            accepted = per_type[vc_type]
            if not accepted:
                # asked for, but this scope names no format anywhere - counted so
                # the report can say so, never judged
                formatless.append("%s/%s" % (service_id, scope))
                continue
            compared += 1
            if fmt not in accepted:
                disagreements.append(
                    "%s in scope `%s` wants %s as %s, and Keycloak issues it as %s"
                    % (service_id, scope, vc_type, "/".join(sorted(accepted)), fmt))

    detail = {"issued": issued, "compared": compared,
              "disagreements": disagreements, "undetermined": undetermined,
              "askedForWithNoFormat": formatless}
    if disagreements:
        return Result.warn(
            "%d registered service(s) ask for a format this realm does not issue"
            % len(disagreements),
            cause="%s. A wallet holding that credential has nothing that satisfies "
                  "the request and says so generically, so the failure looks like a "
                  "wallet problem rather than a configuration one. These are not "
                  "interchangeable spellings of one format: `dc+sd-jwt` and "
                  "`vc+sd-jwt` are different media types" % "; ".join(disagreements),
            fix="align the two - either add the issued format to that scope's "
                "presentation definition and dcql, or change the realm's `format` "
                "for that credential. Changing the realm only takes effect on an "
                "import, so an existing realm needs the Admin API",
            doc=DOC_FORMATS, **detail)

    if not compared:
        if formatless:
            return Result.na(
                "%d scope(s) ask for what this realm issues and name no format"
                % len(formatless),
                cause="%s ask for %s without a presentation definition format or a "
                      "dcql entry, so there is nothing to compare Keycloak's format "
                      "against. An empty set is not a disagreement - it means the "
                      "scope was never told a format, which is a different question "
                      "from this one"
                      % (", ".join(formatless[:5]) +
                         (" and %d more" % (len(formatless) - 5)
                          if len(formatless) > 5 else ""),
                         ", ".join(sorted(issued))))
        return Result.na(
            "no credential type is both issued here and asked for here",
            cause="this realm issues %s and no registered service asks for any of "
                  "them. That is normal where the counterparties issue what this "
                  "verifier consumes" % ", ".join(sorted(issued)))
    summary = "%d (service, credential) pair(s) agree on a format" % compared
    if formatless:
        summary += ", %d name no format" % len(formatless)
    if undetermined:
        summary += " (%d realm block(s) state no type)" % len(undetermined)
    return Result.ok(summary, **detail)


# What the realm ConfigMap calls the kid, per credential. The values call it
# `keycloak.signingKey.did`; both are the same string and a GitOps install has
# only the second.
SIGNING_KID_PATH = "keycloak.signingKey.did"
SIGNING_ALG_PATH = "keycloak.signingKey.keyAlgorithm"
REALM_KID_KEY = "vc.signing_key_id"
# What key type each signing algorithm can be satisfied by: (kty, crv or None).
# ES256 needs an EC P-256 key and an RS256 needs an RSA one, so a kid that
# resolves to the wrong kind is the same fault reached another way - the realm
# and the document disagree about the key, not just about its name. The RSA
# families are here because leaving them out made the check pass an RS256 realm
# against an EC document, which is exactly the case it exists for.
ALG_KEYS = {"ES256": ("EC", "P-256"), "ES384": ("EC", "P-384"),
            "ES512": ("EC", "P-521"),
            "RS256": ("RSA", None), "RS384": ("RSA", None), "RS512": ("RSA", None),
            "PS256": ("RSA", None), "PS384": ("RSA", None), "PS512": ("RSA", None)}


def _keystore_secret(ctx, service: str):
    """(secret name, note) for the key Keycloak's PKCS#12 keystore is built from.

    Found through the init container that builds it - the one whose command runs
    `openssl pkcs12` - and the volume it mounts. Never by guessing a secret name:
    the identity secret is named after the did:web host and a deployment is free to
    call this one anything.
    """
    spec = workload_pod_spec(ctx.kube, ctx.deployment.namespace, service)
    if not spec:
        return None, "the Keycloak pod could not be read"
    secrets = {volume.get("name"): (volume.get("secret") or {}).get("secretName")
               for volume in spec.get("volumes") or []
               if isinstance(volume, dict) and volume.get("secret")}
    for container in spec.get("initContainers") or []:
        command = " ".join(str(part) for part in
                           (container.get("command") or []) + (container.get("args") or []))
        if "pkcs12" not in command:
            continue
        mounted = [secrets.get(mount.get("name"))
                   for mount in container.get("volumeMounts") or []
                   if secrets.get(mount.get("name"))]
        # the CA bundle is mounted beside the key and is not it
        candidates = [name for name in mounted if name and "ca-cert" not in name]
        if len(candidates) == 1:
            return candidates[0], None
        if candidates:
            return None, ("the keystore's init container mounts %d secrets (%s) and "
                          "which holds the signing key cannot be told apart"
                          % (len(candidates), ", ".join(sorted(candidates))))
        return None, "the keystore's init container mounts no secret"
    return None, "no init container on the Keycloak pod builds a PKCS#12 keystore"


def _realm_configmap(ctx, service: str) -> dict:
    """The realm JSON Keycloak actually mounts, as the cluster source for the kid.

    Found through the pod's volumes, not by name. The name does not follow the
    release: one cluster calls it `provider-realm` in a namespace whose release is
    `producer`, so `<release>-realm` matches nothing - and because the values
    answer first, that guess would have gone unnoticed until the one case it
    exists for, a GitOps install with no values at all.
    """
    spec = workload_pod_spec(ctx.kube, ctx.deployment.namespace, service)
    for volume in spec.get("volumes") or []:
        name = (volume.get("configMap") or {}).get("name") if isinstance(volume, dict) else None
        if not name:
            continue
        for key, body in (ctx.kube.configmap(
                name, namespace=ctx.deployment.namespace) or {}).items():
            if not key.endswith(".json") or REALM_KID_KEY not in str(body):
                continue
            try:
                return json.loads(body)
            except ValueError:
                return {}
    return {}


def _kid_from_realm(document: dict) -> Optional[str]:
    """`vc.signing_key_id`, wherever in the realm it was written."""
    found: List[str] = []

    def walk(node):
        if isinstance(node, dict):
            value = node.get(REALM_KID_KEY)
            if isinstance(value, str) and value.strip():
                found.append(value.strip())
            for child in node.values():
                walk(child)
        elif isinstance(node, list):
            for child in node:
                walk(child)

    walk(document)
    return found[0] if found else None


def _matches_kid(kid: str, method_id: str, did: str) -> bool:
    """Is `method_id` the method `kid` names?

    A verification method is published either absolutely (`did:web:x:did#key-1`)
    or relative to the document (`#key-1`, or bare `key-1`), and a realm names its
    kid either way too. Both sides are reduced to an absolute form before they are
    compared, because a deployment using one shape against a document using the
    other is correct and a literal comparison calls it broken.
    """
    def absolute(value: str) -> str:
        value = (value or "").strip()
        if not value:
            return ""
        if value.startswith("did:"):
            return value
        return "%s#%s" % (did, value.lstrip("#"))

    return bool(kid) and absolute(kid) == absolute(method_id)


@check("keycloak-signing-key",
       "Keycloak signs with the key the DID document publishes",
       needs_cluster=True, lanes=None, transport="fiware")
def keycloak_signing_key(ctx) -> Result:
    """A credential nobody can verify, and the issuer reporting success.

    Keycloak signs every credential this deployment issues with a key from a
    PKCS#12 store, and stamps it with a `kid`. A counterparty resolves that `kid`
    in our DID document to get the public half. Two ways that breaks, and neither
    shows up on our side - the issuer logs a clean 200 either way:

    * the `kid` names a verification method the document does not publish, so
      there is nothing to resolve;
    * the keystore was built from a different key than the one published, so the
      signature does not verify against what is there.

    **Two kid shapes are both correct**, which is what a naive rule gets wrong:
    some deployments publish `#key-1` and name `<did>#key-1`, others publish the
    bare DID as the method id and name the bare DID. The rule is "the kid is one of
    the published method ids", not "the kid carries a fragment" - the same lesson
    `holder-kid-fragment` records.

    The keystore's source is found through the **init container that builds it**
    (the one running `openssl pkcs12`) and the volume it reads, never by guessing a
    secret name. Where that resolves to the identity secret,
    `identity-key-consistency` has already proved that key is published and this
    check says so rather than fetching it twice.
    """
    service = ctx.deployment.service("keycloak")
    if not service:
        return Result.na(
            "no Keycloak in this namespace",
            cause="Keycloak is what signs the credentials this deployment issues; "
                  "without it there is no signing key to compare")

    did = ctx.any_participant_id()
    if not did:
        return Result.skip("no participant id discovered",
                           cause="without the DID there is no document to resolve "
                                 "the signing kid against")

    declared = ctx.values.get(SIGNING_KID_PATH)
    origin = "values"
    if not declared or values_mod.has_placeholder(declared):
        # A GitOps install has no values at all, and the realm the chart mounts
        # carries the same string - which is why this is not gated on values.
        declared = _kid_from_realm(_realm_configmap(ctx, service))
        origin = "the realm ConfigMap"
    if not declared:
        return Result.skip(
            "the signing kid could not be read",
            cause="neither `%s` in the values nor `%s` in the realm ConfigMap "
                  "states one, so what Keycloak stamps on a credential is unknown"
                  % (SIGNING_KID_PATH, REALM_KID_KEY))

    document, err = fetch_did_document(did, ctx.insecure)
    if document is None:
        return Result.skip("the DID document could not be resolved", cause=err)
    published = jose.did_document_keys(document)
    if not published:
        return Result.fail(
            "the DID document publishes no key to sign against",
            cause="%s resolves and carries no verificationMethod with a "
                  "publicKeyJwk, so nothing Keycloak signs can be verified by "
                  "anybody" % did,
            fix="republish the DID document with the signing key as a "
                "verificationMethod",
            doc=DOC_SIGNING_KEY, kid=declared)

    matched = next((vm for vm in sorted(published)
                    if _matches_kid(declared, vm, did)), None)
    detail = {"kid": declared, "kidFrom": origin,
              "published": sorted(published), "verificationMethod": matched}

    if matched is None:
        return Result.fail(
            "the kid Keycloak signs with is not published in the DID document",
            cause="the realm signs as `%s` (from %s) and the document publishes "
                  "%s. A counterparty resolves the kid to get the public half, "
                  "finds nothing, and reports it as the same generic failure a "
                  "dozen unrelated faults produce - while this side logs a clean "
                  "issuance" % (declared, origin, ", ".join(sorted(published))),
            fix="name one of the published verification methods in %s, or publish "
                "the method the realm names. Both the absolute form "
                "(`<did>#key-1`) and the relative one (`#key-1`) are accepted, so "
                "this is a real disagreement rather than a spelling difference"
                % SIGNING_KID_PATH,
            doc=DOC_SIGNING_KEY, **detail)

    algorithm = ctx.values.get(SIGNING_ALG_PATH)
    expected = ALG_KEYS.get(str(algorithm or "").upper())
    jwk = published[matched]
    if expected and (jwk.get("kty") != expected[0]
                     or (expected[1] and jwk.get("crv") != expected[1])):
        wanted = "%s %s" % expected if expected[1] else expected[0]
        return Result.fail(
            "the published key cannot carry a %s signature" % algorithm,
            cause="the realm signs with %s, which needs an %s key, and `%s` "
                  "publishes kty=%s crv=%s. The kid resolves and the signature "
                  "still will not verify"
                  % (algorithm, wanted, matched, jwk.get("kty"), jwk.get("crv")),
            fix="align keycloak.signingKey.keyAlgorithm with the published key, or "
                "republish the document with a key of the right type",
            doc=DOC_SIGNING_KEY, algorithm=algorithm, **detail)

    source, note = _keystore_secret(ctx, service)
    detail["keystoreSecret"] = source
    if source is None:
        return Result.warn(
            "the kid resolves; which key feeds the keystore could not be read",
            cause="`%s` is published as `%s`, so the name is right. %s - so this "
                  "cannot say the key behind it is the published one"
                  % (declared, matched, note),
            fix="check by hand which secret the init container that builds the "
                "PKCS#12 keystore reads",
            doc=DOC_SIGNING_KEY, **detail)

    if source == ctx.deployment.identity_secret:
        return Result.ok(
            "signs as `%s`, from the identity secret" % matched, **detail)

    secret = ctx.kube.secret(source) or {}
    key_name = ctx.deployment.identity_secret_key or "tls.key"
    if key_name not in secret:
        return Result.skip(
            "the keystore's secret could not be compared",
            cause="Keycloak builds its keystore from `%s`, which is not the "
                  "identity secret, and it has no `%s` to derive a public key from"
                  % (source, key_name))
    try:
        fingerprint = jose.jwk_fingerprint(jose.public_jwk_from_pem(secret[key_name]))
    except Exception as exc:  # noqa: BLE001
        return Result.skip("the keystore's private key could not be read",
                           cause="%s: %s" % (source, exc))

    detail["fingerprint"] = fingerprint
    elsewhere = sorted(vm for vm, key in published.items()
                       if jose.jwk_fingerprint(key) == fingerprint)
    if not elsewhere:
        return Result.fail(
            "Keycloak signs with a key the DID document does not publish",
            cause="its keystore is built from `%s` (not the identity secret `%s`), "
                  "whose public half is %s, and the document publishes none of it. "
                  "Every credential it issues carries a signature nothing can check"
                  % (source, ctx.deployment.identity_secret, fingerprint),
            fix="point the keystore's init container at the identity secret, or "
                "publish this key as a verification method and name it in %s"
                % SIGNING_KID_PATH,
            doc=DOC_SIGNING_KEY, **detail)
    return Result.warn(
        "Keycloak signs from a second copy of the key",
        cause="its keystore is built from `%s` rather than the identity secret "
              "`%s`. The key is the same one today - published as %s - so nothing "
              "is broken, but a rotation updates one copy and leaves the other, "
              "and that failure arrives later and looks like a signing bug"
              % (source, ctx.deployment.identity_secret, ", ".join(elsewhere)),
        fix="point the keystore's init container at the identity secret so there "
            "is one copy to rotate",
        doc=DOC_SIGNING_KEY, **detail)
