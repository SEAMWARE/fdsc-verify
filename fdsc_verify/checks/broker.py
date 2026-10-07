"""Whether the TMForum storage path mangles JSON-LD, and whether it can.

Both transports end up here. The EDC keeps contract-negotiation state in a TMForum
Quote with the ODRL offer stored as expanded JSON-LD, and the native FIWARE path
serves the same TMForum APIs through the gateway - so a storage layer that drops
`@`-prefixed keys breaks both, and neither check declares a transport.

The failure is two layers deep and only the second was ever ours to fix. Scorpio
>= 6.0.0 drops `@`-prefixed keys inside a Property's JSON value, which it is free
to do; `tm-forum-api` shields the broker from that by escaping reserved words with
a `tmfEscaped-` prefix. The defect was that the escape was dropped on **update**:
the `replaceOnUpdate` path reads the entity back through the mapping library's
`EscapeCleaningParser`, which strips the prefix, and nothing put it back. Raw
keywords then reached the broker and were discarded, leaving a quote the EDC
cannot read - a negotiation stuck forever behind an NPE loop.

So there are two questions, and they want different answers:

- **Can this deployment hit it at all?** A version comparison, no writes, cheap,
  and it runs in `preflight` where it belongs.
- **Does it actually survive a round trip?** Only a real write answers that, so it
  lives in `flow` with everything else that writes.
"""

from __future__ import annotations

import json
import uuid
from typing import Optional, Tuple

from .. import http
from ..kube import KubeError, PortForward
from ..model import Result, check
from ..values import chart_version_tuple

DOC = "scorpio-6-strips-json-ld-keywords"

# tm-forum-api DOES fetch the schema an extension names - a made-up URL comes back
# as `Schema validation failed ... Was not able to validate the input`, with the
# reasons list empty, which is a confusing way to say "I could not read your
# schema". So the probe borrows the two the EDC itself declares on every stored
# negotiation, read off a live quote on demo. Borrowing them is the point rather
# than a shortcut: the check exists to measure what happens to JSON-LD keywords on
# the path the EDC travels, and a probe shaped differently measures a different path.
QUOTE_SCHEMA = ("https://raw.githubusercontent.com/wistefan/edc-dsc/"
                "refs/heads/init/schemas/contract-negotiation.json")
QUOTE_ITEM_SCHEMA = ("https://raw.githubusercontent.com/wistefan/edc-dsc/"
                     "refs/heads/init/schemas/quote-item.json")

# The read-merge-write path that loses the escape arrived in 1.16.1 (the Scorpio 6
# patch) and the re-escape that fixes it landed in 1.18.0, so that half-open range
# is the exposed one. Below it, `PATCH /attrs` is used directly and the escape is
# never dropped - though on Scorpio >= 6 that path has its own fault: it appends
# to array attributes instead of replacing them.
ESCAPE_LOST_FROM = "1.16.1"
ESCAPE_FIXED_IN = "1.18.0"
# The broker that actually discards raw keywords. Below this they survive, so the
# same tm-forum-api is fragile rather than broken.
SCORPIO_DROPS_FROM = "6.0.0"


def _version(image: Optional[str]) -> Optional[Tuple[int, int, int]]:
    """The version out of an image reference, tolerating a `java-` style prefix."""
    if not image:
        return None
    return chart_version_tuple(image.rsplit(":", 1)[-1] if ":" in image else image)


@check("tmforum-reserved-words",
       "The deployed tm-forum-api cannot lose JSON-LD keywords on update",
       needs_cluster=True)
def tmforum_reserved_words(ctx) -> Result:
    """A version comparison, because the answer is knowable without writing anything.

    Two components decide it and both are read from the images that are running:
    whether tm-forum-api re-escapes on the read-merge-write path, and whether this
    broker discards raw keywords at all.
    """
    tmf_workload, tmf_image = ctx.image_of("tmforum", "tm-forum")
    if not tmf_image:
        return Result.na("no tm-forum-api deployment in this namespace",
                         cause="nothing stores TMForum resources here, so this "
                               "cannot bite")
    tmf = _version(tmf_image)
    if tmf is None:
        return Result.skip("the tm-forum-api version could not be read from %s"
                           % tmf_image)

    _, broker_image = ctx.image_of("scorpio")
    broker = _version(broker_image)
    detail = {"tmforum": tmf_image, "broker": broker_image, "workload": tmf_workload}

    lost_from = chart_version_tuple(ESCAPE_LOST_FROM)
    fixed_in = chart_version_tuple(ESCAPE_FIXED_IN)
    drops_from = chart_version_tuple(SCORPIO_DROPS_FROM)

    if tmf >= fixed_in:
        return Result.ok("tm-forum-api %s re-escapes reserved words on update"
                         % ".".join(str(n) for n in tmf), **detail)

    if tmf < lost_from:
        # No read-merge-write path, so no lost escape. But that same old version
        # has the fault the Scorpio 6 patch was written for, and saying only "you
        # are safe from this one" would be half an answer.
        if broker and broker >= drops_from:
            return Result.warn(
                "tm-forum-api %s predates the Scorpio 6 patch"
                % ".".join(str(n) for n in tmf),
                cause="it cannot lose the escape, because the read-merge-write path "
                      "does not exist in it - but this broker is %s, and Scorpio "
                      ">= 6.0.0 appends to array attributes on PATCH /attrs instead "
                      "of replacing them, which that path was added to avoid"
                      % ".".join(str(n) for n in broker),
                fix="upgrade tm-forum-api to %s or later" % ESCAPE_FIXED_IN,
                doc=DOC, **detail)
        return Result.ok(
            "tm-forum-api %s predates the read-merge-write path, so the escape "
            "cannot be lost" % ".".join(str(n) for n in tmf), **detail)

    # In the exposed range. Whether it destroys data depends on the broker.
    exposed = "tm-forum-api %s is between %s and %s" % (
        ".".join(str(n) for n in tmf), ESCAPE_LOST_FROM, ESCAPE_FIXED_IN)
    if broker and broker < drops_from:
        return Result.warn(
            "%s, but this broker keeps raw keywords" % exposed,
            cause="the read-merge-write path writes raw `@id`/`@type` to the broker "
                  "on update, and Scorpio %s keeps them - so nothing is lost today. "
                  "It stops being true the moment the broker is upgraded to 6.x, and "
                  "the data written meanwhile is not conformant."
                  % ".".join(str(n) for n in broker),
            fix="upgrade tm-forum-api to %s or later before touching the broker"
                % ESCAPE_FIXED_IN,
            doc=DOC, **detail)
    return Result.fail(
        "%s, where the escape is lost on update" % exposed,
        cause="the read-merge-write path reads the entity back through the mapping "
              "library's EscapeCleaningParser, which strips the `tmfEscaped-` prefix, "
              "and this version does not put it back - so raw keywords reach a broker "
              "(%s) that discards them. A quote written that way cannot be read, and "
              "the negotiation spins forever on 'Was not able to read negotiation "
              "<id> from quotes'." % (broker_image or "version unknown"),
        fix="upgrade tm-forum-api to %s or later; quotes already stored without the "
            "keywords stay broken and have to be deleted" % ESCAPE_FIXED_IN,
        doc=DOC, **detail)


@check("flow-tmforum-roundtrip",
       "A TMForum resource keeps its JSON-LD keywords across an update",
       phase="flow", needs_cluster=True, mutates=True)
def flow_tmforum_roundtrip(ctx) -> Result:
    """The question the version comparison cannot answer: does it actually survive?

    Written through `tm-forum-api` rather than straight at the broker, which is the
    whole point - the escaping lives in that layer, so a probe that writes raw
    keywords to Scorpio measures the broker's own behaviour (which is allowed) and
    not the fault. The probe is a Quote because that is what the EDC stores its
    negotiations in.

    It creates one throwaway resource and deletes it in a `finally`, so a failure
    mid-probe still cleans up. `--no-write` skips the whole thing.
    """
    service = ctx.deployment.service("tmforum")
    if not service:
        return Result.skip("no tm-forum-api service in this namespace")
    if ctx.config.get("noWrite"):
        return Result.skip("--no-write given; this probe creates a throwaway quote")

    marker = "fdsc-verify-%s" % uuid.uuid4()
    # A free-form value carrying expanded JSON-LD, the shape an ODRL offer has when
    # the EDC stores it. It lands in the entity's additional properties, which is
    # exactly what the read-merge-write path re-escapes.
    policy = {"@id": "urn:uuid:%s" % marker,
              "@type": "http://www.w3.org/ns/odrl/2/Offer",
              "odrl:permission": [{"@type": "odrl:Permission"}]}
    # The same shape the EDC stores a negotiation in, down to the schema URLs: the
    # keywords live in quoteItem[].policy, which is where the read-merge-write path
    # would re-escape them.
    payload = {
        "@schemaLocation": QUOTE_SCHEMA,
        "externalId": marker,
        "state": "inProgress",
        "quoteItem": [{
            "@schemaLocation": QUOTE_ITEM_SCHEMA,
            "id": "1",
            # `state` is required on the ITEM, not only on the quote, and leaving it
            # out is refused with `Unknown value 'null'` - an enum being read from a
            # missing field, and a message that names neither the field nor the
            # entity. Bisected against demo's tm-forum-api: without it 400, with it
            # 201. `action` is genuinely optional.
            "state": "inProgress",
            "externalId": marker,
            "datasetId": marker,
            "policy": policy,
        }],
    }

    created_id = None
    try:
        with PortForward(ctx.kube, service, 8080,
                         namespace=ctx.deployment.namespace) as pf:
            base = "%s/tmf-api/quote/v4/quote" % pf.base_url
            created = http.post(base, body=payload)
            if not created.ok:
                return Result.skip(
                    "could not create the probe quote (HTTP %d)" % created.status,
                    cause=created.text(200))
            created_id = (created.json() or {}).get("id")
            if not created_id:
                return Result.skip("the API returned no id for the probe quote")
            try:
                after_create = _count_keywords(_read(base, created_id))
                # the read-merge-write path is what re-escapes, so update a
                # field on the same entity and read the policy back afterwards
                patched = http.request("PATCH", "%s/%s" % (base, created_id),
                                       body={"state": "approved"})
                after_update = (_count_keywords(_read(base, created_id))
                                if patched.ok else None)
            finally:
                http.request("DELETE", "%s/%s" % (base, created_id))
    except KubeError as exc:
        return Result.skip("could not reach tm-forum-api: %s" % exc)

    detail = {"afterCreate": after_create, "afterUpdate": after_update,
              "quote": created_id}
    if after_create == 0:
        return Result.fail(
            "the keywords are gone before any update",
            cause="a quote written with an expanded policy came back with neither "
                  "raw nor escaped keywords, so they were dropped on create. The "
                  "escape is not being applied at all on this deployment.",
            fix="check that tm-forum-api is talking to the broker with the scorpio "
                "profile and that its mapping library is the expected version",
            doc=DOC, **detail)
    if after_update is None:
        return Result.warn("the probe quote could not be updated; the path that "
                           "loses the escape was not exercised", **detail)
    if after_update < after_create:
        return Result.fail(
            "JSON-LD keywords are lost on update",
            cause="%d keyword(s) survived the create and only %d survived a PATCH. "
                  "That is the read-merge-write path: the entity is read back, the "
                  "escape is dropped, and raw keywords reach a broker that discards "
                  "them. At runtime it shows up as a negotiation stuck forever on "
                  "'Was not able to read negotiation <id> from quotes'."
                  % (after_create, after_update),
            fix="upgrade tm-forum-api to %s or later (see tmforum-reserved-words)"
                % ESCAPE_FIXED_IN,
            doc=DOC, **detail)
    return Result.ok("%d keyword(s) survive create and update" % after_update, **detail)


def _read(base: str, entity_id: str):
    resp = http.get("%s/%s" % (base, entity_id), headers={"Accept": "application/json"})
    return resp.json() if resp.ok else None


def _count_keywords(entity) -> int:
    """Keywords that survived, escaped or raw.

    Either form is fine: what matters is that the information is still there.
    tm-forum-api stores them prefixed, a raw write stores them bare, and a layer
    that drops them leaves neither.
    """
    if not entity:
        return 0
    text = json.dumps(entity)
    return (text.count('"@id"') + text.count('"@type"') + text.count('"@value"')
            + text.count("tmfEscaped-@"))
