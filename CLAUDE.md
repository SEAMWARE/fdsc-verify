# fdsc-verify — does this deployed FIWARE Data Space Connector work, and if not, why

Answers *do the flows of this deployed FDSC work?* and, when they do not, **why**. Python,
no runtime dependencies. Previously lived in the `aux-tools` repo; imported here as a
snapshot (no history).

## Why it exists

It was written after a long debugging session on one real deployment where roughly ten
distinct failures were diagnosed by hand. **In almost none of them was the DSP flow itself
at fault** — the cause was always a precondition: a stale JWKS cache, a controlplane image
inherited from the chart default, a credential signed before a key rotation, a DID copied
from a neighbour, a DNS record pointing at a foreign host. Every one of them surfaced as a
generic `401` or a negotiation stuck in `REQUESTED`, and each cost between half an hour and
half an afternoon of bisection.

So the tool's product is **the cause and the fix**, not the OK/FAIL. A `FAIL` without a
`cause` is treated as an incomplete check.

The failures themselves are written up in **`docs/troubleshooting.md`**, and
every check links to its entry there by anchor (`Result(doc=...)` → a heading slug). That
doc is the companion to this tool: the tool detects, the doc explains. It ships in this
repo so the `see:` line resolves wherever the tool runs; `FDSC_VERIFY_DOC_BASE` overrides
the base (point it at the GitLab blob URL when the output leaves the machine).

It was copied out of the deployment guide it was written in, and that copy still stands
beside it, indexed by symptom. **The two will drift**: on a new diagnosis, add it here and
treat the deployment's copy as that deployment's own record. Only the header and the
outbound relative links differ so far.

`tests/test_docs.py` fails the build on an anchor with no heading behind it, and on a
section the doc's own *Which check points here* index omits — so a new `doc=` value means
a new section, not just a new string.

## Deliberate non-goals

- **Protocol conformance** belongs to `scripts/run-tck.sh` in the **fdsc-edc** repo (the
  Eclipse DSP TCK, run against a locally built controlplane in docker-compose). That
  answers "is the protocol implemented correctly"; this answers "does *this* deployment
  work". Do not reimplement either inside the other.
- **No `--fix`.** Several of these repairs recreate identity state and one silently drops a
  credential store. The tool prints the command; a human runs it.
- The Cucumber suite in `DSC/data-space-connector/it/` has step definitions that overlap
  heavily (key → JWK → Vault → participant → DID document → credential → TIL) and is worth
  reading for reference, but it hard-codes `127.0.0.1.nip.io` endpoints in
  `DSPEnvironment.java` and *provisions* identity rather than verifying it. It is CI
  against ephemeral k3s, not a validator for a deployment someone else built.

## Layout

```
fdsc-verify/
  fdsc_verify/
    __main__.py     CLI. Two groups: what to run (--phase, --static-only, --preflight-only,
                    --only, --edc-lane, --peer) and what to DECLARE (--role, --edc/--no-edc,
                    --edc-protocol, --did, --identity-secret, --values-root, --component)
    profile.py      what the operator declared, with provenance per field
    discovery.py    works out what is deployed; the --config file fills its gaps
    values.py       the release's Helm values, how much they can be trusted, and where the
                    DSC sits inside them (the root, when it is a dependency of a wrapper)
    participant.py  who this deployment is: the DID from every source that states one
    components.py   the canonical role matrix as data, + how to look for each component
    model.py        PHASES / EdcLane / Peer / Deployment / Check / Result + the @check registry
    context.py      cached access for checks: port-forwards, identityhub, TIL, EDC mgmt API
    kube.py         kubectl by subprocess, plus a PortForward context manager
    http.py         stdlib-only HTTP; keeps headers, never raises
    jose.py         base64url, JWT decode, RS256 (native) and ES256 (cryptography) verify
    progress.py     the live line on stderr; stdout is the report's alone
    runner.py       selection, skipping, and "no flows if an earlier phase failed"
    report.py       text + JSON, exit codes, DOC_BASE resolution
    checks/         profile, components, static, keycloak, identity, certs, infra,
                    broker, dashboard, fiware, marketplace, contractmanagement,
                    centralmp, peers, flows   (53 checks)
  docs/troubleshooting.md   the diagnoses every `see:` anchor points into
  docs/fault-injection.md   how to make each check fail on purpose, and undo it
  tests/test_jose.py
  tests/test_docs.py           no dangling anchors, no gaps in the doc's index
  tests/test_progress.py       nothing on stdout, nothing left on screen
  tests/test_phases.py         PHASES is the only source; the gate cuts one way
  tests/test_values.py         the four release encodings, the merge, the trust model
  tests/test_wrapped_release.py the DSC as a dependency, and the values root
  tests/test_static.py         each static check, and the false positives it must not make
  tests/test_profile.py        declarations are validated, and contradicted
  tests/test_participant.py    an identity without an EDC lane
  tests/test_components.py     the role matrix, and the four ways it nearly over-reported
  tests/test_discovery.py      service names, identity secret, context plumbing
  tests/test_report.py         the JSON contract; the manifest never leaks
  tests/test_dashboard.py      the aud fault, and the entries it must not flag
  tests/test_marketplace.py    the two auth stacks, the two lifecycle vocabularies
  tests/test_keycloak.py       the realm's two decisions, and four ways to misread them
  tests/test_contractmanagement.py  declaration, evidence, and what cannot be known
  tests/test_centralmp.py      the shape, and the two conditions that look sufficient
  peers/example.yaml
```

`Check.transports` says **which data path a failure in a check breaks** - `fiware` (VC →
verifier → token → APISIX/OPA) or `edc` (Dataspace Protocol through fdsc-edc) - and
`--transport fiware|edc|all` asks for one. A deployment with both deployed runs both and
they fail independently, which is the whole reason for the axis. Checks that declare none
are about the deployment rather than a data path and always run.

Two things were learned the hard way here. **The field means "breaks", not "exercises".**
Under the narrower reading no preflight check declared anything - reading a ConfigMap
traverses nothing - so `--transport fiware` still ran all eight lane-scoped EDC checks.
**And it is a set**, because `verifier-jwks-matches-key` is lane-scoped and therefore looks
like an EDC check, while a stale JWKS at the gateway breaks every route APISIX guards: the
DSP callbacks *and* the FIWARE data services. A blanket "lane-scoped means EDC" rule would
have hidden it in the run that asks about the gateway.

The names are the dataspace's, not the tool's. `dsp`/`native` were renamed to `edc`/`fiware`
(and `both` to `all`) with **no aliases**; `dsp` in particular collided with the protocol,
which is still DSP everywhere it legitimately appears - `/api/dsp`, the `dsp-route` check,
`dsp-controlplane`, `ctx.dsp_protocol()`, the verifier service id `dsp`. None of those moved.

The FIWARE side is probed **without a credential**, on purpose: presenting one means being
a wallet (OID4VCI from Keycloak, a key, a signed VP) and needs a provisioned test user,
which would break `--no-write`. What the probe does prove is that the gate demands a
credential at all and that the verifier publishes the discovery document and JWKS the
gateway validates with - i.e. that a refusal means something. Verified on `provider-edc`:
`mp-data-service.example.org -> 401 (Bearer realm="apisix")` and 14 services served.

`Check.roles` gates a check by participant role and **is validated in the decorator**;
it replaced `families`, which accepted any string and which no check ever declared - a
misspelling there would have gated a check out of every run in silence. Only three checks
declare a role so far, all `provider`: the EDC-only ones are deliberately *not* gated,
because fdsc-edc is Optional for both roles and they already skip for want of a lane.

**Renamed for honesty** (fdsc-edc is one deployment shape, not the subject): `Lane` is
`EdcLane`, `Deployment.lanes` is `edc_lanes`, `--lane` is `--edc-lane`. Two things
deliberately kept: `--lane` still works as an alias, and the `lanes` key in `--json` and in
the `--config` file is unchanged, because both are contracts somebody may already consume.

Progress goes on **stderr** and only there: the report owns stdout, because `--json | jq`
has to keep working. Checks narrate their own slow sub-steps through `ctx.progress.detail()`
— port-forwards, pod execs, and the negotiation poll, which is the one that looks hung.

## An EDC flow needs a counterparty. There is no loopback.

Without `--peer` the EDC flow checks are **not applicable**, and the row says why. This is
not a missing feature: loopback is the one shape this stack cannot do, and it fails in the
most expensive way available.

The TMF-backed store keeps a negotiation as **one Quote with both roles in
`relatedParty`** and rebuilds it by finding the party whose DID is *not* ours - which is
how it recovers `counterPartyId`, `counterPartyAddress` and `protocol`, the three fields
`ContractNegotiation.Builder.build()` requires (disassembled from `contract-spi 0.14.1`;
there is no check that the counterparty differs from us). With one participant on both
sides that party does not exist, the fields stay null, and every read throws a
NullPointerException. The state machine retries every two seconds **for ever**, and only
deleting the Quote stops it - measured: 151 retries in six minutes from one
negotiation, still going when found.

So it is a limit of the TMF store, not of EDC, and it is not going to be lifted. The tool
used to default to loopback, which meant its safest-looking mode was the one that poisoned
the environment. `dsp-route` still proves our own DSP endpoint answers, which is what
loopback confirmed most of the time.

**What the flow phase found on its first real runs**, all of them tool bugs rather than
deployment faults, and each one a check misreading a healthy deployment:

- `VERIFIED` was treated as terminal. On the consumer side it means "I sent my
  verification"; the agreement is registered at `FINALIZED`, so the transfer posted into a
  window where the EDC answered `Contract agreement <id> not found` - correctly.
- The 90s default was too tight: measured end to end, `INITIAL` -> `FINALIZED` took **103
  seconds**, most of it EDC's own tick intervals. Now 180s, the poll returns a timeline
  ("REQUESTED 11s, AGREED 47s, VERIFIED 68s") so a WARN says whether the thing was moving,
  and it reads once more past the deadline.
- A stall was blamed on the broker dropping JSON-LD keywords **unconditionally**, while
  `tmforum-reserved-words` in the same report said the escape could not be lost there. The
  two causes are now told apart by the stack trace.
- The gateway probe followed redirects, so an APISIX route with `bearer_only: false` -
  which refuses by redirecting to the IdP - read as a host serving data to anybody.
- Cleanup deleted the EDR and left the transfer `STARTED` for ever. Two were found,
  one per lane, from runs whose cleanup reported success.
- The TMForum probe wrote a property outside the Quote schema with no `@schemaLocation`,
  so it was refused and the check skipped on every run - the keyword round trip has still
  never been measured.

## Not applicable is not the same as could not answer

`SKIP` used to mean both, and on a deployment with no fdsc-edc that was seventeen rows of
"no EDC connector lane in this namespace" with the two that were real gaps invisible among
them. `Result.na()` now separates them, and the line is about **who owes what**:

- **not applicable** - no connector here, no vault, no dashboard, one transport asked for,
  the role does not match. The question does not arise, the tool owes nothing. The row is
  left out of the text, summarised on the header's `scope` line, and kept in `--json` and
  under `-v`.
- **skip** - the question does arise and the tool failed to settle it: no cluster access,
  the dashboard served something unparseable, a placeholder that cannot be compared. A
  coverage gap, and it stays visible, because an operator who cannot see that the tool went
  quiet cannot know to go and look themselves.

Both stay `Status.SKIP`: neither is a finding, neither may be reported as a pass, and exit
codes never read SKIP so nothing about failure changed. `--json` keeps every row and adds
`applicable`; its `summary` still counts them all as SKIP, so a consumer diffing two runs
sees no phantom change. Measured read-only: visible skips went 10→2 on `provider-edc`,
11→1 on `consumer-edc`, 17→0 on `provider-remote-mkt`, 17→1 on `provider-mkt` - **and no verdict
moved**. What survives is exactly the right set: a lane with no vault address, a dashboard
that served `NoneType`, a service id that cannot be compared.

The rule the old behaviour protected is still enforced, just moved. An absent row reads
like a check that ran and found nothing, so the absence is now **asserted** in the header:
`EDC  not deployed (inferred)` prints whether or not there are lanes. If discovery is
wrong - and it has been, a wrapper chart hid a whole release - that is a false
sentence an operator can catch, which sixteen skipped rows nobody read were not.

## The two rules everything else follows

**1. Declare before inferring.** The tool points at a DSC somebody already deployed, and
whoever runs it knows what it is meant to be. Every structural property resolves as
`flag > --config > inference > unknown`, and the report says which step answered. Three
consequences: nothing is guessed silently; `unknown` is a legitimate state that produces a
SKIP with a reason rather than a verdict; and **a declaration is an assertion** - saying
`--edc` where no lane exists is a FAIL, because either the flag describes a different
deployment (wrong namespace, wrong context) or the deployment is not what you believe.

**2. The cluster gives the verdict; the values give the reason.** `static` judges with the
values (*is it built right?*), `preflight`/`flow` with the cluster (*is it wired right?*).
So presence is the cluster's to answer - a Service that exists is a component that is
there, whoever installed it - while intent and the fix are the values', which is why a FAIL
names the key somebody will edit. The rendered manifest is the bridge: a release can list a
dependency and render nothing from it, and `provider-remote-mkt` does exactly that with
`fdsc-edc`.

With no readable release - a GitOps install renders with `helm template` and leaves none -
`static` runs off `--values <the file it was deployed from>` at `user` trust, and the
cluster checks run regardless. Never rendering: skipping with the reason.

## The two test environments

Both live in the same GitOps repo, on two branches, and between them they cover every axis
the tool has to handle. **Run read-only**: `--preflight-only --no-write` creates nothing.
The handles are the ones [the README defines](README.md#where-the-evidence-comes-from).

| installed by | what it gives |
|---|---|
| Helmfile | `provider-edc` and `consumer-edc` — EDC with **both** lanes (dcp + oid4vc), IdentityHub serving the DID; `provider-mkt` and `provider-remote-mkt` — **providers with no EDC**, did-helper serving the DID, one of them integrated with a central marketplace |
| **ArgoCD** | `provider-gitops` and a consumer beside it — the simple shapes, no EDC. Deployed as a **wrapper chart** with the DSC aliased `dsc`, which is the case that breaks naive discovery twice over |

**Run against the GitOps environment for the first time on 2026-09-30**, read-only, and it
paid for itself: `provider-gitops` had a did-helper, a verifier and a TIL all running and the
tool still reported *no source states a DID*, which skipped five identity checks
on a deployment able to answer every one of them. The DID was resolved from the
lanes or the values and nothing else, and a GitOps install has neither. So
`participant.resolve` gained a third tier, **the cluster** — the verifier's own
`server.yaml` (`verifier.did` and `verifier.tirAddress`) and the did-helper's
`HOST_URL`, both verified present and correct on all five deployments reachable
from here, across two clusters, charts 9.0.5 and 10.4.12, and both did:web shapes.

That same ConfigMap turned out to answer two more things the values were the only
source of, and `provider-gitops` is again where it showed: `flow-fiware-discovery`
skipped with *the verifier's public host could not be resolved* while `server.host`
sat in the file the tool was already opening, and `clientIdentification` sat beside
it. `Context.verifier_config()` now caches the whole document, `_verifier_host` and
`_client_identification` fall back to it, and `client-id-scheme` and
`cert-san-vs-client-id` lost their `needs_values` gate — a preflight check that
fetches a live certificate has no business requiring a Helm release, and both
bodies already skipped cleanly without one. Measured across six deployments: only
`provider-gitops` moves, gaining two verdicts.

It is consulted last when *picking* the DID and always when *recording* sources,
which is what keeps it safe: measured before and after on all four
deployments of the Helmfile environment, **not one verdict moved** and each gained a corroborating source,
while `provider-gitops` went from 31 skips to 25 — `did-document`,
`identity-key-consistency`, `identity-did-consistency`, `cert-expiry`,
`credential-service-route` and `til-registration` all became answerable. Two
things it also found there, which are the deployment's rather than the tool's:
tm-forum-api 1.15.1 against Scorpio 6.0.1, and `/productSpecification` answering
500.

`provider-gitops` is the one to keep in mind when touching discovery. Its chart is not called
`data-space-connector` (so matching the chart name makes the release invisible) and all its
values sit under `dsc.` (so unprefixed reads report every component absent — an error that
does not look like one). Argo also renders with `helm template`, so expect no release
Secret and pass `--values`.

## Three discovery findings that broke naive implementations

Verified across three independent deployments (`provider-edc-2`,
`provider-edc`, `.../consumer`). If discovery ever misbehaves, start here.

1. **`dcp.enabled` and `oid4vp.enabled` are both `true` on both lanes** in every deployment
   inspected, so neither identifies which protocol a lane speaks. The real discriminator is
   `fdscTransfer.{dcp,oid4vc}.enabled`, which are mutually exclusive. It lives in exactly
   one place — `Lane.identity` in `model.py` — because several checks change verdict on it.
   Getting this wrong produced a confident false FAIL on a healthy lane.
2. **The identity secret name is not stable** (`connector-example-es-tls` here,
   `did-provider-example-org-tls` there), so it is resolved by *type*: the secret-backed
   volume of type `kubernetes.io/tls`. It cannot be found from `oid4vp.holder.key.path`
   either — that path points at an emptyDir holding the *converted* key, and the raw secret
   is only referenced by an init container.
3. **A did:web's document URL depends on its path segments**: `did:web:host` →
   `/.well-known/did.json`, `did:web:host:a:b` → `/a/b/did.json`. Both forms are in use in
   this dataspace (`provider-edc-2` has no suffix, `provider-edc` has `:did`), and assuming
   either breaks the other.

What discovery relies on, and why it is safe to rely on: each lane has a ConfigMap
`<release>-fdsc-edc-<lane>` with `dataspaceconnector-configuration.properties` (~85 keys,
including every `web.http` port and path, so nothing is hard-coded), and the shared
components have fixed service names (`identityhub-service`, `verifier`,
`trusted-issuers-list`, `data-service-scorpio`, `tm-forum-api-svc`). Lanes are
**discovered**, not assumed.

## The static phase, and four things that broke naive implementations

`PHASES = ("static", "preflight", "flow")` lives in `model.py` and is the only place the
phase list exists — it used to be a literal repeated in `runner.py` and `report.py`, and a
third phase is exactly the change that turns that duplication into a silent bug. A phase
says *when* a check runs and what it blocks, **not** what it costs: reading a Deployment is
still static, and requirements stay in `needs_*`.

The gate is deliberately asymmetric. A `static` FAIL closes `flow` (a missing component is
already the diagnosis) but does **not** suppress `preflight`, whose findings — stale JWKS,
copied DID — are independent diagnoses rather than consequences. Suppressing them would
hide what the tool exists to find.

A second reporting rule, learned the hard way: **a check that cannot run still gets a row.**
A lane-scoped check with no lane used to be omitted from the plan entirely, and on a
namespace without `fdsc-edc` that silently removed *fifteen of the thirty-three* — an absent
row reads exactly like a check that ran and had nothing to say. The runner now emits a SKIP
naming the reason ("no EDC connector lane in this namespace"). This matters beyond tidiness:
fdsc-edc is one deployment shape, not a requirement, and the report has to say which half of
itself did not apply.

`values.py` reads Helm's own record of the release. Four findings, each measured against
`provider-edc-2` and `consumer-edc` and `provider-edc`:

1. **The payload is base64 twice** — kubernetes, then Helm, then gzip, then JSON. Decode
   once and you get apparent garbage; decode once and gunzip and you get nothing.
2. **Never guess the revision; use `-l owner=helm,status=deployed`.** Every historical
   revision is kept as its own Secret embedding the whole rendered manifest. `consumer-edc`
   is at rev 36 and producer at rev 113, so an unfiltered list downloads tens of megabytes
   and the tool looks hung.
3. **The stdlib merge *is* `helm get values --all`, not an approximation** — byte-identical
   over 2592 and 2194 leaf keys. `chart.dependencies` is not serialised into the stored
   release, so `helm` cannot coalesce subchart defaults either. The binary therefore buys
   no precision and stays a transport fallback only.
4. **An absent key does not mean disabled.** Helm *enables* a dependency whose `condition`
   does not resolve (`fdsc-edc` has no `enabled` anywhere and is deployed), while for an
   umbrella template absent means false. Hence `Tri` and its `kind` argument: a plain
   `values.get(path, False)` would confidently report the wrong thing. `Tri` has no
   `__bool__` on purpose — `if values.tri(p):` would read as "enabled" and silently treat
   "cannot tell" as "no".

The convention every check follows: **`tri.unknown` ⇒ `Result.skip(cause=tri.why)`**.

Two more traps worth knowing before writing a static check. Values carry placeholders that
are resolved later — `keycloak.issuerDid` is the literal `${DID}` and
`vault.hashicorp.url` is `http://{{ .Release.Name }}-vault:8200` — so
`values.has_placeholder()` before any literal comparison of a DID, host or URL. And keys
containing dots are real (`helm.sh/hook`, `prometheus.io/port`): use `get_at([...])`, not
`get("a.b.c")`.

## The static checks, and what they found

- `values-source` — makes the trust model visible rather than letting a screenful of
  unexplained SKIPs read as a broken tool.
- `release-status` — WARN on anything but `deployed`; explains half of "my config change
  did nothing".
- `registration-job-hooks` — **found a live defect in all three deployments.**
  `verifier-job` is `post-install` only at revisions 18, 113 and 36, so vcverifier's
  services have not been re-registered since first install, which surfaces as a request
  object with no `presentation_definition` and a wallet saying "Could not process the
  information request". One generic rule (a post-install-only hook on a release past
  revision 1), not a list of known-bad names — the names differ per release and the
  defect moved between chart 10.3.2 and 10.4.12.
  It reads the **values**, not the rendered Jobs, because that is where the fix goes; and
  it skips a block whose nearest ancestor `enabled` is false, because `provider-edc` really
  does ship `tm-forum-api.registration.annotations` as post-install-only *and disabled*.
  Without that guard the check over-reported on every deployment.
- `values-unknown-keys` — top-level only, and that limit is measured: a recursive
  comparison produced **51 hits on `provider-edc-2`, essentially all false**, because the stored
  `chart.values` is the umbrella's own and carries no subchart defaults. At the top level
  it is 3 on `provider-edc-2`, 4 on `consumer-edc` and **0 on `provider-edc`** — which is how you know it
  discriminates.
- `client-id-scheme` — the verifier's `clientIdentification.id` and the way the request
  object is signed have to agree. A bare value with no recognised prefix is a legitimate
  pre-registered client id, so it is *named*, not rejected; only a real disagreement fails.
  Its runtime half is `cert-san-vs-client-id`, which needs a lane and a certificate.

## The role matrix, and the four ways it nearly over-reported

`components.py` carries the canonical table (component → role → Required/Optional/–) as
data, because three checks read it and prose would let them drift. `deployment-role` says
what the deployment is and how it knows; `component-inventory` measures it against that
row; `component-consistency` checks the pairs that cannot work apart.

It was validated by running it against all four of those deployments before trusting it, and
**all four failed identically at first** - the signature of a check measuring the wrong
thing rather than of four broken deployments. Each correction is pinned by a test:

1. **A requirement is a capability, not a Deployment object.** The DID document is served
   by the did-helper *or* by the IdentityHub; the credentials-config API by a standalone
   service *or* by the verifier's own config port (8090). Hence `satisfied_by`.
2. **"Listed as a dependency" is not "deployed".** `provider-remote-mkt` lists `fdsc-edc` and
   renders no object of it, so the manifest outranks the dependency list.
3. **The either/or has to compare the real services.** Once the DID requirement became
   satisfiable by the IdentityHub, the XOR reported "both document servers" on every DCP
   deployment.
4. **Service names must be read, not guessed.** The BAE runs as `*-biz-ecosystem-logic-proxy`,
   not `business-api-ecosystem`.

What survived is one finding rather than four: `provider-mkt` runs a verifier and a
TIL with no APISIX and no odrl-pap.

One preflight check belongs with the static ones because it answers what they cannot:
`registration-services-present` reads the verifier's live config repo. The declaration and
the outcome are different facts — `registration-job-hooks` proves a job *cannot* have re-run
since install, but not that anything is missing as a result, and a domain migration where
somebody re-registered by hand leaves the repo complete and the hook still wrong.

## The issuer and the central marketplace, and what they found

Two families added last, both measured before a line was written, and both with findings
waiting on a healthy-looking deployment.

**Keycloak** is Required for every role and nothing read a single key from it. Three checks
now do, and the first two found something on the first run:

- `keycloak-credential-lifetime` — the realm has **two** attributes and only one reaches the
  credential: `expiry_in_seconds` is what the admin UI displays, `refresh_interval_in_seconds`
  is what lands in `exp`, and **unset means Keycloak defaults it to 604800**. Measured on a
  real credential: `nbf` and `exp` seven days apart while the UI said a year, and raising the
  first alone changed nothing. It is also why an identityhub credential copy went stale
  weekly, which read for a long time as a design decision. `provider-mkt` and `provider-remote-mkt`
  are both in that state now.
- `keycloak-verifier-formats` — the realm issues a format and the verifier states, per
  service and per scope, which it accepts. `provider-edc` and `consumer-edc` both issue a credential
  their own verifier will not take (`dc+sd-jwt` against a scope accepting only `vc+sd-jwt`). Four spellings live in one dataspace (`dc+sd-jwt`, `vc+sd-jwt`,
  `jwt_vc_json`, `jwt_vc`) and they are **not** interchangeable.
- `keycloak-signing-key` — the kid the realm signs with has to be a published
  verificationMethod. **Two kid shapes are both correct** — `<did>#key-1` against a published
  `key-1`, and the bare DID against a bare-DID method id — so the rule is "it is published",
  never "it carries a fragment".

Four things would have made a naive version lie, and each is pinned by a test: the block name
is **not** the credential type (`membership-credential` issues `MembershipCredential`) and
older charts omit the type attribute entirely; the accepted formats are spread over three
places; **a scope that names no format is not a disagreement** — nine services on one
deployment declare a type with neither — leftovers from past transfers — and treating an
empty set as a mismatch reported nine
faults on `provider-edc`; and a type the verifier asks for and we do not issue is not
ours to judge, because a counterparty issues it.

**A provider can publish through a central marketplace**, and the tool knew that shape only as
an absence. `central-mp-contract-management-route` and `-wiring` give it a positive reading.
The shape needs **all three** of its conditions — contract-management deployed, no local
marketplace, and the flag declared — because the first two alone also describe a *consumer*,
which was reported as a provider with a broken route until the flag was added; and the flag
alone is no better, being true on deployments that run their own marketplace. The wiring check
found `enableTmForum` on with no tm-forum-api Service in `provider-remote-mkt`'s namespace.

Where a route goes is **only in the values**: every published host points at the APISIX
Service on its Ingress and they answer an identical 401, and there are no APISIX CRDs here.

## State: what is verified and what is not

**Verified.** 18 unit tests on `jose.py` with real openssl-generated keys and signatures
(the ES256 `r||s`→DER conversion in particular — it fails silently as "invalid signature").
The preflight phase was run read-only against `provider-edc` and `consumer-edc`, and found
three genuine defects in `consumer-edc` on the first run, each confirmed by hand:

- `consumer-fdsc-edc-dcp` runs `fdsc-edc-controlplane-oid4vc:1.3.0` (the wrong image — the
  same bug hit twice before, in `provider-edc-2` and `provider-edc`);
- its identity key and its published DID document key differ (`Z4dnTH2u…` vs `K-qAaapn…`);
- its trusted issuers list does not contain its own DID (404), only the producer's.

The third is **now a WARN rather than a FAIL**, and the reason is worth keeping: the TIL a
participant runs is consulted by *its own* verifier, so a DID missing from ours only breaks
something arriving **inwards**. Access to a central marketplace, or to any other
participant, is decided by *their* list and is unaffected. The severity used to hinge on
whether `--peer` was passed - a DSP-shaped criterion ("no peer, so loopback is the target")
applied to every deployment including ones with no connector at all. It now hinges on whose
DID is missing: a peer's is a FAIL, because every presentation from them is refused; ours is
a WARN whose cause enumerates what actually stops - inbound DSP flows if there are lanes,
our own users against our own gateway if we are a provider, and any credential we issued
coming back.

The peer file came from the same EDC-shaped assumption and was decoupled with it. **Only
`participantId` is required now**; `protocolUrl` is optional, because most of what a
counterparty is good for needs nothing but its DID - whether its document resolves,
whether our DID is in its issuers list, whether our dashboard names it correctly - and a
participant reached through its gateway has no DSP endpoint to name. Every consumer of the
field either skips with that reason (`peer-reachable`, `ctx.edc_catalog`) or is already
gated behind one that did. `peer-reachable` now declares `transport="edc"`, which it should
always have: without it `--transport fiware` ran it and reported a DSP failure on a
deployment that speaks no DSP. Measured on `consumer-edc`, the same run with a
`participantId`-only peer moves exactly four rows to SKIP - the two `peer-reachable` lanes,
and the two that want kube access the minimal file does not declare - and `peer-did-resolves`
returns the same verdict either way, which is the point.

**Re-run 2026-09-16/17 across that environment, read-only, after the
generalization.** All four DSC deployments now produce a differentiated report; the two
without EDC used to produce almost nothing. 278 unit tests, and the before/after JSON on
`provider-edc` and `consumer-edc` shows **no verdict changed** by the generalization — the only
movement is `registration-services-present` going FAIL→OK, which is the placeholder fix:
a `${DID}` in `registration.services[].id` is not comparable against the config repo,
so it is now deferred instead of reported missing.

**The reason first written here for that was wrong, and the truth is a better diagnosis.**
`${DID}` is a *shell* variable in the registration script, and whether it survives depends
on the chart the job ran under: up to vcverifier **4.12.1** the body went out through an
unquoted heredoc and the shell expanded it; the refactor in **4.12.5**
(`helm-charts` 4cc25d8) passes the body as a single-quoted argument, which does not. Both
outcomes are live in this dataspace - `provider-mkt` has `did:web:did.central.example.org` registered,
`consumer-edc` has the literal string `${DID}` - and neither is a coincidence: the job is
**post-install only**, so a config repo reflects the chart at *first install*, not the one
deployed now. That is also why the values cannot say which form to look for. Registering
under the literal is a defect in its own right; nothing here consumes
`/services/<did>/…`, so it is latent there.

**On the environment itself.** Of the three defects above, the first two are now fixed:
the dcp lane runs `fdsc-edc-controlplane-dcp:1.3.0` and the key copies agree. The TIL one
stands. Two more surfaced on deployments the tool could not
reach before: `provider-remote-mkt` declares a verifier service that is absent from the
config repo, and `provider-mkt` runs a verifier and a TIL with **no APISIX gateway
and no odrl-pap** — deliberate or not, it is what the canonical matrix calls a Provider
missing two Required components.

**The flow phase has now been executed**, in both directions between `consumer-edc` and
`provider-edc`,
and it took five tool bugs and one real `fdsc-edc` bug to get there (all listed above). The
run that closed it reported `flow-transfer (dcp): data retrieved (2608 bytes)`. Every check in
the tool has been executed at least once.

**Not verified: fault injection, on nine of eighteen rows.** This is the real acceptance
criterion — break one thing on purpose, confirm the right check names it. *A check you cannot
make fail is not verified.* Running a check and watching it pass proves nothing about a check
that reads the wrong key: a healthy deployment and a broken check look identical.

The commands are in `docs/fault-injection.md`, at two levels: **A**, feeding a
check a wrong input (touches nothing, proves the logic) and **B**, breaking the real thing
with a restore step. Of the ticked rows, **five were validated by accident** — `consumer-edc`
and `provider-mkt` happened to carry those faults — **four at level A**, which the declared
profile turned from a trick into the normal way to do it, and **two at level B** on
`provider-gitops`, the first real ones.

**What level B on a shared environment needs, learned by doing it.** Argo's auto-sync is off
there, so nothing reverts a change for you: the restore is entirely yours. The app was already
`OutOfSync`/`Degraded` before anything was touched — a stale Job and grafana's Role and
RoleBinding — so the baseline is not "clean", it is *that*, and the exercise has to return to
it rather than to something tidier. Snapshot first, prove the write path with a no-op write,
restore in a `finally`, and verify against the snapshot rather than against expectation: the
full `--json` report came back identical row for row, and Argo's 137 resources with the same
three adrift.

What is left is every **B** row: the ones that rotate a secret, delete a vault key, edit a
ConfigMap or move a lifecycle field, and therefore need an environment somebody is allowed to
break. The marketplace group is the clearest case of why the split matters — those five
checks read the cluster and not the values, by rule 2, so level A reaches exactly one of
their branches and the rest cannot be done read-only at all.

| Fault to inject | Check that must fire | Status |
|---|---|---|
| Rotate the identity secret without restarting apisix | `verifier-jwks-matches-key` | pending |
| Store a credential signed with another key | `credential-freshness` | pending |
| Point the `dcp` lane at the `-oid4vc` image | `controlplane-image` | ✅ seen on `consumer-edc` |
| Delete one STS alias from vault | `sts-secret-aliases` | pending |
| Set `oid4vp.holder.kid` to the bare DID | `holder-kid-fragment` | ✅ seen on `provider-edc` (WARN) |
| Put our own DID in a counterparty dashboard entry | `dashboard-config` | implemented, injection pending |
| Empty `oid4vp.trustAnchorsFolder` | `trust-anchors-folder` | pending |
| Point the CredentialService at a host that does not resolve | `credential-service-route` | pending — needs a deployment whose IdentityHub serves the DID document |
| Remove a rendered Deployment outside Helm | `deployment-drift` | pending (unit-tested) |
| — | `identity-key-consistency` | ✅ seen on `consumer-edc` |
| Declare `--no-edc` where lanes exist | `deployment-profile` | ✅ run on `consumer-edc` |
| Declare `--role provider` on a deployment without the stack | `component-inventory` | ✅ run on dso-infra |
| Point one of the six DID copies elsewhere (`--values` on an edited copy) | `identity-did-consistency` | ✅ run on `provider-gitops`'s values |
| Declare a login client id the pod does not use (`--values`, four lines) | `marketplace-login-service` | ✅ run on producer and on dso-infra's SIOP path |
| Register nothing in the verifier but the MP's own login client | `marketplace-services-beyond-login` | ✅ seen on dso-infra |
| Retire every discoverable offering | `marketplace-offerings` | ✅ level B on `provider-gitops`, restored |
| Publish an offering whose spec has no credentials characteristic | `marketplace-offering-completeness` | ✅ seen on dso-infra |
| Switch `notification.enabled` off with a marketplace deployed | `contract-management-subscriptions` | ✅ level B on `provider-gitops`, restored |
| Name a kid the DID document does not publish (`--values`, three lines) | `keycloak-signing-key` | ✅ run on producer, both halves |
| Drop, unguard or mis-client the contract-management route (`--values`) | `central-mp-contract-management-route` | ✅ all three run on the central-MP provider |

`dashboard-config` closes the last gap in that plan: it reads the list the dashboard
**serves** at `/config/edc-connector-config.json` — never the ConfigMap, because the image
deep-merges over its own defaults, skips null overrides and is mounted with `subPath`, so
the file and the served list differ — and fails on a counterparty entry carrying our DID, on
one of our own endpoints carrying somebody else's, and, with `--peer`, on an entry whose DID
is not the one that peer identifies as. `peers.py::_classify_catalog_failure` still covers
the reactive half. Two guards keep it from over-reporting, and both are tested: an entry is
recognised as ours by its `protocolUrl` host **or** by a management URL naming one of our
lane services (a gateway alias would otherwise read as a counterparty carrying our DID), and
with no lane at all it SKIPs rather than classifying, because then it cannot tell the two
apart. What it cannot see is the *other* side's dashboard, which is where the original fault
lived — run it on both.

## Running it

```bash
python3 -m fdsc_verify -n provider --preflight-only --no-write     # creates nothing
python3 -m fdsc_verify -n provider --peer peers/example.yaml          # real interop
python3 -m fdsc_verify --list-checks                               # no cluster needed
python3 -m unittest discover -s tests
```

`--preflight-only` is the safe mode for an environment that is not yours, and it needs no
second flag: **nothing outside the `flow` phase writes**, and a test pins that invariant so
the next check cannot quietly break it. The help text used to promise "creates nothing"
while `broker-keyword-escaping` created a throwaway entity in preflight - true only if you
also passed `--no-write`, which the flag never said.

That check is now two, split along the same seam. `tmforum-reserved-words` (preflight)
compares the deployed tm-forum-api and Scorpio versions against the window where the escape
is lost - 1.16.1 up to 1.18.0 - and writes nothing. `flow-tmforum-roundtrip` (flow) creates
one throwaway Quote through **tm-forum-api**, updates it, counts the surviving keywords and
deletes it in a `finally`.

Writing through tm-forum-api rather than straight at the broker is the correction that
mattered: the escaping lives in that layer, so the old probe - raw `@id`/`@type` posted
directly to Scorpio - measured the broker's own behaviour, which is allowed, and then
blamed it with a fix line about upgrading tm-forum-api that did not follow from what was
measured.

Requirements: `python3` ≥ 3.9, `kubectl`, `openssl`. `cryptography` is optional (ES256
only; without it those checks SKIP rather than pass falsely) and `PyYAML` is optional (pass
peer/config files as JSON instead).

## Conventions for this repo

- **No runtime dependencies.** The tool has to run from a bare `python3` in any container,
  with no install step. Optional extras must degrade to `SKIP` with a reason, never to a
  false pass.
- **`kubectl` by subprocess**, not the Python client: it inherits kubeconfig, context, kubie
  and auth plugins for free, which is what an operator running this from a laptop expects.
- **Checks declare their requirements** (`needs_cluster`, `needs_peer`, `mutates`) so the
  runner can skip with a precise reason. Never fail for want of access.
- **Lead a `cause` with the literal string the operator is staring at** — the log line, the
  `www-authenticate` header — because that is what they will search for.
