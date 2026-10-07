# fdsc-verify

Answers two questions about an FDSC somebody has already deployed — **is it built the way
you think it is**, and **do its flows actually work** — and, when the answer is no, says
**why**, with the command that fixes it.

Point it at a namespace and it works out the rest. Nothing to configure, nothing to install
in the cluster, and nothing is written unless you ask for it.

**New here?** [Install](#install), then [Your first run](#your-first-run). The second half of
this file is *why* it behaves the way it does; you do not need it to use the tool.

## Install

```bash
pip install -e '.[all]'
```

Or skip it entirely: the tool has **no runtime dependencies**, so `python3 -m fdsc_verify ...`
from a checkout works in any container with a bare `python3` ≥ 3.9. It also needs `kubectl`
(it uses your current kubeconfig, context and auth plugins) and `openssl`.

The install adds two optional extras, and without them the checks that need them report
`SKIP` with the reason rather than passing falsely:

- **`cryptography`** — verifying **ES256** signatures. RSA is implemented natively.
- **`PyYAML`** — YAML peer and profile files. Without it, pass them as JSON.

## Your first run

You have just deployed an FDSC and want to know whether it is right. Start here:

```bash
fdsc-verify -n <your-namespace> --preflight-only
```

`-n` is the only required argument. `--preflight-only` runs everything except the flows, and
**creates nothing** — it is the mode for an environment you would rather not disturb, your
own included on a first look.

### What comes back

```
FDSC my-cluster / my-namespace

role      consumer+provider  (inferred from apisix, identityhub, keycloak, odrlpap, til, verifier)
release   my-release  rev 38  chart data-space-connector-10.4.12
identity  did:web:did-consumer.example.net:did  (from lane dcp), document served by identityhub
  key     secret did-consumer-example-net-tls
values    effective  (2430 keys)
EDC       2 lane(s): dcp, oid4vc
scope     16 check(s) not applicable  (not part of this deployment: 11; no --peer given: 5)

STATIC
  [OK]    deployment-role          consumer+provider (inferred from apisix, identityhub, …)
  [OK]    component-inventory      12 component(s) present, all consumer+provider requirements met
  [OK]    identity-did-consistency 6 sources agree on did:web:did-consumer.example.net:did
PREFLIGHT
  [OK]    did-document             resolves, 1 key(s), CredentialService present
  [OK]    credential-freshness     1 credential(s) verify against the published key
  [WARN]  keycloak-verifier-formats  1 registered service(s) ask for a format this realm does not issue
          data-service in scope `operator` wants OperatorCredential as vc+sd-jwt, and Keycloak
          issues it as dc+sd-jwt. A wallet holding that credential has nothing that satisfies
          the request and says so generically, so the failure looks like a wallet problem
          rather than a configuration one.
          fix: align the two - either add the issued format to that scope's presentation
               definition and dcql, or change the realm's `format` for that credential
          see: docs/troubleshooting.md#the-verifier-asks-for-a-format-keycloak-does-not-issue

OK=24  WARN=1  SKIP=0  N/A=16
```

**The header answers "what am I looking at" before anything is judged.** Read it first — if
it describes a different deployment than the one in your head, stop there, because every row
below is measured against it:

| line | what it tells you |
|---|---|
| `role` | what it decided this deployment is, **and how it knows**. Wrong? [declare it](#telling-it-about-your-deployment) |
| `release` | which Helm release it read, and at which revision |
| `identity` | the DID it believes you are, which source said so, and what serves the document |
| `values` | how much it is allowed to conclude — see [Where the values come from](#where-the-values-come-from) |
| `EDC` | lanes found, or `not deployed`. Printed either way, so an absence is stated rather than silent |
| `scope` | what was left out of the report, and why |

### What the statuses mean

| | meaning |
|---|---|
| `OK` | checked, and fine |
| `WARN` | a real finding that is not breaking anything yet. Does not fail the run unless `--strict` |
| `FAIL` | broken now. Exit code `1` |
| `SKIP` | **the question applies and the tool could not settle it** — no cluster access, something unparseable. A coverage gap, kept visible |
| `N/A` | the question does not arise here — no connector, no marketplace, one transport asked for. Summarised on `scope`, not printed as rows |

The last two are deliberately different. A `SKIP` is the tool admitting it went quiet; an
`N/A` is it owing you nothing. Use `-v` to print the `N/A` rows anyway.

Exit codes: `0` clean, `1` a failure, `2` the tool itself broke.

### What to do with a finding

Every non-OK row carries three things, and the status is the least useful of them:

- **`cause:`** — what is actually wrong, leading with the string you would search for;
- **`fix:`** — the command or the key to edit. There is no `--fix`: several of these repairs
  recreate identity state and one silently drops a credential store, so the tool prints and
  you run;
- **`see:`** — a link into **[`docs/troubleshooting.md`](docs/troubleshooting.md)**, where that
  exact failure is written up: the symptom as it appears in the logs, the cause, and the
  commands used to confirm it. The tool detects; that file explains.

`see:` prints an absolute path when the file sits next to the package, so you can open it.
When the output is going somewhere the file is not — CI logs, a ticket, a screenshot — point
it at a URL instead:

```bash
FDSC_VERIFY_DOC_BASE=https://github.com/SEAMWARE/fdsc-verify/blob/main/docs/troubleshooting.md \
  fdsc-verify -n <ns>
```

## What to run when

```bash
fdsc-verify -n <ns> --preflight-only    # the safe run: creates nothing
fdsc-verify --list-checks               # what it would check; no cluster needed
fdsc-verify -n <ns>                     # everything that applies, flows included
fdsc-verify -n <ns> --json              # for CI
fdsc-verify -n <ns> -q                  # no progress on stderr
```

`--help` lists every flag; the sections below cover the ones worth explaining.

A full run takes minutes, so it says what it is doing while it does it — **on stderr**, so
`--json | jq` is unaffected. On a terminal that is one line repainted in place and erased
before the report; off a terminal, one plain line per check. `-q` silences it.

### The three phases, and why your flows may not have run

| phase | reads | answers |
|---|---|---|
| `static` | the release's Helm values | is this deployment *built* right |
| `preflight` | live identity: DIDs, JWKS, credentials, certs, the TIL | is it *wired* right |
| `flow` | a real negotiation and transfer | does it *work* |

They run in that order, and **if an earlier phase fails the flows do not run** — the report
says `FLOW (skipped: N preflight failure)`. That is deliberate: a failed flow only tells you
it does not work, which you already knew, while the earlier failure is the answer. The gate
cuts one way only — a `static` failure does not suppress `preflight`, whose findings are
independent diagnoses rather than consequences.

```bash
fdsc-verify -n <ns> --static-only              # configuration only, seconds not minutes
fdsc-verify -n <ns> --phase static,preflight   # any subset
fdsc-verify -n <ns> --force-flows              # run the flows anyway
```

### Checking a deployment you must not disturb

**Nothing outside the `flow` phase writes**, and a test pins that invariant, so
`--preflight-only` is enough on its own. `--no-write` is the other half of the same promise
from the other end: it skips every check that creates an object, wherever it lives, so you
can run the flows and still touch nothing. Use either; use both if it makes you happier.

What the `flow` phase would create, if you let it: one throwaway TMForum Quote, and one
contract negotiation and transfer per EDC lane. All of it is tracked and deleted at the end.

### Checking one data path

A dataspace moves data two ways and most deployments use one:

| transport | how data moves | what you need |
|---|---|---|
| `fiware` | a credential presented to the verifier, exchanged for a token, spent at the APISIX gateway with OPA deciding | nothing beyond cluster access |
| `edc` | Dataspace Protocol through fdsc-edc: catalog → negotiation → transfer → EDR | a counterparty — see below |

```bash
fdsc-verify -n <ns> --transport fiware               # only the FIWARE path
fdsc-verify -n <ns> --transport edc --edc-lane dcp   # only the EDC path, only one lane
```

Asking for one leaves the other's checks out as *not applicable*; they fail independently,
so this is not just noise reduction. An EDC connector can run two **lanes** (`dcp` and
`oid4vc`, differing in the identity protocol) and both are discovered and exercised
separately.

### Testing EDC against a counterparty

**The EDC flows need a `--peer`.** A negotiation has two sides and this stack cannot be both
of them, so without one those checks report *not applicable* rather than passing quietly.

```bash
fdsc-verify -n <ns> --peer peers/example.yaml
```

`--peer` is real interop, which is the only thing that proves the trust anchors, the
`x5c` chain and the `aud` are right in both directions. A peer file with `context` and
`namespace` also unlocks the both-sides checks (is our DID in their issuers list, does
their stored credential still verify) — those catch failures that otherwise look like
*our* connector being broken.

**A peer is a DID first and a DSP endpoint second.** Only `participantId` is required;
`protocolUrl` is optional, because most of what a counterparty is good for needs nothing
but its identity — whether its DID document resolves, whether our DID is in its trusted
issuers list, whether our dashboard names it correctly. Declare a peer without one when
you reach it through its gateway rather than through fdsc-edc: the DSP checks then SKIP
saying so, instead of making you invent a URL nobody serves. `peer-reachable` and the
flow checks declare `transport="edc"`, so `--transport fiware` leaves them out entirely.

A stalled negotiation is classified rather than reported: the tool reads both connectors'
logs and the gateway access log around the attempt and matches the four signatures seen so
far, each pointing at a different side of the wire.

Everything the flows create is tracked and removed at the end. `--keep` leaves it and
lists it; negotiations and agreements cannot be deleted through the management API, so
they are listed rather than silently left behind.

## Where the values come from

The static phase reads Helm's own record of the release, decoded with the standard
library — no `helm` binary required.

Three trust levels, and a check may only conclude what its level supports:

| trust | source | a check may conclude |
|---|---|---|
| `effective` | the live release, or `--effective-values` | anything, including about a key nobody set |
| `user` | `--values FILE` when no release could be read | only about keys the file sets |
| `none` | nothing readable | nothing — every static check SKIPs, with the reason |

`user` is genuinely weaker, not just less convenient: the role matrix disagrees with the
chart defaults (`credentials-config-service` is *Required* for a provider and defaults to
`false`), so a tool that cannot see the defaults would have to guess.

What `user` is missing is the **release**, not the cluster. Only the `static` phase depends
on it; `preflight` and `flow` read the cluster and run either way.

Argo and friends render with `helm template` and install the result, so Helm stores no
release and there is nothing for the static phase to read. Two ways back, in order of
effort:

```bash
fdsc-verify -n <ns> --values <the file it was deployed from>      # static at `user`
fdsc-verify -n <ns> --effective-values merged.json                # static in full
```

The defaults for that second one are still obtainable without a release, because they belong
to the chart and the chart is published: `helm show values <chart> --version <v>`, with your
file merged over them. **That is not a degraded substitute** — `chart.dependencies` is not
serialised into a stored release either, so `helm get values --all` does not coalesce
subchart defaults, and the umbrella's own `values.yaml` is the whole of what would have been
there.

One thing to watch: if the DSC is a **dependency of a wrapper chart**, its values hang off
the alias and the merge has to go under that key. The tool sniffs the root and says so;
`--values-root dsc` declares it when the file is too partial to sniff.
[The troubleshooting doc has the merge script](docs/troubleshooting.md#getting-to-effective-when-there-is-no-release).

## Telling it about your deployment

Discovery is a fallback, not the authority. The tool points at a DSC somebody already
deployed and you know what it is meant to be, so anything you declare wins:

```
explicit flag  >  profile file (--config)  >  inference  >  unknown
```

```bash
fdsc-verify -n consumer --role consumer --no-edc       # a plain consumer
fdsc-verify -n producer --edc-protocol dcp             # stop guessing which lane speaks what
fdsc-verify -n x --did did:web:example.org             # when nothing publishes it locally
fdsc-verify -n x --values-root dsc                     # DSC deployed under a wrapper chart
```

**A declaration is also an assertion.** `--edc` where no lane exists, `--no-edc` where one
appears, a `--did` the lane configuration disagrees with, a `--release` that is not in the
namespace: each is a FAIL from `deployment-profile`, because either the flag describes a
different deployment — wrong namespace, wrong context — or the deployment is not what you
believe. It never fails for want of a declaration: with no flags it is pure information,
and with no cluster to compare against it skips rather than blaming you for its own lack
of access.

Every flag is shorthand for the same key in the profile file, which also carries what does
not fit on a command line:

```yaml
role: consumer+provider          # or --role
edc: {enabled: false, protocol: dcp}   # or --edc / --no-edc / --edc-protocol
did: did:web:example.org         # or --did
valuesRoot: dsc                  # or --values-root
components: {did-helper: on}     # or --component did-helper=on
release: my-release              # or --release
identity: {secret: my-identity-tls, key: tls.key}
services: {verifier: my-verifier}      # a component under a non-standard service name
lanes:                                 # a lane discovery cannot see, declared by hand
  oid4vc:
    props: {"oid4vp.enabled": "true", "ebsiTir.tilAddress": "http://trusted-issuers-list:8080"}
identityhub: {token: "...", port: 8082}
timeouts: {negotiation: 90, transfer: 90}
```

Unknown stays unknown: a field nobody declared and nothing could infer produces a `SKIP`
with the reason, never a verdict.

## What it does not check

**Protocol conformance.** That is `scripts/run-tck.sh` in the **fdsc-edc** repo, which
runs the Eclipse DSP TCK against a locally built controlplane. It answers "is the protocol
implemented correctly". `fdsc-verify` answers "does *this* deployment work". Do not
reimplement one inside the other.

**A repair tool.** It diagnoses and prints the command it would run. There is no `--fix`,
on purpose: several of these fixes recreate identity state, and one of them silently
deletes a credential store. Those want a human.

**A participant.** This is the boundary that decides what several checks stop short of,
so it is worth stating plainly rather than discovering it one check at a time.

The tool **observes** a deployment. It does not **act as somebody in** it. Two things fall
on the far side of that line, and both are deliberate — presenting a credential, and
[buying something](#why-no-purchase-is-simulated):

* **Presenting a credential.** Doing it properly means being a wallet: a VC obtained from
  Keycloak over OID4VCI, a key, a signed Verifiable Presentation, and a provisioned test
  user. So the FIWARE path is probed *without* one, and the OID4VC transfer stops once the
  EDR is issued. What that still proves is worth having — that the gate demands a
  credential at all, and that the verifier publishes the discovery document and JWKS the
  gateway validates with, so that a refusal means something. What it cannot prove is that
  a real credential gets you in.

The rule behind both: a check may **create a throwaway object of its own** and delete it —
`flow-tmforum-roundtrip` writes one Quote, `flow-negotiation` opens one negotiation — but it
does not impersonate a user or transact on somebody's behalf. Where that stops it, the
check says so in its own words instead of reporting a limit as a fault.

---

## Why it behaves this way

Nothing below is needed to run the tool. It is here because every rule in it was paid for:
each failure this tool encodes was diagnosed by hand at least once, and in almost every case
the flow itself was fine — the cause was a precondition. A stale JWKS cache, an image
inherited from the chart default, a credential signed before a key rotation, a DID copied
from a neighbour. All of them surface as a generic `401` or a negotiation stuck in
`REQUESTED`, and all of them cost between half an hour and half an afternoon of bisection.

### Where the evidence comes from

Every diagnosis, measurement and ✅ in these documents was taken from a **real deployment**,
and the counts are quoted because a count is the difference between a claim and an
observation. The deployments are named by their **shape** rather than by whose they are,
since the shape is what makes a measurement transferable:

| handle | shape |
|---|---|
| `provider-edc` | provider with two EDC lanes (dcp + oid4vc), IdentityHub serving the DID |
| `provider-edc-2` | a second, independent provider with EDC, in another cluster: a bare DID with no path suffix, and a newer vcverifier. Several diagnoses turn on the contrast with the one above |
| `consumer-edc` | consumer with two EDC lanes |
| `provider-mkt` | provider with a local marketplace, no EDC, did-helper serving the DID |
| `provider-remote-mkt` | provider with no marketplace of its own, integrated with a central one |
| `provider-gitops` | provider installed by GitOps, the DSC a dependency of a wrapper chart |

Hosts and DIDs in the examples use `example.org` and `example.net`. The two are not
interchangeable: `did:web:did-provider.example.org:did` is served from `/did/did.json` and
`did:web:did-consumer.example.net` from `/.well-known/did.json`, and several diagnoses turn
on exactly that difference.

Names that belong to the **software** rather than to a deployment are left verbatim —
Java packages in stack traces, image repositories, chart names and versions, in-cluster
service names like `trusted-issuers-list`. They are the same strings in your cluster, and
`docs/troubleshooting.md` is meant to be searched for the string you are staring at.

### How it finds things

`fdsc-verify -n <ns>` and nothing else is the whole design goal, so discovery matters — and
it has to work on a deployment that looks nothing like the one this tool was written
against. What it leans on, in the order it asks:

1. **The Helm release**, read from Helm's own record with the standard library. It answers
   what was *asked for*, which is where a fix goes. A release counts as a DSC when its
   chart is one, **or when it lists one as a dependency** — the second half matters: one
   environment here wraps the connector in a `provider` chart of its own.
2. **The cluster**, by service name. That answers what is *running*, whoever installed it:
   a component deployed as a sibling release is still that component.
3. **The EDC lane ConfigMaps**, `<release>-fdsc-edc-<lane>`, when there are any — around 85
   keys including every `web.http` port and path, so nothing is hard-coded. Lanes are
   discovered, not assumed.

### Two authorities, and which answers what

| Phase | Authority | Question |
|---|---|---|
| `static` | the **values** | is it *built* the way you think? |
| `preflight` / `flow` | the **cluster** | is it *wired* right, does it work? |

So **presence is the cluster's to answer** — values that enable a component with nothing
running behind it are a finding, not an absence — while **intent and the fix are the
values'**, which is why a FAIL names the key you will edit. The rendered manifest is the
bridge between them: a release can list a dependency and render nothing from it, and
calling that "enabled but not running" sends you hunting a workload that was never created.

With no readable release at all — a GitOps install renders with `helm template` and leaves
none — `static` runs off `--values <the file it was deployed from>` at reduced trust, and
the cluster checks run regardless.

### Findings that broke naive implementations

Each of these cost a wrong answer before it was understood:

- **The DSC is not always at the root of the values.** Deployed as a dependency under an
  alias, everything moves under it (`dsc.did.enabled`), and reading the unprefixed path
  does not error — it reports every component absent, which is the worst way to be wrong.
  The root is taken from the dependency's alias, or `--values-root`.
- **An absent key does not mean disabled.** Helm *enables* a dependency whose `condition`
  does not resolve, while for an umbrella template absent means false. Hence `Tri`, which
  has no `__bool__` so "cannot tell" can never be read as "no".
- **Values carry placeholders.** `keycloak.issuerDid` really is the literal `${DID}`, and
  comparing it reports a mismatch that is not there.
- **The identity secret name is not stable** (`connector-example-es-tls` in one
  deployment, `did-provider-example-org-tls` in another — the chart derives it from the
  host, and the hosts differ), so it is resolved by *type* — the secret-backed volume of
  type `kubernetes.io/tls` — and never by name.
- **`dcp.enabled` and `oid4vp.enabled` are both `true` on both lanes** in every deployment
  inspected, so neither says which protocol a lane speaks. The discriminator is
  `fdscTransfer.{dcp,oid4vc}.enabled`, in one place (`EdcLane.identity`), and
  `--edc-protocol` settles it outright.
- **A did:web's document URL depends on its path segments**: `did:web:host` resolves to
  `/.well-known/did.json`, `did:web:host:a:b` to `/a/b/did.json`. Both forms are in use
  here, and the same rule runs backwards to derive the DID from the did-helper's host.

### Who this participant is

The DID is not an EDC fact: a Consumer with nothing but Keycloak and a did-helper has one.
It is resolved from every place that states it — the lanes, the verifier,
contract-management, the did-helper's `hostUrl` — and **every source is kept**, because a
DSC writes its DID in up to six independent places and the one left behind after a domain
change is a real fault with a generic symptom. That comparison is `identity-did-consistency`.

### What role this deployment plays

Consumer, provider, or both, declared with `--role` or inferred from what is deployed, and
measured against the canonical component matrix (`components.py`, from the
data-space-connector docs). A requirement there is a **capability**, not a Deployment
object: the DID document is served by the did-helper *or* by the IdentityHub, and the
credentials-config API by a standalone service *or* by the verifier's own config port.

### Why the static phase trusts what it trusts

From Helm's own record of the release, decoded with the standard library — no `helm`
binary required. Measured against `helm get values --all`, the merge is byte-identical
(2592 leaf keys on one deployment, 2194 on another — a provider with EDC and a consumer
without), because `chart.dependencies` is not
serialised into the stored release and so `helm` cannot coalesce subchart defaults either.

### Why a check belongs to one data path

What a check declares is **which path a failure in it breaks**, not which one it
traverses — under the narrower reading every preflight check declared nothing, because
reading a ConfigMap traverses nothing, and `--transport fiware` ran all the fdsc-edc ones
anyway. It is a set: `verifier-jwks-matches-key` is lane-scoped and so looks like an EDC
check, but a stale JWKS at the gateway breaks every route APISIX guards, so it declares
both and survives either selection. A check that declares none is about the deployment
rather than a data path and always runs.

Asking for one transport leaves the other's checks out as **not applicable**: they are
counted in the tally, summarised on the header's `scope` line, kept in `--json` and
printed under `-v`, but they do not take a line each.

The DSP hosts are left to `dsp-route` even though the same APISIX fronts them — in one
deployment here, `dsp-producer` and `mp-data-service` are the same gateway.

### What the FIWARE probe proves without a credential

**The FIWARE probe presents no credential**, and that is a deliberate limit rather than an
oversight: doing it properly means being a wallet — a VC out of Keycloak over OID4VCI, a
key, a signed Verifiable Presentation — and it needs a test user somebody has to provision,
which would break the promise that `--no-write` creates nothing. What it does instead is
separate *the door is hung wrong* from *my credential was refused*, which get confused
constantly:

- `flow-fiware-gate` asks every host the gateway publishes for data with no token. A `401`
  carrying a `WWW-Authenticate` is the gate doing its job; a published host that answers
  nothing at all is a finding, because an Ingress exists for it.
- `flow-fiware-discovery` fetches the OIDC discovery document for every service registered
  in the verifier, and the JWKS behind it. That is exactly what APISIX consumes, and a
  service registered but not served is a login nothing can validate however good the
  credential is.

### Why there is no EDC loopback

Without `--peer`, the EDC flow checks are **not applicable** and say so. That is not a
missing feature; it is the one shape this stack cannot do.

Loopback — a lane negotiating against its own public DSP endpoint — reads as the safe
option: self-contained, repeatable, nobody else's environment touched. The tool used to
default to it. It cannot work here, and it fails in the most expensive way available.

The TMF-backed negotiation store keeps a negotiation as **one Quote with both roles in
`relatedParty`**, and rebuilds it by finding the party whose DID is *not* ours — which is
how it recovers `counterPartyId`, `counterPartyAddress` and `protocol`, the three fields
`ContractNegotiation.Builder.build()` requires. With one participant on both sides that
party does not exist, the fields stay null, and **every read throws a
NullPointerException**. The state machine then retries every two seconds, for ever, and
the only cure is deleting the Quote by hand. Measured: 151 retries in six minutes from a
single negotiation, still going when it was found.

EDC itself permits it — the builder checks only that the three fields are present, never
that the counterparty differs from us — so this is a limit of the TMF store, and one that
is not going to be lifted. Offering loopback anyway would mean handing somebody a run that
poisons their environment.

`dsp-route` still proves our own DSP endpoint answers, which is what loopback was
confirming most of the time anyway.

### Why no purchase is simulated

Reaching the end of the marketplace chain means placing a product order — parties, a
billing account, the charging backend — because a policy in odrl-pap is created by a
*purchase*, not by a publication. Measured on a live provider with its own marketplace:
23 of 25 policies carry a `urn:ngsi-ld:product-order:<uuid>` and none references an
offering. A probe that published an offering and waited was written, run, and removed for
exactly that reason. What is checked instead is that what is already published carries the
pieces the chain needs.

## Adding a check

```python
@check("my-check", "One line, in the present tense",
       needs_cluster=True, lanes=["*"])          # lanes=None -> runs once
def my_check(ctx, lane) -> Result:
    if not some_precondition:
        return Result.skip("what is missing")     # never fail for want of access
    return Result.fail("what is wrong",
                       cause="why, in the words the operator will see in the logs",
                       fix="the command that fixes it",
                       doc="a-heading-in-docs-troubleshooting-md")
```

Three rules:

- **A `FAIL` without a `cause` is incomplete.** The status is packaging; the cause and the
  fix are the product.
- **Declare requirements, do not discover them.** `needs_cluster` / `needs_peer` /
  `mutates` / `needs_values` / `needs_release` / `roles` let the runner skip with a precise
  reason. The tool must stay useful with nothing but HTTP access. `roles=("provider",)`
  gates a check that makes no sense for a consumer — and only that; a check that merely
  needs an EDC lane says so with `lanes`, because the connector is optional for both roles.
- **`doc` must be a real anchor.** It is the GitHub slug of a heading in
  [`docs/troubleshooting.md`](docs/troubleshooting.md); if the diagnosis is not written up
  there yet, write it, and add the row to that file's *Which check points here* table.
  `python3 -m unittest tests.test_docs` fails on an anchor that does not resolve.

Lead the `cause` with the literal string the operator is staring at — the log line, the
`www-authenticate` header — because that is what they will search for.

## Tests

```bash
python3 -m unittest discover -s tests
```

`jose.py` is the only module with cryptography of its own, so it has real vectors: keys
generated with openssl, tokens signed with them, and assertions that a wrong key and a
tampered payload are both rejected. The ES256 case matters most — the `r||s` to DER
conversion fails silently as "invalid signature" when wrong, which sends you hunting a key
mismatch that does not exist.

The checks themselves are verified by **fault injection**: break one thing on purpose and
confirm the right check names it. A check you cannot make fail is not verified.
[`docs/fault-injection.md`](docs/fault-injection.md) has the break-and-restore commands, at
two levels — feeding a check a wrong input through `--config`, which touches nothing and
proves the logic, and breaking the real thing, which proves discovery too.
