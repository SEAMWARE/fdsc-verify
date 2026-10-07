# FDSC troubleshooting

Every failure a deployed FDSC has hit here, what caused it, and how it was fixed. This is the
companion to [`fdsc-verify`](../README.md): **the tool detects, this doc explains**. Every `see:`
line the tool prints is an anchor into this file.

Each entry leads with the **literal symptom** — a log line, an HTTP response, a header — because
that is what you have when something breaks. Search this file for the string you are looking at.

**Provenance.** Every entry below was written against a **real deployment** while the failure
was in front of somebody, which is why the counts and versions are specific. The deployments are
named by their shape — `provider-edc`, `consumer-edc`, `provider-mkt` and the rest — and
[the README defines them](../README.md#where-the-evidence-comes-from); hosts and DIDs use
`example.org` / `example.es`. **The causes and the fixes are generic; only the identifiers are
not.**

Names that belong to the *software* are left verbatim — Java packages in stack traces, image
repositories, chart names and versions, in-cluster service names. They are the same strings in
your cluster, and this file is meant to be searched for the string you are staring at.

**Status legend**

| | |
|---|---|
| **RESOLVED** | fixed; kept because the diagnosis is expensive to rebuild and several of these can come back on an image bump or a certificate rotation |
| **WORKAROUND** | working, but on a detour that should be undone when the real cause is fixed |
| **OPEN** | still broken, with the owner named |

A general warning that applies to most of what follows: several of these failures look like the
counterparty's fault and are not, or vice versa. Before blaming a peer, check the direction that
actually failed — a catalog request only exercises one direction, negotiation exercises both.

---

## Which check points here

Run `python3 -m fdsc_verify --list-checks` for the full inventory. These are the sections a
non-OK result can send you to:

| Section | Checks that reference it |
|---|---|
| [contract-management is not listening to the marketplace](#contract-management-is-not-listening-to-the-marketplace) | `contract-management-subscriptions` |
| [An offering is published and nothing downstream happens](#an-offering-is-published-and-nothing-downstream-happens) | `marketplace-offering-completeness` |
| [The marketplace cannot log anyone in](#the-marketplace-cannot-log-anyone-in) | `marketplace-login-service`, `marketplace-services-beyond-login` |
| [Nothing in the catalogue is discoverable](#nothing-in-the-catalogue-is-discoverable) | `marketplace-offerings` |
| [A credential expires in a week and the UI says a year](#a-credential-expires-in-a-week-and-the-ui-says-a-year) | `keycloak-credential-lifetime` |
| [The verifier asks for a format Keycloak does not issue](#the-verifier-asks-for-a-format-keycloak-does-not-issue) | `keycloak-verifier-formats` |
| [Keycloak signs with a key the DID document does not publish](#keycloak-signs-with-a-key-the-did-document-does-not-publish) | `keycloak-signing-key` |
| [The central marketplace cannot reach contract-management](#the-central-marketplace-cannot-reach-contract-management) | `central-mp-contract-management-route` |
| [contract-management is wired to something that is not deployed](#contract-management-is-wired-to-something-that-is-not-deployed) | `central-mp-contract-management-wiring` |
| [APISIX caches the verifier's JWKS](#apisix-caches-the-verifiers-jwks-and-the-kid-never-changes) | `verifier-jwks-matches-key`, `identity-key-consistency`, `flow-negotiation` |
| [The DID endpoints API: `PATCH` appends](#the-did-endpoints-api-patch-appends-it-does-not-replace) | `did-document` |
| [The DID is written down in several places, and they drift](#the-did-is-written-down-in-several-places-and-they-drift) | `identity-did-consistency` |
| [A stale credential outlives a key rotation](#a-stale-credential-in-the-identityhub-outlives-a-key-rotation) | `credential-freshness`, `credential-two-copies`, `peer-credential-valid`, `peer-catalog`, `flow-negotiation` |
| [The wildcard cert cannot be an `x509_san_dns` client id](#the-wildcard-certificate-cannot-be-an-x509_san_dns-client-id) | `cert-san-vs-client-id` |
| [The client id scheme and the request object have to agree](#the-client-id-scheme-and-the-request-object-have-to-agree) | `client-id-scheme`, `cert-san-vs-client-id` |
| [OID4VP trust anchors](#oid4vp-trust-anchors-use-the-images-public-root-store) | `trust-anchors-folder` |
| [`/credential-repo` must project a single key](#credential-repo-must-project-a-single-key) | `credential-repo-single-key` |
| [The HARICA anchor is missing for callbacks to us](#peer-side-the-harica-anchor-is-missing-for-callbacks-to-us) | `peer-catalog` |
| [Reading EDC's DCP token failures](#reading-edcs-dcp-token-failures) | `holder-kid-fragment` |
| [The DCP instance needs the DCP controlplane image](#the-dcp-instance-needs-the-dcp-controlplane-image) | `controlplane-image` |
| [The DCP lane needs an STS client secret](#the-dcp-lane-needs-an-sts-client-secret-that-dev-mode-vault-loses) | `sts-secret-aliases`, `vault-mode` |
| [Wrong `aud`: the counterparty's dashboard carries the wrong DID](#wrong-aud-the-counterpartys-dashboard-carries-the-wrong-did) | `dashboard-config`, `peer-catalog`, `flow-negotiation` |
| [Image defaults leak into the connector list](#image-defaults-leak-into-the-connector-list) | `dashboard-config` |
| [Working around the broken `atdih` record](#working-around-the-broken-atdih-record) | `credential-service-route`, `dsp-route` |
| [The EDR token lives 5 minutes](#the-edr-token-lives-5-minutes-and-cannot-be-refreshed) | `edr-token-lifetime`, `flow-transfer` |
| [The dashboard never sends the EDR token](#the-dashboard-never-sends-the-edr-token) | `flow-transfer` |
| [Scorpio 6 strips JSON-LD keywords](#scorpio-6-strips-json-ld-keywords) | `tmforum-reserved-words`, `flow-tmforum-roundtrip`, `flow-negotiation` |
| [A role is missing a component it requires](#a-role-is-missing-a-component-it-requires) | `component-inventory` |
| [Components that cannot work without each other](#components-that-cannot-work-without-each-other) | `component-consistency` |
| [Reading the values of a release](#reading-the-values-of-a-release) | `values-source` |
| [A release that is not `deployed`](#a-release-that-is-not-deployed) | `release-status` |
| [A `post-install`-only registration job](#a-post-install-only-registration-job-stops-registering-on-upgrade) | `registration-job-hooks`, `registration-services-present` |
| [Values keys that no chart key consumes](#values-keys-that-no-chart-key-consumes) | `values-unknown-keys` |

Two sections still have no check behind them: the `vcverifier` and VP entries under
[OID4VC lane](#oid4vc-lane), both of which are diagnoses about the *peer's* deployment
rather than this one.

---

## Configuration and the release

Everything here is read from Helm's own record of the release - the
`sh.helm.release.v1.<release>.v<N>` Secret - rather than from the cluster's
behaviour. It answers "is this deployment built the way you think it is", which is
a different and usually cheaper question than "is it working".

### Reading the values of a release

Not a fault: this is the tool telling you how much the static checks below are
allowed to claim.

The Secret's `release` key is **base64 twice** (kubernetes, then Helm) wrapping
gzip wrapping JSON, and decodes to `chart` (the chart's own `values.yaml` plus
metadata), `config` (what the operator supplied), `hooks`, `manifest`, and
`version` (the revision). Merging `chart.values` under `config` with Helm's
coalesce rules gives the **effective** values, and that merge is not an
approximation - measured against `helm get values --all` it is byte-identical, on
`<cluster-a>/provider` (2592 leaf keys) and on `<cluster-b>/consumer`
(2194). The reason is structural: `chart.dependencies` is not serialised into the
stored release, so `helm` cannot coalesce subchart defaults either.

```bash
kubectl -n provider get secret -l owner=helm,status=deployed \
  -o jsonpath='{.items[*].metadata.name}'
```

Always narrow with `status=deployed`. Helm keeps every historical revision as its
own Secret, each embedding the whole rendered manifest: ``consumer-edc`` is at
revision 36, so an unfiltered list downloads roughly 36 MB for one namespace and
the tool looks like it has hung.

Three trust levels, and the difference matters:

| trust | source | what a check may conclude |
|---|---|---|
| `effective` | the live release, or `--effective-values` | anything, including about a key nobody set |
| `user` | `--values FILE` with no cluster | only about keys the file sets |
| `none` | nothing readable | nothing; every static check SKIPs |

`user` is genuinely weaker rather than merely less convenient, because the role
matrix disagrees with the chart defaults: `credentials-config-service` is
*Required* for a provider and defaults to `false`, and `did` is *Required* for all
three participant roles and defaults to `false`. A tool that could not see the
defaults would have to guess, and guessing here produces confident nonsense.

#### Getting to `effective` when there is no release

Where Helm stores the release, `--effective-values $(helm get values <rel> -n <ns>
--all -o json)` is the short route, and passing nothing at all is shorter still.

**But `user` means no release could be read**, so on a GitOps install that command
has nothing to ask - which is exactly what this check's `fix:` line used to
recommend, in the one situation where it cannot work. The defaults are still
obtainable, because they are the chart's and the chart is published. On
`provider-gitops` the DSC is a *dependency* of a wrapper chart, aliased `dsc`, so the merge
goes under that key:

```bash
# <your-gitops-repo>/provider/Chart.yaml:
#   dependencies: [{name: data-space-connector, alias: dsc, version: 10.9.0,
#                   repository: oci://quay.io/fiware/helm-charts}]
helm show values oci://quay.io/fiware/helm-charts/data-space-connector \
  --version 10.9.0 > /tmp/dsc-defaults.yaml

cd <your-gitops-repo>/provider
python3 - > /tmp/effective.yaml <<'EOF'
import yaml
defaults = yaml.safe_load(open('/tmp/dsc-defaults.yaml')) or {}
user = yaml.safe_load(open('values.yaml')) or {}
def merge(base, over):
    out = dict(base)
    for k, v in (over or {}).items():
        out[k] = merge(out[k], v) if isinstance(out.get(k), dict) and isinstance(v, dict) else v
    return out
merged = dict(user)
merged['dsc'] = merge(defaults, user.get('dsc') or {})
print(yaml.safe_dump(merged, default_flow_style=False))
EOF

python3 -m fdsc_verify -n provider --effective-values /tmp/effective.yaml
```

Without a wrapper chart, drop the `merged['dsc']` line and merge at the top level.

**This is not a degraded substitute**: it is the same fidelity a live release
gives. `chart.dependencies` is not serialised into the stored release, so
`helm get values --all` does not coalesce subchart defaults either - the umbrella's
own `values.yaml`, which is what `helm show values` returns, is the whole of what
would have been there.

Measured on `provider-gitops`: `values-source` WARN -> OK (1148 keys), while
`client-id-scheme`, `registration-services-present` and `cert-san-vs-client-id`
go from SKIP to a verdict and `identity-did-consistency` goes from two
corroborating sources to five.

### A role is missing a component it requires

**Status**: informational — what it means depends entirely on what this deployment is
*for*, which is why the check refuses to run without a role.

Each participant role needs a different subset of the connector. The canonical table is
[`doc/deployment-integration/roles/README.md`](https://github.com/FIWARE/data-space-connector)
in the data-space-connector repo; `fdsc-verify` carries it as data in `components.py` so the
checks cannot drift from each other. The short version:

| | Consumer | Provider |
|---|---|---|
| Keycloak, DID document | Required | Required |
| VCVerifier, credentials-config, trusted-issuers-list, APISIX, odrl-pap | – | Required |
| tmforum-api, contract-management, broker, marketplace, **FDSC-EDC** | – / Optional | Optional |

**A requirement is a capability, not a Deployment object**, and forgetting that produces a
report that fails on a healthy deployment. Two cases in this dataspace:

- the **DID document** is served by the did-helper *or* by the IdentityHub — a DCP lane
  brings the second and disables the first, and both are correct;
- the **credentials-config API** is served by a standalone service *or* by the verifier's
  own config port (8090), which is what the charts deployed here do.

Two different findings come out of this check and they are not the same problem:

```
2 component(s) this role requires are not deployed      # the role needs it, nothing has it
1 component(s) are enabled but not running              # the values ask for it, nothing runs
```

The second is the interesting one, and it has a trap of its own: a release can **list a
dependency and render nothing from it**. `provider-remote-mkt` lists `fdsc-edc` and its
rendered manifest holds not one object of it, so "enabled but not running" there would send
you hunting a workload that was never created. The check consults the rendered manifest
before saying it, which is why that case reports as simply absent.

```bash
python3 -m fdsc_verify -n <ns> --only deployment-role,component-inventory --static-only
python3 -m fdsc_verify -n <ns> --role consumer --static-only   # when inference is wrong
```

If the role is wrong, everything below it is wrong. Check `deployment-role` first: it says
which components it inferred the role from.

### Components that cannot work without each other

**Status**: informational, and each pair below is a real runtime dependency rather than a
tidiness rule.

| If this is deployed | this must be too | because |
|---|---|---|
| VCVerifier | credentials-config-service, trusted-issuers-list | it asks the first which credentials a service demands and the second whether the issuer is trusted |
| APISIX | odrl-pap | the gateway delegates to OPA, which runs the Rego odrl-pap generates from the ODRL policies |
| FDSC-EDC | tmforum-api | the EDC uses the TMForum APIs as the storage backend for assets, contracts and policies |

A verifier without a source of credential configuration is the one that hurts most, because
it does not fail: it answers every login with a request object carrying no
`presentation_definition`, and the wallet reports **"could not process the information
request"** — the same generic message a dozen unrelated faults produce.

**The DID document server is an either/or.** `did.enabled` and `identityhub.enabled` are
mutually exclusive by design, and both extremes are reported:

- *both deployed* — a counterparty resolves whichever one the ingress routes to, which is
  not a decision anybody made;
- *neither* — nothing serves this participant's DID document and no counterparty can
  resolve it at all.

```bash
python3 -m fdsc_verify -n <ns> --only component-consistency --static-only
```

### A release that is not `deployed`

**Status**: informational, and the first thing to rule out when "my config change
did nothing".

`helm` records a status per revision. Anything other than `deployed` -
`pending-upgrade`, `pending-rollback`, `failed` - means the manifests in the
cluster are not the ones the values describe, so every other static finding is a
statement about what was *asked for* rather than about what is running.

```bash
helm history <release> -n <namespace>
helm status <release> -n <namespace>
```

A `pending-upgrade` that never settles is usually a hook Job that cannot complete
(see the next section) or an immutable field: `vault.server.dataStorage` renders
as a StatefulSet `volumeClaimTemplate`, and a Bitnami-to-CloudPirates Keycloak
move needs the StatefulSet deleted first.

### A `post-install`-only registration job stops registering on upgrade

**Status**: OPEN on `<cluster-a>/provider` at the time of writing (revision 18).

Several components are wired together after install by a Helm hook Job:
`vcverifier` registers its services with the config repo, the TIL registration Job
registers participant DIDs, `tm-forum-api` registers itself with the credentials
config service. If the hook declares only `post-install`, it runs once - at the
very first install - and is skipped by every `helm upgrade` afterwards. Whatever
it registered then keeps reflecting the chart as it was at install time.

The symptom is remote from the cause. A service missing from the verifier's config
repo makes the verifier serve an authorization request with **no
`presentation_definition`**, which a wallet reports as:

```
Could not process the information request
```

and which looks like a wallet bug, a DCQL shape problem, or a credential problem -
anything but a Helm hook.

**How to see it.** Both halves of the evidence are in the release itself: what the
hook declared, and how many upgrades have happened since. On `provider-edc-2`,
revision 18:

```bash
kubectl -n provider get secret sh.helm.release.v1.provider.v18 \
  -o jsonpath='{.data.release}' | base64 -d | base64 -d | gunzip | \
  python3 -c 'import json,sys
r=json.load(sys.stdin)
print("revision", r["version"])
for h in r["hooks"]: print("  %-46s %s" % (h["name"], ",".join(h.get("events") or [])))'
```

```
revision 18
  provider-vault-server-test                     test
  provider-etcd-pre-upgrade                      pre-upgrade
  apisix-routes-job                              post-install,post-upgrade
  verifier-job                                   post-install          <- never re-ran
  identityhub-participant-registration-job       post-install,post-upgrade
  provider-til-registration-job                  post-install          <- never re-ran
```

`apisix-routes-job` and the identityhub Job are the control group: they carry
`post-upgrade` and are correct, which is what makes the rule discriminating rather
than a blanket complaint.

`registration-job-hooks` reads the **values** rather than these rendered names,
because the names change between releases and chart versions while the annotation
block is where the hook is declared and therefore where the fix goes. On `provider-edc-2`
(chart 10.3.2) three blocks are `post-install` only:

```
decentralizedIam.vcAuthentication.vcverifier.registration.job.annotations
registration.annotations
tm-forum-api.registration.annotations
```

Note that this moves between chart versions - `registration.annotations` gained
`post-upgrade` after 10.3.2 - which is exactly why the check inspects the release
in front of it instead of carrying a list of known-bad versions.

**Fix.** Add the event **and** the delete policy, then upgrade once so the Job runs:

```bash
helm upgrade <release> -n <ns> --reuse-values \
  --set 'decentralizedIam.vcAuthentication.vcverifier.registration.job.annotations.helm\.sh/hook=post-install\,post-upgrade' \
  --set 'decentralizedIam.vcAuthentication.vcverifier.registration.job.annotations.helm\.sh/hook-delete-policy=before-hook-creation'
```

**The second `--set` is not optional, and leaving it out fails later rather than
now.** The vcverifier chart defaults to:

```yaml
"helm.sh/hook": post-install
"helm.sh/hook-delete-policy": hook-succeeded
```

`hook-succeeded` deletes the Job only when it **succeeds**. Add `post-upgrade`
alone and the first failing run - the verifier not ready yet, the config repo
refusing a body - leaves the Job behind; the next `helm upgrade` then tries to
create a hook Job of the same name and dies with

```
Error: UPGRADE FAILED: failed to create resource: jobs.batch "verifier-job" already exists
```

which reads like a Helm problem rather than like a Job that failed weeks ago.
`before-hook-creation` deletes the previous one first, and is what the working
hooks in these same releases already use - `identityhub-bootstrap` and
`apisix-routes-job` both carry `post-install,post-upgrade` with it. Copy them.

Deleting the Job by hand and letting it be recreated works as a one-off, but the
next upgrade will skip it again.

### Values keys that no chart key consumes

**Status**: informational; a WARN, because a key can be consumed by a mechanism
not visible from the release.

Helm silently ignores a values key nothing reads. A `credentials.enabled: false`
left over from an older chart version looks exactly like a setting that is in
effect, and reads like one in a review.

The check compares **top-level keys only**, against the chart's own defaults plus
the dependency aliases and `condition` paths. That limit was measured, not
assumed: a recursive comparison on `provider-edc-2` produced **51 hits, essentially
all false** - `did.config`, `did.ingress`, `fdsc-dashboard.*`,
`identityhub.didIngress.hosts`, `fdsc-edc.deployment.dcp` and so on. The reason is
that the stored `chart.values` is the umbrella's own `values.yaml` and does **not**
include its subcharts' defaults, so every subchart key the umbrella does not
itself override looks orphaned. (`fdsc-edc.enabled` is in that list too: a
`condition:` key need not appear in `chart.values` at all.)

At the top level the same deployment yields four:

```
credentials, mysql, postgresql, x-certs
```

`x-` prefixed keys are the conventional home for YAML anchors - they exist to be
referenced, not consumed - so they are allowlisted. The other three are real
leftovers. Going deeper would need the subchart defaults, which the release does
not carry.

### A credential expires in a week and the UI says a year

**Status**: RESOLVED where both attributes were set; OPEN wherever they are not, which is the
default state of an older realm.

Two attributes govern the lifetime of an issued credential and **only one of them reaches
it**:

| attribute | what it does |
|---|---|
| `expiry_in_seconds` | what the admin UI displays |
| `refresh_interval_in_seconds` | what lands in the credential's `exp`; unset, Keycloak defaults it to `604800` |

Measured on a real credential: `nbf` and `exp` exactly **604800 s** apart — seven days — while
the admin UI reported a year. Raising `expiry_in_seconds` alone changed nothing; raising
`refresh_interval_in_seconds` moved `exp`. Neither attribute had been set by the deployment:
both numbers were Keycloak's own defaults.

This is also the real cause of a copy of the credential going stale every week in the
identityhub. That read for a long time as a design decision about refresh intervals, and it
was this default: the credential the copy was made from had already expired.

```bash
# what is actually in the credential, as opposed to what the UI claims
echo "$VC" | cut -d. -f2 | base64 -d 2>/dev/null \
  | jq '{nbf, exp, lifetime_s: (.exp - .nbf)}'
```

**The fix is to move both together.** Which of the two Keycloak honours is not worth
depending on, and setting them to the same number means the UI and the wallet finally say the
same thing. It only takes effect on a **realm import**, though — on a realm that already
exists the attributes have to go through the Admin API, which for ClientScope attributes does
accept updates (component configuration does not).

`keycloak-credential-lifetime` reads the realm in the values, so it answers before anything
has been issued.

### The verifier asks for a format Keycloak does not issue

**Status**: OPEN on two deployments at the time of writing.

Keycloak issues a credential in one format and the verifier states, per registered service and
per scope, which formats it will accept. When the two do not intersect, a wallet holding a
perfectly valid credential has nothing that satisfies the request and reports the same generic
"could not process the information request" that a dozen unrelated faults produce.

Four spellings are in use in one dataspace and **they are not interchangeable**: `dc+sd-jwt`,
`vc+sd-jwt`, `jwt_vc_json` and `jwt_vc`. A realm issuing `dc+sd-jwt` against a scope that
accepts only `vc+sd-jwt` is the shape seen live.

Three things make this awkward to read by hand, and all three are why the check exists:

* **The block name is not the credential type.** `membership-credential` declares
  `verifiable_credential_type: MembershipCredential`. Older charts omit that attribute
  entirely, and then the type cannot be determined at all — the check names those blocks and
  skips them rather than guessing.
* **The accepted formats are spread over three places**: `presentationDefinition.format`, the
  same key on each `input_descriptors` entry, and a `format` on each `dcql.credentials` entry.
  The dcql entries are the precise ones — each carries a format *and* the type it applies to,
  in `meta.vct_values` (older versions: `meta.type_values`).
* **A scope that states no format at all is not a disagreement.** Nine registered services on
  one deployment — leftovers from past transfers — declare a credential type with neither a
  presentation definition format nor a dcql entry. Treating an empty set as a mismatch
  reported nine faults on a healthy deployment.

```bash
kubectl -n provider port-forward svc/verifier 8090:8090 &
curl -s localhost:8090/service | jq -r '
  .[] | .id as $id | .oidcScopes // {} | to_entries[] |
  "\($id) \(.key): types=\([.value.credentials[]?.type] | join(","))
     pd=\([.value.presentationDefinition.format? // {} | keys[]] | join(","))
     dcql=\([.value.dcql.credentials[]? | .format] | join(","))"'
```

**Only the intersection with ourselves is judged.** A type the verifier asks for and this
Keycloak does not issue is not a fault: in a working dataspace a counterparty issues it.

### Keycloak signs with a key the DID document does not publish

**Status**: the check exists; every deployment measured so far is correct, by construction.

Keycloak signs every credential this deployment issues with a key out of a PKCS#12 keystore
and stamps it with a `kid`. A counterparty resolves that `kid` in our DID document to get the
public half. Two ways it breaks, and **neither shows up on our side** — the issuer logs a
clean issuance either way:

* the `kid` names a verification method the document does not publish, so there is nothing
  to resolve;
* the keystore was built from a different key than the one published, so the signature does
  not verify against what is there.

**Two kid shapes are both correct.** Some deployments publish `#key-1` and name
`<did>#key-1`; others publish the bare DID as the method id and name the bare DID. A rule
like "the kid must carry a fragment" calls the second one broken, which is the same mistake
[`holder-kid-fragment`](#reading-edcs-dcp-token-failures) records on the EDC side. The rule
is: **the kid is one of the published method ids**, in either the absolute or the relative
form.

**The keystore is built in an init container**, not shipped:

```
initContainer (alpine/openssl):
  openssl pkcs12 -export -in /certs-did/tls.crt -inkey /certs-did/tls.key \
    -out /did-material/cert.pfx -name "didPrivateKey" -passout env:STORE_PASS
```

so the key it uses is whatever secret backs the volume that init container reads. That is how
the check finds it — never by guessing a name, because the identity secret is named after the
did:web host and this one is free to be called anything. Where the two are the same secret,
[`identity-key-consistency`](#the-did-is-written-down-in-several-places-and-they-drift) has
already proved the key is published and this check says so rather than fetching it twice.

```bash
# which secret really feeds it
kubectl -n provider get statefulset <release>-keycloak -o json \
  | jq -r '.spec.template.spec as $s
      | $s.initContainers[] | select((.command//[]) + (.args//[]) | join(" ") | test("pkcs12"))
      | .volumeMounts[].name as $v
      | $s.volumes[] | select(.name==$v and .secret) | "\($v) -> \(.secret.secretName)"'

# and what the document actually publishes
curl -s https://<did host>/did.json | jq -r '.verificationMethod[] | "\(.id)  \(.publicKeyJwk.kty)/\(.publicKeyJwk.crv)"'
```

The algorithm is checked along the same line: `ES256` can only be satisfied by an EC P-256
key, so a kid that resolves to an RSA method is the same fault reached another way.

**What is not checked** is that Keycloak really signs with it — that needs a credential, and
getting one issued needs a wallet, which is the boundary the README draws.

### The central marketplace cannot reach contract-management

**Status**: the checks exist; the deployment measured is correct, so the faults below were
produced by injection rather than found.

A provider need not run a marketplace. It can publish through a **central** one, and then the
central marketplace drives this provider's catalogue by calling its contract-management —
through this provider's own APISIX. Four things have to hold, and none of them is visible
from inside: the marketplace simply never manages to publish anything, and nothing in this
namespace logs a reason.

| what must hold | how it fails |
|---|---|
| a route forwards to contract-management | no way in at all |
| its host is published on an Ingress | routed in the gateway, unreachable from outside |
| `bearer_only: true` | refuses by **redirecting to the IdP** — right for a browser, useless for a machine-to-machine caller |
| its `client_id` is registered in the verifier | APISIX validates against a discovery document that does not exist |

**Where a route goes is only in the values.** Every published host points at the APISIX
Service on its Ingress and they answer an identical `401`, so neither the Ingress nor a probe
from outside tells one from another. There are no APISIX CRDs here either. The upstream lives
in `decentralizedIam.odrlAuthorization.apisix.routes`, which is also where the fix goes:

```yaml
- host: provider-cm.<domain>
  uri: /*
  upstream: {nodes: {"contract-management:8080": 1}}
  plugins:
    openid-connect: {client_id: contract-management, bearer_only: true, use_jwks: true}
    opa: {policy: policy/main, with_body: true}
```

Note `upstream.nodes` is a mapping of `host:port` to weight, not a list — the service name is
what precedes the colon in each key.

### contract-management is wired to something that is not deployed

**Status**: OPEN on the central-MP provider measured — `enableTmForum` is on and no
tm-forum-api exists in that namespace.

contract-management reaches a handful of APIs, each switched on by its own `enable*` flag and
addressed by a URL under `contract-management.services`. Where the flag is on and the URL
names an in-cluster service that is not there, every call down that path goes to a host that
does not resolve, and the deployment looks complete:

```
contract-management.enableTmForum: true
contract-management.services.product-catalog.url: http://tm-forum-api:8080
$ kubectl -n <ns> get svc tm-forum-api
Error from server (NotFound)
```

**The flag matters as much as the URL.** `services.rainbow` is configured on every deployment
inspected while `enableRainbow` is false on all of them, so holding a URL against the
deployment without checking its flag reports a fault on every one. Only in-cluster names are
judged: an external URL is somebody else's deployment and resolving it is not this check's
business.

The same check carries one more assertion, because the two belong together: with no local
marketplace and `enableCentralMarketplace` off, **nothing** turns a published offering into
something negotiable — neither a local marketplace nor a central one.

---

## Certificates and identity keys

### APISIX caches the verifier's JWKS, and the `kid` never changes

**Status**: RESOLVED — `rollout restart deploy/provider-apisix` after any key rotation. This is
step 7 of *Rotating the identity certificate* in the deployment's own guide and
it is not optional.

The `/api/dsp` routes are guarded by `openid-connect` with `use_jwks: true` against
`https://verifier.example.es/services/data-service/.well-known/openid-configuration`. A
counterparty calling back to us presents a token issued by **our own** verifier, and APISIX
verifies it against the cached JWKS.

`clientIdentification.kid` is the fixed literal `random-kid1`, so after a rotation the verifier
publishes the **new** key under the **same** kid. A kid *miss* would make APISIX refetch; a kid
*hit* with the wrong key just fails, forever. Symptom — our own consumer negotiation sits in
`REQUESTED` while the counterparty gives up:

```
# apisix
POST /api/dsp/2025-1/negotiations/<id>/agreement    401
POST /api/dsp/2025-1/negotiations/<id>/termination  401
[lua] openid-connect.lua:772: OIDC introspection failed: jwt signature verification failed
```

Everything else looks healthy, which is what makes it misleading: a catalog request succeeds (that
direction does not traverse this route), our verifier issues the counterparty a token with
`POST /services/dsp/token 200`, and the negotiation even has a `correlationId`. Check the APISIX
access log for `/api/dsp` before blaming the peer:

```bash
kubectl -n provider logs deploy/provider-apisix --since=10m \
  | grep -E '^[0-9.]+ - - \[' | grep /api/dsp | grep -v curl/
```

Then verify that all four copies of the key agree — a mismatch is silent until a peer rejects a
signature. Compare the private key in the secret, the published DID document, the participant's
`publicKeyJwk` in the identityhub, and the actual signature on the MembershipCredential:

```bash
curl -s https://connector.example.es/.well-known/did.json | python3 -c 'import sys,json; print(json.load(sys.stdin)["verificationMethod"][0]["publicKeyJwk"]["n"][:40])'
kubectl -n provider get secret connector-example-es-tls -o jsonpath='{.data.tls\.key}' | base64 -d | openssl rsa -noout -modulus
```

Finally confirm the eight wildcard hosts still serve `CN=*.example.es` and only `atd` /
`atdverifier` serve the identity certificate (macOS has no `timeout(1)`, so do not wrap this in
one):

```bash
for h in atd atdverifier atdcb atddsp atdedc atdih atdidm atdmkt atdtir edc-dashboard; do
  echo -n "$h "
  echo | openssl s_client -connect $h.example.es:443 -servername $h.example.es 2>/dev/null \
    | openssl x509 -noout -subject
done
```

### The DID endpoints API: `PATCH` appends, it does not replace

**Status**: RESOLVED — use delete-then-add. Observed on `tractusx/identityhub:sha-687d69f`.

Changing the published endpoint does **not** need the participant recreated — but the verb
semantics of `/v1alpha/participants/{participantContextId}/dids/{did}/endpoints` are surprising,
and getting them wrong publishes an invalid DID document with two entries sharing one id:

| Verb | Observed behaviour |
|---|---|
| `POST` | adds the service. Use this. |
| `PATCH` | requires the id to already exist (`400` otherwise) but then **appends a duplicate** instead of replacing it |
| `DELETE ?serviceId=X` | removes **every** entry with that id |

Both path params are **base64url of the DID**, including `{did}` — passing the raw DID fails with
`java.lang.IllegalArgumentException: Illegal base64 character 3a` (`3a` is `:`), surfacing as a
bare `400` with an empty body.

So the safe sequence is delete-then-add, verifying in between, because between the two calls the
DID document advertises no CredentialService at all:

```bash
D=$(printf 'did:web:connector.example.es' | base64 | tr '+/' '-_' | tr -d '=')
TOKEN="$(printf 'super-user' | base64).$(kubectl -n provider get secret identityhub-secret -o jsonpath='{.data.superuser}' | base64 -d)"
kubectl -n provider port-forward svc/identityhub-service 18082:8082 &
B=http://127.0.0.1:18082/api/identity/v1alpha

curl -X DELETE "$B/participants/$D/dids/$D/endpoints?serviceId=credential-service&autoPublish=true" \
  -H "x-api-key: $TOKEN"
curl -X POST "$B/participants/$D/dids/$D/endpoints?autoPublish=true" \
  -H "x-api-key: $TOKEN" -H 'Content-Type: application/json' -d '{
    "id": "credential-service", "type": "CredentialService",
    "serviceEndpoint": "https://edc.example.es/api/credentials/v1/participants/'"$D"'" }'
```

`autoPublish=true` republishes the did:web document, so there is no separate publish step. Check
that exactly **one** entry survives:
`curl -s https://connector.example.es/.well-known/did.json | jq .service`.

### A stale credential in the identityhub outlives a key rotation

**Status**: RESOLVED here (step 5 of the rotation runbook). Hit **again on `provider-edc`** afterwards,
which is what broke the DCP lane in the `provider-edc` → `provider-edc-2` direction.

There are **two independent copies** of the MembershipCredential, and a rotation only refreshes
one of them:

| copy | who reads it | refreshed by |
|---|---|---|
| the file `/credential-repo/membership-credential.jwt` | the **OID4VC** lane (`FileSystemCredentialsRepository`) | the `vc-operator` Secret, or an init container |
| the row in the identityhub's `credential_resource` table | the **credential service**, i.e. the **DCP** lane | nothing — it must be updated by hand |

So after rotating the signing key, OID4VC keeps working and DCP breaks, which makes it look like a
DCP-specific problem. The stored credential is still signed with the pre-rotation key, and the
receiving connector rejects it.

The row also **survives deleting and recreating the participant** — that was the surprise here; the
credential store does not cascade. Verify a stored credential against the currently published key:

```bash
# stored copy (needs the identityhub DB credentials)
psql ... -t -A -c "select raw_vc from credential_resource;" > /tmp/stored.jwt
curl -s https://connector.example.es/.well-known/did.json > /tmp/did.json
python3 - <<'EOF'
import base64, hashlib, json
def b64d(v): return base64.urlsafe_b64decode(v + "=" * (-len(v) % 4))
h, p, s = open("/tmp/stored.jwt").read().strip().split(".")
jwk = json.load(open("/tmp/did.json"))["verificationMethod"][0]["publicKeyJwk"]
# RSA: recover the PKCS#1 v1.5 block and compare the embedded digest
n = int.from_bytes(b64d(jwk["n"]), "big"); e = int.from_bytes(b64d(jwk["e"]), "big")
rec = pow(int.from_bytes(b64d(s), "big"), e, n).to_bytes((n.bit_length() + 7) // 8, "big")
print("valid:", hashlib.sha256(f"{h}.{p}".encode()).digest() == rec[-32:])
EOF
```

For EC (`ES256`) credentials — which is what `provider-edc` issues — use `cryptography`:
`ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key().verify(der_sig, signed, ec.ECDSA(hashes.SHA256()))`,
converting the JWS `r||s` signature with `utils.encode_dss_signature`.

To fix, `PUT` the freshly issued JWT into the store. The container's JSON key is
**`verifiableCredentialContainer`**, *not* `credential` — the validator's error path says
`credential`, which is misleading:

```
PUT /api/identity/v1alpha/participants/{didB64}/credentials
{ "id": "membership-credential", "participantContextId": "<did>",
  "verifiableCredentialContainer": { "credential": {...}, "rawVc": "<new JWT>", "format": "VC1_0_JWT" } }
```

A detail that makes this persistent: the stored credential has **no `exp`**, so nothing expires it
or forces a renewal. It stays broken until someone updates it.

### The DID is written down in several places, and they drift

**Status**: informational — the check exists because the symptom names neither the file nor
the key.

A DSC states its own DID in up to six independent places, and nothing re-reads them all
after a domain change or a copy of a values file from a neighbour:

| Where | Shape |
|---|---|
| `decentralizedIam.vcAuthentication.vcverifier.deployment.verifier.did` | a resolved DID |
| `contract-management.did` | a resolved DID |
| `did.config.server.hostUrl` | a **URL** the DID derives from |
| `edc.participant.id` in each lane's ConfigMap | a resolved DID |
| `keycloak.issuerDid` | usually the literal `${DID}` |
| `registration.issuer[].did` | usually the literal `${DID}` |

The URL form is the one that catches people: `https://did.example.org` is
`did:web:did.example.org`, while `https://did.example.org/did` is
`did:web:did.example.org:did`. Both are in use in this dataspace, so a hostUrl that gained
or lost a path segment renames the participant without touching anything that looks like
an identifier.

The last two are **not** faults when they hold `${DID}`: an init container substitutes
them at runtime, and a check that compares them literally reports a mismatch that is not
there. `fdsc-verify` reports them as placeholders and leaves them alone.

The symptom of a real drift is on the other side of the wire. The component that signs
with the odd one out looks healthy — it starts, it serves, it issues tokens — and the
counterparty rejects those tokens as coming from a participant it has never heard of:

```
Unauthorized: Token audience claim (aud -> [did:web:the-other-one])
  did not contain expected audience: did:web:the-one-you-meant
```

```bash
python3 -m fdsc_verify -n <ns> --only identity-did-consistency
```

Settle on one value and update the rest. There is no component that owns the DID, which is
why this drifts in the first place.

### The wildcard certificate cannot be an `x509_san_dns` client id

**Status**: RESOLVED — replaced by the identity certificate, which carries an explicit
`DNS:verifier.example.es` SAN. See *Certificates* in the deployment's own guide.

```
ClientResolutionException: The client is not contain in the SAN of the x5c
  at X509SanDnsClientResolver.getPublicKey(X509SanDnsClientResolver.java:73)
```

Note the line number: `:73`, not `:113`. `:113` is chain validation (a trust-anchor problem, see
[OID4VP trust anchors](#oid4vp-trust-anchors-use-the-images-public-root-store)); `:73` is the *next*
check — the client id must appear literally in a SAN of the signing certificate, and the resolver
does no wildcard matching.

| | declared `client_id` | cert SAN |
|---|---|---|
| `provider-edc` | `x509_san_dns:verifier.example.org` | `DNS:verifier.example.org` → match |
| here, before | `x509_san_dns:verifier.example.es` | `DNS:*.example.es` → no literal match |
| here, before (workaround) | `x509_san_dns:*.example.es` | `DNS:*.example.es` → match, but not spec-compliant |
| here, now | `x509_san_dns:verifier.example.es` | `DNS:atd…`, `DNS:verifier.example.es` → match |

Using a `did:` client id is *not* an option even though VCVerifier supports it (`config.go:193`):
`OID4VPExtension` registers `List.of(clientResolver)` with only the X509 resolver, so a peer could
not resolve it.

That last paragraph is about **who resolves the client id**, and the answer differs by consumer —
which is the whole subject of the next section.

### The client id scheme and the request object have to agree

`clientIdentification.id` is an opaque string to VCVerifier. There is no `client_id_scheme`
handling anywhere in the code: it always signs the request object
(`verifier/verifier.go:1470-1479` has no unsigned branch) and it never emits `client_metadata`
(the term does not appear in the repo). The prefix therefore carries obligations that nothing on
our side enforces, and a mismatch is invisible locally — the verifier logs a healthy 200 while the
wallet shows something generic.

**Two different consumers, two different rules.** Getting these confused is what makes this
section necessary:

| Who resolves our client id | How | Consequence |
|---|---|---|
| A **wallet**, in the OID4VP login | Per the OID4VP prefix: `x509_san_dns` → x5c, DID → DID document, `redirect_uri` → unsigned + `client_metadata` | Any prefix can work, if we honour its rules |
| An **EDC peer**, over DCP | `OID4VPExtension` registers only `X509SanDnsClientResolver` | Only `x509_san_dns` resolves at all |

So "a DID client id is not an option" is true *toward an EDC peer* and false *toward a wallet*.

**What each prefix demands:**

- **`redirect_uri:<uri>`** — OID4VP: *"Requires `client_metadata`. MUST NOT be signed."* We do the
  opposite of both. A wallet that enforces the prefix rejects the request; a lenient one ignores
  the signature, which leaves the request object unauthenticated. Choosing this is a deliberate
  trade, not a fix — record which wallets were actually tested.
- **`x509_san_dns:<host>`** — needs an `x5c` header, which the verifier only adds when
  `certificatePath` is set. Unset, it logs `No certificate chain for client identity` at debug and
  signs with the `kid` alone, leaving the peer nothing to compare the id against. The host must
  also appear *literally* in a SAN — see the section above.
- **a DID (`did:web:…`)** — the wallet resolves the DID document and takes the key from the
  `verificationMethod` named by `kid`. The bare DID is not a verification method: the document
  publishes keys as `<did>#<fragment>`. When `kid` is unset the verifier falls back to `id`, i.e.
  the bare DID, and the wallet has nothing to check the signature against.

**Which check points here**: `client-id-scheme`, which reads the configured prefix and warns on
each of those three combinations rather than assuming one of them.

Note that `cert-san-vs-client-id` reads the same value to decide whether it applies at all. It
used to synthesise the client id from `fdscTransfer.oid4vc.verifierHost` and assume the
`x509_san_dns` prefix, so a deployment identifying by DID or `redirect_uri` got a confident FAIL
about a certificate nobody uses.

---

## OID4VC lane

### OID4VP trust anchors: use the image's public root store

**Status**: RESOLVED — `oid4vp.trustAnchorsFolder=/etc/ssl/certs` on both `fdsc-edc` instances.

The `X509SanDnsClientResolver` PKIX-validates the `x5c` of a counterparty verifier's
authorization-request JWT against every certificate in `oid4vp.trustAnchorsFolder`. That is set to
**`/etc/ssl/certs`**, the Alpine base image's own `ca-certificates` store (149 roots).

The setting must stay non-empty: `OID4VPExtension` only builds
`X509SanDnsClientResolver(trustAnchors, false)` when anchors are configured. Leave it unset and it
falls back to the JVM default truststore *with revocation checking*, which fails with
`Could not determine revocation status`.

A hand-curated bundle was used here first, and it is the wrong shape for a dataspace: it is CA
pinning, it scales with the number of participants, and it broke this deployment twice — once per
direction — when a peer used a CA that was not on the list (Let's Encrypt inbound, HARICA
outbound), each time surfacing as:

```
ClientResolutionException: Was not able to validate the x5c
CertPathValidatorException: Path does not chain with any of the trust anchors
```

This is not a weaker trust decision. The `x5c` only binds a verifier to a DNS name — the web PKI
model. Authorization stays in the credential layer: `trustedParticipantsLists` against the TIR and
`trustedIssuersLists` against the TIL.

Two caveats:

* `loadCertificatesFromFolder` does a flat `Files.list` and **throws** on any file it cannot parse
  as X.509, so a single stray non-cert file in the folder breaks startup. `/etc/ssl/certs` holds
  exactly 299 parseable entries (149 hash symlinks + 149 `ca-cert-*.pem` + `ca-certificates.crt`);
  the certs load in triplicate, which is harmless. Re-check if the base image changes:

  ```bash
  kubectl -n provider exec deploy/provider-fdsc-edc-oid4vc -c dsp-controlplane -- \
    sh -c 'ls /etc/ssl/certs | grep -vE "^[0-9a-f]{8}[.][0-9]$" | grep -vE "^ca-cert-.*[.]pem$"'
  # expect only: ca-certificates.crt
  ```

* A participant using a **private** CA that is not publicly trusted still needs it added.
  `/etc/ssl/certs` is read-only, so that means an initContainer copying `ca-certificates.crt` into
  an emptyDir, appending the extra roots, and pointing `trustAnchorsFolder` there.

### `/credential-repo` must project a single key

**Status**: RESOLVED — the volume projects only the `credential` key.

The `vc-operator` writes three keys into `vc-fdsc-edc-credential` (`credential`, `format`,
`expiryTimestamp`). Mounting the Secret whole creates one file per key, and
`FileSystemCredentialsRepository` scans the entire folder and infers the credential format from
each file's extension — it aborts on the extensionless `format` file with:

```
Unsupported file extension: /credential-repo/format
```

So the volume projects only `credential`, named `membership-credential.jwt`, leaving exactly one
file (the same end state as the peer, which fills an `emptyDir` from an init container instead).

### Peer-side: a wildcard `trustedIssuersLists` needs vcverifier ≥ 6.14.0

**Status**: RESOLVED on the peer by configuring the explicit TIL.

With both mounts fixed, the OID4VP exchange gets all the way to the peer's verifier, which then
returns **400**. Its log shows the DID resolving and the participant check passing against
`https://tir.example.org`, then:

```
Failed to verify credential ... Err: no_til_defined_for_credential_type
Request "POST /services/dsp/token HTTP/1.1" 400
```

Cause: `provider-edc`'s `dsp` service was configured with `trustedIssuersLists: ["*"]`, but the wildcard
was only introduced in vcverifier **6.14.0** (`WILDCARD_TIL` in `verifier/trustedissuer.go`) and
`provider-edc` ran **6.12.9**, so it read as "no TIL configured". `provider-edc-2` runs 6.14.0,
which is why the two
environments disagreed.

Fix on the peer (no image bump needed — its internal TIL already registers
`did:web:connector.example.es` with `MembershipCredential`):

```bash
kubectl --context <cluster-b> -n producer port-forward svc/verifier 8090:8090 &
curl -X PUT http://localhost:8090/service/dsp \
  -H 'Content-Type: application/json' \
  -d '{"authorizationType":"DEEPLINK","defaultOidcScope":"openid","id":"dsp","oidcScopes":{"openid":{"credentials":[{"jwtInclusion":{"enabled":true,"fullInclusion":true},"trustedIssuersLists":["http://trusted-issuers-list:8080"],"trustedParticipantsLists":["https://tir.example.org"],"type":"MembershipCredential"}],"dcql":{"credentials":[{"format":"jwt_vc_json","id":"mc-query","meta":{"type_values":[["MembershipCredential"]]},"multiple":true}]}}}}'
```

This repo's own `dsp` service uses the explicit TIL for the same reason, so the two sides stay
symmetric.

### Peer-side: the HARICA anchor is missing for callbacks to us

**Status**: RESOLVED on the peer.

A catalog request only needs one direction. **Negotiation needs both**: the provider calls back to
the consumer, so the peer has to authenticate against *our* verifier. Symptom — the consumer UI
shows `INITIAL → REQUESTED` and stops, while the peer's connector loops in `AGREEING`:

```
ContractNegotiation: ID <id>. Attempt #0 failed to [Provider] send agreement.
  Cause: Unable to obtain credentials: Was not able to successfully get a token through OID4VP.
Caused by: ClientResolutionException: Was not able to validate the x5c.
```

This is the exact mirror of
[OID4VP trust anchors](#oid4vp-trust-anchors-use-the-images-public-root-store) with the roles
swapped: the peer's `/root-ca` held only Let's Encrypt (`E7`, `ISRG Root X1`, `ISRG Root X2`),
while `verifier.example.es` presents a HARICA chain:

```
*.example.es -> GEANT TLS RSA 1 -> HARICA TLS RSA Root CA 2021
                -> Hellenic Academic and Research Institutions RootCA 2015   <- the anchor needed
```

**Preferred fix — same as ours: point the peer at its own public root store.** One config change,
no bundle to maintain, and it covers every future participant with a publicly-trusted cert:

```
oid4vp.trustAnchorsFolder=/etc/ssl/certs
```

Check the folder is safe first — `loadCertificatesFromFolder` throws on any file it cannot parse as
X.509, and `provider-edc`'s two connectors run different images, so verify each:

```bash
for d in producer-fdsc-edc-oid4vc producer-fdsc-edc-dcp; do
  echo "== $d"
  kubectl --context <cluster-b> -n producer exec deploy/$d -c dsp-controlplane -- \
    sh -c 'ls /etc/ssl/certs | grep -vE "^[0-9a-f]{8}[.][0-9]$" | grep -vE "^ca-cert-.*[.]pem$"'
done
# expect only: ca-certificates.crt
```

**Fallback — curated bundle.** Use this if a connector's `/etc/ssl/certs` is not clean, or once a
participant with a private CA joins. Do not put it in the peer's `ca-cert` Secret: that one is also
mounted by `producer-keycloak`. Give the connectors their own:

```bash
# bundle = the peer's current anchors + HARICA RootCA 2015 (taken from our ca-cert)
kubectl --context <cluster-a> -n provider get secret ca-cert \
  -o jsonpath='{.data.ca\.crt}' | base64 -d > /tmp/harica.pem
kubectl --context <cluster-b> -n producer get secret ca-cert \
  -o jsonpath='{.data.ca\.crt}' | base64 -d > /tmp/peer-le.pem
cat /tmp/peer-le.pem /tmp/harica.pem | awk '/BEGIN CERT/{p=1} p' > /tmp/peer-bundle.pem

kubectl --context <cluster-b> -n producer create secret generic oid4vp-trust-anchors \
  --from-file=ca.crt=/tmp/peer-bundle.pem

# point both connectors' /root-ca at it (volume index may differ per deployment)
for d in producer-fdsc-edc-oid4vc producer-fdsc-edc-dcp; do
  IDX=$(kubectl --context <cluster-b> -n producer get deploy $d -o json \
    | python3 -c "import sys,json;v=json.load(sys.stdin)['spec']['template']['spec']['volumes'];print(next(i for i,x in enumerate(v) if x['name']=='root-ca'))")
  kubectl --context <cluster-b> -n producer patch deploy $d --type=json \
    -p "[{\"op\":\"replace\",\"path\":\"/spec/template/spec/volumes/$IDX/secret/secretName\",\"value\":\"oid4vp-trust-anchors\"}]"
done
```

Verify a curated bundle before applying — it must accept both verifiers:

```bash
# split each chain into leaf + intermediates, then:
openssl verify -purpose any -CAfile /tmp/peer-bundle.pem -untrusted <intermediates> <leaf>
# expected: OK for *.example.es AND still OK for verifier.example.org
```

Note the peer's chain terminates in a **cross-signed** ISRG Root X2 whose issuer is X1, which is
why both ISRG roots must stay in the bundle — dropping X1 would break the peer's own validation.

### Peer-side: VP signed with a key absent from its DID document

**Status**: RESOLVED on the peer — its DID document now publishes the key it signs with.

Our verifier rejected the peer's VP token with HTTP 400:

```
JWT signature verification failed for did:web:did-provider.example.org:did:
  jws.Verify: ... failed to verify signature using ecdsa
Was not able to extract the credentials from the vp_token
```

The peer's `oid4vc` connector signs with the TLS key of the `did-provider.example.org-tls` Secret,
while its DID document published a different one:

| | key |
|---|---|
| DID document `#key-1`, before | `x: FwmZXUAGsgO5dzwpfV8Q60plA_S6GrhOu-qAYUHj0tM` |
| key it signs with, and what it publishes now | `x: _6ZGwv4JdRiXaExn6SYqg1WCak3M4SWoVbDRTei-ko8` |

Any counterparty that resolves the DID and verifies the signature must fail. This deployment does
not have the problem because the identityhub bootstrap publishes the *same* key it signs with.

A caution learned when this was fixed: the peer has **one** verificationMethod but more than one
component signing as that DID, so aligning the document with one signer can break the other. If a
participant genuinely needs two signing keys, publish **two** verification methods with distinct
fragments and give each component the matching `kid`; EDC resolves by `kid`.

---

## DCP lane

### Reading EDC's DCP token failures

Not a failure in itself — the lookup table that makes the rest of this section quick. EDC's
`TokenValidationServiceImpl.validate` has three distinct exits, and they mean very different
things:

| What you see | What it means |
|---|---|
| the resolver's own error | the `kid` could not be resolved to a public key at all |
| `Token verification failed` | **exactly one thing**: `SignedJWT.verify()` returned false — the signature does not validate against the key resolved from the `kid`. Not a rule failure. |
| a specific message, e.g. `Token audience claim (aud -> [...]) did not contain expected audience: ...` | a validation **rule** failed; the rules return their own messages |

So a flat `Token verification failed` means *go look at keys and signatures*, and anything
descriptive means *go look at the claim it names*. The rules in play are `AudienceValidationRule`,
`IssuerKeyIdValidationRule` (`kid header '%s' expected to correlate to 'iss' claim`),
`IssuerEqualsSubjectRule`, `SubJwkIsNullRule`, `JtiValidationRule`, `HasSubjectRule` and
`TokenNotNullRule`.

### The DCP instance needs the DCP controlplane image

**Status**: RESOLVED here (the `dcp` instance pins its repository). Hit **again on `provider-edc`**
later, with the same root cause.

The chart's `common` default image is `quay.io/seamware/fdsc-edc-controlplane-oid4vc`, and
`deployment.<name>` instances inherit it. Overriding only `tag` for the `dcp` instance therefore
runs the **OID4VC build under the name `dcp`**, which is not a working DCP connector:
`OID4VPExtension` registers `OID4VPIdentityService` as the connector's `IdentityService` whenever
`oid4vp.enabled` is true, so outbound DSP requests carry a verifier-signed token instead of a DCP
self-issued one. The counterparty then cannot resolve its `kid`:

```
IllegalArgumentException: The given ID must conform to 'did:method:identifier[:fragment]' but did not
  at DidPublicKeyResolverImpl.resolveInternal
  at SelfIssueIdTokenValidationAction.apply
```

The giveaway on our side is the `dcp` instance logging `Try to obtain credential via OID4VP.`. So
the `dcp` instance pins `repository: quay.io/seamware/fdsc-edc-controlplane-dcp` explicitly. With
the right image it loads `IdentityAndTrustExtension` / `DcpDefaultServicesExtension` / `DCPExtension`
instead. Check which stack is live with:

```bash
kubectl -n provider logs deploy/provider-fdsc-edc-dcp | grep -E "IdentityAndTrust|OID4VP"
```

Seen from the **receiving** side, the same misconfiguration on a peer looks like this — and the
class name in the stack trace identifies the image, because `controlplane-dcp` does not depend on
`oid4vc-extension` at all:

```
java.lang.IllegalArgumentException: Was not able to extract the issuer.
  at org.seamware.edc.identity.OID4VPParticipantIdExtractionFunction.apply
  at ProtocolTokenValidatorImpl.verify
```

That message means a DCP token arrived at an **OID4VC** connector: it walked the configurable
`issuerClaim` path looking for the claim shape an OID4VC token has, and a DCP self-issued token
does not have it. Either the peer is running the wrong image, or the lanes are crossed — check
which endpoint was targeted before assuming the former.

### The DCP lane needs an STS client secret that dev-mode Vault loses

**Status**: RESOLVED — `register.sh` provisions it unconditionally, under two key names.

The DCP identity service fetches its STS client secret from Vault under the alias
`<DID>-sts-client-secret` (`edc.iam.sts.oauth.client.secret.alias`). If it is missing:

```
Unable to obtain credentials: Failed to fetch client secret from the vault with alias:
did:web:connector.example.es-sts-client-secret
```

Three facts combine into a trap:

1. Vault runs `vault server -dev` (see the `provider-vault` args), so its storage is **in-memory**
   and every restart wipes it.
2. The identityhub only reveals a participant's `clientSecret` **once, at creation**.
3. The `identityhub-participant-bootstrap` script used to treat HTTP 409 ("participant already
   exists") by **skipping STS client-secret provisioning entirely**.

The participant lives in Postgres (`provider_ih`, table `edc_sts_client`), so once Vault has been
recreated — which is what happened when the deployment moved from production mode back to dev mode
— the participant still exists, the bootstrap takes the 409 branch forever, and the secret is never
restored. The OID4VC lane is unaffected because it does not use the identityhub STS.

**How it is fixed.** Neither side ever stores the secret itself: `edc_sts_client` only keeps a
`secret_alias`, and *both* the EDC oauth client and the STS resolve that alias from Vault and
compare the values. The secret is therefore ours to choose. So `register.sh` now:

* takes a fixed value from `identityhub-secret.sts-client-secret` (exposed to the job as
  `STS_CLIENT_SECRET`) instead of the unrecoverable one the identityhub generates, and
* writes it to Vault **unconditionally on every run** — the same "repair it every run" pattern the
  script already used for the super-user credential — so it survives both dev-mode Vault wipes and
  the 409 path.

**Why two Vault keys.** EDC's Hashicorp vault client URL-encodes the alias and the HTTP layer then
encodes the `%`, so a lookup for `did:web:x-sts-client-secret` actually resolves a key *literally
named* `did%3Aweb%3Ax-sts-client-secret`. `curl` (this script) writes the plain-colon name. The
working peer environment has **both** names present, which is why DCP works there, so the script
writes both:

```
did:web:connector.example.es-sts-client-secret
did%3Aweb%3Aconnector.example.es-sts-client-secret
```

To write the second one with curl the `%` must itself be escaped, hence the `%253A` in the script.

Diagnosing this class of failure: point the alias at a colon-free key that exists and see whether
the error changes. If it becomes `401 invalid_client` from the STS instead of "Failed to fetch
client secret", Vault access is fine and only the alias name is at fault:

```bash
kubectl -n provider set env deploy/provider-fdsc-edc-dcp EDC_IAM_STS_OAUTH_CLIENT_SECRET_ALIAS=key-1
# ...test, then revert:
kubectl -n provider set env deploy/provider-fdsc-edc-dcp EDC_IAM_STS_OAUTH_CLIENT_SECRET_ALIAS-
```

Verify the provisioning after a change (it is a `post-install,post-upgrade` hook, so `helm upgrade`
re-runs it; to run it standalone, re-create the Job from the rendered chart):

```bash
kubectl -n provider logs job/identityhub-participant-registration-job | grep -i "sts client-secret"
# expect two "-> HTTP 200" lines, one per alias form
```

### Wrong `aud`: the counterparty's dashboard carries the wrong DID

**Status**: RESOLVED — fixed in `provider-edc`'s dashboard ConfigMap.

```
Unauthorized: Token audience claim (aud -> [did:web:did-provider.example.org:did])
  did not contain expected audience: did:web:connector.example.es
DSP: Service call failed: Request not authorized.
```

The peer minted its self-issued token with `aud` set to **its own** DID. That happens when the
initiating side thinks the counterparty is itself, and the usual source is the dashboard: the
Catalog view uses **exactly two fields** of the selected entry — `did` → `counterPartyId` and
`protocolUrl` → `counterPartyAddress`. `provider-edc`'s entries for us had the right URL and
`provider-edc`'s **own** DID — a copy-paste of its own entry with only the URL changed.

Two things to get right when adding a counterparty entry:

* the `did` must be the **other** participant's `edc.participant.id`, and
* the two sides here use **different `did:web` shapes**: ours has no path suffix
  (`did:web:connector.example.es`, served from `/.well-known/did.json`) and theirs does
  (`did:web:did-provider.example.org:did`, served from `/did/did.json`). Copying the
  counterparty's pattern blindly fails the same way.

This only bites when the peer **initiates**. Responding to a negotiation we started works, because
then it takes our identifier from the incoming message — which is why a working negotiation does
not prove the entry is right.

Also note the ConfigMap is mounted with `subPath`, which kubelet does not auto-update: a
`rollout restart` of the dashboard is required.

`fdsc-verify --only dashboard-config` checks this from here: it reads the list the dashboard
actually serves and fails on an entry that pairs a counterparty's `protocolUrl` with our own DID,
on one of our own endpoints carrying somebody else's, and — with `--peer` — on an entry whose DID
is not the one that peer identifies as. What it cannot see is the *other* participant's dashboard,
which is where this particular instance of the fault lived; run it on both sides.

### Working around the broken `atdih` record

**Status**: WORKAROUND — undo it when the DNS record is fixed. See
*DNS records* in the deployment's own guide.

The DCP lane needs a counterparty to reach **our** credential service: it resolves our DID, reads
the `CredentialService` entry and posts a presentation query there. That entry pointed at
`identityhub.example.es`, whose A record resolves to `203.0.113.10` instead of the traefik LB, so it
was unreachable from outside and no DCP test was possible.

Nothing about that host is special, so rather than waiting on a DNS change the credential service
is advertised on **`edc.example.es`**: it resolves correctly, is already this participant's
public DCP host (`fdsc-edc.deployment.dcp.config.edc.hostname`), and its catch-all `/*` route is
the only one *without* the `openid-connect` plugin, so a more specific `/api/credentials/*` route
slots in without fighting the guard. The identityhub does its own DCP token authentication, which
is why no guard is wanted there. Both hosts are routed in APISIX, so fixing the DNS record later
needs no rollback — only the published endpoint changes (see
[The DID endpoints API](#the-did-endpoints-api-patch-appends-it-does-not-replace)).

Confirm it end to end — the endpoint must answer with the identityhub's own auth error, over public
DNS and with no `--resolve`:

```bash
EP=$(curl -s https://connector.example.es/.well-known/did.json \
     | python3 -c 'import sys,json; print(json.load(sys.stdin)["service"][0]["serviceEndpoint"])')
curl -s -X POST "$EP/presentations/query" -H 'Content-Type: application/json' -d '{}'
# expected: [{"message":"Authorization header missing","type":"AuthenticationFailed",...}]
# a 404 means DNS resolved to the foreign host; a 401 from apisix means the guard caught it
```

---

## Data transfer and the EDR

### The EDR token lives 5 minutes and cannot be refreshed

**Status**: OPEN — needs a change in `fdsc-edc` (`fdsc-transfer-extension`).

```
HTTP/2 401
www-authenticate: Bearer realm="apisix", error="invalid_token", error_description="JWT expired"
```

`FDSCDcpEndpointDataReferenceService.java:63` has

```java
// TODO: make configurable
private static final int EXPIRATION_MS = 300_000;
```

and mints the token **once**, in `createEndpointDataReference(DataFlow)`, when the data flow
starts. So the clock starts at transfer time, not when you fetch the EDR, and you have five
minutes total.

There is no way to renew it:

* the EDR carries only `endpoint`, `endpointType`, `token`, `tokenType` — no `refreshToken`, no
  `refreshEndpoint`, no `expiresIn`;
* `revokeEndpointDataReference` states outright that "the token is not stored internally";
* this EDC's `EdrCacheApiV3Controller.getEdrEntryDataAddressV3(String)` takes only the id — there
  is **no `auto_refresh` parameter**, so calling `/dataaddress` again returns the same stored,
  already-expired token.

Until it is configurable, script the whole chain so no human delay creeps in, and check the
remaining lifetime before spending it:

```bash
DA=$(curl -s "http://localhost:8085/api/v1/management/v3/edrs/$T/dataaddress")
EP=$(echo "$DA" | jq -r .endpoint); TK=$(echo "$DA" | jq -r .token)
echo "$TK" | cut -d. -f2 | base64 -d 2>/dev/null | jq '{iat, exp, left_s: (.exp - now | floor)}'
curl -s "$EP/ngsi-ld/v1/entities/urn:ngsi-ld:UptimeReport:fms-1" \
  -H "Authorization: Bearer $TK" -H 'Content-Type: application/json' | jq .
```

Two ways out, both in `fdsc-edc` and both on the side that *provides* the data: honour the TODO and
move `EXPIRATION_MS` into `TransferConfig` (small, enough for demos), or carry a `refreshToken` and
`refreshEndpoint` like EDC's standard data plane (correct for production, considerably more work,
and it touches both sides).

### The dashboard never sends the EDR token

**Status**: OPEN — needs a change in the dashboard image (`mortega5/edc-dashboard`).

```
HTTP/2 401
www-authenticate: Bearer realm="apisix"
```

Note what is **not** there: no `error="invalid_token"`, no `error_description`. That is how you
tell this apart from the expired-token 401 above — same status code, different cause. This one
happens even with a token four seconds old.

`/app/dist/controllers/proxy.controller.js` reads the wrong field names:

```js
const authorization = extractEdrField(edr, 'authorization');
const isBearer      = extractEdrField(edr, 'authType') === 'bearer';
...
const dataRes = await fetch(targetUrl.toString(), {
    headers: authorization ? { Authorization: tokenHeader } : {},   // ← {} when not found
});
```

`extractEdrField` tries `authorization`, `edc:authorization` and the full-namespace form. The EDR
has **`token`** and **`tokenType`**. None of the variants match, so the request goes out with no
`Authorization` header at all.

The mismatch originates in `fdsc-transfer-extension`, which builds the DataAddress with
`.property(EDC_NAMESPACE + "authorization", ...)` and `"authType"` while the Management API
serialises them as `token`/`tokenType`. The dashboard was written against the internal names.

Fix in the dashboard, accepting both so it keeps working with EDC's standard data plane too:

```js
const authorization = extractEdrField(edr, 'authorization') ?? extractEdrField(edr, 'token');
const authType      = extractEdrField(edr, 'authType')      ?? extractEdrField(edr, 'tokenType');
```

Renaming in `fdsc-transfer-extension` instead would break any consumer already reading `token`,
which is the name the Management API exposes.

A second, independent discrepancy on the same path: the dashboard fetches the **bare** endpoint and
only copies `req.query` onto it, so it cannot append `/ngsi-ld/v1/entities/...`. Fixing the header
may therefore not be enough to show data — check whether the base URL returns anything useful:

```bash
curl -s -o /dev/null -w "base, no path -> %{http_code}\n" "$EP" -H "Authorization: Bearer $TK"
```

---

## Dashboard

### Image defaults leak into the connector list

**Status**: RESOLVED — the two local entries reuse the keys `consumer` and `provider`.

`config.service.js` does `deepMerge(applicationDefaultYaml, applicationYaml)` and **skips null
overrides** (`if (override[key] == null) continue`), so a key cannot be deleted — only shadowed.
The image's `application.default.yaml` defines `connectors.consumer` (→ `http://localhost:8084/protocol`)
and `connectors.provider` (→ the peer's internal DNS). Renaming our keys left both alive, and they
showed up as bogus options in the dropdown.

After editing the dashboard ConfigMap — or after bumping the dashboard
image — check the config the dashboard actually serves. The ConfigMap is mounted with `subPath`,
which kubelet does **not** auto-update, so the restart is required for the change to be picked up:

```bash
kubectl -n provider apply -f edc-dashboard/cm.yaml
kubectl -n provider rollout restart deploy/edc-dashboard-data-dashboard
kubectl -n provider rollout status deploy/edc-dashboard-data-dashboard

kubectl -n provider port-forward svc/edc-dashboard-data-dashboard 19001:8080 &
curl -s http://127.0.0.1:19001/config/edc-connector-config.json | python3 -c '
import sys, json
for c in json.load(sys.stdin):
    mgmt = "yes" if c.get("managementUrl") else "NO"
    print("%-12s %-28s %-52s mgmt=%s" % (c["id"], c["connectorName"], c.get("protocolUrl"), mgmt))
'
```

(Uses `%` formatting on purpose: an f-string with escaped quotes is a syntax error on Python 3.9,
which is what ships on macOS.)

Expected: exactly four entries, the two counterparty ones with `mgmt=NO`, and **no** entry pointing at
`localhost:8084` or `producer-fdsc-edc-dcp.producer.svc.cluster.local` — either of those means a
default connector from the image leaked through.

---

## TMForum and the broker

### Scorpio 6 strips JSON-LD keywords

**Status**: RESOLVED — merged as
[PR #168](https://github.com/FIWARE/tmforum-api/pull/168) (`9e4baef`) and released in
**tm-forum-api 1.18.0**. Anything on **1.16.1 … 1.17.x** is exposed; anything below 1.16.1
has no read-merge-write path and cannot lose the escape.

Which versions are running is `tmforum-reserved-words` (preflight, reads the deployed
images, writes nothing); whether a resource actually survives a round trip is
`flow-tmforum-roundtrip`, which creates and deletes one throwaway quote and is therefore
in the `flow` phase with everything else that writes.

Neither declares a transport: the EDC stores its negotiations in a TMForum Quote and the
native FIWARE path serves the same APIs through the gateway, so this breaks both and
`--transport` must not hide it from either.

Catalog requests succeed but negotiation never advances. The initiating connector logs, in a loop
(roughly twice a second):

```
WARNING Was not able to read negotiation <id> from quotes.
java.lang.NullPointerException: Cannot invoke "jakarta.json.JsonArray.stream()" because the return
  value of "jakarta.json.JsonObject.getJsonArray(String)" is null
  at org.seamware.edc.store.TMFEdcMapper.toContractNegotiation
  at org.seamware.edc.store.TMFBackedContractNegotiationStore.getNegotiations
```

**Chain of events.** The EDC keeps contract-negotiation state in a TMForum Quote
(`TMFBackedContractNegotiationStore`), storing the ODRL offer as expanded JSON-LD. `tm-forum-api`
persists that Quote in the NGSI-LD broker. On read-back, `TMFEdcMapper.fromQuoteItem` → `fromOdrl`
parses the policy as JSON-LD — but the `@type`/`@id` keywords are gone and `odrl:permission` is not
an array, so `getJsonArray` returns `null` and the mapper throws. The negotiation can then never be
read, so the state machine spins forever and the negotiation stays stuck.

**Root cause.** Two layers, and only the second is fixable by us.

Scorpio `java-6.0.2` drops `@`-prefixed keys inside a Property's JSON value. Reproduced in
isolation, with no TMForum involved:

```bash
kubectl -n provider port-forward svc/data-service-scorpio 9090:9090 &
ID=urn:ngsi-ld:ClaudeDiagTest:probe
curl -X POST http://127.0.0.1:9090/ngsi-ld/v1/entities -H 'Content-Type: application/json' \
  -d "{\"id\":\"$ID\",\"type\":\"ClaudeDiagTest\",\"payload\":{\"type\":\"Property\",\"value\":{\"@id\":\"urn:x:1\",\"@type\":\"http://example.org/Offer\"}}}"
curl -s http://127.0.0.1:9090/ngsi-ld/v1/entities/$ID   # -> the '@' keys are gone
curl -X DELETE http://127.0.0.1:9090/ngsi-ld/v1/entities/$ID
```

But `tm-forum-api` is supposed to shield the broker from that by escaping reserved words with a
`tmfEscaped-` prefix, and it did so on create. The defect was on **update**: with
`replaceOnUpdate=true` (needed because Scorpio ≥ 6.0.0 appends instead of replacing on
`POST /entities/{id}/attrs`), `NgsiLdBaseRepository.updateDomainEntity` reads the entity back
through the mapping library's `EscapeCleaningParser` — which strips the prefix from every reserved
word except the VO field collisions `id`, `type` and `value` — and wrote it out again **without
re-escaping**. So raw keywords reached the broker on the first update and were dropped.

The fix re-applies the escape recursively (property values, sub-attributes and multi-attributes)
before the merged entity goes out. `escapeReservedWords` is idempotent, so keys that kept their
prefix during parsing are untouched.

**Recognising a recurrence.** Count escaped keywords per quote; a quote with **0** is unreadable
and produces the NPE loop, and the count is structural rather than a fixed number (a policy with a
`constraint` carries more):

```bash
kubectl -n provider port-forward svc/data-service-scorpio 19090:9090 &
curl -s "http://127.0.0.1:19090/ngsi-ld/v1/entities?type=quote&limit=50" -H 'Accept: application/json' \
  | python3 -c '
import json, sys
for e in json.load(sys.stdin):
    t = json.dumps(e)
    raw = t.count(chr(34) + "@type" + chr(34)) + t.count(chr(34) + "@id" + chr(34))
    print("%s escaped=%d raw=%d" % (e["id"], t.count("tmfEscaped-@"), raw))
'
```

The fix only protects **future** writes. Quotes already stored with the keywords gone stay broken
and must be deleted — the negotiation record *is* the quote, so deleting it removes the stuck
negotiation:

```bash
curl -X DELETE "http://127.0.0.1:18080/tmf-api/quote/v4/quote/urn:ngsi-ld:quote:<id>"
```

A related trap when repairing entities by hand: on Scorpio ≥ 6, `PATCH /attrs` **appends** to
multi-attributes instead of replacing, so a hand-written repair can silently grow the attribute and
leave the old broken instance first — and therefore still in effect. Removing an attribute needs
`DELETE /attrs/{attr}?deleteAll=true`; a plain `DELETE` only removes the *default* instance, which
often does not exist and returns 404.

### The marketplace cannot log anyone in

**Status**: one half seen live on `provider-edc` (a `${DID}` row in the verifier),
the other on `provider-mkt` (a verifier holding nothing but the login client).

The marketplace's logic proxy authenticates users by presenting a client id to the
verifier. If the verifier's config repo does not hold a service under exactly that
id, the login redirect resolves to a request object with **no
`presentation_definition`**, and the wallet says:

```
Could not process the information request
```

which is the same sentence half a dozen unrelated faults produce.

**Which variable carries the id depends on the auth stack**, and the two
marketplaces in this dataspace use different ones:

| deployment | stack | flag | client id lives in |
|---|---|---|---|
| `producer` | OIDC | `BAE_LP_OIDC_ENABLED=true` | `BAE_LP_OAUTH2_CLIENT_ID` |
| `provider-mkt` | SIOP | `BAE_LP_SIOP_ENABLED=true` | `BAE_LP_SIOP_CLIENT_ID` |

The other variable is absent entirely in each case, so a check reading one fixed
name reports a false negative on one of the two sites.

**How to see it.** The logic proxy is a **StatefulSet**, so `kubectl get deploy`
answers NotFound; go through the Service:

```bash
kubectl -n provider get svc -o name | grep logic-proxy
kubectl -n provider exec sts/<release>-biz-ecosystem-logic-proxy -- \
  sh -c 'echo $BAE_LP_OIDC_ENABLED $BAE_LP_SIOP_ENABLED \
              $BAE_LP_OAUTH2_CLIENT_ID $BAE_LP_SIOP_CLIENT_ID'

kubectl -n provider port-forward svc/verifier 8090:8090
curl -s http://localhost:8090/service | jq -r '.services[].id'
```

The two strings have to match exactly, **path suffix included** - `did:web:host` and
`did:web:host:did` are different participants as far as the verifier is concerned.

**Two neighbouring faults the same check reports.**

An id that is an **unexpanded placeholder**. `provider-edc` has a service literally
named `${DID}`, because the registration script passes the JSON body as a
single-quoted shell argument while expanding the first one only:

```sh
export DID=did:web:did-provider.example.org:did
register_service "${DID}" '{..."id":"${DID}"...}'   # the body does NOT expand
```

The job's own log prints `Registering service 'did:web:did-producer...'`, so the log
says the registration succeeded under a name that was never used. Login still works
wherever the literal id is registered alongside it, which is why nobody notices.

And a verifier whose **only** service is the login client: a user can authenticate
and there is nothing behind the gateway to let them into. Not broken, but not
offering anything either - the shape a fresh install has before somebody registers a
data service.

### Nothing in the catalogue is discoverable

**Status**: informational; a WARN, because a deployment that was just installed
legitimately has nothing published yet.

A provider whose catalogue holds no offering in a discoverable state is not offering
anything to anybody, however healthy the rest of the stack is.

**The lifecycle vocabularies are not the same across charts**, so there is no single
status string to look for:

| deployment | statuses present |
|---|---|
| `producer` (chart 10.4.12) | `Launched`, `Retired` |
| `provider-mkt` (chart 9.0.5) | `Active`, `In design`, `Launched` |

Both `Launched` and `Active` count as discoverable. A filter pinned to one of them
reports an empty catalogue on a deployment whose catalogue is full.

**And `lifecycleStatus` can be absent altogether.** `provider-edc` has a catalog
with no status field at all, which `== "Launched"` drops in silence - so the check
names those separately rather than letting them vanish into a count.

```bash
kubectl -n provider port-forward svc/tm-forum-api-svc 8080:8080
curl -s 'http://localhost:8080/tmf-api/productCatalogManagement/v4/productOffering?limit=1000' \
  | jq -r '.[] | "\(.lifecycleStatus // "(none)")\t\(.name)"'
```

`limit=1000` matters: the default page size is 100, and a truncated list makes this
check wrong in the reassuring direction.

**Offerings that exist and are all retired** is reported differently from an empty
catalogue on purpose. The first is almost always somebody retiring the last one by
accident; the second is usually just a deployment nobody has published to yet.

### contract-management is not listening to the marketplace

**Status**: OPEN on `provider-remote-mkt` (`notification.enabled: false`,
`entities: []`), ambiguous there because it has no local marketplace.

An offering published in the marketplace becomes negotiable only because
contract-management hears the event and turns it into an ODRL policy and a
registered service. If it is not subscribed, everything upstream looks healthy -
the catalogue fills, the MP responds - and nothing downstream ever appears. There
is no error anywhere, because nothing failed: nobody was listening.

**The subscription cannot be read back, and that is the hard part.** TMForum's
`/hub` answers **405** on both deployments here: the implementation takes POST to
register and DELETE to remove, and offers no listing. So the question "is it
subscribed, and how many times" has no answer from the TMForum side. The logs do
not help either - 24 hours of contract-management logs on `provider-edc` contain
no registration line at all, and startup logs are long rotated away.

So this check separates what it knows from what it infers, the same way
`registration-job-hooks` does from `registration-services-present`:

| | |
|---|---|
| **declaration** | `notification.enabled`, and an entity for each of ProductOffering, ProductOrder, Catalog, Quote |
| **outcome** | the health endpoint's subscription indicator, when it is visible |
| **not observable** | that the hubs were registered, and how many times |

**Making the outcome readable, with no code change.** The Micronaut health
aggregator already computes a `Subscription Health` indicator - it is visible in
contract-management's own DEBUG logs. It is hidden because
`endpoints.health.details-visible` defaults to `AUTHENTICATED`:

```bash
# today: only the roll-up
kubectl -n provider port-forward pod/<contract-management-pod> 9090:9090
curl -s http://localhost:9090/health          # {"status":"UP"}
```

Set `ENDPOINTS_HEALTH_DETAILS_VISIBLE=ANONYMOUS` and the per-indicator breakdown
appears, including the subscriptions. It goes under
`contract-management.additionalEnvVars`, and that is the whole change.

**Publishing 9090 on the Service is not part of it**, though an earlier version of
this page said so. The chart renders exactly one Service port, so it would need a
chart change, and it buys the tool nothing: `_health` resolves the pod by selector
on every run precisely because the port is not published. It is worth doing only
for a human who wants a stable address to curl.

**A symptom that points the other way.** Duplicate subscriptions are as damaging
as absent ones and look like health. `provider-edc` takes **6215 inbound events
in 24 hours**, about three every nineteen seconds, and each one it acts on
produces three or four identical downstream GETs within the same millisecond
band. That is the signature of the same callback registered several times - and
`{"status":"UP"}` will never say so.

**What it costs when it is off.** Nothing is logged, nothing errors, and the only
visible consequence is downstream: no policy in odrl-pap, no service registered
in the verifier, and therefore an offering that a counterparty can see in the
catalogue and can never negotiate for.

### An offering is published and nothing downstream happens

**Status**: the probe that answers it exists; the chain itself was traced live on
`provider-edc`, from the inbound event to `POST http://odrl-pap:8080/policy`.

Publishing is not the end of anything. An offering becomes negotiable because
contract-management hears the event and turns it into two things: an **ODRL policy
in odrl-pap**, which is what OPA later evaluates at the gateway, and a **service in
the verifier's config repo**, which is what decides the credential a caller must
present. Until both exist, a counterparty can see the offering in the catalogue and
can never obtain anything through it.

The observed chain, from contract-management's own log:

```
POST /listener/event 204
  → GET /tmf-api/party/v4/organization/...
  → GET /tmf-api/productOffering/...
  → GET /tmf-api/productSpecification/...
  → PAPAdapter: the final policy {...}
  → POST http://odrl-pap:8080/policy 200
```

**Measured correction: a publication is not the trigger — a purchase is.** A probe
that published an offering against a healthy `producer` reached neither end of the
chain, and the policy store says why:

```
23  derived from a product-ORDER   (urn:ngsi-ld:product-order:<uuid> in the uid)
 1  another participant            (no catalogue reference)
 1  contractManagement             (no catalogue reference)
 0  derived from a product-offering
```

Every policy that came from the catalogue came from an **order**. The traced chain
above bears it out: it fetches a `quote` on its way through.

**So the probe was removed**, and this is the reasoning, kept because the next
person will have the same idea. Publishing an offering and watching for a policy
measures the wrong trigger; reaching the real one means placing a purchase, which
means parties, a billing account and the charging backend — writing a great deal
into somebody else's environment to observe something a human can confirm once.
That is the same line the tool declines to cross for wallets, and for the same
reason.

**What is checked instead, and without writing anything**, is that what is already
published carries the pieces the chain needs: `marketplace-offering-completeness`
reads the catalogue and reports a **discoverable** offering whose specification has
no `authorizationPolicy` (nothing authorises access) or no credentials
characteristic (the verifier is never told what to demand). A retired offering
missing everything is not judged — nobody will find it.

**How bad that is depends on what the deployment can still do**, not on how many
rows are bad:

| | verdict | why |
|---|---|---|
| no discoverable offering is complete | **FAIL** | nothing published is obtainable: a Provider that provides nothing |
| some are complete, some are not | **WARN** | the chain works; this is the state of the catalogue, not of the deployment. `--strict` still fails the run |
| an offering points at a specification that is not there | **FAIL** | a broken reference, not an incomplete one |

The rule is deliberately *not* "one good offering, so downgrade": that would let an
unrelated offering decide how bad this one is, which is the mistake
`til-registration` made once and was corrected for. What changed the severity here
is that an offering is published **content** while this tool's exit code is a
statement about the **deployment** — and a catalogue carrying nine samples next to
one working product is not a broken deployment.

**The verdict leads with what works**, and names it: *only 1 of 10 discoverable
offering(s) can be used: CM Logging Test Offer*. It did not use to, and the case
that exposed it is the common one — somebody adds a good offering to a catalogue
full of examples, runs the tool, sees nine failures that are not theirs and no
mention of the one that is, and reasonably concludes it was not detected. It was;
it was the only one that passed.

**The shortfall is aggregated, not enumerated.** On a real catalogue the unusable
offerings nearly all fall short the same way, so the cause counts them once —
*of the other 9, every one of them lacks both an `authorizationPolicy` and a
credentials characteristic* — instead of repeating two clauses per offering, which
turned ten offerings into fifteen lines nobody read. The per-offering breakdown is
still there in `unusable`, which `-v` and `--json` print.

**Two traps in that reading**, both met in practice:

* the credentials characteristic is spelled **two ways in the same catalogue** —
  `credentialsConfig` on one offering and `credentialsConfiguration` on three.
  Both work. A checker that knows one of them reports a complete offering as
  missing its credentials, which a first cut of this check did.
* `endpointUrl` and the other transport characteristics are **absent from a
  perfectly good offering**: one served only through the gateway has no DSP
  endpoint to name. Both shapes occur in the same dataspace, so their absence is reported and
  never judged.

**How to look by hand.**

```bash
kubectl -n provider port-forward svc/odrl-pap 8084:8080
curl -s http://localhost:8084/policy | jq -r '.[]."odrl:uid"' | sort | uniq -c

kubectl -n provider port-forward svc/verifier 8090:8090
curl -s http://localhost:8090/service | jq -r '.services[].id'
```

On `provider-edc` the policies group by uid, and each one derived from an order
carries that order's urn as a suffix - so a policy is traceable back to what caused
it.

**Cleaning up after a probe is the dangerous part**, and the rules the check
follows are worth repeating for anyone doing it by hand. Take a snapshot of both
stores *before* creating anything; treat only what is new afterwards as a
candidate; and remove a candidate only if it also carries your marker, because
somebody else's policy may have appeared in between. A `DELETE /policy/<id>`
against odrl-pap answers 204 whether or not the id existed, so the response tells
you nothing - re-list and compare instead.
