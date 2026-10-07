# Verifying the checks: fault injection

A check you cannot make fail is not verified. It may be reading the wrong key, comparing the
wrong pair of values, or skipping quietly on a condition that never happens — and every one of
those looks identical to a healthy deployment. This file is the acceptance criterion for
[`fdsc-verify`](../README.md): break one thing on purpose, confirm the right check names it,
put it back.

**Two rows were done at level B for the first time**, on a shared GitOps environment, and what
that took is worth more than the two ticks. Argo's auto-sync was off, so nothing would revert a
mistake: the restore was entirely ours. The app was already `OutOfSync`/`Degraded` before
anything was touched — a stale Job and grafana's Role and RoleBinding — so the baseline to
return to was *that*, not something tidier, and no sync was run to "fix" it. The protocol that
made it safe:

1. snapshot everything first — the full `--json` report, Argo's resource list, the ConfigMap,
   and every offering's id and `lifecycleStatus`, to files;
2. **prove the write path without changing anything**: one `PATCH` setting a value it already
   had. If that fails you stop, and nothing has been touched;
3. one injection at a time: break → run only that check → restore;
4. restore in a `finally`, so an exception mid-way restores anyway;
5. verify against the snapshot, not against expectation. The report came back identical row
   for row, and Argo's 137 resources with the same three adrift.

The offering injection has a real blast radius — eleven offerings retired and republished, with
the catalogue visibly empty in between — so it was kept to one short window: **14.6 seconds**,
measured.

Five more rows were validated by accident, because a real deployment happened to carry the fault
when the tool was first run against it: `controlplane-image`, `identity-key-consistency` and
`holder-kid-fragment` on `consumer-edc` and `provider-edc`,
`marketplace-services-beyond-login` and `marketplace-offering-completeness` on
`provider-mkt`. Four more are ticked at level A below. The rest are here and undone.

The handles name deployment *shapes*, defined in [the README](../README.md#where-the-evidence-comes-from).
They are kept rather than dropped: a ✅ whose provenance is anonymous is a ✅ nobody can
check.

## Two levels, and why both

| | What it proves | Risk |
|---|---|---|
| **A — harness injection** | the check's *logic* fires: given a wrong input it fails, with the right cause and the right `see:` | none; nothing in the cluster is touched |
| **B — cluster injection** | the whole path, discovery included: the check reads the thing that actually broke | real, always reversible below |

A on its own is not enough — it cannot catch a check that reads the wrong key from the cluster.
B on its own is expensive and needs an environment you are allowed to break. Do A first: it is
free and it fails fast when the logic is wrong.

Both start from a clean baseline, so that "it went red" means something:

```bash
python3 -m fdsc_verify -n provider --preflight-only --no-write --json > /tmp/before.json
```

Every B below restores what it changed. **Read the restore step before running the break step.**

---

## `verifier-jwks-matches-key`

The verifier publishes a JWKS that no longer matches the signing key, and apisix caches it under
an unchanged `kid`. See [APISIX caches the verifier's
JWKS](troubleshooting.md#apisix-caches-the-verifiers-jwks-and-the-kid-never-changes).

**A.** Point the tool at a different TLS secret in the namespace — any other one will do, the
wildcard is convenient — so the key it compares against the published JWKS is not the key the
verifier signed with:

```bash
kubectl -n provider get secret --field-selector type=kubernetes.io/tls -o name
cat > /tmp/wrong-key.json <<'JSON'
{"identity": {"secret": "SOME-OTHER-TLS-SECRET"}}
JSON
python3 -m fdsc_verify -n provider --only verifier-jwks-matches-key --config /tmp/wrong-key.json
```

Expect FAIL "the verifier publishes a JWKS that does not match the signing key", with both
fingerprints in the cause. A SKIP here means the secret has no `tls.key` under the expected
name — pick another one.

**B.** Rotate the identity secret and do *not* restart the verifier:

```bash
kubectl -n provider get secret <identity-secret> -o yaml > /tmp/identity-backup.yaml   # FIRST
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=injected" \
  -keyout /tmp/i.key -out /tmp/i.crt
kubectl -n provider create secret tls <identity-secret> --cert=/tmp/i.crt --key=/tmp/i.key \
  --dry-run=client -o yaml | kubectl -n provider apply -f -

python3 -m fdsc_verify -n provider --only verifier-jwks-matches-key,identity-key-consistency
```

Restore, then restart everything that caches the key — this is the same list as step 7 of the
rotation runbook, and skipping it leaves the deployment in the state the check exists to detect:

```bash
kubectl -n provider apply -f /tmp/identity-backup.yaml
kubectl -n provider rollout restart deploy/<release>-apisix deploy/verifier
python3 -m fdsc_verify -n provider --preflight-only --no-write   # back to the baseline
```

## `dsp-route` and `credential-service-route`

A published endpoint that resolves to somebody else's server, which answers a plausible 404.
See [Working around the broken `atdih` record](troubleshooting.md#working-around-the-broken-atdih-record).

**A.** Give the lane a hostname that resolves but is not us:

```bash
cat > /tmp/wrong-host.json <<'JSON'
{"lanes": {"dcp": {"props": {"edc.hostname": "example.com"}}}}
JSON
python3 -m fdsc_verify -n provider --only dsp-route --edc-lane dcp --config /tmp/wrong-host.json
```

Expect FAIL naming `https://example.com/api/dsp/.well-known/dspace-version -> 404`. This is the
cheapest row in the table and it exercises the 404-versus-401 distinction the check is for.

The check was split in two: `dsp-route` probes the lane's own DSP endpoint and stays
EDC-only, while `credential-service-route` probes whatever the DID document publishes and
needs no lane at all - which is the half that caught the real fault.

**B.** Republish the CredentialService endpoint of the DID document at a host that does not
resolve, and `credential-service-route` reports the 404. That is a write to the identityhub
and it is only worth doing on an environment you own; the A form already proves the
comparison.

## `sts-secret-aliases`

Only one of the two alias encodings is present in Vault, which is a false pass for anything
that checks a single form. See [The DCP lane needs an STS client
secret](troubleshooting.md#the-dcp-lane-needs-an-sts-client-secret-that-dev-mode-vault-loses).

**B**, and read the value out before deleting it — dev-mode Vault cannot give it back:

```bash
ALIAS=$(kubectl -n provider get cm <release>-fdsc-edc-dcp \
  -o jsonpath='{.data.dataspaceconnector-configuration\.properties}' \
  | grep '^edc.iam.sts.oauth.client.secret.alias=' | cut -d= -f2-)
TOKEN=$(kubectl -n provider get cm <release>-fdsc-edc-dcp \
  -o jsonpath='{.data.dataspaceconnector-configuration\.properties}' \
  | grep '^edc.vault.hashicorp.token=' | cut -d= -f2-)
kubectl -n provider port-forward svc/<release>-vault 18200:8200 &

curl -s -H "X-Vault-Token: $TOKEN" \
  "http://127.0.0.1:18200/v1/secret/data/${ALIAS//:/%253A}" | tee /tmp/sts-alias.json
curl -s -X DELETE -H "X-Vault-Token: $TOKEN" \
  "http://127.0.0.1:18200/v1/secret/metadata/${ALIAS//:/%253A}"

python3 -m fdsc_verify -n provider --only sts-secret-aliases --lane dcp
```

Expect FAIL or WARN naming the percent-encoded form as the missing one. Restore from the value
you saved:

```bash
VALUE=$(python3 -c 'import json;print(json.load(open("/tmp/sts-alias.json"))["data"]["data"]["content"])')
curl -s -X POST -H "X-Vault-Token: $TOKEN" -d "{\"data\":{\"content\":\"$VALUE\"}}" \
  "http://127.0.0.1:18200/v1/secret/data/${ALIAS//:/%253A}"
```

The key name inside `data` is whatever the bootstrap job wrote; check `/tmp/sts-alias.json`
before assuming `content`.

## `trust-anchors-folder`

`loadCertificatesFromFolder` does a flat listing and throws on anything it cannot parse, so one
stray file in the anchor folder stops the controlplane from starting. See [OID4VP trust
anchors](troubleshooting.md#oid4vp-trust-anchors-use-the-images-public-root-store).

**B**, the cheap branch — one file, one deletion, no restart needed because the check reads the
folder rather than the running truststore:

```bash
FOLDER=$(kubectl -n provider get cm <release>-fdsc-edc-oid4vc \
  -o jsonpath='{.data.dataspaceconnector-configuration\.properties}' \
  | grep '^oid4vp.trustAnchorsFolder=' | cut -d= -f2-)
kubectl -n provider exec deploy/<release>-fdsc-edc-oid4vc -c dsp-controlplane -- \
  sh -c "touch $FOLDER/injected-not-a-cert.txt"

python3 -m fdsc_verify -n provider --only trust-anchors-folder --lane oid4vc

kubectl -n provider exec deploy/<release>-fdsc-edc-oid4vc -c dsp-controlplane -- \
  sh -c "rm -f $FOLDER/injected-not-a-cert.txt"
```

Expect FAIL naming `injected-not-a-cert.txt`. If the mount is read-only the `touch` fails; that
is a legitimate reason to leave this row at A-only, and the empty-setting branch is then the one
to inject instead, through `--config` with `oid4vp.trustAnchorsFolder` set to `""`.

## `credential-freshness`

A credential in the store signed with a key that is no longer the published one — what a
rotation leaves behind. See [A stale credential in the
identityhub](troubleshooting.md#a-stale-credential-in-the-identityhub-outlives-a-key-rotation).

**B.** The credentials folder is an emptyDir filled by an init container, so a copy survives
only until the pod restarts — which is also how you undo this:

```bash
FOLDER=$(... oid4vp.credentialsFolder, as above ...)
POD=$(kubectl -n provider get pod -l app.kubernetes.io/instance=<release> \
  -o name | grep oid4vc | head -1)
kubectl -n provider exec $POD -c dsp-controlplane -- sh -c "ls -1 $FOLDER"
# overwrite the .jwt with a credential signed by another key, then:
python3 -m fdsc_verify -n provider --only credential-freshness,credential-two-copies
# restore: the init container rebuilds the folder
kubectl -n provider delete $POD
```

Expect FAIL saying the signature does not verify against the published key. Deleting the pod is
the restore step, which is why this row is safe to inject and awkward to inject *precisely*: the
identityhub's own copy is not touched, so `credential-two-copies` should fire as well, and that
is worth confirming in the same run.

## `dashboard-config`

A counterparty entry carrying our own DID — the `aud` mismatch, seen from the side that can
still fix it. See [Wrong
`aud`](troubleshooting.md#wrong-aud-the-counterpartys-dashboard-carries-the-wrong-did).

**B**, and note the `rollout restart`: the ConfigMap is mounted with `subPath`, which kubelet
does not refresh, so without it nothing changes and the injection silently does not happen.

```bash
kubectl -n provider get cm edc-dashboard-cm -o yaml > /tmp/dashboard-backup.yaml   # FIRST
kubectl -n provider edit cm edc-dashboard-cm    # set a counterparty entry's `did` to OUR did
kubectl -n provider rollout restart deploy/edc-dashboard-data-dashboard
kubectl -n provider rollout status deploy/edc-dashboard-data-dashboard

python3 -m fdsc_verify -n provider --only dashboard-config
```

Expect FAIL "…carries our own DID", `see:` the `aud` section. Then:

```bash
kubectl -n provider apply -f /tmp/dashboard-backup.yaml
kubectl -n provider rollout restart deploy/edc-dashboard-data-dashboard
```

A second, free variant: run with `--peer peers/example.yaml` after pointing the peer file's
`participantId` at a DID the dashboard does not carry. That exercises the third rule (an entry
whose DID is not the one that peer identifies as) with no cluster change at all.

## The marketplace and contract-management checks

These five read the **cluster** and almost nothing else: the logic proxy's environment, the
verifier's config repo, the TMForum catalogue, contract-management's ConfigMap. That is rule 2
working as intended - the cluster gives the verdict - and it has a price here. The `--values`
injector that exercises every static check for free reaches exactly **one** of their branches.
Everything else needs level **B**, so each row below says which level is even available before
it says how.

Four branches are already ticked, and not by design: two deployments happened to carry the
fault when the checks were first run against them.

| Branch | Seen on |
|---|---|
| `marketplace-login-service` WARN - an unexpanded `${DID}` sitting in the registry | `provider-edc` |
| `marketplace-services-beyond-login` WARN - nothing registered but the login client | `provider-mkt` |
| `marketplace-offering-completeness` FAIL - four offerings with no credentials characteristic | `provider-mkt` |
| `marketplace-offering-completeness` WARN - two spellings of it in one catalogue | `provider-edc` |

### A - the declared login client id, and the variable it is read from

The one free injection, and it needs no copy of the deployed values: `--values` replaces the
user layer, and this check reads a single key out of it, so a four-line file is a complete
injector.

```bash
cat > /tmp/drifted-login.yaml <<'YAML'
marketplace:
  bizEcosystemLogicProxy:
    additionalEnvVars:
      - name: BAE_LP_OAUTH2_CLIENT_ID
        value: did:web:somebody-elses-client.example.org
YAML
python3 -m fdsc_verify -n <provider-ns> --preflight-only --no-write \
  --values /tmp/drifted-login.yaml --only marketplace-login-service
#   -> WARN "the values declare a different login client id than the pod uses",
#      naming both strings and BAE_LP_OAUTH2_CLIENT_ID
```

Worth doing twice, because the second run tests the thing that actually broke the first
implementation. Declare **both** variables, with the decoy in the one the deployment does not
use, and the check must name the other:

```bash
# on a SIOP marketplace (`provider-mkt`), with a decoy in the OIDC variable
python3 -m fdsc_verify -n <ns> --release <name> --preflight-only --no-write \
  --values /tmp/drifted-siop.yaml --only marketplace-login-service
#   -> WARN naming BAE_LP_SIOP_CLIENT_ID, never BAE_LP_OAUTH2_CLIENT_ID
```

A check that reads one fixed variable name passes the first command and fails this one, which
is why the pair is the row rather than either half. ✅ Both run, on `provider-edc` and
`provider-mkt` respectively.

### B - `marketplace-login-service`, the FAIL branch

The id the check compares against comes from the running pod, so no values file can reach it.

```bash
kubectl -n <ns> get statefulset <release>-biz-ecosystem-logic-proxy \
  -o jsonpath='{.spec.template.spec.containers[0].env}' > /tmp/lp-env.json   # keep this
kubectl -n <ns> set env statefulset/<release>-biz-ecosystem-logic-proxy \
  BAE_LP_OAUTH2_CLIENT_ID=did:web:not-registered.example.org
#   -> FAIL "the marketplace's login client is not registered in the verifier",
#      listing what the config repo does hold
# restore:
kubectl -n <ns> set env statefulset/<release>-biz-ecosystem-logic-proxy \
  BAE_LP_OAUTH2_CLIENT_ID=<the id from /tmp/lp-env.json>
```

This one really does break login while it is applied - the pod rolls with an id no wallet can
satisfy. Do not run it anywhere somebody else is using the MP.

### Where `credential-service-route` cannot be done

Not on a deployment whose DID document comes from the **did-helper**: the document it serves
carries no `service` array at all, and the chart exposes no key to add one — `did.config` and
`did.config.server` are both empty. A `CredentialService` only appears where the **IdentityHub**
serves the document, which is the DCP shape, so that is the only kind of deployment where this
row can be ticked. Injecting it anywhere else would mean replacing what answers at the DID
document's URL, which breaks identity for everyone resolving it.

### B - `marketplace-offerings`  ✅ done

Retire whatever is discoverable and put it back. Observed: `11 of 12 offering(s) discoverable`
→ **WARN** `12 offering(s), none of them discoverable`, with the cause naming the states
present (`{'(none)': 1, 'Retired': 11}`) → restored, and back to `11 of 12`. Nothing is created or deleted, only a
lifecycle field moved, which is the least destructive write available here.

```bash
kubectl -n <ns> port-forward svc/tm-forum-api-svc 8080:8080 &
curl -s 'localhost:8080/tmf-api/productCatalogManagement/v4/productOffering?limit=1000' \
  | python3 -c 'import json,sys; print([(o["id"],o.get("lifecycleStatus")) for o in json.load(sys.stdin)])'
curl -sX PATCH -H 'Content-Type: application/json' \
  -d '{"lifecycleStatus":"Retired"}' \
  localhost:8080/tmf-api/productCatalogManagement/v4/productOffering/<id>   # every live one
#   -> WARN "N offering(s), none of them discoverable", naming the states present
# restore: PATCH each one back to the status recorded above
```

The empty-catalogue branch has no injection short of an install with nothing published; it is
the one shape this file cannot manufacture without deleting somebody's catalogue, and it is
also the harmless one.

### B - `marketplace-offering-completeness`, the dangling branch

Point a discoverable offering at a specification id that does not exist. The spec itself is
never touched, so the restore is the original id and nothing has to be recreated.

```bash
curl -sX PATCH -H 'Content-Type: application/json' \
  -d '{"productSpecification":{"id":"does-not-exist","href":"does-not-exist"}}' \
  localhost:8080/tmf-api/productCatalogManagement/v4/productOffering/<id>
#   -> FAIL "1 discoverable offering(s) point at a specification that is not there"
# restore: PATCH productSpecification back to the id it had
```

### B - `contract-management-subscriptions`  ✅ done

Observed: **OK** → **FAIL** `contract-management is not subscribed to anything`, the branch
that needs a local marketplace to be present and had never been reached → ConfigMap restored
byte for byte → back to OK.

Unusually safe, and for a reason worth understanding before running it: this check reads the
**ConfigMap**, not the running process. Editing it changes the verdict without changing what
contract-management does, because nothing is restarted. The declaration is what is being
tested, and the declaration is exactly what moves.

```bash
kubectl -n <ns> get configmap contract-management -o yaml > /tmp/cm.yaml        # keep this
# (a) the FAIL: switch the subscription off where a marketplace is deployed
kubectl -n <ns> patch configmap contract-management --type merge \
  -p "$(python3 - <<'PY'
import json, yaml, subprocess
cm = yaml.safe_load(subprocess.check_output(
    "kubectl -n <ns> get configmap contract-management -o yaml", shell=True))
app = yaml.safe_load(cm["data"]["application.yaml"])
app["notification"]["enabled"] = False
print(json.dumps({"data": {"application.yaml": yaml.safe_dump(app)}}))
PY
)"
#   -> FAIL "contract-management is not subscribed to anything"
# (b) the WARN: drop one entityType instead, e.g. ProductOrder
#   -> WARN "1 event type(s) nobody is subscribed to: ProductOrder"
# restore:
kubectl -n <ns> apply -f /tmp/cm.yaml
```

The remaining branch - the health indicator reporting anything but `UP` - cannot be reached at
all today, because Micronaut suppresses the per-indicator detail and the check never sees one.
It becomes injectable the moment somebody sets `ENDPOINTS_HEALTH_DETAILS_VISIBLE=ANONYMOUS`,
which is the same change the check's own `fix:` line asks for. Until then it is dead code, and
saying so here is better than leaving a row that looks covered.

## The checks that need no cluster at all

The declared profile turned level **A** from a trick into the normal way to verify these.
Each command below touches nothing, needs no namespace that exists, and must produce the
FAIL named beside it.

```bash
# deployment-profile: say the deployment is something it is not
python3 -m fdsc_verify -n <ns-with-edc> --no-edc --only deployment-profile --static-only
#   -> FAIL "says there is no EDC connector, but N lane(s) were found"
python3 -m fdsc_verify -n <ns-with-edc> --did did:web:not-this-one --only deployment-profile
#   -> FAIL "but the lane configuration carries did:web:…"

# component-inventory: claim a role the deployment does not fill
python3 -m fdsc_verify -n <consumer-ns> --role provider --only component-inventory --static-only
#   -> FAIL naming the provider components that are absent, with their values keys

# keycloak-signing-key: name a kid the DID document does not publish
cat > /tmp/bad-kid.yaml <<'YAML'
keycloak:
  signingKey:
    did: "#key-9"
YAML
python3 -m fdsc_verify -n <ns> --preflight-only --no-write \
  --values /tmp/bad-kid.yaml --only keycloak-signing-key
#   -> FAIL "the kid Keycloak signs with is not published in the DID document",
#      naming both the kid and the ids the document does publish
# and the other half of the same fault, an algorithm the published key cannot carry:
#   keycloak.signingKey.keyAlgorithm: RS256 against an EC document
#   -> FAIL "the published key cannot carry a RS256 signature"

# central-mp-contract-management-route: three ways in, all from one values file.
# Take the real route list, change one thing, and pass it back. The environment
# measured is healthy, so these injections are the only thing that validates it.
#   drop the route whose upstream is contract-management:8080
#     -> FAIL "no gateway route forwards to contract-management"
#   set that route's openid-connect.bearer_only to false
#     -> WARN "refuses by redirecting, not by 401"
#   set its openid-connect.client_id to something the verifier has not registered
#     -> FAIL "authenticates as a client the verifier does not know"
python3 -m fdsc_verify -n <ns> --preflight-only --no-write \
  --values /tmp/edited-routes.yaml --only central-mp-contract-management-route

# identity-did-consistency: point one of the six DID copies somewhere else
sed 's/did:web:the-real-one/did:web:stale.example.org/' values.yaml > /tmp/drifted.yaml
python3 -m fdsc_verify -n <ns> --values /tmp/drifted.yaml \
  --only identity-did-consistency --static-only
#   -> FAIL "1 of 3 places name a different participant", naming the odd one out
```

The last one is the pattern worth reusing: **a values file is a fault injector**. `--values`
replaces the user layer over the real chart defaults, so any static check can be exercised
by editing a copy of the file the deployment was rendered from, with nothing at risk.

Three cautions learned by doing exactly this:

- A declaration that is *checked* is not the same as one that is *believed*. `--role provider`
  makes `component-inventory` measure against the provider row; it does not make the
  deployment one, which is the point.
- `--no-edc` against a deployment that has lanes exercises `deployment-profile`. It is **not**
  a way to test the no-EDC path: the lanes are still there and the lane checks still run.
- With no cluster reachable, `deployment-profile` skips rather than contradicting anything -
  "no lane was found" then means "nobody looked". Injecting at level A needs the cluster
  readable even though nothing is written to it.

---

## Recording the result

A row is done when the check failed **for the right reason** — not merely failed. Check three
things before ticking it off, because a check can go red on the wrong evidence and still look
like a pass of this exercise:

1. the `cause` names the thing you broke, in the words the logs use;
2. the `see:` anchor resolves to the section that explains it;
3. after the restore, the check is green again and `--json` matches `/tmp/before.json`.

Then update the table in [`CLAUDE.md`](../CLAUDE.md): it is the record of what is verified, and an
unticked row there is a promise the tool has not yet kept.
