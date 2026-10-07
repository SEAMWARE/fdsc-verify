"""Read the Helm values of a deployed release, and be honest about the confidence.

Until now the tool read the *rendered* config out of a lane's ConfigMap, which is
excellent but only covers fdsc-edc. Anything about the deployment as a whole - is
the credentials-config-service even enabled, which chart version is this, has the
release been upgraded - lives in Helm's own storage, and getting there turned out
to need four things that a naive implementation gets wrong. All four were measured
against two independent clusters, not assumed:

1. **The payload is base64 twice.** `secret .data.release` is base64 (kubernetes)
   wrapping base64 (helm) wrapping gzip wrapping JSON. Decode once and you get
   what looks like binary garbage; decode once and gunzip and you get nothing.

2. **Never guess the revision.** The Secrets are `sh.helm.release.v1.<rel>.v<N>`
   and every historical N is kept, each embedding the whole rendered manifest.
   `demo/consumer` is at v36: listing without `status=deployed` downloads ~36 MB
   for one namespace, and the tool looks hung. The label selector gives exactly
   the live revision of each release in a single call.

3. **The stdlib merge is not an approximation of `helm get values --all` - it is
   the same answer.** Verified on demo's consumer: 2194 leaf keys each way, no
   extra keys, no differing values. The reason is structural: `chart.dependencies`
   is not serialised into the stored release, so `helm` cannot coalesce subchart
   defaults either. The binary therefore buys no precision and stays a transport
   fallback only.

4. **An absent key does not mean disabled.** `fdsc-edc` has no `enabled` anywhere
   in the chart defaults and is deployed regardless, because Helm *enables* a
   dependency whose `condition` does not resolve. For an umbrella template
   (`dataSpaceConfig`, `statusListServer`, ...) absent means false. Same syntax,
   opposite meaning - hence `Tri` and the `kind` argument, rather than a plain
   `values.get(path, False)` that would confidently report the wrong thing.
"""

from __future__ import annotations

import base64
import binascii
import gzip
import json
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .kube import Kube, KubeError
from .progress import null

# chart name -> which role family it can play. A namespace often holds several
# releases (one provider has four; another namespace has a participant AND the trust
# anchor), so the chart name is what picks ours out - and it is deliberately not a
# label on the Secret, so it costs a decode to find.
CHART_FAMILIES = {
    "data-space-connector": "participant",
    "trust-anchor": "operator",
}

HELM_SELECTOR = "owner=helm,status=deployed"

_GZIP_MAGIC = b"\x1f\x8b"
_SOURCE_RE = re.compile(r"^#\s*Source:\s*(\S+)", re.M)
_VERSION_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)")
# "${DID}", "{{ .Release.Name }}" - values that are not values yet
_PLACEHOLDER_RE = re.compile(r"\$\{[^}]*\}|\{\{.*?\}\}")


def has_placeholder(value: Any) -> bool:
    """Is this value resolved later, by an init container or by Helm itself?

    `keycloak.issuerDid` really is the literal string `${DID}` in a working
    deployment, and `vault.hashicorp.url` really is `http://{{ .Release.Name
    }}-vault:8200`. A check that compares either literally reports a mismatch
    that is not there, so every comparison of a DID, host or URL has to ask this
    first and SKIP rather than guess.
    """
    return isinstance(value, str) and bool(_PLACEHOLDER_RE.search(value))


def chart_version_tuple(version: Optional[str]) -> Optional[Tuple[int, int, int]]:
    """`10.4.12-173` -> (10, 4, 12). Tolerates a `v` prefix and a build suffix.

    Needed because chart versions in the wild are not tidy: one runs 10.3.2 while
    the repo is at 10.4.12, and 9.0.5 coexists with 10.4.12 on the demo cluster,
    so version-gated checks are unavoidable.
    """
    if not version:
        return None
    match = _VERSION_RE.search(version)
    if not match:
        return None
    return (int(match.group(1)), int(match.group(2)), int(match.group(3)))


def deep_merge(base: dict, over: Optional[dict]) -> dict:
    """Helm's coalesce semantics, and only those.

    Three rules, each deliberate: dicts merge recursively; a `None` in the
    override *deletes* the key, because that is how Helm disables a default; and
    lists replace wholesale rather than merging, which is why `--set` on a list
    silently drops the entries you did not mention.
    """
    out = dict(base or {})
    for key, value in (over or {}).items():
        if value is None:
            out.pop(key, None)
        elif isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = deep_merge(out[key], value)
        else:
            out[key] = value
    return out


def _leaf_paths(tree: Any, prefix: str = "") -> List[str]:
    if not isinstance(tree, dict) or not tree:
        return [prefix] if prefix else []
    out: List[str] = []
    for key, value in tree.items():
        path = "%s.%s" % (prefix, key) if prefix else str(key)
        out.extend(_leaf_paths(value, path))
    return out


@dataclass(frozen=True)
class Tri:
    """A boolean that admits not knowing, and always says why.

    Deliberately has no `__bool__`: `if values.tri(path):` would read as "enabled"
    and quietly treat "we could not tell" as "no", which is the single most
    dangerous mistake available in this module.
    """

    value: Optional[bool]
    why: str
    origin: str  # user | chart | dependency | missing | unknown

    @property
    def is_true(self) -> bool:
        return self.value is True

    @property
    def is_false(self) -> bool:
        return self.value is False

    @property
    def unknown(self) -> bool:
        return self.value is None


@dataclass(frozen=True)
class Dependency:
    """One entry of `chart.metadata.dependencies` in the stored release.

    Worth knowing: the stored list is already filtered to the *enabled*
    dependencies, with the alias and the resolved version. That makes it ground
    truth for "did this subchart render", with none of Helm's condition semantics
    reimplemented here.
    """

    name: str
    alias: Optional[str] = None
    condition: Optional[str] = None
    version: Optional[str] = None
    enabled: bool = True

    @property
    def key(self) -> str:
        """The key this dependency is configured under - the alias, if it has one."""
        return self.alias or self.name


@dataclass(frozen=True)
class ManifestObject:
    kind: str
    name: str
    source: str  # the "# Source: <chart>/templates/..." line, i.e. provenance


@dataclass
class ReleaseInfo:
    name: str
    namespace: str
    chart_name: str = ""
    chart_version: str = ""
    app_version: Optional[str] = None
    revision: int = 0
    status: str = ""
    last_deployed: Optional[str] = None
    defaults: dict = field(default_factory=dict)
    user: dict = field(default_factory=dict)
    dependencies: List[Dependency] = field(default_factory=list)
    hooks: List[dict] = field(default_factory=list)
    # kept in memory only: it embeds rendered Secrets, so it must never be
    # serialised into --json output
    manifest: str = ""
    secret: Optional[str] = None
    _manifest_index: Optional[List[ManifestObject]] = field(default=None, repr=False)

    @property
    def family(self) -> str:
        """participant | operator | unknown, by chart name or by what it depends on.

        The dependency half is not a nicety: the dev environment deploys the DSC
        as a dependency of a wrapper chart called `consumer` / `provider`, so
        matching the chart name alone made that whole environment invisible.
        """
        direct = CHART_FAMILIES.get(self.chart_name)
        if direct:
            return direct
        for dep in self.dependencies:
            family = CHART_FAMILIES.get(dep.name)
            if family:
                return family
        return "unknown"

    @property
    def values_root(self) -> Tuple[str, ...]:
        """Where this release's DSC values start.

        Empty when the release *is* the DSC. When it is a wrapper, Helm nests a
        dependency's values under its alias, so everything the checks look for -
        `decentralizedIam.…`, `did.enabled`, `fdsc-edc.enabled` - lives under that
        key instead. Reading the unprefixed paths there does not error: it reports
        every component as absent, which is the worst possible way to be wrong.
        """
        if self.chart_name in CHART_FAMILIES:
            return ()
        for dep in self.dependencies:
            if dep.name in CHART_FAMILIES:
                return (dep.key,)
        return ()

    @property
    def chart(self) -> str:
        return "%s-%s" % (self.chart_name, self.chart_version) if self.chart_name else ""

    def dependency(self, key: str) -> Optional[Dependency]:
        for dep in self.dependencies:
            if dep.key == key or dep.name == key:
                return dep
        return None

    def chart_at_least(self, version: str) -> Optional[bool]:
        mine, floor = chart_version_tuple(self.chart_version), chart_version_tuple(version)
        if mine is None or floor is None:
            return None
        return mine >= floor

    def manifest_index(self) -> List[ManifestObject]:
        """Parse the rendered manifest into (kind, name, source), lazily and once.

        Cheap enough to be worth it: it is what lets a check say "Helm rendered
        this and it is not in the cluster", which is a different diagnosis from
        "it was never asked for".
        """
        if self._manifest_index is None:
            self._manifest_index = _index_manifest(self.manifest)
        return self._manifest_index

    def hook_events(self) -> List[Tuple[str, List[str]]]:
        """(name, events) per hook, from the stored release rather than the cluster.

        Reading the release rather than looking for Jobs is the point: Helm
        deletes hook Jobs that carry `hook-succeeded`, so their absence proves
        nothing, while the release always remembers what it declared.
        """
        out = []
        for hook in self.hooks or []:
            name = hook.get("name") or ""
            events = [str(event) for event in (hook.get("events") or [])]
            out.append((name, events))
        return out

    def to_json(self) -> dict:
        """Compact and safe: no manifest, no values, no secrets."""
        return {
            "name": self.name,
            "chart": self.chart,
            "chartName": self.chart_name,
            "chartVersion": self.chart_version,
            "revision": self.revision,
            "status": self.status,
            "family": self.family,
            "secret": self.secret,
            "dependencies": [dep.key for dep in self.dependencies],
            "manifestObjects": len(self.manifest_index()),
            "hooks": [{"name": name, "events": events} for name, events in self.hook_events()],
        }


def _index_manifest(manifest: str) -> List[ManifestObject]:
    out: List[ManifestObject] = []
    if not manifest:
        return out
    for chunk in manifest.split("\n---"):
        source_match = _SOURCE_RE.search(chunk)
        kind = name = ""
        for line in chunk.splitlines():
            stripped = line.strip()
            if not kind and stripped.startswith("kind:"):
                kind = stripped.split(":", 1)[1].strip()
            # the first `name:` at two-space indent is the metadata name; deeper
            # ones belong to containers, ports and the like
            elif not name and line.startswith("  name:"):
                name = line.split(":", 1)[1].strip().strip('"')
            if kind and name:
                break
        if kind:
            out.append(ManifestObject(kind=kind, name=name,
                                      source=source_match.group(1) if source_match else ""))
    return out


def decode_release(raw: Any) -> Tuple[Optional[ReleaseInfo], Optional[str]]:
    """Decode one stored Helm release. Never raises; returns (info, error).

    Accepts every shape Helm's storage drivers produce - base64 twice (the secret
    driver, which is the default), base64 once (the configmap driver), gzipped or
    plain JSON - by looking for the gzip magic after each unwrapping instead of
    assuming a fixed depth.
    """
    if raw is None:
        return None, "no release payload"
    blob = raw.encode() if isinstance(raw, str) else raw

    # Peel layers until JSON appears, testing what we have rather than assuming a
    # depth: the secret driver wraps twice, the configmap driver once, and a
    # hand-saved payload may be neither.
    for _ in range(4):
        if blob[:2] == _GZIP_MAGIC:
            try:
                blob = gzip.decompress(blob)
            except OSError as exc:
                return None, "gzip: %s" % exc
            continue
        if blob.lstrip()[:1] in (b"{", b"["):
            break
        try:
            blob = base64.b64decode(blob, validate=False)
        except (binascii.Error, ValueError) as exc:
            return None, "base64: %s" % exc
    else:
        return None, "could not find JSON or gzip after four unwrappings"

    try:
        payload = json.loads(blob)
    except (ValueError, UnicodeDecodeError) as exc:
        return None, "json: %s" % exc
    if not isinstance(payload, dict):
        return None, "release payload is not an object"

    chart = payload.get("chart") or {}
    metadata = chart.get("metadata") or {}
    info = payload.get("info") or {}
    deps = []
    for entry in metadata.get("dependencies") or []:
        deps.append(Dependency(
            name=entry.get("name") or "",
            alias=entry.get("alias"),
            condition=entry.get("condition"),
            version=entry.get("version"),
            enabled=entry.get("enabled", True),
        ))
    return ReleaseInfo(
        name=payload.get("name") or "",
        namespace=payload.get("namespace") or "",
        chart_name=metadata.get("name") or "",
        chart_version=metadata.get("version") or "",
        app_version=metadata.get("appVersion"),
        revision=int(payload.get("version") or 0),
        status=info.get("status") or "",
        last_deployed=info.get("last_deployed"),
        defaults=chart.get("values") or {},
        user=payload.get("config") or {},
        dependencies=deps,
        hooks=payload.get("hooks") or [],
        manifest=payload.get("manifest") or "",
    ), None


class Values:
    """The effective values of a release, plus how much they can be trusted.

    `trust` is the whole point of this class existing rather than passing a dict
    around:

    - `effective` - chart defaults merged with the user's values. A check can
      make a statement about a key nobody set.
    - `user` - only what someone wrote in a file. A check may NOT conclude
      anything from an absent key, because the chart default is unknown, and the
      role matrix disagrees with those defaults often enough that guessing is
      worse than skipping.
    - `none` - nothing was readable.
    """

    def __init__(self, defaults: Optional[dict] = None, user: Optional[dict] = None,
                 trust: str = "none", source: str = "", release: Optional[ReleaseInfo] = None,
                 notes: Optional[List[str]] = None, root: Sequence[str] = ()):
        self.defaults = defaults or {}
        self.user = user or {}
        self.effective = deep_merge(self.defaults, self.user)
        self.trust = trust
        self.source = source
        self.release = release
        self.notes = notes or []
        # Where the DSC's own values start. Applied by every accessor so a check
        # asks for `did.enabled` and gets the right answer whether the DSC is the
        # release or a dependency of one. Checks must not know about this.
        self.root: Tuple[str, ...] = tuple(root)

    @classmethod
    def empty(cls, why: str) -> "Values":
        return cls(trust="none", source=why)

    # ------------------------------------------------------------------ metadata

    @property
    def revision(self) -> Optional[int]:
        return self.release.revision if self.release else None

    @property
    def chart_version(self) -> Optional[str]:
        return self.release.chart_version if self.release else None

    def chart_at_least(self, version: str) -> Optional[bool]:
        return self.release.chart_at_least(version) if self.release else None

    def count(self) -> int:
        return len(_leaf_paths(self.effective))

    # -------------------------------------------------------------------- access

    @staticmethod
    def _dig(tree: Any, keys: Sequence[str]) -> Tuple[bool, Any]:
        cur = tree
        for key in keys:
            if not isinstance(cur, dict) or key not in cur:
                return False, None
            cur = cur[key]
        return True, cur

    def rooted(self, keys: Sequence[str]) -> Tuple[str, ...]:
        """A caller's path, resolved against the DSC's position in this release."""
        return self.root + tuple(keys)

    def get_at(self, keys: Sequence[str], default: Any = None) -> Any:
        """Look up an explicit key sequence - for keys that contain a dot."""
        found, value = self._dig(self.effective, self.rooted(keys))
        return value if found else default

    def get(self, dotted: str, default: Any = None) -> Any:
        return self.get_at(dotted.split("."), default)

    def origin(self, dotted: str) -> str:
        keys = self.rooted(dotted.split("."))
        if self._dig(self.user, keys)[0]:
            return "user"
        if self._dig(self.defaults, keys)[0]:
            return "chart"
        return "missing"

    def _where(self) -> str:
        if not self.release:
            return self.source or "the supplied values"
        return "release %s rev %d, chart %s" % (
            self.release.name, self.release.revision, self.release.chart)

    def tri(self, dotted: str, kind: str = "template") -> Tri:
        """Resolve a boolean toggle, with the reason attached.

        `kind` decides what an absent key means, and getting it wrong inverts the
        answer:

        - `dependency` - a `condition:` in Chart.yaml. Helm enables the
          dependency when the condition does not resolve, so absent means TRUE.
          `fdsc-edc` is the live proof.
        - `template`   - an `{{ if .Values.x.enabled }}` in the umbrella. Absent
          means FALSE.
        """
        keys = self.rooted(dotted.split("."))
        where = self._where()

        found, value = self._dig(self.user, keys)
        if found:
            return Tri(_as_bool(value), "user values: %s=%s (%s)" % (dotted, value, where),
                       "user")

        if self.trust == "none":
            return Tri(None, "values could not be read (%s)" % (self.source or "no source"),
                       "unknown")

        found, value = self._dig(self.defaults, keys)
        if found:
            return Tri(_as_bool(value), "chart default: %s=%s (%s)" % (dotted, value, where),
                       "chart")

        if self.trust == "user":
            return Tri(None,
                       "the supplied values do not set %s, and the chart defaults are unknown "
                       "without the live release; pass --effective-values or drop --values"
                       % dotted, "missing")

        if kind == "dependency":
            if self.root:
                # The stored release carries the *wrapper's* dependency list, not
                # the DSC's own, so there is nothing here to answer with. Saying
                # "not listed, therefore off" would be a confident wrong answer
                # about every optional component at once.
                return Tri(None,
                           "%s is unset, and this release only records the dependencies of "
                           "the chart that wraps the DSC (under %s), so whether Helm enabled "
                           "it cannot be read from the values; look at what is deployed"
                           % (dotted, ".".join(self.root)), "unknown")
            key = keys[0]
            dep = self.release.dependency(key) if self.release else None
            if dep is not None:
                return Tri(True, "%s lists the %s dependency (condition %s)"
                           % (where, dep.key, dep.condition or "none"), "dependency")
            return Tri(False, "%s is unset and %s does not list a %s dependency"
                       % (dotted, where, key), "dependency")
        return Tri(False, "%s is unset; the umbrella template treats that as disabled (%s)"
                   % (dotted, where), "chart")

    def to_json(self) -> dict:
        return {
            "trust": self.trust,
            "source": self.source,
            "keys": self.count(),
            "notes": self.notes,
        }


def _as_bool(value: Any) -> Optional[bool]:
    if isinstance(value, bool):
        return value
    if value is None:
        return None
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in ("true", "yes", "on", "1"):
            return True
        if lowered in ("false", "no", "off", "0", ""):
            return False
        return None
    if isinstance(value, (int, float)):
        return bool(value)
    # a dict or list under an `.enabled` path is a config mistake, not a boolean
    return None


# --------------------------------------------------------------------- discovery


def discover_releases(kube: Kube, namespace: str, progress=None
                      ) -> Tuple[Dict[str, ReleaseInfo], List[str]]:
    """Every DSC-family release live in the namespace, plus notes about the rest."""
    progress = progress or null()
    notes: List[str] = []
    found: Dict[str, ReleaseInfo] = {}

    progress.detail("listing helm releases")
    for kind in ("secret", "configmap"):
        try:
            data = kube.get_json(kind, namespace=namespace, check=False,
                                 selector=HELM_SELECTOR)
        except KubeError as exc:
            notes.append("could not list helm %ss: %s" % (kind, exc))
            continue
        for item in (data or {}).get("items", []) or []:
            name = (item.get("metadata") or {}).get("name") or ""
            raw = (item.get("data") or {}).get("release")
            info, error = decode_release(raw)
            if info is None:
                notes.append("helm release %s could not be decoded (%s)" % (name, error))
                continue
            info.secret = name
            # `family` matches the chart name OR a dependency, so a wrapper chart
            # that pulls the DSC in under an alias counts. Filtering on the chart
            # name alone is what made the ArgoCD environment invisible.
            if info.family == "unknown":
                continue
            info.namespace = info.namespace or namespace
            found[info.name] = info
        if found:
            break  # the secret driver is the default; do not double-count
    return found, notes


def choose_primary(releases: Dict[str, ReleaseInfo], preferred: Optional[str] = None,
                   lane_release: Optional[str] = None) -> Tuple[Optional[str], List[str]]:
    """Pick the release this run is about, and say so when the pick is a guess.

    A namespace routinely holds more than one: one provider has four releases and
    demo/dso-infra holds a participant, the trust anchor and two onboarding
    releases. Guessing silently would attribute one release's components to
    another, so anything less than certain produces a note.
    """
    notes: List[str] = []
    if not releases:
        return None, notes
    if preferred:
        if preferred in releases:
            return preferred, notes
        return None, ["--release %s is not a DSC release in this namespace (found: %s)"
                      % (preferred, ", ".join(sorted(releases)) or "none")]
    if lane_release and lane_release in releases:
        return lane_release, notes
    if len(releases) == 1:
        return next(iter(releases)), notes

    # A participant and a trust anchor sharing a namespace is a normal shape, not
    # an ambiguity: this tool checks participants, so the participant is the one
    # being asked about. demo/dso-infra is exactly that (central-mk + trust-anchor)
    # and used to yield no primary at all, which skipped every release-bound check.
    participants = {name: info for name, info in releases.items()
                    if info.family == "participant"}
    if len(participants) == 1:
        name = next(iter(participants))
        others = sorted(set(releases) - {name})
        notes.append("picked %s: it is the only participant release here (also present: "
                     "%s). Pass --release to choose another" % (name, ", ".join(others)))
        return name, notes

    described = ", ".join("%s (%s)" % (name, info.chart)
                          for name, info in sorted(releases.items()))
    notes.append("this namespace holds %d DSC releases: %s; pass --release to choose"
                 % (len(releases), described))
    return None, notes


def _helm_values(kube: Kube, namespace: str, release: str) -> Tuple[Optional[dict], Optional[str]]:
    """Transport fallback only - it buys no precision over our own merge (see 3.)."""
    if shutil.which("helm") is None:
        return None, "helm is not on PATH"
    cmd = ["helm"]
    if kube.context:
        cmd += ["--kube-context", kube.context]
    cmd += ["get", "values", release, "-n", namespace, "--all", "-o", "json"]
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, "helm: %s" % exc
    if proc.returncode != 0:
        return None, "helm: %s" % proc.stderr.decode("utf-8", "replace").strip().splitlines()[:1]
    try:
        return json.loads(proc.stdout or b"{}"), None
    except ValueError as exc:
        return None, "helm output: %s" % exc


def resolve(kube: Optional[Kube], namespace: str, releases: Optional[Dict[str, ReleaseInfo]],
            primary: Optional[str], overrides: Optional[dict] = None,
            load_document=None) -> Values:
    """Build the Values for a run, from the most precise source available.

    Order, and the reason for it:

    1. `--effective-values FILE` - someone already merged for us (CI with no
       cluster, at full precision).
    2. the live release - defaults AND user values, so an unset key still has an
       answer.
    3. `helm get values --all` - only if the stored release would not decode.
    4. `--values FILE` - replaces the *user layer* on top of whatever defaults
       stages 2 or 3 found.

    Stage 4 layering rather than replacing is a deliberate choice: it keeps full
    precision whenever a cluster is reachable, and it answers a question nobody
    could ask before - "what would happen if I applied this file?".
    """
    overrides = overrides or {}
    notes: List[str] = []

    effective_path = overrides.get("effectiveValues")
    values_paths = overrides.get("values") or []
    if isinstance(values_paths, str):
        values_paths = [values_paths]

    defaults: dict = {}
    user: dict = {}
    trust = "none"
    source = ""
    release = releases.get(primary) if (releases and primary) else None

    if effective_path:
        loaded = _read_document(effective_path, load_document, notes)
        if loaded is not None:
            defaults, trust = loaded, "effective"
            source = "--effective-values %s (revision unknown)" % effective_path
    elif release is not None:
        defaults, user = release.defaults, release.user
        trust = "effective"
        source = "secret %s (rev %d, chart %s, status %s)" % (
            release.secret or "?", release.revision, release.chart, release.status)
        if not defaults and kube is not None:
            fallback, error = _helm_values(kube, namespace, release.name)
            if fallback is not None:
                defaults, user = fallback, {}
                source += " + helm get values --all (stored chart values were empty)"
            else:
                notes.append("stored chart values were empty and the helm fallback "
                             "failed: %s" % error)

    if values_paths:
        merged: dict = {}
        for path in values_paths:
            loaded = _read_document(path, load_document, notes)
            if loaded is not None:
                merged = deep_merge(merged, loaded)
        user = merged
        if trust == "effective":
            source = "%s + --values %s" % (source or "chart defaults",
                                           ", ".join(values_paths))
        else:
            trust = "user"
            source = "--values %s (user values only; chart defaults unknown)" % \
                     ", ".join(values_paths)

    if trust == "none" and not source:
        source = ("no DSC release could be read in %s and no --values was given, so the "
                  "static phase has nothing to judge. The cluster checks still run; pass "
                  "--values <the file this was deployed from> to get the static phase "
                  "back (GitOps installs often leave no Helm release behind)" % namespace)

    root = _resolve_root(overrides, release, defaults, user, notes)
    return Values(defaults=defaults, user=user, trust=trust, source=source,
                  release=release, notes=notes, root=root)


# Keys that only a DSC values tree carries. Used to spot the tree when it is
# nested under a wrapper chart's alias and there is no release to ask.
_DSC_MARKERS = ("decentralizedIam", "fdsc-edc", "tm-forum-api", "contract-management",
                "identityhub", "scorpio", "marketplace", "trusted-issuers-list")


def _resolve_root(overrides: dict, release: Optional[ReleaseInfo],
                  defaults: dict, user: dict, notes: List[str]) -> Tuple[str, ...]:
    """Where the DSC's values start: declared, then from the release, then sniffed.

    The sniff exists because the case that needs it most has no release to ask:
    a GitOps install renders with `helm template`, so the values file is all there
    is, and in the dev environment that file nests everything under `dsc`.
    """
    declared = overrides.get("valuesRoot")
    if declared:
        keys = declared if isinstance(declared, (list, tuple)) else str(declared).split(".")
        return tuple(str(k).strip() for k in keys if str(k).strip())

    if release is not None:
        root = release.values_root
        if root:
            notes.append("the DSC is a dependency of chart %s, so its values live under "
                         "%s" % (release.chart_name, ".".join(root)))
        return root

    for tree in (user, defaults):
        root = _sniff_root(tree)
        if root:
            notes.append("values root detected as %s (the supplied file nests the DSC "
                         "under it); pass --values-root to override" % ".".join(root))
            return root
    return ()


def _sniff_root(tree: Any) -> Tuple[str, ...]:
    """A single nesting level, and only on strong evidence.

    Two markers rather than one on purpose: a file with a lone `keycloak:` key is
    far more likely to be a Keycloak values file than a wrapped DSC.
    """
    if not isinstance(tree, dict) or not tree:
        return ()
    if sum(1 for marker in _DSC_MARKERS if marker in tree) >= 2:
        return ()
    for key, value in tree.items():
        if isinstance(value, dict) and \
                sum(1 for marker in _DSC_MARKERS if marker in value) >= 2:
            return (str(key),)
    return ()


def _read_document(path: str, load_document, notes: List[str]) -> Optional[dict]:
    if load_document is None:
        notes.append("%s could not be read: no loader was provided" % path)
        return None
    try:
        loaded = load_document(path)
    except SystemExit as exc:            # _load_document raises this for a bad file
        notes.append("%s: %s" % (path, exc))
        return None
    except OSError as exc:
        notes.append("%s: %s" % (path, exc))
        return None
    if not isinstance(loaded, dict):
        notes.append("%s does not contain a values mapping" % path)
        return None
    return loaded
