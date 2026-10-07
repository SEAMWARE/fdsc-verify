"""What the operator declared about the deployment, and where each fact came from.

The tool points at a DSC that is **already deployed**, usually somebody else's.
Whoever runs it knows what that deployment is meant to be; the tool does not. So
every structural property resolves in one order, and the report says which step
answered:

    explicit flag  >  profile file (--config)  >  inference  >  unknown

Three consequences, and the third is the one that earns this module:

1. **Never guess silently.** `Lane.identity` already documents that `dcp.enabled`
   and `oid4vp.enabled` are both true on both lanes in every deployment
   inspected, so neither discriminates; the current tie-break is
   `fdscTransfer.{dcp,oid4vc}.enabled` plus the lane's own name. `--edc-protocol`
   turns that tie-break into a statement.
2. **Unknown is a legitimate state.** A field nobody declared and nothing could
   infer is `None`, which a check turns into SKIP with a reason - never into a
   verdict.
3. **A declaration is also an assertion.** Saying `--role provider` is not only
   an override: it is a claim the deployment has to live up to, and
   `deployment-profile` reports the contradiction when it does not. Saying
   `--edc` where no lane exists means either the flag is wrong or the connector
   never deployed, and both are worth a line.

The profile is deliberately a thin typed view over the same document `--config`
already accepted, not a parallel mechanism: `--role provider` is exactly
`role: provider` in the file. Everything the file supported before - synthetic
lanes, service names, identityhub tokens, timeouts - still lives in `raw` and is
read by `discovery._apply_overrides` unchanged.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

# The participant roles of the canonical component matrix
# (DSC/data-space-connector/doc/deployment-integration/roles/README.md). Operator
# is deliberately absent: a trust anchor is not a participant and this tool does
# not check one - it only has to avoid mistaking it for the participant when they
# share a namespace.
ROLES = ("consumer", "provider")
ROLE_ALIASES = {
    "consumer+provider": ("consumer", "provider"),
    "consumer-provider": ("consumer", "provider"),
    "provider+consumer": ("consumer", "provider"),
}

# The two identity protocols an EDC lane can speak. `oid4vp` is accepted because
# that is what the specification is called and what an operator will type; the
# deployment's own configuration key is `fdscTransfer.oid4vc.enabled`, so that is
# the spelling everything downstream uses.
EDC_PROTOCOLS = ("dcp", "oid4vc")
PROTOCOL_ALIASES = {"oid4vp": "oid4vc"}

_FLAG_SOURCE = "flag"
_FILE_SOURCE = "--config"


class ProfileError(ValueError):
    """A declaration that cannot be honoured. Always a usage error, never a finding."""


class Profile:
    """The declared shape of the deployment, with provenance per field.

    Fields are `None` when nobody declared them - which is the common case, and
    is why every consumer has to treat `None` as "ask discovery", not as "false".
    """

    def __init__(self, raw: Optional[dict] = None):
        self.raw: dict = raw if raw is not None else {}
        self._origins: Dict[str, str] = {}
        self.roles: Optional[Tuple[str, ...]] = None
        self.edc: Optional[bool] = None
        self.edc_protocol: Optional[str] = None
        self.did: Optional[str] = None
        self.identity_secret: Optional[str] = None
        self.values_root: Optional[Tuple[str, ...]] = None
        self.components: Dict[str, bool] = {}
        self.release: Optional[str] = None

    # ------------------------------------------------------------------ building

    @classmethod
    def from_args(cls, args, config: Optional[dict] = None) -> "Profile":
        """Merge the profile file and the flags, flags winning, validating both.

        Validation happens here rather than in argparse because the same keys
        arrive by two routes, and a bad value in the file has to fail as loudly
        as a bad value on the command line.
        """
        profile = cls(dict(config or {}))
        profile._take_roles(getattr(args, "role", None))
        profile._take_edc(getattr(args, "edc", None))
        profile._take_protocol(getattr(args, "edc_protocol", None))
        profile._take_scalar("did", getattr(args, "did", None), "--did")
        profile._take_scalar("identity_secret", getattr(args, "identity_secret", None),
                             "--identity-secret")
        profile._take_values_root(getattr(args, "values_root", None))
        profile._take_components(getattr(args, "component", None))
        profile._take_release(getattr(args, "release", None))
        return profile

    def _set(self, field: str, value, origin: str) -> None:
        setattr(self, field, value)
        self._origins[field] = origin

    def _take_roles(self, flag: Optional[str]) -> None:
        value, origin = self._pick(flag, "role", "--role")
        if value is None:
            return
        tokens: List[str] = []
        raw_items = value if isinstance(value, (list, tuple)) else str(value).split(",")
        for item in raw_items:
            name = str(item).strip().lower()
            if not name:
                continue
            if name in ROLE_ALIASES:
                tokens.extend(ROLE_ALIASES[name])
            elif name in ROLES:
                tokens.append(name)
            else:
                raise ProfileError(
                    "%s: unknown role %r (expected any of %s, or consumer+provider)"
                    % (origin, item, ", ".join(ROLES)))
        if tokens:
            # sorted so "provider,consumer" and "consumer+provider" are one value
            self._set("roles", tuple(sorted(set(tokens))), origin)

    def _take_edc(self, flag: Optional[bool]) -> None:
        if flag is not None:
            self._set("edc", bool(flag), "--edc" if flag else "--no-edc")
            return
        block = self.raw.get("edc")
        if isinstance(block, dict) and "enabled" in block:
            self._set("edc", bool(block["enabled"]), _FILE_SOURCE)
        elif isinstance(block, bool):
            self._set("edc", block, _FILE_SOURCE)

    def _take_protocol(self, flag: Optional[str]) -> None:
        value, origin = self._pick(flag, ("edc", "protocol"), "--edc-protocol")
        if value is None:
            return
        name = str(value).strip().lower()
        name = PROTOCOL_ALIASES.get(name, name)
        if name not in EDC_PROTOCOLS:
            raise ProfileError("%s: unknown EDC protocol %r (expected %s; oid4vp is "
                               "accepted as oid4vc)"
                               % (origin, value, " or ".join(EDC_PROTOCOLS)))
        self._set("edc_protocol", name, origin)
        # Declaring a protocol declares the connector: refusing to join those two
        # would let `--no-edc --edc-protocol dcp` through as a silent nonsense.
        if self.edc is False:
            raise ProfileError("--no-edc and %s contradict each other: a protocol is "
                               "something only a deployed connector can speak" % origin)
        if self.edc is None:
            self._set("edc", True, "implied by %s" % origin)

    def _take_scalar(self, field: str, flag: Optional[str], flag_name: str) -> None:
        key = {"did": "did", "identity_secret": ("identity", "secret")}[field]
        value, origin = self._pick(flag, key, flag_name)
        if value is None:
            return
        text = str(value).strip()
        if not text:
            raise ProfileError("%s: empty value" % origin)
        if field == "did" and not text.startswith("did:"):
            raise ProfileError("%s: %r is not a DID (expected something starting with "
                               "'did:', e.g. did:web:example.org)" % (origin, text))
        self._set(field, text, origin)
        # Mirrored into the document so `discovery._apply_overrides`, which owns
        # `Deployment.identity_secret`, needs no new wiring: the flags really are
        # shorthand for the file, including where the file already had a key.
        identity = self.raw.setdefault("identity", {})
        if isinstance(identity, dict):
            identity["secret" if field == "identity_secret" else "participantId"] = text

    def _take_values_root(self, flag: Optional[str]) -> None:
        value, origin = self._pick(flag, "valuesRoot", "--values-root")
        if value is None:
            return
        keys = value if isinstance(value, (list, tuple)) else str(value).split(".")
        path = tuple(str(k).strip() for k in keys if str(k).strip())
        if not path:
            raise ProfileError("%s: empty values root" % origin)
        self._set("values_root", path, origin)

    def _take_components(self, flags: Optional[List[str]]) -> None:
        declared: Dict[str, bool] = {}
        origin = None
        from_file = self.raw.get("components")
        if isinstance(from_file, dict):
            for name, state in from_file.items():
                declared[str(name)] = _as_bool(state, "%s: components.%s"
                                               % (_FILE_SOURCE, name))
            origin = _FILE_SOURCE
        for item in flags or []:
            if "=" not in item:
                raise ProfileError("--component %s: expected name=on or name=off" % item)
            name, _, state = item.partition("=")
            declared[name.strip()] = _as_bool(state, "--component %s" % item)
            origin = "--component"
        if declared:
            self._set("components", declared, origin or _FILE_SOURCE)

    def _take_release(self, flag: Optional[str]) -> None:
        value, origin = self._pick(flag, "release", "--release")
        if value is not None:
            self._set("release", str(value), origin)
            # kept in raw as well: choose_primary already reads it from there
            self.raw["release"] = str(value)

    def _pick(self, flag, key, flag_name: str):
        """Flag first, then the file. Returns (value, where it came from)."""
        if flag is not None:
            return flag, flag_name
        keys = key if isinstance(key, tuple) else (key,)
        node = self.raw
        for part in keys:
            if not isinstance(node, dict) or part not in node:
                return None, None
            node = node[part]
        return node, _FILE_SOURCE

    # ------------------------------------------------------------------- reading

    def origin(self, field: str) -> Optional[str]:
        """How this field was declared, or None when nobody declared it."""
        return self._origins.get(field)

    def declared(self) -> Dict[str, object]:
        """Everything the operator said, for the report and for --json."""
        out: Dict[str, object] = {}
        for field in ("roles", "edc", "edc_protocol", "did", "identity_secret",
                      "values_root", "components", "release"):
            value = getattr(self, field)
            if value is None or value == {} or value == ():
                continue
            if field == "values_root":
                value = ".".join(value)
            elif field == "roles":
                value = list(value)
            out[field] = {"value": value, "from": self._origins.get(field)}
        return out

    def is_empty(self) -> bool:
        return not self._origins

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "Profile(%s)" % ", ".join(
            "%s=%r" % (k, getattr(self, k)) for k in sorted(self._origins))


def _as_bool(value, where: str) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in ("on", "true", "yes", "1", "enabled"):
        return True
    if text in ("off", "false", "no", "0", "disabled"):
        return False
    raise ProfileError("%s: expected on/off, got %r" % (where, value))
