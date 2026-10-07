"""Core data model: what a deployment looks like, and what a check returns."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Callable, Dict, List, Optional, Tuple

if TYPE_CHECKING:  # avoids coupling the core model to the values reader
    from .values import ReleaseInfo, Values


class Status(enum.Enum):
    """Outcome of a single check.

    WARN is for things that are true and worth knowing but not broken - a
    hard-coded token lifetime, vault in dev mode. They do not fail the run
    unless --strict is given, because otherwise nobody would look at them.
    """

    OK = "OK"
    WARN = "WARN"
    FAIL = "FAIL"
    SKIP = "SKIP"
    ERROR = "ERROR"  # the check itself blew up; a tool bug, not a deployment one


@dataclass
class Result:
    """What a check reports.

    `cause` and `fix` are the point of this tool. A bare OK/FAIL tells the
    operator what they already knew ("it does not work"); the expensive part is
    always *why*, so a FAIL without a cause is considered incomplete.
    """

    status: Status
    summary: str
    cause: Optional[str] = None
    fix: Optional[str] = None
    doc: Optional[str] = None
    detail: Dict[str, object] = field(default_factory=dict)
    # False = "not applicable" rather than "could not answer". Both are SKIP, because
    # neither is a finding and neither may be reported as a pass; the difference is
    # whether the tool owes you something. See `na()`.
    applicable: bool = True

    @classmethod
    def ok(cls, summary: str, **detail) -> "Result":
        return cls(Status.OK, summary, detail=detail)

    @classmethod
    def warn(cls, summary: str, cause: str = None, fix: str = None, doc: str = None, **detail) -> "Result":
        return cls(Status.WARN, summary, cause, fix, doc, detail)

    @classmethod
    def fail(cls, summary: str, cause: str = None, fix: str = None, doc: str = None, **detail) -> "Result":
        return cls(Status.FAIL, summary, cause, fix, doc, detail)

    @classmethod
    def skip(cls, summary: str, cause: str = None) -> "Result":
        """Could not answer: the question applies here and the tool failed to settle it.

        A coverage gap. It stays visible in the report, because an operator who does
        not know the tool went quiet cannot know to go and look themselves.
        """
        return cls(Status.SKIP, summary, cause)

    @classmethod
    def na(cls, summary: str, cause: str = None) -> "Result":
        """Not applicable: the question does not arise for this deployment or scope.

        There is no fdsc-edc here; no dashboard is deployed; the operator asked for one
        transport and this breaks the other. The tool owes nothing, so the row is left
        out of the text report and summarised in the header instead - it stays in
        `--json` and under `-v`, because the *reason* a check did not run is data even
        when it is not news.

        The line between this and `skip()` is the whole point: "no vault service in this
        namespace" is a fact about the deployment, while "could not read the verifier's
        config repo" is a fact about the run. Reporting them the same way is what made a
        healthy no-EDC deployment produce seventeen SKIPs that nobody read.
        """
        return cls(Status.SKIP, summary, cause, applicable=False)


@dataclass
class EdcLane:
    """One EDC controlplane instance and everything its ConfigMap tells us.

    `props` is the parsed dataspaceconnector-configuration.properties, which is
    the single richest discovery source in the whole deployment: ports, paths,
    participant id, the STS alias, the holder kid, the TIL address. Checks read
    it instead of hard-coding anything.
    """

    name: str  # "dcp" / "oid4vc" - taken from the ConfigMap suffix, not assumed
    release: str
    deployment: str
    service: str
    configmap: str
    props: Dict[str, str]

    def prop(self, key: str, default: Optional[str] = None) -> Optional[str]:
        return self.props.get(key, default)

    @property
    def participant_id(self) -> Optional[str]:
        return self.prop("edc.participant.id")

    @property
    def hostname(self) -> Optional[str]:
        return self.prop("edc.hostname")

    def port(self, api: str, default: str) -> str:
        return self.prop("web.http.%s.port" % api, default)

    def path(self, api: str, default: str) -> str:
        return self.prop("web.http.%s.path" % api, default)

    @property
    def identity(self) -> str:
        """Which identity protocol this lane actually speaks: 'dcp', 'oid4vc' or 'unknown'.

        One place to be right about this, because several checks change verdict on
        it. The obvious candidates do NOT work: `dcp.enabled` and `oid4vp.enabled`
        are both true on both lanes in every deployment inspected, so either would
        classify every lane as DCP.

        `fdscTransfer.{dcp,oid4vc}.enabled` are mutually exclusive and correct,
        verified across three deployments. The lane name is only a tiebreaker for
        a config that sets neither.
        """
        dcp = self.prop("fdscTransfer.dcp.enabled", "").lower() == "true"
        oid4vc = self.prop("fdscTransfer.oid4vc.enabled", "").lower() == "true"
        if dcp and not oid4vc:
            return "dcp"
        if oid4vc and not dcp:
            return "oid4vc"
        lowered = self.name.lower()
        if lowered in ("dcp", "oid4vc"):
            return lowered
        return "unknown"

    @property
    def speaks_dcp(self) -> bool:
        return self.identity == "dcp"

    @property
    def protocol_url(self) -> Optional[str]:
        """Public DSP endpoint, as a counterparty would address it."""
        if not self.hostname:
            return None
        return "https://%s%s" % (self.hostname, self.path("protocol", "/api/dsp"))

    @property
    def management_url(self) -> str:
        """In-cluster management API. Not exposed publicly, so always via the service."""
        return "http://%s:%s%s" % (
            self.service,
            self.port("management", "8085"),
            self.path("management", "/api/v1/management"),
        )


@dataclass
class Peer:
    """A counterparty, for whichever transport this deployment shares with it.

    Only `participant_id` is required. **`protocol_url` is the DSP endpoint and is
    optional**, because most of what a peer is good for needs nothing but its DID:
    whether its DID document resolves, whether our DID is in its trusted issuers
    list, whether the credential it stores still verifies. A counterparty reached
    through its gateway rather than through the Dataspace Protocol has no DSP
    endpoint at all, and demanding one would have meant inventing a URL nobody
    uses. The DSP checks skip with a reason when it is absent.

    `context`/`namespace` are optional too and unlock the both-sides checks when we
    happen to have kube access to the other side.
    """

    name: str
    participant_id: str
    protocol_url: Optional[str] = None
    context: Optional[str] = None
    namespace: Optional[str] = None
    lane: Optional[str] = None  # which of our lanes it pairs with; None = any


@dataclass
class Deployment:
    """Everything discovery found about one FDSC.

    `release` is the release *name* and predates the values reader - it is
    inferred from a lane's ConfigMap. `releases` and `primary_release` come from
    Helm's own storage, which is the only source that works when there are no
    lanes at all: a consumer with fdsc-edc off, or the trust anchor, whose
    namespace holds nothing but `tir`.
    """

    context: Optional[str]
    namespace: str
    release: Optional[str]
    edc_lanes: Dict[str, EdcLane] = field(default_factory=dict)
    services: Dict[str, str] = field(default_factory=dict)
    identity_secret: Optional[str] = None
    identity_secret_key: Optional[str] = None
    notes: List[str] = field(default_factory=list)
    releases: Dict[str, "ReleaseInfo"] = field(default_factory=dict)
    primary_release: Optional[str] = None
    values: Optional["Values"] = None

    def lane(self, name: str) -> Optional[EdcLane]:
        return self.edc_lanes.get(name)

    def service(self, name: str) -> Optional[str]:
        return self.services.get(name)

    @property
    def primary(self) -> Optional["ReleaseInfo"]:
        return self.releases.get(self.primary_release) if self.primary_release else None

    @property
    def family(self) -> str:
        """participant | operator | unknown - which role family this can play.

        Drives whether the participant component table applies at all. Without it
        a trust-anchor namespace would be measured against a matrix of components
        it is never meant to run, and report a screenful of absurd findings.
        """
        primary = self.primary
        return primary.family if primary else "unknown"


TRANSPORTS: Tuple[str, ...] = ("fiware", "edc")
"""How data actually moves in a FIWARE dataspace, and both can be deployed at once.

- `fiware` the FIWARE DSC path: a VC presented to the verifier, exchanged for a token,
           and spent at the gateway, which asks OPA whether the ODRL policy allows it.
- `edc`    Dataspace Protocol over fdsc-edc: catalog, contract negotiation, transfer, EDR.

They are named after the flows people name in this dataspace. `native` and `dsp` said the
same thing in the tool's own vocabulary and nobody else's - and `dsp` in particular
collided with the protocol, which is still called DSP everywhere it legitimately appears:
the `/api/dsp` path, the `dsp-route` check, `dsp-controlplane`.

A deployment with both runs both, and they fail independently - which is why a check
declares which path its finding is about, and `--transport` can ask for one at a time.
A check with none declared is about the deployment rather than about a data path, and
runs either way.

**It is a set, and what it means is which path a failure here BREAKS** - not which one
the check itself traverses. The narrower reading (what it exercises) left every
preflight check undeclared, because reading a ConfigMap traverses nothing, and
`--transport fiware` then ran the eight lane-scoped ones anyway. The set matters for at
least one real case: `verifier-jwks-matches-key` is lane-scoped, so it looks like an fdsc-edc
check, but a stale JWKS at the gateway breaks every route APISIX guards - the DSP
callbacks *and* the FIWARE data services. Forcing it to pick one would have hidden it in
the mode where it matters most.
"""

ROLES: Tuple[str, ...] = ("consumer", "provider")
"""The participant roles of the canonical component matrix.

Operator is deliberately absent: a trust anchor is not a participant and this tool
does not check one. Kept here rather than in `components` so the `@check` decorator
can validate a declaration without importing the matrix.
"""

PHASES: Tuple[str, ...] = ("static", "preflight", "flow")
"""The phases, in the order they run and in the order they are reported.

A phase says *when* a check runs and what it blocks - not what it costs and not
what it needs. Reading a Deployment is perfectly static; requirements live in the
`needs_*` flags. Do not reach for `phase="static"` as a synonym for "no cluster".

- `static`   configuration as declared: values, the role matrix, cross-component
             consistency. Answers "is this deployment built right".
- `preflight` live identity: DID documents, JWKS, credentials, certificates, the
             trusted issuers list. Answers "is this deployment wired right".
- `flow`     negotiation and transfer. Answers "does it actually work".

A FAIL in an earlier phase does not stop a later *diagnostic* phase, but it does
close the gate on `flow` - see `runner.run`.
"""


@dataclass
class Check:
    """A registered check.

    Requirements are declared, not discovered at runtime, so the runner can skip
    with a precise reason ("needs cluster access", "needs --peer") instead of
    failing. The tool has to stay useful with nothing but HTTP access.
    """

    id: str
    title: str
    fn: Callable
    phase: str = "preflight"  # one of PHASES
    needs_cluster: bool = False
    needs_peer: bool = False
    lanes: Optional[List[str]] = None  # None = lane-independent, runs once
    mutates: bool = False
    needs_values: bool = False         # cannot conclude anything without the values
    needs_release: bool = False        # needs to know WHICH release it is looking at
    # Which participant roles this check applies to; () = every one. A check gated
    # here skips with "not applicable to a consumer" rather than failing for some
    # unrelated reason twelve lines further down.
    roles: Tuple[str, ...] = ()        # consumer | provider
    # Which data paths a failure here breaks; () = none, so it always runs. See the
    # TRANSPORTS docstring: a set, because a finding can break both.
    transports: Tuple[str, ...] = ()   # any of TRANSPORTS


REGISTRY: List[Check] = []


def check(id: str, title: str, phase: str = "preflight", needs_cluster: bool = False,
          needs_peer: bool = False, lanes: Optional[List[str]] = None, mutates: bool = False,
          needs_values: bool = False, needs_release: bool = False,
          roles: Tuple[str, ...] = (), transport=()):
    """Register a check. Order of registration is the order of the report.

    The phase and the id are validated at import time on purpose. A mistyped
    phase used to leave the check silently unregistered-for-any-phase: it never
    ran and never appeared in the report, which is the worst possible failure for
    a tool whose job is to notice things. A duplicated id is just as quiet - both
    checks run and `--only` picks an arbitrary one.
    """
    if phase not in PHASES:
        raise ValueError("check %r: unknown phase %r (expected one of %s)"
                         % (id, phase, ", ".join(PHASES)))
    if any(spec.id == id for spec in REGISTRY):
        raise ValueError("check %r is already registered" % id)
    # Validated for the same reason as the phase: a misspelled role would gate the
    # check out of every run and say nothing, which is the failure this replaced -
    # `families` accepted anything and no check ever declared one.
    unknown = [role for role in roles if role not in ROLES]
    if unknown:
        raise ValueError("check %r: unknown role(s) %s (expected any of %s)"
                         % (id, ", ".join(unknown), ", ".join(ROLES)))
    # A single string stays legal - most checks name one path and `transport="edc"`
    # reads better than a one-tuple - but it is stored as a set either way.
    transports = (transport,) if isinstance(transport, str) and transport else tuple(transport)
    unknown = [t for t in transports if t not in TRANSPORTS]
    if unknown:
        raise ValueError("check %r: unknown transport(s) %s (expected any of %s)"
                         % (id, ", ".join(unknown), ", ".join(TRANSPORTS)))

    def wrap(fn):
        REGISTRY.append(Check(id, title, fn, phase, needs_cluster, needs_peer, lanes,
                              mutates, needs_values, needs_release, roles, transports))
        return fn

    return wrap
