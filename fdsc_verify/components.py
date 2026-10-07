"""Which components a role needs, and how to tell whether each one is there.

The canonical table lives in
`DSC/data-space-connector/doc/deployment-integration/roles/README.md`. It is
reproduced here as data rather than prose because three checks need to agree on
it, and because the interesting question is never "what does the table say" but
"does this deployment match the row it claims".

Two rules decide every answer, and they are the tool's two authorities:

- **Presence is the cluster's to answer.** A Service that exists is a component
  that is there, whoever deployed it - in one environment the did-helper is a
  subchart and in another it is a sibling release, and both are correct. Values
  that enable a component with no Service behind it are a finding, not an
  absence.
- **Intent and the fix are the values' to answer.** A FAIL has to name the key
  somebody will edit, which is why every entry carries its values path.

The values path is the *weakest* of the three signals and is never used alone to
call a component missing. It cannot be: the identity components live two subchart
levels down (`decentralizedIam.vcAuthentication.…`), the sub-umbrella's own
dependency list is not stored in the release, and `fdsc-edc` carries no `enabled`
key at all while being deployed - so an absent key there means "Helm decided",
not "off".
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional, Tuple

REQUIRED = "required"
OPTIONAL = "optional"
NOT_APPLICABLE = "-"


@dataclass(frozen=True)
class Component:
    """One row of the matrix, plus the three ways to look for it."""

    key: str                     # what discovery calls it in Deployment.services
    label: str                   # what the canonical table calls it
    consumer: str
    provider: str
    values_path: Optional[str] = None
    # `dependency` for a subchart of the umbrella, `template` for a block the
    # umbrella renders itself. Getting this backwards inverts the answer for an
    # unset key - see Values.tri.
    values_kind: str = "template"
    # Other components that satisfy the same requirement. A requirement is about a
    # capability, not about a Deployment object: the DID document is served by the
    # did-helper OR by the IdentityHub, and in current charts the
    # credentials-config API is served by the verifier's own config port rather
    # than by a standalone service. Without this, every deployment inspected
    # reported the same two components missing while working perfectly.
    satisfied_by: Tuple[str, ...] = ()
    # The directory name this component's templates render under, used to ask the
    # rendered manifest whether Helm actually produced anything for it.
    chart_dir: Optional[str] = None
    note: str = ""

    def requirement(self, roles: Tuple[str, ...]) -> str:
        """The strongest requirement across the roles this deployment plays."""
        levels = [getattr(self, role) for role in roles if hasattr(self, role)]
        if REQUIRED in levels:
            return REQUIRED
        if OPTIONAL in levels:
            return OPTIONAL
        return NOT_APPLICABLE


# The canonical matrix. Keycloak and the DID document are Required for every
# participant role; the identity and authorization stack is Required for a
# Provider and absent for a pure Consumer; everything that carries data is
# Optional, FDSC-EDC included - which is the fact this whole generalization
# rests on.
MATRIX: Tuple[Component, ...] = (
    Component("keycloak", "Keycloak (VC issuer)", REQUIRED, REQUIRED,
              "keycloak.enabled", "dependency"),
    Component("did", "DID document", REQUIRED, REQUIRED,
              "did.enabled", "dependency", satisfied_by=("identityhub",),
              note="served by the IdentityHub instead when a DCP lane is deployed"),
    Component("verifier", "VCVerifier", NOT_APPLICABLE, REQUIRED,
              "decentralizedIam.vcAuthentication.vcverifier.enabled"),
    Component("ccs", "credentials-config-service", NOT_APPLICABLE, REQUIRED,
              "decentralizedIam.vcAuthentication.credentials-config-service.enabled",
              satisfied_by=("verifier",),
              note="the verifier serves the same configuration API on its config port "
                   "(8090) in the charts deployed here, so a standalone service is one "
                   "way to have it rather than the only one"),
    Component("til", "trusted-issuers-list", NOT_APPLICABLE, REQUIRED,
              "decentralizedIam.vcAuthentication.trusted-issuers-list.enabled"),
    Component("apisix", "APISIX gateway", NOT_APPLICABLE, REQUIRED,
              "decentralizedIam.odrlAuthorization.apisix.enabled"),
    Component("odrlpap", "odrl-pap", NOT_APPLICABLE, REQUIRED,
              "decentralizedIam.odrlAuthorization.odrl-pap.enabled"),
    Component("tmforum", "tmforum-api", NOT_APPLICABLE, OPTIONAL,
              "tm-forum-api.enabled", "dependency"),
    Component("contractmanagement", "contract-management", NOT_APPLICABLE, OPTIONAL,
              "contract-management.enabled", "dependency"),
    Component("broker", "NGSI-LD broker", NOT_APPLICABLE, OPTIONAL,
              "scorpio.enabled", "dependency"),
    # Its own key, not `marketplace.enabled`: sharing that one would have made the
    # charging backend read as present whenever the marketplace was switched on,
    # whatever the cluster held - which is exactly the question this component
    # exists to ask. `template` kind, because for a subchart's own block an absent
    # key does mean off.
    Component("marketplacecharging", "marketplace (charging backend)",
              NOT_APPLICABLE, OPTIONAL,
              "marketplace.bizEcosystemChargingBackend.enabled", "template",
              note="half of the BAE; the logic proxy is the other half"),
    Component("marketplace", "marketplace", NOT_APPLICABLE, OPTIONAL,
              "marketplace.enabled", "dependency",
              note="a provider may use a central one instead of its own"),
    Component("edc", "FDSC-EDC", OPTIONAL, OPTIONAL,
              "fdsc-edc.enabled", "dependency", chart_dir="fdsc-edc",
              note="the lanes are discovered directly, not through this key"),
    Component("identityhub", "IdentityHub", OPTIONAL, OPTIONAL,
              "identityhub.enabled", "dependency",
              note="comes with a DCP lane and then serves the DID document"),
)

BY_KEY: Dict[str, Component] = {component.key: component for component in MATRIX}

# Components whose presence implies another must be there too. Each is a real
# dependency, not a stylistic rule: the verifier asks the ccs what to demand and
# the TIL whether the issuer is trusted, the gateway delegates to OPA running the
# Rego odrl-pap produces, and the EDC stores its assets in TMForum.
IMPLIES: Tuple[Tuple[str, Tuple[str, ...], str], ...] = (
    ("verifier", ("ccs", "til"),
     "the verifier asks the credentials-config-service which credentials a service "
     "demands and the trusted-issuers-list whether the issuer is trusted"),
    ("apisix", ("odrlpap",),
     "the gateway delegates the decision to OPA, which runs the Rego that odrl-pap "
     "generates from the ODRL policies"),
    ("edc", ("tmforum",),
     "the EDC uses the TMForum APIs as the storage backend for assets, contracts "
     "and policies"),
    ("marketplace", ("marketplacecharging", "tmforum"),
     "the BAE is not one service: the logic proxy authenticates the user and the "
     "charging backend turns an order into something billable, and both read and "
     "write the catalogue through the TMForum APIs"),
)


def roles_for(deployment, profile) -> Tuple[Tuple[str, ...], str]:
    """(roles, how we know). Declared beats inferred, and unknown is allowed.

    Inference reads what is deployed rather than what the values ask for, because
    a component that is running is a component the deployment has whoever
    installed it. A Provider is recognised by the authorization stack it must run
    to verify anybody; a Consumer by having an identity and nothing to verify
    with. Neither is a guess dressed as a fact: when nothing distinguishes them
    the answer is `()`, which every consumer of this turns into a SKIP.
    """
    if profile is not None and getattr(profile, "roles", None):
        return profile.roles, profile.origin("roles") or "declared"

    services = deployment.services
    provider_side = [key for key in ("verifier", "ccs", "til", "apisix", "odrlpap")
                     if services.get(key)]
    consumer_side = [key for key in ("keycloak", "did", "identityhub")
                     if services.get(key)]
    roles = []
    if provider_side:
        roles.append("provider")
    if consumer_side:
        roles.append("consumer")
    if not roles:
        return (), "nothing deployed identifies a role"
    return tuple(sorted(roles)), "inferred from %s" % ", ".join(
        sorted(provider_side + consumer_side))


@dataclass(frozen=True)
class Presence:
    """Whether a component is there, what was asked for, and how we know.

    `present` and `wanted` are deliberately separate. "Off and absent" is a
    correctly built deployment; "enabled and absent" is a component that failed
    to come up, and reporting the two the same way is how a tool loses an
    operator's trust.
    """

    present: Optional[bool]
    wanted: Optional[bool]
    why: str

    @property
    def unknown(self) -> bool:
        return self.present is None


def presence(deployment, values, profile, key: str) -> Presence:
    """Three sources, in the order the tool trusts them.

    What the operator declared, then what is running, and only then what the
    values asked for - which never on its own makes a component present.
    """
    declared = (getattr(profile, "components", None) or {}).get(key)
    if declared is not None:
        return Presence(declared, declared,
                        "declared %s" % ("present" if declared else "absent"))

    service = deployment.services.get(key)
    if service:
        return Presence(True, None, "service %s" % service)
    if key == "edc" and deployment.edc_lanes:
        return Presence(True, None, "%d EDC lane(s)" % len(deployment.edc_lanes))

    component = BY_KEY.get(key)
    for alternative in (component.satisfied_by if component else ()):
        other = deployment.services.get(alternative)
        if other:
            return Presence(True, None, "provided by %s (service %s)"
                            % (BY_KEY[alternative].label if alternative in BY_KEY
                               else alternative, other))

    if component is None or values is None or not component.values_path:
        return Presence(None, None, "nothing to read")
    tri = values.tri(component.values_path, kind=component.values_kind)
    if tri.unknown:
        return Presence(None, None, tri.why)
    if tri.is_true and component.chart_dir:
        # "Enabled" from a dependency list is not the same as deployed. A release
        # can list a dependency and render nothing from it - provider-central
        # lists fdsc-edc and its manifest holds not one object of it - and calling
        # that "enabled but not running" sends the operator hunting a crashed
        # workload that was never created.
        rendered = _rendered(values.release, component.chart_dir)
        if rendered is False:
            return Presence(False, False,
                            "%s lists it, but the release rendered no %s objects"
                            % (tri.origin, component.chart_dir))
    return Presence(False, tri.is_true, tri.why)


def _rendered(release, chart_dir: str) -> Optional[bool]:
    """Did Helm render anything from this subchart? None when there is no manifest."""
    if release is None or not getattr(release, "manifest", ""):
        return None
    marker = "/%s/" % chart_dir
    for obj in release.manifest_index():
        source = obj.source or ""
        if marker in source or source.startswith("%s/" % chart_dir):
            return True
    return False
