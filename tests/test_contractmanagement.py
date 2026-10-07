"""contract-management's subscriptions, and the line between knowing and inferring.

The subscription itself is not observable. TMForum's `/hub` answers 405 - POST to
register, DELETE to remove, no listing - and contract-management logs nothing
about registering, with startup logs long rotated away. So a check here can
verify the declaration, can read a health indicator when it is exposed, and
cannot confirm the hubs exist. Saying which is which is the whole point; a check
that implied it had verified the subscription would be worse than none.

The ambiguous case is real and live: demo's `provider-central` has
`notification.enabled: false` with no local marketplace. That may be deliberate -
a central marketplace drives the chain - or it may be a provider that reacts to
nothing. From outside there is no way to tell, so it is a WARN that names both
readings rather than a FAIL that picks one.
"""

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fdsc_verify.checks import contractmanagement as cm  # noqa: E402
from fdsc_verify.model import Status
from fdsc_verify.values import Values  # noqa: E402

ALL_FOUR = [{"entityType": e} for e in
            ("ProductOffering", "ProductOrder", "Catalog", "Quote")]


def context(notification=None, marketplace=True, present=True, health=None,
            central=None):
    def service(name):
        if name == "contractmanagement":
            return "contract-management" if present else None
        if name == "marketplace":
            return "bae-logic-proxy" if marketplace else None
        return None

    tree = {"contract-management": {"enableCentralMarketplace": central}} \
        if central is not None else {}
    ctx = SimpleNamespace(
        values=Values(defaults=tree, trust="effective", source="test"),
        deployment=SimpleNamespace(namespace="ns", service=service),
        kube=SimpleNamespace(configmap=lambda name: {}, get_json=lambda *a, **k: {}))
    cm._notification = lambda _ctx: ((notification, None) if notification is not None
                                     else (None, "no config"))
    cm._health = lambda _ctx: ((health, None) if health is not None
                               else (None, "not reachable"))
    return ctx


class Restore(unittest.TestCase):
    def setUp(self):
        self._n, self._h = cm._notification, cm._health

    def tearDown(self):
        cm._notification, cm._health = self._n, self._h


class TestItOnlyAppliesWhereItCanMean(Restore):
    def test_no_contract_management_is_not_applicable(self):
        result = cm.contract_management_subscriptions(context(present=False))
        self.assertIs(result.status, Status.SKIP)
        self.assertFalse(result.applicable)


class TestSubscribedToNothing(Restore):
    def test_with_a_local_marketplace_it_is_unambiguous(self):
        result = cm.contract_management_subscriptions(
            context(notification={"enabled": False}, marketplace=True))
        self.assertIs(result.status, Status.FAIL)
        self.assertIn("no error to explain it", result.cause)

    def test_a_declared_central_marketplace_settles_it(self):
        """This WARN used to say, in its own words, that from outside there was no
        way to tell the two shapes apart. There is: a deployment that declares a
        central marketplace has said which one it is, and subscribing to its own
        catalogue is not its job."""
        result = cm.contract_management_subscriptions(
            context(notification={"enabled": False}, marketplace=False, central=True))
        self.assertIs(result.status, Status.SKIP)
        self.assertFalse(result.applicable)
        self.assertIn("central marketplace drives", result.summary)

    def test_with_neither_nothing_drives_the_catalogue(self):
        """No local marketplace, no central one declared: an offering can be
        published here and nothing will ever act on it."""
        result = cm.contract_management_subscriptions(
            context(notification={"enabled": False}, marketplace=False))
        self.assertIs(result.status, Status.WARN)
        self.assertIn("nothing drives", result.summary)
        self.assertIn("enableCentralMarketplace", result.fix)


class TestTheDeclaration(Restore):
    def test_a_missing_entity_type_is_named(self):
        result = cm.contract_management_subscriptions(context(notification={
            "enabled": True, "entities": [{"entityType": "ProductOffering"}]}))
        self.assertIs(result.status, Status.WARN)
        self.assertIn("ProductOrder", result.summary)
        self.assertIn("until the first purchase", result.cause)

    def test_all_four_declared_but_unreadable_says_so(self):
        result = cm.contract_management_subscriptions(
            context(notification={"enabled": True, "entities": ALL_FOUR}))
        self.assertIs(result.status, Status.WARN)
        self.assertIn("cannot be read", result.summary)
        self.assertIn("405", result.cause)
        self.assertIn("ENDPOINTS_HEALTH_DETAILS_VISIBLE", result.fix)


class TestTheHealthIndicator(Restore):
    def test_an_exposed_indicator_settles_it(self):
        result = cm.contract_management_subscriptions(context(
            notification={"enabled": True, "entities": ALL_FOUR},
            health={"status": "UP", "details": {"Subscription Health": {"status": "UP"}}}))
        self.assertIs(result.status, Status.OK)
        self.assertIn("health reports", result.summary)

    def test_a_down_indicator_is_the_one_direct_reading_available(self):
        result = cm.contract_management_subscriptions(context(
            notification={"enabled": True, "entities": ALL_FOUR},
            health={"status": "DOWN",
                    "details": {"Subscription Health": {"status": "DOWN"}}}))
        self.assertIs(result.status, Status.FAIL)
        self.assertIn("DOWN", result.summary)

    def test_a_roll_up_with_no_details_is_not_treated_as_evidence(self):
        """{"status":"UP"} says nothing about subscriptions; it must not pass."""
        result = cm.contract_management_subscriptions(context(
            notification={"enabled": True, "entities": ALL_FOUR},
            health={"status": "UP"}))
        self.assertIs(result.status, Status.WARN)
        self.assertIn("cannot be read", result.summary)


if __name__ == "__main__":
    unittest.main()
