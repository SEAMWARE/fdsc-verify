"""The four ways the flow phase reported something that was not true.

Every case here was found by running the phase for the first time against demo,
and each one is a check misreading a healthy deployment - which is worse than a
missed fault, because the operator goes and looks for something that is not there.

1. A negotiation reaching VERIFIED was called done. On the consumer side VERIFIED
   means "I sent my verification"; the provider finalizes after it, and only then
   is the agreement in our store. flow-transfer fired immediately and the EDC
   answered `Contract agreement <id> not found` - correctly. Measured: the same
   negotiation read FINALIZED moments later with that exact agreement resolvable.
2. A stalled negotiation was blamed on the broker dropping JSON-LD keywords,
   unconditionally, while `tmforum-reserved-words` in the same report said the
   escape could not be lost on that deployment. The real cause was a NullPointer
   in TMFEdcMapper rebuilding a loopback negotiation.
3. The gateway probe followed redirects, so an APISIX route with
   `bearer_only: false` - which refuses by redirecting to the IdP - looked like a
   host serving data to anybody.
4. The TMForum probe wrote a property outside the Quote schema with no
   `@schemaLocation`, so it was refused and the check skipped on every run.
"""

import inspect
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fdsc_verify.checks import broker, fiware, flows  # noqa: E402
from fdsc_verify.model import Status  # noqa: E402


def resp(status, headers=None):
    return SimpleNamespace(
        status=status, error=None, ok=200 <= status < 300,
        header=lambda name: (headers or {}).get(name))


class TestVerifiedIsNotDone(unittest.TestCase):
    def test_only_finalized_settles_a_negotiation(self):
        self.assertEqual(flows.NEGOTIATION_DONE, {"FINALIZED"})

    def test_verified_is_still_accepted_once_a_transfer_is_running(self):
        # the transfer's own poll keeps the wider set; it is the negotiation that
        # must not hand an unregistered agreement to the next step
        self.assertIn("VERIFIED", flows.TERMINAL_OK)
        self.assertIn("FINALIZED", flows.TERMINAL_OK)


class TestAnAuthRedirectIsARefusal(unittest.TestCase):
    def test_a_302_to_an_authorization_request_counts_as_guarded(self):
        location = ("https://accounts.example/realms/r/protocol/openid-connect/auth"
                    "?client_id=edc&response_type=code&state=abc")
        self.assertEqual(fiware._auth_redirect(resp(302, {"location": location})),
                         "https://accounts.example/realms/r/protocol/openid-connect/auth")

    def test_it_is_recognised_by_the_oauth_shape_not_by_the_provider(self):
        # so it holds for something other than Keycloak
        location = "https://idp.example/authorize?response_type=code&client_id=x"
        self.assertTrue(fiware._auth_redirect(resp(307, {"location": location})))

    def test_an_ordinary_redirect_is_not_a_refusal(self):
        self.assertIsNone(fiware._auth_redirect(
            resp(302, {"location": "https://example.org/login-page"})))

    def test_a_200_is_never_a_refusal(self):
        self.assertIsNone(fiware._auth_redirect(resp(200, {})))

    def test_the_probe_does_not_follow_redirects(self):
        """Following them is what turned a guarded host into an open one."""
        import inspect
        source = inspect.getsource(fiware.flow_native_gate)
        self.assertIn("follow_redirects=False", source)


class TestTheTmforumProbeCanBeWritten(unittest.TestCase):
    """Two refusals in a row, each teaching something about TMForum extensions.

    First: a property outside the Quote schema with no `@schemaLocation` is
    refused outright. Then, with one: tm-forum-api actually FETCHES the schema,
    and a made-up URL comes back as `Was not able to validate the input` with an
    empty reasons list - a confusing way to say "I could not read your schema".

    So the probe borrows the two schemas the EDC declares on every negotiation it
    stores, read off a live quote. That is the point rather than a shortcut: the
    check measures what happens to JSON-LD keywords on the path the EDC travels,
    and a differently shaped probe measures a different path.
    """

    def test_it_declares_the_schemas_the_edc_uses(self):
        import inspect
        source = inspect.getsource(broker.flow_tmforum_roundtrip)
        self.assertIn("@schemaLocation", source)
        self.assertIn("QUOTE_SCHEMA", source)
        self.assertIn("QUOTE_ITEM_SCHEMA", source)

    def test_the_schema_urls_are_the_ones_the_connector_declares(self):
        for url in (broker.QUOTE_SCHEMA, broker.QUOTE_ITEM_SCHEMA):
            self.assertTrue(url.startswith("https://"), url)
            self.assertIn("edc-dsc", url)

    def test_the_keywords_go_where_the_edc_puts_them(self):
        """quoteItem[].policy - not a made-up top-level property."""
        import inspect
        source = inspect.getsource(broker.flow_tmforum_roundtrip)
        self.assertIn('"quoteItem"', source)
        self.assertIn('"policy": policy', source)


class TestTheStallDiagnosisFollowsTheEvidence(unittest.TestCase):
    def _classify(self, logs):
        ctx = SimpleNamespace(
            kube=SimpleNamespace(logs=lambda *a, **k: logs),
            deployment=SimpleNamespace(service=lambda name: None))
        lane = SimpleNamespace(name="dcp", deployment="edc-dcp")
        return flows._classify_negotiation_stall(
            ctx, lane, SimpleNamespace(name="p"), "REQUESTED", {}, {})

    def test_a_mapper_nullpointer_names_the_mapper(self):
        result = self._classify(
            "Was not able to read negotiation abc from quotes.\n"
            "java.lang.NullPointerException\n"
            "  at org.seamware.edc.store.TMFEdcMapper.toContractNegotiation")
        self.assertIs(result.status, Status.FAIL)
        self.assertIn("TMFEdcMapper", result.cause)
        self.assertIn("loopback", result.cause)
        self.assertNotIn("keyword", result.cause)

    def test_without_that_stack_the_broker_is_a_suspect_not_a_verdict(self):
        result = self._classify("Was not able to read negotiation abc from quotes.")
        self.assertIs(result.status, Status.FAIL)
        self.assertIn("tmforum-reserved-words", result.cause)

    def test_no_branch_points_at_a_check_that_no_longer_exists(self):
        for logs in ("Was not able to read negotiation x",
                     "Was not able to read negotiation x\nTMFEdcMapper "
                     "NullPointerException"):
            result = self._classify(logs)
            self.assertNotIn("broker-keyword-escaping", (result.fix or ""))


if __name__ == "__main__":
    unittest.main()


class TestPollingReportsMovement(unittest.TestCase):
    """A bare "it did not finish" cannot be acted on.

    The negotiation that prompted this was working: INITIAL -> FINALIZED in 103s
    against a 90s deadline, most of it the EDC state machine's own tick intervals.
    The run reported VERIFIED and the operator had no way to tell that from a
    genuine stall without going to the logs.
    """

    def setUp(self):
        # the poll sleeps 2s between reads; left alone these tests took 8s of a
        # suite that otherwise runs in under half a second
        self._sleep = flows.time.sleep
        flows.time.sleep = lambda _: None

    def tearDown(self):
        flows.time.sleep = self._sleep

    def _ctx(self, states, timeouts=None):
        seen = list(states)

        class Resp:
            ok = True

            def __init__(self, state):
                self._state = state

            def json(self):
                return {"state": self._state}

        def request(lane, method, path, body=None):
            return Resp(seen.pop(0) if seen else states[-1]), None

        return SimpleNamespace(
            edc_request=request,
            timeouts=timeouts or {"negotiation": 180, "transfer": 120},
            progress=SimpleNamespace(detail=lambda *a, **k: None))

    def test_the_timeline_names_each_state_and_when(self):
        state, _, timeline = flows._poll(
            self._ctx(["REQUESTED", "AGREED", "FINALIZED"]), None, "/n", timeout=30,
            wanted={"FINALIZED"})
        self.assertEqual(state, "FINALIZED")
        self.assertEqual([entry.split()[0] for entry in timeline],
                         ["REQUESTED", "AGREED", "FINALIZED"])

    def test_a_state_seen_twice_is_recorded_once(self):
        _, _, timeline = flows._poll(
            self._ctx(["REQUESTED", "REQUESTED", "FINALIZED"]), None, "/n", timeout=30,
            wanted={"FINALIZED"})
        self.assertEqual([entry.split()[0] for entry in timeline],
                         ["REQUESTED", "FINALIZED"])

    def test_the_deadline_is_followed_by_one_more_read(self):
        """The loop sleeps between reads, so the window can expire on something
        that settled a moment earlier. Reporting "not finished" about a thing that
        finished is the worst of both outcomes."""
        state, _, _ = flows._poll(
            self._ctx(["FINALIZED"]), None, "/n", timeout=0, wanted={"FINALIZED"})
        self.assertEqual(state, "FINALIZED")

    def test_the_default_negotiation_window_allows_for_the_measured_run(self):
        from fdsc_verify.context import Context
        ctx = Context.__new__(Context)
        ctx.timeouts = {"negotiation": 180, "transfer": 120}
        # measured on demo: 103s end to end
        self.assertGreater(ctx.timeouts["negotiation"], 103)


class TestThereIsNoLoopback(unittest.TestCase):
    """An EDC flow needs a counterparty, and the tool must not pretend otherwise.

    Loopback - a lane negotiating against its own public DSP endpoint - reads as
    the safe option: self-contained, nobody else's environment touched. On this
    stack it cannot work, and it fails in the most expensive way available. The
    TMF-backed store keeps a negotiation as one Quote with both roles in
    relatedParty and recovers counterPartyId from the party whose DID is not
    ours; with one participant on both sides that party does not exist, the field
    stays null, and ContractNegotiation.Builder.build() throws on every read. The
    state machine retries every two seconds for ever and only deleting the Quote
    stops it. EDC permits one participant on both sides - its builder checks only
    that the three fields are present - so this is the store's limit, and it is
    not going to be lifted.

    So: no peer, no EDC flow, and the row says why rather than quietly inventing
    a target.
    """

    def _lane(self):
        return SimpleNamespace(name="dcp", protocol_url="https://us.example/api/dsp",
                               participant_id="did:web:us.example", deployment="edc-dcp")

    def _ctx(self, peer=None):
        return SimpleNamespace(peer_for=lambda name: peer, peers=[peer] if peer else [])

    def test_no_peer_means_not_applicable_rather_than_a_verdict(self):
        result = flows.flow_catalog(self._ctx(), self._lane())
        self.assertIs(result.status, Status.SKIP)
        self.assertFalse(result.applicable)

    def test_the_reason_names_the_flag_that_fixes_it(self):
        result = flows.flow_catalog(self._ctx(), self._lane())
        self.assertIn("--peer", result.cause)

    def test_and_says_why_there_is_no_loopback(self):
        # so nobody re-adds it, and nobody goes hunting for a deployment fault
        result = flows.flow_negotiation(self._ctx(), self._lane())
        self.assertIn("loopback", result.cause)
        self.assertIn("counterPartyId", result.cause)

    def test_every_edc_flow_check_refuses_the_same_way(self):
        for fn in (flows.flow_catalog, flows.flow_negotiation, flows.flow_transfer):
            result = fn(self._ctx(), self._lane())
            self.assertFalse(result.applicable, fn.__name__)

    def test_the_tool_no_longer_knows_how_to_build_a_loopback_target(self):
        """The helper is gone, not merely unused: an unused one gets called again."""
        self.assertFalse(hasattr(flows, "_loopback_peer"))


class TestTheRefusalIsReadNotAssumed(unittest.TestCase):
    """The gateway says why; the check used to say something else.

    The canned cause claimed "no error_description means no usable token was
    presented" even when the header carried one. On demo it carried `RSA key with
    id sig not found`, which is the opposite problem - a well-formed token whose
    signing key the gateway could not resolve - and it sent the reader hunting for
    a missing token.
    """

    def test_an_unresolvable_key_says_whose_gateway_it_is(self):
        why = flows._why_refused(
            'Bearer realm="apisix", error="invalid_token", '
            'error_description="RSA key with id sig not found"')
        # the data endpoint is the counterparty's: nothing on our side will fix it
        self.assertIn("COUNTERPARTY", why)
        self.assertIn("not found", why)

    def test_it_explains_why_a_check_cannot_catch_it(self):
        why = flows._why_refused('error_description="RSA key with id sig not found"')
        self.assertIn("verifier-jwks-matches-key", why)

    def test_an_expired_token_is_a_different_story(self):
        why = flows._why_refused('error_description="token expired"')
        self.assertIn("minted when the data flow starts", why)

    def test_no_description_is_still_the_no_token_case(self):
        why = flows._why_refused('Bearer realm="apisix"')
        self.assertIn("authType", why)

    def test_it_names_the_fields_the_edr_really_carries(self):
        """The advice used to be backwards.

        It told the reader the EDR carries token/tokenType and not
        authorization/authType. FDSCDcpEndpointDataReferenceService writes
        `authorization` and `authType` - so a consumer reading token/tokenType is
        the one that finds nothing, which is the opposite of what it said.
        """
        why = flows._why_refused('Bearer realm="apisix"')
        self.assertIn("FDSCDcpEndpointDataReferenceService", why)
        self.assertIn("`authorization`", why)

    def test_the_old_claim_is_not_made_unconditionally(self):
        """It was, and that is the bug this pins."""
        why = flows._why_refused('error_description="RSA key with id sig not found"')
        self.assertNotIn("authType", why)
        self.assertIn("tokenKid", why)


class TestTheEdrEndpointNeedsItsSlash(unittest.TestCase):
    """A one-character mismatch that the gateway reports as a token problem.

    fdsc-edc builds the EDR endpoint as `https://host/<dataFlowId>` and registers
    the gateway route as `/<dataFlowId>/*`, which cannot match it. A consumer
    following the EDR verbatim lands on some other route, whose JWKS has no such
    key, and gets `401 RSA key with id sig not found` - an accusation against a
    token that is perfectly valid. Measured on demo: the same token on the same
    endpoint is 401 bare and 404 with one slash appended, and 404 only happens
    after authentication passes.

    Probing both is not papering over the fault. It is still a FAIL, because a
    consumer using the EDR as handed over does not get their data; what the retry
    buys is naming the right cause instead of the token.
    """

    def test_the_cause_names_the_url_not_the_token(self):
        import inspect
        source = inspect.getsource(flows.flow_transfer)
        self.assertIn("not fetchable as handed over", source)
        self.assertIn("dataStatusWithSlash", source)

    def test_the_fix_points_at_both_sides_of_the_mismatch(self):
        import inspect
        source = inspect.getsource(flows.flow_transfer)
        self.assertIn("FDSCEndpoints.buildEndpoint", source)
        self.assertIn("toDcpServiceRoute", source)

    def test_it_only_retries_when_there_is_no_slash_already(self):
        import inspect
        source = inspect.getsource(flows.flow_transfer)
        self.assertIn('not endpoint.endswith("/")', source)


class TestTheOid4vcEdrCarriesNoToken(unittest.TestCase):
    """And that is the design, not a fault.

    FDSCOid4VpEndpointDataReferenceService puts only `endpoint` and `endpointType`
    in the EDR - "token handling happens at the OID4VC level", as its own revoke
    method says - because the consumer earns a token by presenting a credential to
    the verifier that the route's discovery names. Doing that means being a wallet:
    OID4VCI from Keycloak, a key, a signed VP, a provisioned test user. That is the
    same line flow-fiware-gate declines to cross, and for the same reason.

    The check used to report the resulting 401 as `the data endpoint rejected the
    request as unauthenticated` and then explain it with the DCP class's field
    names - the wrong class for this path - and a fix about a JWKS cache. All of it
    pointed away from the truth, which is that there was never a token to send.

    What can still be proven is worth keeping: the EDR was issued, and the endpoint
    it names refuses an anonymous request. An endpoint that serves the data with no
    credential at all is a real FAIL, and stays one.
    """

    def test_a_guarded_endpoint_with_no_token_is_not_a_failure(self):
        source = inspect.getsource(flows.flow_transfer)
        self.assertIn("no token to spend", source)
        self.assertIn("(401, 403)", source)

    def test_an_open_endpoint_with_no_token_still_fails(self):
        source = inspect.getsource(flows.flow_transfer)
        self.assertIn("served the data with no credential at all", source)

    def test_the_reason_names_the_oid4vc_design_not_the_dcp_field_names(self):
        source = inspect.getsource(flows.flow_transfer)
        self.assertIn("OID4VC", source)
        self.assertIn("FDSCOid4VpEndpointDataReferenceService", source)
