"""identity-key-consistency, and the multi-key document it used to fail on.

This is the check that would have saved the most time: four copies of one key
have to agree - the private key in the TLS secret, the public key in the
published DID document, the identityhub's `publicKeyJwk`, and whatever signed
the stored credential - and a mismatch is silent until a counterparty rejects a
signature. It is what found demo/consumer's `Z4dnTH2u` vs `K-qAaapn`.

It compared the secret against `sorted(keys)[0]`, the FIRST published method.
That is right only while a document publishes one, which every deployment
inspected did. A document may legitimately publish one method per component
signing as that DID, and against such a document the old form compared the
secret with an arbitrary key and FAILed, naming two fingerprints that were never
meant to be equal. What has to hold is that each copy is published *somewhere*.

Keys are generated with openssl, so the fingerprints are real.
"""

import subprocess
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fdsc_verify import jose  # noqa: E402
from fdsc_verify.checks import identity  # noqa: E402
from fdsc_verify.model import Status  # noqa: E402

DID = "did:web:example.org"


def _keypair():
    pem = subprocess.run(["openssl", "ecparam", "-genkey", "-name", "prime256v1", "-noout"],
                         capture_output=True, check=True).stdout
    return pem, jose.public_jwk_from_pem(pem)


def _document(*methods):
    """A DID document publishing one verificationMethod per (fragment, jwk)."""
    return {"id": DID,
            "verificationMethod": [
                {"id": "%s#%s" % (DID, frag), "type": "JsonWebKey2020",
                 "controller": DID, "publicKeyJwk": jwk}
                for frag, jwk in methods]}


class _Ctx:
    """The narrow surface identity_key_consistency actually touches."""

    def __init__(self, secret_pem, ih_jwk=None, has_identityhub=True, ih_error=None):
        self.deployment = SimpleNamespace(
            identity_secret="tls-secret", identity_secret_key="tls.key",
            service=lambda name: object() if has_identityhub else None)
        self.kube = SimpleNamespace(secret=lambda name: {"tls.key": secret_pem})
        # fetch_did_document takes it from here: it has a DID and no context of
        # its own, so the flag has to be threaded through every caller
        self.insecure = False
        self._ih_jwk = ih_jwk
        self.identityhub_error = ih_error

    def any_participant_id(self):
        return DID

    def identityhub_participant_key(self, did):
        return self._ih_jwk

    def identityhub_credentials(self, did):
        return None, self.identityhub_error


class IdentityKeyCase(unittest.TestCase):
    def setUp(self):
        self._real_fetch = identity.fetch_did_document

    def tearDown(self):
        identity.fetch_did_document = self._real_fetch

    def run_check(self, ctx, document):
        identity.fetch_did_document = lambda did, insecure=False: (document, None)
        return identity.identity_key_consistency(ctx)


class TestAMultiKeyDocument(IdentityKeyCase):
    """The regression: several published methods must not read as a disagreement."""

    def test_the_secret_matching_a_later_method_is_not_a_failure(self):
        other_pem, other_jwk = _keypair()
        ours_pem, ours_jwk = _keypair()
        # "auth" sorts before "sign", so the old code compared against the wrong one
        doc = _document(("auth", other_jwk), ("sign", ours_jwk))
        result = self.run_check(_Ctx(ours_pem, ih_jwk=ours_jwk), doc)
        self.assertEqual(result.status, Status.OK)
        self.assertEqual(result.detail["verificationMethod"], "%s#sign" % DID)

    def test_two_components_on_two_published_methods_both_pass(self):
        conn_pem, conn_jwk = _keypair()
        ih_pem, ih_jwk = _keypair()
        doc = _document(("conn", conn_jwk), ("ih", ih_jwk))
        result = self.run_check(_Ctx(conn_pem, ih_jwk=ih_jwk), doc)
        self.assertEqual(result.status, Status.OK)
        self.assertEqual(result.detail["matched"],
                         {"secret": "%s#conn" % DID, "identityhub": "%s#ih" % DID})

    def test_an_unpublished_key_still_fails_even_with_several_published(self):
        stale_pem, _ = _keypair()
        doc = _document(("a", _keypair()[1]), ("b", _keypair()[1]))
        result = self.run_check(_Ctx(stale_pem, ih_jwk=None, has_identityhub=False), doc)
        self.assertEqual(result.status, Status.FAIL)
        self.assertIn("secret", result.summary)
        # the cause has to carry what is published, or there is nothing to act on
        self.assertIn("#a", result.cause)
        self.assertIn("#b", result.cause)


class TestTheSingleKeyShapeIsUnchanged(IdentityKeyCase):
    """Every deployment inspected publishes one method; no verdict may move."""

    def test_all_copies_agree(self):
        pem, jwk = _keypair()
        result = self.run_check(_Ctx(pem, ih_jwk=jwk), _document(("key-1", jwk)))
        self.assertEqual(result.status, Status.OK)
        self.assertIn(jose.jwk_fingerprint(jwk), result.summary)

    def test_the_identityhub_copy_differing_is_a_failure(self):
        pem, jwk = _keypair()
        _, stale_jwk = _keypair()
        result = self.run_check(_Ctx(pem, ih_jwk=stale_jwk), _document(("key-1", jwk)))
        self.assertEqual(result.status, Status.FAIL)
        self.assertIn("identityhub", result.summary)

    def test_the_secret_differing_is_a_failure(self):
        stale_pem, _ = _keypair()
        _, published = _keypair()
        result = self.run_check(_Ctx(stale_pem, ih_jwk=published),
                                _document(("key-1", published)))
        self.assertEqual(result.status, Status.FAIL)
        self.assertIn("secret", result.summary)


class TestTheThirdCopyMayBeAbsent(IdentityKeyCase):
    def test_no_identityhub_deployed_is_not_a_gap(self):
        # a deployment without a DCP lane keeps its key in two places, not three;
        # warning there tells a correctly built provider something is missing
        pem, jwk = _keypair()
        result = self.run_check(_Ctx(pem, ih_jwk=None, has_identityhub=False),
                                _document(("key-1", jwk)))
        self.assertEqual(result.status, Status.OK)
        self.assertIn("no identityhub here", result.summary)

    def test_an_unreadable_identityhub_warns_rather_than_passing(self):
        pem, jwk = _keypair()
        result = self.run_check(
            _Ctx(pem, ih_jwk=None, has_identityhub=True, ih_error="401 from the hub"),
            _document(("key-1", jwk)))
        self.assertEqual(result.status, Status.WARN)
        self.assertIn("401 from the hub", result.cause)


class TestInsecureReachesTheDidDocument(unittest.TestCase):
    """`--insecure` has to reach the one request that resolves the DID document.

    For a long time it did not. `fetch_did_document` takes a DID and no context,
    so it called `http.get(url)` with no flag while fourteen other call sites
    passed `insecure=ctx.insecure` - and on a deployment with a self-signed
    certificate, a local k3s on nip.io say, the operator passed `--insecure` and
    four checks still failed on `unable to get local issuer certificate`, two of
    them outright and two as a cascade.

    Asserted at the HTTP boundary rather than on a verdict, because the verdict
    looked identical either way: the document simply never resolved.
    """

    def setUp(self):
        self.seen = []
        self._real_get = identity.http.get

        def spy(url, **kw):
            self.seen.append((url, kw.get("insecure")))
            return SimpleNamespace(error=None, ok=True, status=200,
                                   json=lambda: {"id": "did:web:host"})

        identity.http.get = spy

    def tearDown(self):
        identity.http.get = self._real_get

    def test_the_flag_arrives(self):
        identity.fetch_did_document("did:web:host", True)
        self.assertEqual(self.seen, [("https://host/.well-known/did.json", True)])

    def test_and_defaults_to_verifying(self):
        """The default has to stay "verify": a flag nobody passed must not make
        the tool quietly skip TLS validation."""
        identity.fetch_did_document("did:web:host")
        self.assertEqual(self.seen, [("https://host/.well-known/did.json", False)])

    def test_every_caller_threads_it_through(self):
        """The signature alone is not enough - the eight callers have to pass it,
        and a ninth added later must too. Read off the source, because a caller
        that forgets is exactly how this broke the first time."""
        import pathlib as _p
        root = _p.Path(identity.__file__).parent.parent
        missed = []
        for path in sorted(root.rglob("checks/*.py")):
            for n, line in enumerate(path.read_text().splitlines(), 1):
                if "fetch_did_document(" not in line or "def fetch_did_document" in line:
                    continue
                if "insecure" not in line:
                    missed.append("%s:%d" % (path.name, n))
        self.assertEqual(missed, [], "callers not forwarding --insecure: %s" % missed)


if __name__ == "__main__":
    unittest.main()
