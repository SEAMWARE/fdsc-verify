"""Unit tests for jose.py, the only module with cryptography of its own.

Key material is generated once per session with openssl and tokens are signed
with it, so the tests assert real signature verification rather than a mock. No
network, no cluster.
"""

import json
import os
import subprocess
import tempfile
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fdsc_verify import jose  # noqa: E402


def _openssl(args, stdin=None):
    proc = subprocess.run(["openssl"] + args, input=stdin, capture_output=True)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.decode()[:400])
    return proc.stdout


def _sign(signing_input: bytes, key_pem: bytes, kind: str) -> bytes:
    """Sign with openssl. ES256 output is DER, which JWS does not use, so convert."""
    # openssl dgst -sign needs the key as a file, not on stdin (stdin carries the data)
    with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as fh:
        fh.write(key_pem)
        key_path = fh.name
    try:
        der = _openssl(["dgst", "-sha256", "-sign", key_path, "-binary"], stdin=signing_input)
    finally:
        os.unlink(key_path)
    if kind == "RSA":
        return der
    # DER SEQUENCE{INTEGER r, INTEGER s} -> raw r||s, 32 bytes each for P-256
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    r, s = decode_dss_signature(der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def _make_token(key_pem: bytes, kind: str, payload: dict) -> str:
    alg = "RS256" if kind == "RSA" else "ES256"
    header = jose.b64url_encode(json.dumps({"alg": alg, "typ": "JWT"}).encode())
    body = jose.b64url_encode(json.dumps(payload).encode())
    signing_input = ("%s.%s" % (header, body)).encode()
    sig = _sign(signing_input, key_pem, kind)
    return "%s.%s.%s" % (header, body, jose.b64url_encode(sig))


class TestB64Url(unittest.TestCase):
    def test_decodes_without_padding(self):
        # every JOSE field arrives unpadded; this is the classic hand-debugging trap
        self.assertEqual(jose.b64url_decode("YQ"), b"a")
        self.assertEqual(jose.b64url_decode("YWI"), b"ab")
        self.assertEqual(jose.b64url_decode("YWJj"), b"abc")

    def test_roundtrip(self):
        raw = bytes(range(256))
        self.assertEqual(jose.b64url_decode(jose.b64url_encode(raw)), raw)

    def test_url_alphabet(self):
        raw = b"\xfb\xff\xfe"
        encoded = jose.b64url_encode(raw)
        self.assertNotIn("+", encoded)
        self.assertNotIn("/", encoded)
        self.assertEqual(jose.b64url_decode(encoded), raw)


class TestDecode(unittest.TestCase):
    def test_rejects_malformed(self):
        for bad in ("", "a", "a.b", "a.b.c.d"):
            with self.assertRaises(jose.MalformedToken):
                jose.split_jwt(bad)

    def test_rejects_non_json_segment(self):
        token = "%s.%s.%s" % (jose.b64url_encode(b"not json"), jose.b64url_encode(b"{}"), "sig")
        with self.assertRaises(jose.MalformedToken):
            jose.decode_jwt(token)


class TestRsa(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pem = _openssl(["genrsa", "2048"])
        cls.jwk = jose.public_jwk_from_pem(cls.pem)

    def test_public_jwk_from_pem(self):
        self.assertEqual(self.jwk["kty"], "RSA")
        self.assertEqual(self.jwk["e"], "AQAB")
        # 2048-bit modulus -> 256 bytes
        self.assertEqual(len(jose.b64url_decode(self.jwk["n"])), 256)

    def test_verifies_own_signature(self):
        token = _make_token(self.pem, "RSA", {"iss": "did:web:example.com"})
        self.assertTrue(jose.verify_jwt(token, self.jwk))

    def test_rejects_other_key(self):
        token = _make_token(self.pem, "RSA", {"iss": "did:web:example.com"})
        other = jose.public_jwk_from_pem(_openssl(["genrsa", "2048"]))
        self.assertFalse(jose.verify_jwt(token, other))

    def test_rejects_tampered_payload(self):
        token = _make_token(self.pem, "RSA", {"iss": "did:web:example.com"})
        header, _, sig = token.split(".")
        forged = "%s.%s.%s" % (header, jose.b64url_encode(b'{"iss":"did:web:evil.com"}'), sig)
        self.assertFalse(jose.verify_jwt(forged, self.jwk))

    def test_fingerprint_is_stable_and_discriminating(self):
        other = jose.public_jwk_from_pem(_openssl(["genrsa", "2048"]))
        self.assertEqual(jose.jwk_fingerprint(self.jwk), jose.jwk_fingerprint(self.jwk))
        self.assertNotEqual(jose.jwk_fingerprint(self.jwk), jose.jwk_fingerprint(other))


@unittest.skipUnless(jose.HAVE_CRYPTOGRAPHY, "needs cryptography")
class TestEc(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pem = _openssl(["ecparam", "-genkey", "-name", "prime256v1", "-noout"])
        cls.jwk = jose.public_jwk_from_pem(cls.pem)

    def test_public_jwk_from_pem(self):
        self.assertEqual(self.jwk["kty"], "EC")
        self.assertEqual(self.jwk["crv"], "P-256")
        self.assertEqual(len(jose.b64url_decode(self.jwk["x"])), 32)
        self.assertEqual(len(jose.b64url_decode(self.jwk["y"])), 32)

    def test_verifies_own_signature(self):
        # the r||s -> DER conversion is the part that silently reads as
        # "invalid signature" when wrong, so this is the test that matters
        token = _make_token(self.pem, "EC", {"iss": "did:web:producer.example"})
        self.assertTrue(jose.verify_jwt(token, self.jwk))

    def test_rejects_other_key(self):
        token = _make_token(self.pem, "EC", {"iss": "did:web:producer.example"})
        other = jose.public_jwk_from_pem(
            _openssl(["ecparam", "-genkey", "-name", "prime256v1", "-noout"]))
        self.assertFalse(jose.verify_jwt(token, other))


class TestDidDocument(unittest.TestCase):
    def test_extracts_keys_by_method_id(self):
        doc = {
            "id": "did:web:example.com",
            "verificationMethod": [
                {"id": "did:web:example.com#key-1", "publicKeyJwk": {"kty": "RSA", "n": "AQ", "e": "AQAB"}},
                {"id": "did:web:example.com#key-2", "publicKeyMultibase": "z6Mk"},  # no JWK
            ],
        }
        keys = jose.did_document_keys(doc)
        self.assertEqual(list(keys), ["did:web:example.com#key-1"])

    def test_tolerates_missing_section(self):
        self.assertEqual(jose.did_document_keys({"id": "did:web:example.com"}), {})


class TestLifetime(unittest.TestCase):
    def test_computes_ttl_and_remaining(self):
        token = "%s.%s.%s" % (
            jose.b64url_encode(b'{"alg":"RS256"}'),
            jose.b64url_encode(b'{"iat":1000,"exp":1300}'),
            jose.b64url_encode(b"sig"),
        )
        info = jose.token_lifetime(token, now=1200)
        self.assertEqual(info["ttl"], 300)
        self.assertEqual(info["remaining"], 100)

    def test_expired_token_reports_negative_remaining(self):
        # this is the EDR case: fetched long after the data flow started
        token = "%s.%s.%s" % (
            jose.b64url_encode(b'{"alg":"RS256"}'),
            jose.b64url_encode(b'{"iat":1000,"exp":1300}'),
            jose.b64url_encode(b"sig"),
        )
        self.assertLess(jose.token_lifetime(token, now=1500)["remaining"], 0)

    def test_absent_claims_are_none(self):
        token = "%s.%s.%s" % (
            jose.b64url_encode(b'{"alg":"RS256"}'),
            jose.b64url_encode(b"{}"),
            jose.b64url_encode(b"sig"),
        )
        info = jose.token_lifetime(token, now=1500)
        self.assertIsNone(info["exp"])
        self.assertIsNone(info["ttl"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
