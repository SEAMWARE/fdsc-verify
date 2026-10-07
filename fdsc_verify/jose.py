"""JWT / JWK / signature helpers.

This is the only module with real cryptography in it, and it is what makes the
expensive checks possible: "does the credential stored in the identityhub still
verify against the key the DID document publishes today" cannot be answered any
other way, and answering it by hand costs hours.

RSA verification is implemented natively (textbook PKCS#1 v1.5 recovery, no
dependency) so the tool still works in a minimal container. EC/ES256 needs
`cryptography`; when it is missing the EC paths raise CryptoUnavailable and the
calling check degrades to SKIP rather than lying.
"""

from __future__ import annotations

import base64
import hashlib
import json
import subprocess
from typing import Dict, Optional, Tuple

try:  # pragma: no cover - exercised by absence, not presence
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils

    HAVE_CRYPTOGRAPHY = True
except ImportError:  # pragma: no cover
    HAVE_CRYPTOGRAPHY = False


class CryptoUnavailable(RuntimeError):
    """Raised when a verification needs `cryptography` and it is not installed."""


class MalformedToken(ValueError):
    """The string is not a well-formed JWS compact serialisation."""


def b64url_decode(value: str) -> bytes:
    """Decode base64url without requiring correct padding.

    Every JOSE field arrives unpadded; forgetting this is the classic source of
    "Invalid base64" while debugging tokens by hand.
    """
    if isinstance(value, bytes):
        value = value.decode("ascii")
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64url_to_int(value: str) -> int:
    return int.from_bytes(b64url_decode(value), "big")


def split_jwt(token: str) -> Tuple[str, str, str]:
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise MalformedToken("expected 3 dot-separated segments, got %d" % len(parts))
    return parts[0], parts[1], parts[2]


def decode_jwt(token: str) -> Dict[str, object]:
    """Return {header, payload, signing_input, signature} without verifying."""
    header_b64, payload_b64, signature_b64 = split_jwt(token)
    try:
        header = json.loads(b64url_decode(header_b64))
        payload = json.loads(b64url_decode(payload_b64))
    except (ValueError, TypeError) as exc:
        raise MalformedToken("segment is not JSON: %s" % exc)
    return {
        "header": header,
        "payload": payload,
        "signing_input": ("%s.%s" % (header_b64, payload_b64)).encode("ascii"),
        "signature": b64url_decode(signature_b64),
    }


# ---------------------------------------------------------------- verification


def _verify_rs256(jwk: Dict[str, str], signing_input: bytes, signature: bytes) -> bool:
    """Textbook RSA PKCS#1 v1.5 verification: recover the block, compare the digest.

    Deliberately dependency-free. We only ever need to answer "was this signed
    by that key", never to produce a signature, so the absence of padding
    hardening is not a concern here.
    """
    n = b64url_to_int(jwk["n"])
    e = b64url_to_int(jwk["e"])
    recovered = pow(int.from_bytes(signature, "big"), e, n)
    block = recovered.to_bytes((n.bit_length() + 7) // 8, "big")
    return hashlib.sha256(signing_input).digest() == block[-32:]


_CURVES = {"P-256": "SECP256R1", "P-384": "SECP384R1", "P-521": "SECP521R1"}
_EC_HASHES = {"P-256": "SHA256", "P-384": "SHA384", "P-521": "SHA512"}


def _verify_es(jwk: Dict[str, str], signing_input: bytes, signature: bytes) -> bool:
    """ECDSA verification.

    The JWS signature is raw `r||s`; `cryptography` wants DER, hence
    encode_dss_signature. Getting this wrong reads as "signature invalid" and
    sends you chasing a key mismatch that does not exist.
    """
    if not HAVE_CRYPTOGRAPHY:
        raise CryptoUnavailable("ES* verification needs the 'cryptography' package")
    crv = jwk.get("crv", "P-256")
    if crv not in _CURVES:
        raise CryptoUnavailable("unsupported curve %s" % crv)
    curve = getattr(ec, _CURVES[crv])()
    digest = getattr(hashes, _EC_HASHES[crv])()
    half = len(signature) // 2
    der = utils.encode_dss_signature(
        int.from_bytes(signature[:half], "big"), int.from_bytes(signature[half:], "big")
    )
    public = ec.EllipticCurvePublicNumbers(
        b64url_to_int(jwk["x"]), b64url_to_int(jwk["y"]), curve
    ).public_key()
    try:
        public.verify(der, signing_input, ec.ECDSA(digest))
        return True
    except InvalidSignature:
        return False


def verify_jwt(token: str, jwk: Dict[str, str]) -> bool:
    """Verify a compact JWS against a public JWK.

    Dispatches on the JWK key type rather than the token's `alg`: a token can
    claim anything, and what we actually want to know is whether *this* key
    produced it.
    """
    parts = decode_jwt(token)
    kty = jwk.get("kty")
    if kty == "RSA":
        return _verify_rs256(jwk, parts["signing_input"], parts["signature"])
    if kty == "EC":
        return _verify_es(jwk, parts["signing_input"], parts["signature"])
    raise CryptoUnavailable("unsupported key type %s" % kty)


# ------------------------------------------------------------------- identity


def jwk_fingerprint(jwk: Dict[str, str]) -> str:
    """A short, stable, comparable label for a public key.

    Used to say "these four copies of the key agree" in a way that fits on one
    line. Not a JWK thumbprint (RFC 7638) - it only needs to be comparable
    between values this tool itself produced.
    """
    kty = jwk.get("kty")
    if kty == "RSA":
        material = b64url_decode(jwk["n"])
    elif kty == "EC":
        material = b64url_decode(jwk["x"]) + b64url_decode(jwk.get("y", ""))
    else:
        material = json.dumps(jwk, sort_keys=True).encode()
    return hashlib.sha256(material).hexdigest()[:16]


def public_jwk_from_pem(pem: bytes) -> Dict[str, str]:
    """Derive the public JWK of a PEM private key, shelling out to openssl.

    openssl rather than `cryptography` on purpose: it handles PKCS#1 and PKCS#8,
    RSA and EC, encrypted or not, with one code path, and it is present wherever
    this tool will run. The parsing target is the stable `-noout -text` output.
    """
    for kind in ("rsa", "ec", "pkey"):
        proc = subprocess.run(
            ["openssl", kind, "-noout", "-modulus"] if kind == "rsa"
            else ["openssl", kind, "-noout", "-text"],
            input=pem, capture_output=True,
        )
        if proc.returncode != 0:
            continue
        out = proc.stdout.decode("utf-8", "replace")
        if kind == "rsa" and "Modulus=" in out:
            modulus = out.split("Modulus=", 1)[1].strip().split()[0]
            n = int(modulus, 16)
            return {
                "kty": "RSA",
                "e": "AQAB",
                "n": b64url_encode(n.to_bytes((n.bit_length() + 7) // 8, "big")),
            }
        if "pub:" in out and "NIST CURVE" in out:
            return _ec_jwk_from_openssl_text(out)
    raise ValueError("could not parse the private key with openssl")


def _ec_jwk_from_openssl_text(text: str) -> Dict[str, str]:
    curve_line = [l for l in text.splitlines() if "NIST CURVE" in l][0]
    crv = curve_line.split(":", 1)[1].strip()
    hex_bytes, collecting = [], False
    for line in text.splitlines():
        if line.strip().startswith("pub:"):
            collecting = True
            continue
        if collecting:
            if ":" in line and line.strip().replace(":", "").replace(" ", "").isalnum() \
                    and all(c in "0123456789abcdef: " for c in line.strip()):
                hex_bytes.append(line.strip())
            else:
                break
    raw = bytes.fromhex("".join(hex_bytes).replace(":", ""))
    if raw and raw[0] == 0x04:  # uncompressed point
        raw = raw[1:]
    half = len(raw) // 2
    return {
        "kty": "EC",
        "crv": crv,
        "x": b64url_encode(raw[:half]),
        "y": b64url_encode(raw[half:]),
    }


def did_document_keys(did_document: Dict[str, object]) -> Dict[str, Dict[str, str]]:
    """Map verificationMethod id -> public JWK, for the methods that carry one."""
    keys = {}
    for method in did_document.get("verificationMethod") or []:
        jwk = method.get("publicKeyJwk")
        if jwk:
            keys[method.get("id")] = jwk
    return keys


def token_lifetime(token: str, now: Optional[int] = None) -> Dict[str, Optional[int]]:
    """iat / exp / seconds remaining. Returns None fields when the claim is absent."""
    import time

    payload = decode_jwt(token)["payload"]
    now = int(time.time()) if now is None else now
    exp = payload.get("exp")
    iat = payload.get("iat") or payload.get("nbf")
    return {
        "iat": iat,
        "exp": exp,
        "ttl": (exp - iat) if (exp and iat) else None,
        "remaining": (exp - now) if exp else None,
    }
