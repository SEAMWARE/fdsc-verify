"""HTTP helpers built on the standard library only.

No `requests`, so the tool runs from a bare python3 in any container. The
response object keeps the headers because several diagnoses depend on them
rather than on the body - notably `www-authenticate`, which is the only thing
that tells an expired EDR token apart from one that was never sent.
"""

from __future__ import annotations

import json
import socket
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple


@dataclass
class Response:
    status: int
    body: bytes
    headers: Dict[str, str] = field(default_factory=dict)
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    def json(self):
        try:
            return json.loads(self.body)
        except (ValueError, TypeError):
            return None

    def text(self, limit: int = 400) -> str:
        return self.body.decode("utf-8", "replace")[:limit]

    def header(self, name: str) -> Optional[str]:
        return self.headers.get(name.lower())


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Hand the 3xx back to the caller instead of chasing it.

    Returning None from `redirect_request` makes urllib raise HTTPError for the
    redirect itself, which the caller below already turns into a Response - so the
    status and the `location` header survive.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def request(method: str, url: str, body=None, headers: Optional[Dict[str, str]] = None,
            timeout: int = 15, insecure: bool = False,
            follow_redirects: bool = True) -> Response:
    """Perform a request, never raise.

    Checks want to reason about 401 vs 404 vs a TLS failure, so transport errors
    come back as a Response with status 0 and `error` set instead of an
    exception.

    `follow_redirects=False` matters for any check that judges a *refusal*. An
    APISIX route with `bearer_only: false` refuses an unauthenticated request with
    a 302 to the OIDC authorization endpoint, not a 401; followed, that lands on a
    login page and reads as a 200 - the gateway wide open. The default stays True
    because every other caller wants the resource.
    """
    data = None
    headers = dict(headers or {})
    # urllib sends no Accept header at all, which is not what any other client does
    # and not what some servers tolerate: Scorpio answers an NGSI-LD query without
    # one with `406 Provided accept types are not supported`, so the last step of
    # the EDC flow - spending the EDR at the data endpoint - failed on a deployment
    # where everything worked. `*/*` is what curl and browsers send, it is strictly
    # more permissive than sending nothing, and a caller that cares still wins
    # because this only fills a gap.
    headers.setdefault("Accept", "*/*")
    if body is not None:
        if isinstance(body, (dict, list)):
            data = json.dumps(body).encode()
            headers.setdefault("Content-Type", "application/json")
        elif isinstance(body, str):
            data = body.encode()
        else:
            data = body

    req = urllib.request.Request(url, data=data, method=method.upper())
    for key, value in headers.items():
        req.add_header(key, value)

    context = ssl._create_unverified_context() if insecure else None
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=context),
        *([] if follow_redirects else [_NoRedirect]))
    try:
        with opener.open(req, timeout=timeout) as resp:
            return Response(resp.status, resp.read(),
                            {k.lower(): v for k, v in resp.headers.items()})
    except urllib.error.HTTPError as exc:
        # a 4xx/5xx is a perfectly good answer for most checks
        return Response(exc.code, exc.read() or b"",
                        {k.lower(): v for k, v in (exc.headers or {}).items()})
    except urllib.error.URLError as exc:
        reason = exc.reason
        if isinstance(reason, ssl.SSLCertVerificationError):
            return Response(0, b"", error="TLS verification failed: %s" % reason.verify_message)
        return Response(0, b"", error="%s" % reason)
    except (socket.timeout, TimeoutError):
        return Response(0, b"", error="timeout after %ds" % timeout)
    except Exception as exc:  # noqa: BLE001 - a check must never die on transport
        return Response(0, b"", error="%s: %s" % (type(exc).__name__, exc))


def tls_capability_warning() -> Optional[str]:
    """Say so when this interpreter cannot negotiate TLS 1.3.

    Worth a dedicated probe because the failure is maximally misleading. A
    gateway configured for TLS 1.3 only - which is now the common case, and is
    how some hosts in this dataspace are set up - rejects the handshake, and OpenSSL
    reports that as `SSLV3_ALERT_HANDSHAKE_FAILURE`. Every host-facing check then
    fails or warns at once, each with a `cause` and a `fix` pointing confidently
    at DNS, ingress or certificates. Six wrong diagnoses beat no diagnosis only
    in volume.

    macOS ships a python linked against LibreSSL 2.8.3, which predates TLS 1.3,
    so this fires on `/usr/bin/python3` and on anything installed with it.
    """
    if getattr(ssl, "HAS_TLSv1_3", False):
        return None
    return ("this interpreter cannot negotiate TLS 1.3 (%s): hosts that require it "
            "will report handshake failures that are NOT deployment problems. "
            "Re-run with a python built against OpenSSL 1.1.1+ "
            "(e.g. PYTHONPATH=<repo> /opt/homebrew/bin/python3 -m fdsc_verify ...)"
            % ssl.OPENSSL_VERSION)


def get(url: str, **kw) -> Response:
    return request("GET", url, **kw)


def post(url: str, body=None, **kw) -> Response:
    return request("POST", url, body=body, **kw)


def peer_cert(host: str, port: int = 443, timeout: int = 10) -> Tuple[Optional[bytes], Optional[str]]:
    """Fetch the leaf certificate a host serves, in DER, without validating it.

    Validation is deliberately off: the point is to inspect what is served -
    subject, SANs, expiry - including when it is the wrong certificate, which is
    precisely the case worth reporting.
    """
    context = ssl._create_unverified_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                return tls.getpeercert(binary_form=True), None
    except Exception as exc:  # noqa: BLE001
        return None, "%s: %s" % (type(exc).__name__, exc)


def resolve(host: str) -> Tuple[Optional[str], Optional[str]]:
    """First A record for a host, or an error string."""
    try:
        return socket.gethostbyname(host), None
    except OSError as exc:
        return None, str(exc)
