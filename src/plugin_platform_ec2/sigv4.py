"""AWS Signature Version 4, written here with hashlib and hmac (the user, 2026-11-11: "Write the SigV4 signing in the
plugin"), as the IAM User Guide gives it ("Create a signed AWS API request"):

1. the canonical request: the method, the path (URI-encoded), the query (each name and value URI-encoded, sorted), the
   headers signed (lowercased names, trimmed values, sorted, each "name:value"), their names joined by ";", and the
   payload's SHA-256 in hex;
2. the string to sign: "AWS4-HMAC-SHA256", the time (YYYYMMDDTHHMMSSZ, UTC), the credential scope
   (date/region/service/aws4_request) and the canonical request's SHA-256;
3. the signing key: HMAC-SHA256 chained from "AWS4" + the secret key over the date, the region, the service and
   "aws4_request";
4. the signature: HMAC-SHA256 of the string to sign with that key, in hex, sent in the Authorization header
   ("AWS4-HMAC-SHA256 Credential=<key id>/<scope>, SignedHeaders=..., Signature=...") beside X-Amz-Date, and
   X-Amz-Security-Token for temporary credentials (signed too).

URI encoding is AWS's own: every byte but A-Z a-z 0-9 - . _ ~ as %XY (uppercase hex), a space as %20, never "+". The path
is taken as the request sends it and encoded once more, as every service but S3 wants it (the plugin's paths hold no
character that the two ways encode differently). tests/test_sigv4.py checks it against AWS's published examples
(Amazon S3 User Guide, "Signature Calculations for the Authorization Header", their canonical requests, strings to sign
and signatures).

`Signer` is the `auth=` of a liminal_libs RestClient: (method, url, headers, body) -> the headers signed, the region and
service read off the host (ec2.<region>.amazonaws.com, route53.amazonaws.com)."""
from __future__ import annotations

import hashlib
import hmac
import re
import string
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from urllib.parse import unquote, urlsplit

ALGORITHM = "AWS4-HMAC-SHA256"
TERMINATOR = "aws4_request"
UNRESERVED = frozenset(string.ascii_letters + string.digits + "-_.~")
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()  # e3b0c442...: a body that is none
EC2_HOST = re.compile(r"^ec2\.([a-z]{2}(?:-[a-z]+)+-\d{1,2})\.amazonaws\.com$")
ROUTE53_HOST = "route53.amazonaws.com"
ROUTE53_SCOPE = ("us-east-1", "route53")  # Route 53 is global: its requests are signed for us-east-1


@dataclass(frozen=True)
class Credentials:
    """An IAM access key (its ID and secret) and, for temporary credentials, the session token."""

    access_key: str = field(repr=False)
    secret_key: str = field(repr=False)
    token: str = field(default="", repr=False)


def uri_encode(text: str, slash: bool = True) -> str:
    """`text` URI-encoded AWS's way (UTF-8 bytes; A-Z a-z 0-9 - . _ ~ kept; %XY otherwise); "/" kept when not `slash`."""
    out = []
    for byte in str(text).encode("utf-8"):
        ch = chr(byte)
        if ch in UNRESERVED or (ch == "/" and not slash):
            out.append(ch)
        else:
            out.append(f"%{byte:02X}")
    return "".join(out)


def sha256_hex(data: bytes | str) -> str:
    return hashlib.sha256(data.encode("utf-8") if isinstance(data, str) else data).hexdigest()


def _hmac(key: bytes, data: str) -> bytes:
    return hmac.new(key, data.encode("utf-8"), hashlib.sha256).digest()


def canonical_uri(path: str) -> str:
    """The path as the request sends it, encoded once more ("/" kept); "/" when there is none."""
    return uri_encode(path or "/", slash=False)


def canonical_query(query: str) -> str:
    """The query's names and values decoded, each URI-encoded, sorted (after encoding): "a=1&b=2"; a name alone is "name="."""
    pairs = []
    for part in (query or "").split("&"):
        if not part:
            continue
        name, _, value = part.partition("=")
        pairs.append((uri_encode(unquote(name)), uri_encode(unquote(value))))
    return "&".join(f"{n}={v}" for n, v in sorted(pairs))


def canonical_headers(headers: Mapping[str, str]) -> tuple[str, str]:
    """The headers signed as the canonical request holds them ("name:value\\n" each, sorted by lowercased name, values
    trimmed and inner runs of spaces made one), and their names joined by ";"."""
    norm = {str(k).strip().lower(): " ".join(str(v).split()) for k, v in headers.items()}
    names = sorted(norm)
    return "".join(f"{n}:{norm[n]}\n" for n in names), ";".join(names)


def canonical_request(method: str, url: str, headers: Mapping[str, str], payload_hash: str) -> tuple[str, str]:
    """The canonical request of a request to `url` signing `headers`, and its signed headers' names."""
    parts = urlsplit(url)
    lines, signed = canonical_headers(headers)
    return "\n".join([method.upper(), canonical_uri(parts.path), canonical_query(parts.query), lines, signed,
                      payload_hash]), signed


def scope_of(date: str, region: str, service: str) -> str:
    return f"{date}/{region}/{service}/{TERMINATOR}"


def string_to_sign(amz_date: str, scope: str, request: str) -> str:
    return "\n".join([ALGORITHM, amz_date, scope, sha256_hex(request)])


def signing_key(secret: str, date: str, region: str, service: str) -> bytes:
    key = _hmac(("AWS4" + secret).encode("utf-8"), date)
    key = _hmac(key, region)
    key = _hmac(key, service)
    return _hmac(key, TERMINATOR)


@dataclass(frozen=True)
class Signed:
    """A signature and what it was made of (the tests compare each step with AWS's published examples)."""

    authorization: str
    signature: str
    canonical_request: str
    string_to_sign: str
    signed_headers: str
    scope: str


def sign(method: str, url: str, headers: Mapping[str, str], body: bytes | str, credentials: Credentials, region: str,
         service: str, amz_date: str, payload_hash: str | None = None) -> Signed:
    """A request signed: `headers` are the ones signed, x-amz-date (= `amz_date`) among them, as sent."""
    payload = payload_hash or sha256_hex(body or b"")
    request, signed = canonical_request(method, url, headers, payload)
    scope = scope_of(amz_date[:8], region, service)
    to_sign = string_to_sign(amz_date, scope, request)
    signature = hmac.new(signing_key(credentials.secret_key, amz_date[:8], region, service), to_sign.encode("utf-8"),
                         hashlib.sha256).hexdigest()
    authorization = (f"{ALGORITHM} Credential={credentials.access_key}/{scope}, SignedHeaders={signed}, "
                     f"Signature={signature}")
    return Signed(authorization, signature, request, to_sign, signed, scope)


def host_of(url: str) -> str:
    """The Host header a request to `url` sends: its host, lowercased, with a port only when not 443."""
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    return host if parts.port in (None, 443) else f"{host}:{parts.port}"


def aws_scope(host: str) -> tuple[str, str]:
    """(region, service) of an AWS endpoint the plugin asks: EC2's regional ones and Route 53's; ValueError for another."""
    host = (host or "").lower()
    if host == ROUTE53_HOST:
        return ROUTE53_SCOPE
    m = EC2_HOST.match(host)
    if m:
        return m.group(1), "ec2"
    raise ValueError(f"{host or 'no host'} is none of the endpoints this plugin signs for (EC2's regional ones, Route 53's)")


class Signer:
    """The `auth=` of a RestClient: each request signed with `credentials` for the region and service of its host (`scope`),
    at the time `clock` says (a test's fixed one)."""

    HEADERS = ("content-type",)  # the standard headers signed besides host and the x-amz- ones

    def __init__(self, credentials: Credentials, scope: Callable[[str], tuple[str, str]] = aws_scope,
                 clock: Callable[[], float] = time.time):
        self.credentials = credentials
        self._scope = scope
        self._clock = clock

    def __call__(self, method: str, url: str, headers: Mapping[str, str], body: bytes | None) -> dict:
        region, service = self._scope(urlsplit(url).hostname or "")
        amz_date = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(self._clock()))
        out = {k: v for k, v in headers.items()
               if k.lower() not in ("authorization", "x-amz-date", "x-amz-security-token", "host")}
        out["X-Amz-Date"] = amz_date
        if self.credentials.token:
            out["X-Amz-Security-Token"] = self.credentials.token
        signed = {"host": host_of(url)}
        for k, v in out.items():
            low = k.lower()
            if low.startswith("x-amz-") or low in self.HEADERS:
                signed[low] = v
        made = sign(method, url, signed, body or b"", self.credentials, region, service, amz_date)
        out["Authorization"] = made.authorization
        return out
