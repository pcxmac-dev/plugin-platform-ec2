"""What the plugin's two AWS APIs share: their XML (EC2's Query API answers XML, Route 53's REST API takes and answers XML),
read with xml.etree by local names whatever the namespace; their errors (EC2: <Response><Errors><Error><Code>,
<Message></Error></Errors><RequestID>; Route 53: <ErrorResponse><Error><Type><Code><Message></Error><RequestId>, and
<InvalidChangeBatch><Messages><Message>) worded for the user with what to do, the keys scrubbed; and the client: the
library's RestClient with the plugin's SigV4 signer as its `auth=`, its error reader as `error=`.

Route 53's change is an XML document, sent as it is (RestClient's `data=`, liminal-libs 1.49.1) and signed with it; Route
53's own "slow down" (HTTP 400, Throttling or PriorRequestNotComplete: nothing was done) is waited out like a 429
(`throttled=`, `route53_throttled`), EC2's (RequestLimitExceeded, a 503) tried again for a read by the client itself."""
from __future__ import annotations

import xml.etree.ElementTree as ET
from collections.abc import Callable, Iterable, Mapping

from liminal_libs.machines.rest import Answer, RestClient, RestError

from .sigv4 import Signer, uri_encode

AGENT = "Liminal platform plugin (ec2)"
HINTS = {  # an AWS error code -> what to do, said after AWS's own words
    "AuthFailure": "the access key is wrong or inactive: EC2_ACCESS_KEY_ID and EC2_SECRET_ACCESS_KEY as IAM gave them",
    "InvalidClientTokenId": "the access key ID is not one AWS knows: EC2_ACCESS_KEY_ID",
    "SignatureDoesNotMatch": "the secret does not match the key ID: EC2_SECRET_ACCESS_KEY",
    "IncompleteSignature": "the request's signature was not whole",
    "MissingAuthenticationToken": "no key was sent: EC2_ACCESS_KEY_ID and EC2_SECRET_ACCESS_KEY",
    "UnauthorizedOperation": "the key's IAM policy does not allow this action (the README writes out the policy it needs)",
    "AccessDenied": "the key's IAM policy does not allow this action (the README writes out the policy it needs)",
    "OptInRequired": "the region is not enabled for the account (Account > AWS Regions), or the account is not signed up for EC2",
    "RequestExpired": "this PC's clock is off by more than a few minutes, or the temporary credentials (EC2_SESSION_TOKEN) expired",
    "ExpiredToken": "the temporary credentials expired: enter new ones (EC2_ACCESS_KEY_ID, EC2_SECRET_ACCESS_KEY, EC2_SESSION_TOKEN)",
    "InvalidToken": "EC2_SESSION_TOKEN is not a token AWS knows",
    "RequestLimitExceeded": "AWS's request rate for the account was reached: it is tried again later",
    "Throttling": "Route 53's request rate for the account was reached: it is tried again later",
    "PriorRequestNotComplete": "Route 53 is still applying the zone's last change: try again in a few seconds",
    "Blocked": "AWS says the account is blocked: AWS Support",
    "PendingVerification": "AWS is still verifying the account",
    "IncorrectInstanceState": "the instance is not in a state that allows it now",
    "UnsupportedOperation": "AWS does not offer it for this instance (an instance store-backed one cannot be stopped)",
    "InvalidPermission.Duplicate": "the group has that rule already",
    "InvalidPermission.NotFound": "the group has no such rule (read again: it may be gone)",
    "InvalidKeyPair.Duplicate": "the region has a key pair of that name already",
    "InvalidKey.Format": "the public key is not in OpenSSH's format (ssh-ed25519 AAAA… or ssh-rsa AAAA…)",
    "InvalidKeyPair.Format": "the public key is not in OpenSSH's format (ssh-ed25519 AAAA… or ssh-rsa AAAA…)",
    "InvalidChangeBatch": "Route 53 refused the change as written",
    "NoSuchHostedZone": "the zone is gone (read again)",
}


class AwsError(RestError):
    """A request AWS refused or that failed, in words (the keys scrubbed): RestError's status, code and request id, and
    the action and region it was (`action`, `region`)."""

    def __init__(self, message: str, status: int = 0, code: str = "", request_id: str = "", retry_after=None,
                 action: str = "", region: str = ""):
        super().__init__(message, status, code, request_id, retry_after)
        self.action, self.region = action, region

    @classmethod
    def of(cls, e: RestError, action: str, region: str = "") -> "AwsError":
        """A RestError said as the plugin says it: "DescribeInstances in eu-west-1: AuthFailure: ... (HTTP 401)"."""
        words = str(e)
        if e.status and f"HTTP {e.status}: " in words:  # RestClient's "GET /: HTTP 401: <words>": AWS's own words first
            words = words.split(f"HTTP {e.status}: ", 1)[1] + f" (HTTP {e.status})"
        elif ": " in words and words.split(" ", 1)[0] in ("GET", "POST"):
            words = words.split(": ", 1)[1]
        where = f"{action} in {region}" if region else action
        return cls(f"{where}: {words}", e.status, e.code, e.request_id, e.retry_after, action, region)


# -- XML ---------------------------------------------------------------------------------------------------------------
def parse(body: bytes) -> ET.Element:
    """An answer's XML, every tag by its local name (EC2's and Route 53's namespaces taken off). ValueError for one that is
    no XML or declares a document type (no entity of a document type is ever expanded)."""
    data = body or b""
    if b"<!DOCTYPE" in data[:4096].upper():
        raise ValueError("an XML answer declaring a document type is not read")
    try:
        root = ET.fromstring(data)
    except ET.ParseError as e:
        raise ValueError(f"an answer that is no XML ({e})") from None
    for el in root.iter():
        if isinstance(el.tag, str) and "}" in el.tag:
            el.tag = el.tag.split("}", 1)[1]
    return root


def text(el: ET.Element | None, path: str, default: str = "") -> str:
    """The text at `path` under `el` (a/b/c, local names), trimmed; `default` when there is none."""
    if el is None:
        return default
    found = el.find(path)
    if found is None or found.text is None:
        return default
    return found.text.strip()


def items(el: ET.Element | None, path: str) -> list[ET.Element]:
    """The <item> children of the container at `path` (EC2's lists: reservationSet, instancesSet, tagSet ...)."""
    if el is None:
        return []
    box = el.find(path)
    return [] if box is None else box.findall("item")


def tags_of(el: ET.Element | None) -> dict[str, str]:
    return {text(t, "key"): text(t, "value") for t in items(el, "tagSet") if text(t, "key")}


def flag(value: str) -> bool | None:
    v = (value or "").strip().lower()
    return True if v == "true" else False if v == "false" else None


def error_words(answer: Answer) -> tuple[str, str]:
    """AWS's error in words and its code (the RestClient's `error=`): "AuthFailure: AWS was not able to validate the provided
    access credentials (the access key is wrong ...)"."""
    try:
        root = parse(answer.body)
    except ValueError:
        return "", ""
    code = text(root, ".//Error/Code") or text(root, "Code")
    message = text(root, ".//Error/Message") or text(root, "Message")
    if root.tag == "InvalidChangeBatch":
        code = code or "InvalidChangeBatch"
        said = [" ".join((m.text or "").split()) for m in root.iter("Message") if (m.text or "").strip()]
        message = "; ".join(said) or message
    words = f"{code}: {message}" if code and message else code or message
    if not words:
        return "", ""
    hint = HINTS.get(code)
    return (f"{words} ({hint})" if hint else words), code


def query(params: Mapping[str, object]) -> str:
    """Parameters as a query AWS reads and signs alike: each name and value URI-encoded its way, sorted (None left out)."""
    pairs = sorted((uri_encode(str(k)), uri_encode(str(v))) for k, v in params.items() if v is not None)
    return "&".join(f"{k}={v}" for k, v in pairs)


def https(method: str, url: str, headers: Mapping[str, str], body: bytes | None, timeout: float):
    """The requests package over HTTPS (redirects not followed): (status, headers, body)."""
    import requests

    resp = requests.request(method, url, headers=dict(headers), data=body, timeout=timeout, allow_redirects=False)
    return resp.status_code, dict(resp.headers), resp.content


class AwsClient(RestClient):
    """A RestClient for AWS: signed with `signer`, AWS's errors read, XML asked for; `post_xml` sends an XML document."""

    def __init__(self, base: str, *, signer: Signer, transport: Callable | None = None, secrets: Iterable[str] = (),
                 throttled: Callable[[Answer], bool] | None = None, **options):
        self.signer = signer
        super().__init__(base, auth=signer, transport=transport or https, secrets=secrets, error=error_words,
                         throttled=throttled, headers={"Accept": "application/xml, text/xml", "User-Agent": AGENT}, **options)

    def post_xml(self, url: str, document: bytes, ok: Iterable[int] = (200,)) -> Answer:
        """`document` sent by POST as it is (Content-Type text/xml), signed with it."""
        return self.request("POST", url, headers={"Content-Type": "text/xml; charset=utf-8"}, ok=ok, data=document)


def route53_throttled(answer: Answer) -> bool:
    """Whether Route 53 asked to slow down (its HTTP 400 Throttling, or PriorRequestNotComplete: the zone's last change
    still being applied); neither was done, so it is asked again after a wait."""
    return error_words(answer)[1] in ("Throttling", "PriorRequestNotComplete")
