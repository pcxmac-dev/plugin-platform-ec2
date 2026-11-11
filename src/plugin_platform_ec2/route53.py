"""Amazon Route 53's API (Version 2013-04-01) as the plugin asks it: https://route53.amazonaws.com/2013-04-01/..., signed
with SigV4 for us-east-1 and the route53 service, XML both ways. Reads: ListHostedZones, ListResourceRecordSets, GetChange;
the one change: ChangeResourceRecordSets, with an UPSERT (a record set made, or its values replaced) or a DELETE (the set
given exactly as it is, as Route 53 asks), one record set a change, so every other record of the zone is untouched.

A record set is a name and a type with its TTL and values; one with an alias target, a routing policy (a SetIdentifier) or
a traffic policy is read and shown but never written here (WRITABLE says which simple sets are).

Its requests are spaced (SPACING_S apart: Route 53 refills 10 a second for the whole account), so reading twenty zones
never goes out as a burst; a throttle is waited out by the client (aws.route53_throttled)."""
from __future__ import annotations

import ipaddress
import re
import threading
import time
import xml.etree.ElementTree as ET
from collections.abc import Iterable
from dataclasses import dataclass

from liminal_libs.machines.rest import RestError

from .aws import AwsClient, AwsError, flag, parse, query, text

VERSION = "2013-04-01"
BASE = f"https://route53.amazonaws.com/{VERSION}"
NAMESPACE = f"https://route53.amazonaws.com/doc/{VERSION}/"
READS = ("ListHostedZones", "ListResourceRecordSets", "GetChange")
WRITES = ("ChangeResourceRecordSets",)
ZONES_PAGE = 100  # ListHostedZones' most a response
RECORDS_PAGE = 300  # ListResourceRecordSets' most a response
RECORD_PAGES = 10  # a zone's records read up to 3,000
TTL_DEFAULT = 300
SPACING_S = 0.15  # the least time between two of its requests (under Route 53's 10 a second)
TTL_MOST = 2147483647
WRITABLE = ("A", "AAAA", "CNAME", "TXT", "MX", "NS", "CAA", "SRV")
TEXT_CHUNK = 255  # a TXT value's strings are at most 255 characters each
CAA = re.compile(r'^(\d{1,3})\s+(issue|issuewild|iodef|issuemail|issuevmc)\s+"(.*)"$', re.I)
SRV = re.compile(r"^(\d{1,5})\s+(\d{1,5})\s+(\d{1,5})\s+(\S+)$")
MX = re.compile(r"^(\d{1,5})\s+(\S+)$")
LABEL = re.compile(r"^(?:\*|[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)$")


@dataclass(frozen=True)
class Zone:
    id: str  # Z1D633PJN98FT9 (the API's /hostedzone/ taken off)
    name: str  # example.com (no trailing dot)
    private: bool = False
    records: int | None = None
    comment: str = ""


@dataclass(frozen=True)
class RecordSet:
    name: str  # www.example.com (no trailing dot, escapes read: \052 is *)
    type: str
    ttl: int | None = None
    values: tuple[str, ...] = ()
    alias: str = ""  # an alias target's DNS name
    set_id: str = ""  # a routing policy's SetIdentifier
    routing: str = ""  # "weighted", "latency", "failover", "geolocation", "multivalue", "geoproximity", "ip-based"
    traffic_policy: str = ""
    health_check: str = ""

    @property
    def simple(self) -> bool:
        """A simple record set: no alias, no routing policy, no traffic policy."""
        return not (self.alias or self.set_id or self.traffic_policy)

    @property
    def kind_words(self) -> str:
        if self.alias:
            return f"alias to {self.alias}"
        if self.traffic_policy:
            return "a traffic policy's"
        if self.set_id:
            return f"{self.routing or 'routing policy'} ({self.set_id})"
        return "simple"


@dataclass(frozen=True)
class ChangeInfo:
    id: str
    status: str  # PENDING, INSYNC
    submitted: str = ""
    comment: str = ""


# -- names ----------------------------------------------------------------------------------------------------------------
def unescape(name: str) -> str:
    """A name as Route 53 writes it (octal escapes: \\052 is *, \\100 is @) read as a name, no trailing dot, lowercased."""
    out = re.sub(r"\\(\d{3})", lambda m: chr(int(m.group(1), 8)), str(name or ""))
    return out.rstrip(".").lower()


def fqdn(name: str, zone: str) -> str:
    """A name typed in `zone` (@, www, home.example.com, *.example.com) as its full name; ValueError when it is outside."""
    z = zone.rstrip(".").lower()
    typed = str(name or "").strip().lower()
    n = typed.rstrip(".")
    if n in ("", "@"):
        return z
    if n.endswith("." + z) or n == z:
        full = n
    elif typed.endswith("."):  # a name given whole (its trailing dot) outside the zone
        raise ValueError(f"{str(name).strip()!r} is not a name in {z}: it is outside the zone")
    else:
        full = f"{n}.{z}"
    labels = full[: -len(z)].rstrip(".").split(".") if full != z else []
    if len(full) > 253 or not all(LABEL.match(x) for x in labels) or ("*" in labels and labels[0] != "*"):
        raise ValueError(f"{str(name).strip()!r} is not a name in {z} (@, www, home, *.{z})")
    return full


def host_value(value: str, what: str) -> str:
    v = str(value or "").strip().rstrip(".").lower()
    labels = v.split(".")
    if len(v) > 253 or len(labels) < 2 or not all(LABEL.match(x) and x != "*" for x in labels):
        raise ValueError(f"{str(value).strip()!r} is not a host name ({what})")
    return v


def txt_value(value: str) -> str:
    """A TXT value as Route 53 takes it: quoted strings of at most 255 characters ("v=spf1 ..."); a text typed bare is
    quoted (and split into strings of 255)."""
    v = str(value or "").strip()
    if not v:
        raise ValueError("no text given")
    if any(ord(c) < 32 or ord(c) == 127 for c in v):
        raise ValueError("a TXT record's text is one line")
    if re.fullmatch(r'(?:"(?:[^"\\]|\\.)*"\s*)+', v):
        return " ".join(re.findall(r'"(?:[^"\\]|\\.)*"', v))
    esc = v.replace("\\", "\\\\").replace('"', '\\"')
    chunks, cur = [], ""
    for ch in re.findall(r'\\.|.', esc):
        if len(cur) + len(ch) > TEXT_CHUNK:
            chunks.append(cur)
            cur = ""
        cur += ch
    chunks.append(cur)
    return " ".join(f'"{c}"' for c in chunks)


def value_of(rtype: str, value: str) -> str:
    """A record's value as written to Route 53; ValueError when it is none of its type."""
    t = rtype.upper()
    v = str(value or "").strip()
    if not v:
        raise ValueError("no value given")
    if t == "A":
        try:
            return str(ipaddress.IPv4Address(v))
        except ValueError:
            raise ValueError(f"{v!r} is not an IPv4 address (an A record's)") from None
    if t == "AAAA":
        try:
            return str(ipaddress.IPv6Address(v))
        except ValueError:
            raise ValueError(f"{v!r} is not an IPv6 address (an AAAA record's)") from None
    if t in ("CNAME", "NS"):
        return host_value(v, f"a {t} record's")
    if t == "TXT":
        return txt_value(v)
    if t == "MX":
        m = MX.match(v)
        if not m or int(m.group(1)) > 65535:
            raise ValueError("an MX value is its preference and its mail server: 10 mail.example.com")
        return f"{int(m.group(1))} {host_value(m.group(2), 'an MX record mail server')}"
    if t == "CAA":
        m = CAA.match(v)
        if not m or int(m.group(1)) > 255:
            raise ValueError('a CAA value is flags, tag and value: 0 issue "letsencrypt.org"')
        return f'{int(m.group(1))} {m.group(2).lower()} "{m.group(3)}"'
    if t == "SRV":
        m = SRV.match(v)
        if not m or any(int(m.group(i)) > 65535 for i in (1, 2, 3)):
            raise ValueError("an SRV value is priority, weight, port and target: 10 5 5060 sip.example.com")
        return f"{int(m.group(1))} {int(m.group(2))} {int(m.group(3))} {host_value(m.group(4), 'an SRV target')}"
    raise ValueError(f"{rtype!r} is no record type written here: {', '.join(WRITABLE)}")


def same_value(rtype: str, a: str, b: str) -> bool:
    """Whether two values of a record type are the same value (host names without their trailing dot, in any case)."""
    t = rtype.upper()
    if t in ("CNAME", "NS", "MX", "SRV"):
        return a.strip().rstrip(".").lower() == b.strip().rstrip(".").lower()
    if t in ("A", "AAAA"):
        try:
            return ipaddress.ip_address(a.strip()) == ipaddress.ip_address(b.strip())
        except ValueError:
            return a.strip() == b.strip()
    return a.strip() == b.strip()


def ttl_of(value) -> int:
    try:
        t = int(value)
    except (TypeError, ValueError):
        raise ValueError(f"the TTL is a number of seconds, 0 to {TTL_MOST:,}") from None
    if not 0 <= t <= TTL_MOST:
        raise ValueError(f"the TTL is 0 to {TTL_MOST:,} seconds")
    return t


# -- the API ----------------------------------------------------------------------------------------------------------------
class Route53Api:
    """Route 53 through one client (route53.amazonaws.com)."""

    def __init__(self, client: AwsClient, sleep=time.sleep, spacing: float = SPACING_S):
        self.client = client
        self._sleep = sleep
        self._spacing = max(0.0, float(spacing))
        self._lock = threading.Lock()
        self._last = 0.0

    def _paced(self) -> None:
        """Waits until SPACING_S has passed since its last request (the requests of every thread spaced alike)."""
        with self._lock:
            wait = self._last + self._spacing - time.monotonic()
            if wait > 0:
                self._sleep(wait)
            self._last = time.monotonic()

    def _get(self, action: str, path: str, params: dict | None = None):
        url = f"{BASE}{path}" + (("?" + query(params)) if params else "")
        self._paced()
        try:
            return parse(self.client.request("GET", url).body)
        except RestError as e:
            raise AwsError.of(e, action) from None
        except ValueError as e:
            raise AwsError(f"{action}: {e}", action=action) from None

    def zones(self) -> list[Zone]:
        """The account's hosted zones (ListHostedZones, a page of 100 at a time)."""
        out, marker = [], None
        for _ in range(50):
            root = self._get("ListHostedZones", "/hostedzone", {"maxitems": ZONES_PAGE, "marker": marker})
            for z in root.iter("HostedZone"):
                count = text(z, "ResourceRecordSetCount")
                out.append(Zone(id=text(z, "Id").rsplit("/", 1)[-1], name=unescape(text(z, "Name")),
                                private=flag(text(z, "Config/PrivateZone")) is True,
                                records=int(count) if count.isdigit() else None, comment=text(z, "Config/Comment")))
            if flag(text(root, "IsTruncated")) is not True or not text(root, "NextMarker"):
                break
            marker = text(root, "NextMarker")
        return out

    def records(self, zone: str, most_pages: int = RECORD_PAGES) -> tuple[list[RecordSet], bool]:
        """The zone's record sets (ListResourceRecordSets, 300 a page, `most_pages` pages): (sets, more left)."""
        out: list[RecordSet] = []
        params: dict = {"maxitems": RECORDS_PAGE}
        for _ in range(max(1, most_pages)):
            root = self._get("ListResourceRecordSets", f"/hostedzone/{zone_id(zone)}/rrset", params)
            out += [record_of(r) for r in root.iter("ResourceRecordSet")]
            if flag(text(root, "IsTruncated")) is not True:
                return out, False
            params = {"maxitems": RECORDS_PAGE, "name": text(root, "NextRecordName"), "type": text(root, "NextRecordType"),
                      "identifier": text(root, "NextRecordIdentifier") or None}
        return out, True

    def at(self, zone: str, name: str) -> list[RecordSet]:
        """The record sets at `name` (every type), read now: the list begins at the name, those of another name dropped."""
        root = self._get("ListResourceRecordSets", f"/hostedzone/{zone_id(zone)}/rrset",
                         {"name": name.rstrip(".") + ".", "maxitems": 100})
        return [r for r in (record_of(x) for x in root.iter("ResourceRecordSet")) if r.name == unescape(name)]

    def record_set(self, zone: str, name: str, rtype: str) -> RecordSet | None:
        """The record set of `name` and `rtype`, read now (a simple one first when several routing ones share them)."""
        found = [r for r in self.at(zone, name) if r.type == rtype.upper()]
        return next((r for r in found if r.simple), found[0] if found else None)

    def change(self, zone: str, changes: Iterable[tuple[str, RecordSet]], comment: str = "") -> ChangeInfo:
        """ChangeResourceRecordSets: each (UPSERT | DELETE, a simple record set) applied at once, or none."""
        document = change_document(changes, comment)
        url = f"{BASE}/hostedzone/{zone_id(zone)}/rrset/"
        self._paced()
        try:
            answer = self.client.post_xml(url, document)
        except RestError as e:
            raise AwsError.of(e, "ChangeResourceRecordSets") from None
        return change_of(parse(answer.body))

    def get_change(self, change: str) -> ChangeInfo:
        """GetChange: whether a change has reached every Route 53 name server (INSYNC) or not yet (PENDING)."""
        return change_of(self._get("GetChange", f"/change/{str(change).rsplit('/', 1)[-1]}"))


def zone_id(zone: str) -> str:
    z = str(zone or "").strip().rsplit("/", 1)[-1]
    if not re.fullmatch(r"[A-Z0-9]{1,32}", z):
        raise ValueError(f"{zone!r} is not a hosted zone ID (Z…)")
    return z


def record_of(el) -> RecordSet:
    routing = ("weighted" if el.find("Weight") is not None else "latency" if el.find("Region") is not None
               else "failover" if el.find("Failover") is not None else "geolocation" if el.find("GeoLocation") is not None
               else "geoproximity" if el.find("GeoProximityLocation") is not None
               else "ip-based" if el.find("CidrRoutingConfig") is not None
               else "multivalue" if el.find("MultiValueAnswer") is not None else "")
    ttl = text(el, "TTL")
    return RecordSet(name=unescape(text(el, "Name")), type=text(el, "Type").upper(), ttl=int(ttl) if ttl.isdigit() else None,
                     values=tuple(text(v, "Value") for v in el.iter("ResourceRecord")),
                     alias=unescape(text(el, "AliasTarget/DNSName")), set_id=text(el, "SetIdentifier"), routing=routing,
                     traffic_policy=text(el, "TrafficPolicyInstanceId"), health_check=text(el, "HealthCheckId"))


def change_of(root) -> ChangeInfo:
    info = root.find(".//ChangeInfo")
    return ChangeInfo(id=text(info, "Id").rsplit("/", 1)[-1], status=text(info, "Status"),
                      submitted=text(info, "SubmittedAt"), comment=text(info, "Comment"))


def change_document(changes: Iterable[tuple[str, RecordSet]], comment: str = "") -> bytes:
    """The ChangeResourceRecordSetsRequest, its elements in the order the reference's basic syntax gives: ChangeBatch
    (Comment, Changes), each Change (Action, ResourceRecordSet: Name, Type, TTL, ResourceRecords)."""
    root = ET.Element("ChangeResourceRecordSetsRequest", {"xmlns": NAMESPACE})
    batch = ET.SubElement(root, "ChangeBatch")
    if comment:
        ET.SubElement(batch, "Comment").text = comment
    box = ET.SubElement(batch, "Changes")
    count = 0
    for action, rs in changes:
        if action not in ("UPSERT", "DELETE"):
            raise ValueError(f"{action} is not a change this plugin makes")
        if not rs.simple:
            raise ValueError(f"{rs.name} {rs.type} is {rs.kind_words}: written in Route 53's console, not here")
        if not rs.values:
            raise ValueError(f"{rs.name} {rs.type}: a record set holds a value at least")
        change = ET.SubElement(box, "Change")
        ET.SubElement(change, "Action").text = action
        rrs = ET.SubElement(change, "ResourceRecordSet")
        ET.SubElement(rrs, "Name").text = rs.name.rstrip(".") + "."
        ET.SubElement(rrs, "Type").text = rs.type
        ET.SubElement(rrs, "TTL").text = str(rs.ttl if rs.ttl is not None else TTL_DEFAULT)
        records = ET.SubElement(rrs, "ResourceRecords")
        for v in rs.values:
            ET.SubElement(ET.SubElement(records, "ResourceRecord"), "Value").text = v
        count += 1
    if not count:
        raise ValueError("no change given")
    return b'<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding="utf-8")


def plan_set(current: list[RecordSet], zone: Zone, name: str, rtype: str, value: str, ttl=None,
             how: str | None = None) -> tuple[RecordSet | None, RecordSet, str]:
    """A value set at `name` (`current`: the sets read at that name now): (the set as it was, the set as it will be, what
    is done in words). `how`: "replace" (the set holds this value alone) or "add" (it is added beside its values); unless
    said, an A, AAAA or CNAME is replaced and the rest added. ValueError (nothing sent) when it cannot be."""
    t = str(rtype or "").strip().upper()
    if t not in WRITABLE:
        raise ValueError(f"{rtype!r} is no record type written here: {', '.join(WRITABLE)}")
    full = fqdn(name, zone.name)
    v = value_of(t, value)
    if t == "NS" and full == zone.name:
        raise ValueError(f"{zone.name}'s own NS records are Route 53's (its delegation): changed in Route 53's console")
    if t == "CNAME" and full == zone.name:
        raise ValueError("a CNAME cannot stand for the zone's own name")
    others = [r for r in current if r.type != t]
    if t == "CNAME" and others:
        raise ValueError(f"{full} holds other records ({', '.join(sorted({r.type for r in others}))}): a CNAME stands alone")
    if t != "CNAME" and any(r.type == "CNAME" for r in current):
        raise ValueError(f"{full} is a CNAME: it holds no {t} record beside it")
    was = next((r for r in current if r.type == t and r.simple), None)
    if any(r.type == t and not r.simple for r in current) and was is None:
        other = next(r for r in current if r.type == t)
        raise ValueError(f"{full} {t} is {other.kind_words}: written in Route 53's console, not here")
    mode = (how or ("replace" if t in ("A", "AAAA", "CNAME") else "add")).strip().lower()
    if mode not in ("replace", "add"):
        raise ValueError("how is replace (the set holds the value alone) or add (beside its values)")
    if t == "CNAME" and mode == "add" and was is not None and was.values:
        raise ValueError("a CNAME holds one value: it is replaced")
    new_ttl = ttl_of(ttl) if ttl not in (None, "") else (was.ttl if was and was.ttl is not None else TTL_DEFAULT)
    kept = list(was.values) if was and mode == "add" else []
    if any(same_value(t, x, v) for x in kept):
        values = tuple(kept)
    else:
        values = tuple([*kept, v])
    after = RecordSet(name=full, type=t, ttl=new_ttl, values=values)
    if was is None:
        words = f"made {full} {t} {v}"
    elif mode == "add":
        words = (f"{v} is in {full} {t} already" if values == was.values else f"added {v} to {full} {t}") + \
            (f" ({len(values)} values)" if len(values) > 1 else "")
    else:
        words = f"set {full} {t} to {v}" + (f" (it held {', '.join(was.values)})" if was.values else "")
    if was is not None and was.ttl != new_ttl:
        words += f"; TTL {new_ttl}"
    return was, after, words


def plan_remove(current: list[RecordSet], zone: Zone, name: str, rtype: str, value: str) -> tuple[RecordSet, RecordSet | None, str]:
    """A value taken out of the set at `name`: (the set as it is, the set as it will be: None when it is deleted, what is
    done in words). ValueError (nothing sent) when there is no such value, or it is Route 53's own."""
    t = str(rtype or "").strip().upper()
    full = fqdn(name, zone.name)
    if t == "SOA" or (t == "NS" and full == zone.name):
        raise ValueError(f"{zone.name}'s {t} record is Route 53's own: it stays")
    was = next((r for r in current if r.type == t and r.simple), None)
    if was is None:
        other = next((r for r in current if r.type == t), None)
        if other is not None:
            raise ValueError(f"{full} {t} is {other.kind_words}: removed in Route 53's console, not here")
        raise ValueError(f"{zone.name} has no {t} record at {full}")
    typed = str(value or "")
    try:
        written = value_of(t, typed) if t in WRITABLE else typed  # as it would be written (a TXT typed bare, quoted)
    except ValueError:
        written = typed
    keep = tuple(x for x in was.values if not (same_value(t, x, typed) or same_value(t, x, written)))
    if len(keep) == len(was.values):
        raise ValueError(f"{full} {t} holds no value {str(value).strip()!r} (it holds {', '.join(was.values)})")
    if keep:
        return was, RecordSet(name=full, type=t, ttl=was.ttl, values=keep), f"removed {value} from {full} {t} ({len(keep)} kept)"
    return was, None, f"deleted {full} {t} (its one value {value})"
