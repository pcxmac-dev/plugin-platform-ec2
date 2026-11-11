"""Stand-ins for AWS: the tests never reach AWS, a resolver or the network. `FakeAws` is EC2's Query API in each region and
Route 53's API as one transport, an account in memory answered in the XML the references show (EC2's namespace
2016-11-15, Route 53's 2013-04-01, AWS's error documents); every request it is sent is kept (`requests`) and its SigV4
signature checked against what was sent (its key, its scope, its signed headers and body). `Pairs` is a Login holding pairs
by name."""
from __future__ import annotations

import base64
import itertools
import re
import struct
import xml.etree.ElementTree as ET
from urllib.parse import parse_qsl, unquote, urlsplit
from xml.sax.saxutils import escape

import pytest

import liminal_libs.dns as dns_mod
import plugin_platform_ec2.aws as aws_mod
from liminal_libs.apps import Login, Unauthorized, pair_name
from plugin_platform_ec2 import Ec2Plugin
from plugin_platform_ec2.settings import NAMES
from plugin_platform_ec2.sigv4 import Credentials, host_of, sign

NS_EC2 = "http://ec2.amazonaws.com/doc/2016-11-15/"
NS_R53 = "https://route53.amazonaws.com/doc/2013-04-01/"
KEY_ID = "AKIA0TESTKEY0000ID01"  # a stand-in key (no account's)
SECRET = "Test/Secret+Key0123456789abcdefghijKLMNOP"
TOKEN = "IQoJb3JpZ2luX2VjTESTTOKEN0123456789abcdefghij"
ACCOUNT = "123456789012"
HOME = "93.184.216.34"  # this network's public address in the tests
ED25519 = "ssh-ed25519 " + base64.b64encode(struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32)
                                         + bytes(range(32))).decode() + " you@laptop"  # a stand-in public key (no one's)
ZONE = "Z0EXAMPLE1"  # example.com, public
PRIVATE = "Z0EXAMPLE2"  # corp.internal, private


def q(v) -> str:
    return escape(str(v), {'"': "&quot;"})


def ec2_xml(action: str, inner: str) -> bytes:
    return (f'<?xml version="1.0" encoding="UTF-8"?>\n<{action}Response xmlns="{NS_EC2}">'
            f"<requestId>59dbff89-35bd-4eac-99ed-be587EXAMPLE</requestId>{inner}</{action}Response>").encode()


def ec2_error(code: str, message: str) -> bytes:
    return (f'<?xml version="1.0" encoding="UTF-8"?>\n<Response><Errors><Error><Code>{code}</Code><Message>{q(message)}'
            "</Message></Error></Errors><RequestID>ea966190-f9aa-478e-9ede-example</RequestID></Response>").encode()


def r53_error(code: str, message: str) -> bytes:
    return (f'<?xml version="1.0"?>\n<ErrorResponse xmlns="{NS_R53}"><Error><Type>Sender</Type><Code>{code}</Code>'
            f"<Message>{q(message)}</Message></Error><RequestId>0a1b2c3d-example</RequestId></ErrorResponse>").encode()


def items(tag: str, rows) -> str:
    return f"<{tag}>" + "".join(f"<item>{r}</item>" for r in rows) + f"</{tag}>"


def tag_set(tags: dict) -> str:
    return items("tagSet", (f"<key>{q(k)}</key><value>{q(v)}</value>" for k, v in tags.items()))


def instance(iid, name, state="running", itype="t3.micro", zone="us-east-1a", ip="54.194.252.215", ipv6="",
             root="ebs", groups=(("sg-0web", "web"),), launched="2026-10-01T08:30:00.000Z", reason="",
             platform="Linux/UNIX", asg="") -> dict:
    return {"id": iid, "name": name, "state": state, "type": itype, "zone": zone, "ip": ip, "ipv6": ipv6, "root": root,
            "groups": list(groups), "launched": launched, "reason": reason, "platform": platform, "asg": asg}


def default_account() -> dict:
    return {
        "us-east-1": {
            "instances": [instance("i-0web0000000000001", "web", ipv6="2001:db8:1234:1a2b::123"),
                          instance("i-0db00000000000002", "db", state="stopped", itype="m5d.large", ip="",
                                   groups=(("sg-0db", "db"),), reason="User initiated (2026-10-02 09:00:00 GMT)"),
                          instance("i-0eph0000000000003", "", state="running", itype="m5d.large", ip="3.80.1.2",
                                   root="instance-store", groups=(("sg-0web", "web"),))],
            "groups": [{"id": "sg-0web", "name": "web", "about": "web servers", "vpc": "vpc-1"},
                       {"id": "sg-0db", "name": "db", "about": "databases", "vpc": "vpc-1"}],
            "rules": [{"id": "sgr-0ssh0000000000001", "group": "sg-0web", "egress": False, "protocol": "tcp", "from": 22,
                       "to": 22, "cidr4": "203.0.113.7/32", "description": "home"},
                      {"id": "sgr-0http000000000002", "group": "sg-0web", "egress": False, "protocol": "tcp", "from": 443,
                       "to": 443, "cidr4": "0.0.0.0/0", "description": ""},
                      {"id": "sgr-0out0000000000003", "group": "sg-0web", "egress": True, "protocol": "-1", "from": None,
                       "to": None, "cidr4": "0.0.0.0/0", "description": ""},
                      {"id": "sgr-0dbssh00000000004", "group": "sg-0db", "egress": False, "protocol": "tcp", "from": 22,
                       "to": 22, "cidr4": "203.0.113.7/32", "description": ""}],
            "keys": [{"id": "key-0laptop000000001", "name": "laptop", "type": "ed25519",
                      "fingerprint": "SHA256:abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG", "created": "2026-09-01T10:00:00.000Z"}],
            "volumes": [{"id": "vol-0root00000000001", "size": 8, "type": "gp3", "iops": 3000, "state": "in-use",
                         "zone": "us-east-1a", "attached": [("i-0web0000000000001", "/dev/xvda")]},
                        {"id": "vol-0data00000000002", "size": 100, "type": "gp3", "iops": 3000, "state": "in-use",
                         "zone": "us-east-1b", "attached": [("i-0db00000000000002", "/dev/sdf")]},
                        {"id": "vol-0spare0000000003", "size": 20, "type": "gp2", "iops": 100, "state": "available",
                         "zone": "us-east-1a", "attached": []}],
            "addresses": [{"ip": "203.0.113.41", "allocation": "eipalloc-08229861", "instance": "i-0db00000000000002",
                           "private": "10.0.0.228"}],
            "snapshots": 2, "images": 1},
        "eu-west-1": {"instances": [], "groups": [{"id": "sg-0eudef", "name": "default", "about": "default VPC security group",
                                                    "vpc": "vpc-2"}],
                      "rules": [], "keys": [], "volumes": [], "addresses": [], "snapshots": 0, "images": 0},
    }


TYPES = {"t3.micro": (2, 1024, False, None), "m5d.large": (2, 8192, True, 75)}


class FakeAws:
    """EC2 (every region of `account`) and Route 53 in memory; every request kept (`requests`), its signature checked."""

    def __init__(self, key: str = KEY_ID, secret: str = SECRET, token: str = ""):
        self.key, self.secret, self.token = key, secret, token
        self.requests: list[dict] = []
        self.account = default_account()
        self.enabled = ["eu-west-1", "us-east-1"]
        self.refuse: dict[str, tuple[int, str, str]] = {}  # region -> (status, code, message) for every action there
        self.fail: dict[str, tuple[int, str, str]] = {}  # action -> (status, code, message)
        self.page = None  # a describe's page size (None: MaxResults)
        self.zones = [{"id": ZONE, "name": "example.com", "private": False, "comment": "the user's"},
                      {"id": PRIVATE, "name": "corp.internal", "private": True, "comment": ""}]
        self.rrsets = {
            ZONE: [{"name": "example.com", "type": "SOA", "ttl": 900,
                    "values": ["ns-2048.awsdns-64.net. hostmaster.awsdns.com. 1 7200 900 1209600 86400"]},
                   {"name": "example.com", "type": "NS", "ttl": 172800,
                    "values": ["ns-2048.awsdns-64.net.", "ns-2049.awsdns-65.co.uk."]},
                   {"name": "example.com", "type": "MX", "ttl": 300, "values": ["10 mail.protonmail.ch.", "20 mailsec.protonmail.ch."]},
                   {"name": "example.com", "type": "TXT", "ttl": 300,
                    "values": ['"v=spf1 include:_spf.protonmail.ch ~all"', '"protonmail-verification=0123456789abcdef"']},
                   {"name": "home.example.com", "type": "A", "ttl": 60, "values": ["198.51.100.20"]},
                   {"name": "www.example.com", "type": "CNAME", "ttl": 300, "values": ["example.net"]},
                   {"name": "*.example.com", "type": "A", "ttl": 300, "values": ["192.0.2.10"]},
                   {"name": "cdn.example.com", "type": "A", "alias": "d111111abcdef8.cloudfront.net."}],
            PRIVATE: [{"name": "corp.internal", "type": "SOA", "ttl": 900, "values": ["ns-1.awsdns-00.com. x 1 7200 900 1209600 86400"]},
                      {"name": "db.corp.internal", "type": "A", "ttl": 300, "values": ["10.0.0.5"]}],
        }
        self.throttle = 0  # ListHostedZones answered with Route 53's Throttling this many times first
        self.change_ids = (f"C{n:012d}" for n in itertools.count(1))
        self.changes: dict[str, str] = {}
        self.ids = (f"{n:017x}" for n in itertools.count(0xabc))

    # -- what was sent -----------------------------------------------------------------------------------------------------
    def actions(self) -> list[str]:
        return [r["action"] for r in self.requests]

    def last(self, action: str) -> dict:
        return next(r for r in reversed(self.requests) if r["action"] == action)

    def zone_sets(self, zid: str = ZONE) -> list[tuple]:
        return [(r["name"], r["type"], r.get("ttl"), tuple(r.get("values", ()))) for r in self.rrsets[zid]]

    # -- the transport ----------------------------------------------------------------------------------------------------
    def __call__(self, method, url, headers, body, timeout):
        parts = urlsplit(url)
        assert parts.scheme == "https", url
        headers = dict(headers)
        record = {"method": method, "url": url, "host": parts.hostname, "path": parts.path, "headers": headers,
                  "body": body, "params": {}, "action": ""}
        self.requests.append(record)
        refused = self.verify(record)
        if parts.hostname == "route53.amazonaws.com":
            return self.route53(record, refused)
        m = re.match(r"^ec2\.([a-z0-9-]+)\.amazonaws\.com$", parts.hostname or "")
        assert m, url
        return self.ec2(record, m.group(1), refused)

    def verify(self, record) -> str:
        """The request's signature checked as AWS would: '' when it holds, else the error code AWS gives."""
        auth = record["headers"].get("Authorization", "")
        m = re.match(r"^AWS4-HMAC-SHA256 Credential=([^/]+)/(\d{8})/([a-z0-9-]+)/([a-z0-9]+)/aws4_request, "
                     r"SignedHeaders=([a-z0-9;-]+), Signature=([0-9a-f]{64})$", auth)
        assert m, f"no SigV4 Authorization header: {auth!r}"
        key, date, region, service, signed, signature = m.groups()
        low = {k.lower(): v for k, v in record["headers"].items()}
        low["host"] = host_of(record["url"])
        names = signed.split(";")
        assert {"host", "x-amz-date"} <= set(names) and low["x-amz-date"][:8] == date
        if record["host"] == "route53.amazonaws.com":
            assert (region, service) == ("us-east-1", "route53")
        else:
            assert service == "ec2" and record["host"] == f"ec2.{region}.amazonaws.com"
        if self.token or "x-amz-security-token" in low:
            assert "x-amz-security-token" in names
        if "content-type" in low:
            assert "content-type" in names
        if key != self.key:
            return "InvalidClientTokenId" if record["host"].startswith("route53") else "AuthFailure"
        if self.token and low.get("x-amz-security-token") != self.token:
            return "InvalidToken"
        made = sign(record["method"], record["url"], {n: low[n] for n in names}, record["body"] or b"",
                    Credentials(key, self.secret, low.get("x-amz-security-token", "")), region, service, low["x-amz-date"])
        return "" if made.signature == signature else "SignatureDoesNotMatch"

    # -- EC2 ----------------------------------------------------------------------------------------------------------------
    def ec2(self, record, region, refused):
        if record["method"] == "GET":
            params = dict(parse_qsl(urlsplit(record["url"]).query, keep_blank_values=True))
        else:
            assert record["method"] == "POST"
            assert record["headers"].get("Content-Type", "").startswith("application/x-www-form-urlencoded")
            params = dict(parse_qsl((record["body"] or b"").decode(), keep_blank_values=True))
        record["params"] = params
        action = record["action"] = params.get("Action", "")
        assert params.get("Version") == "2016-11-15", params
        if refused:
            sent_key = record["headers"]["Authorization"].split("Credential=", 1)[1].split("/", 1)[0]
            return 401, {}, ec2_error(refused, {"AuthFailure": "AWS was not able to validate the provided access credentials",
                                                "SignatureDoesNotMatch": "The request signature we calculated does not "
                                                "match the signature you provided. Check your AWS Secret Access Key and "
                                                f"signing method. (Credential={sent_key}/...)"}.get(refused, refused))
        if action in self.fail:
            status, code, message = self.fail[action]
            return status, {}, ec2_error(code, message)
        if region in self.refuse:
            status, code, message = self.refuse[region]
            return status, {}, ec2_error(code, message)
        acct = self.account.get(region)
        if acct is None:
            return 401, {}, ec2_error("OptInRequired", f"You are not subscribed to this service in {region}.")
        handler = getattr(self, "do_" + action, None)
        assert handler is not None, f"the fake has no {action}"
        return 200, {"Content-Type": "text/xml;charset=UTF-8"}, handler(region, acct, params)

    def paged(self, params, rows):
        size = self.page or int(params.get("MaxResults") or 1000)
        start = int(params.get("NextToken") or 0)
        chunk = rows[start:start + size]
        more = start + size < len(rows)
        return chunk, (f"<nextToken>{start + size}</nextToken>" if more else "")

    def do_DescribeRegions(self, region, acct, params):
        assert region == "us-east-1" and "AllRegions" not in params
        return ec2_xml("DescribeRegions", items("regionInfo", (
            f"<regionName>{r}</regionName><regionEndpoint>ec2.{r}.amazonaws.com</regionEndpoint>"
            "<optInStatus>opt-in-not-required</optInStatus>" for r in self.enabled)))

    def do_DescribeAccountAttributes(self, region, acct, params):
        attrs = {"default-vpc": ["vpc-1"], "vpc-max-elastic-ips": ["5"], "max-instances": ["20"]}
        return ec2_xml("DescribeAccountAttributes", items("accountAttributeSet", (
            f"<attributeName>{k}</attributeName>" + items("attributeValueSet", (f"<attributeValue>{v}</attributeValue>"
                                                                                 for v in vs)) for k, vs in attrs.items())))

    def instance_xml(self, i) -> str:
        nic = ""
        if i["ipv6"]:
            nic = items("networkInterfaceSet", ["<networkInterfaceId>eni-551ba033</networkInterfaceId>" +
                                                items("ipv6AddressesSet", [f"<ipv6Address>{i['ipv6']}</ipv6Address>"])])
        codes = {"pending": 0, "running": 16, "stopping": 64, "stopped": 80}
        return (f"<instanceId>{i['id']}</instanceId><imageId>ami-bff32ccc</imageId><instanceState><code>"
                f"{codes.get(i['state'], 48)}</code><name>{i['state']}</name></instanceState>"
                f"<reason>{q(i['reason'])}</reason><keyName>laptop</keyName><instanceType>{i['type']}</instanceType>"
                f"<launchTime>{i['launched']}</launchTime><placement><availabilityZone>{i['zone']}</availabilityZone>"
                "<tenancy>default</tenancy></placement>" + (f"<ipAddress>{i['ip']}</ipAddress>" if i["ip"] else "") +
                "<privateIpAddress>10.0.0.9</privateIpAddress>" +
                items("groupSet", (f"<groupId>{g}</groupId><groupName>{n}</groupName>" for g, n in i["groups"])) +
                f"<rootDeviceType>{i['root']}</rootDeviceType><platformDetails>{i['platform']}</platformDetails>" +
                tag_set({**({"Name": i["name"]} if i["name"] else {}),
                         **({"aws:autoscaling:groupName": i["asg"]} if i["asg"] else {})}) + nic)

    def do_DescribeInstances(self, region, acct, params):
        found = acct["instances"]
        if "InstanceId.1" in params:
            assert "MaxResults" not in params  # AWS refuses IDs and MaxResults together
            found, token = [i for i in found if i["id"] == params["InstanceId.1"]], ""
            if not found:
                return ec2_xml("DescribeInstances", "<reservationSet/>")
        else:
            assert params.get("MaxResults") == "100"  # paginated: EC2's larger token bucket
            found, token = self.paged(params, found)
        return ec2_xml("DescribeInstances", items("reservationSet", (
            f"<reservationId>r-{i['id'][2:]}</reservationId><ownerId>{ACCOUNT}</ownerId><groupSet/>"
            + items("instancesSet", [self.instance_xml(i)]) for i in found)) + token)

    def do_DescribeInstanceTypes(self, region, acct, params):
        names = [v for k, v in sorted(params.items()) if k.startswith("InstanceType.")]
        rows = []
        for n in names:
            vcpus, mib, store, gb = TYPES[n]
            rows.append(f"<instanceType>{n}</instanceType><vCpuInfo><defaultVCpus>{vcpus}</defaultVCpus></vCpuInfo>"
                        f"<memoryInfo><sizeInMiB>{mib}</sizeInMiB></memoryInfo>"
                        f"<instanceStorageSupported>{str(store).lower()}</instanceStorageSupported>"
                        + (f"<instanceStorageInfo><totalSizeInGB>{gb}</totalSizeInGB></instanceStorageInfo>" if store else ""))
        return ec2_xml("DescribeInstanceTypes", items("instanceTypeSet", rows))

    def do_DescribeSecurityGroups(self, region, acct, params):
        rows, token = self.paged(params, acct["groups"])

        def perms(group, egress):
            out = []
            for r in acct["rules"]:
                if r["group"] == group and r["egress"] == egress:
                    ports = "" if r["from"] is None else f"<fromPort>{r['from']}</fromPort><toPort>{r['to']}</toPort>"
                    out.append(f"<ipProtocol>{r['protocol']}</ipProtocol>{ports}<groups/>"
                               + items("ipRanges", [f"<cidrIp>{r['cidr4']}</cidrIp>"] if r.get("cidr4") else [])
                               + "<prefixListIds/>")
            return out
        return ec2_xml("DescribeSecurityGroups", items("securityGroupInfo", (
            f"<ownerId>{ACCOUNT}</ownerId><groupId>{g['id']}</groupId><groupName>{g['name']}</groupName>"
            f"<groupDescription>{q(g['about'])}</groupDescription><vpcId>{g['vpc']}</vpcId>"
            + items("ipPermissions", perms(g["id"], False)) + items("ipPermissionsEgress", perms(g["id"], True))
            for g in rows)) + token)

    def rule_xml(self, r) -> str:
        ports = "" if r["from"] is None else f"<fromPort>{r['from']}</fromPort><toPort>{r['to']}</toPort>"
        return (f"<securityGroupRuleId>{r['id']}</securityGroupRuleId><groupId>{r['group']}</groupId>"
                f"<groupOwnerId>{ACCOUNT}</groupOwnerId><isEgress>{str(r['egress']).lower()}</isEgress>"
                f"<ipProtocol>{r['protocol']}</ipProtocol>{ports}"
                + (f"<cidrIpv4>{r['cidr4']}</cidrIpv4>" if r.get("cidr4") else "")
                + (f"<cidrIpv6>{r['cidr6']}</cidrIpv6>" if r.get("cidr6") else "")
                + (f"<description>{q(r['description'])}</description>" if r.get("description") else "") + "<tagSet/>")

    def do_DescribeSecurityGroupRules(self, region, acct, params):
        if "SecurityGroupRuleId.1" in params:
            rows, token = [r for r in acct["rules"] if r["id"] == params["SecurityGroupRuleId.1"]], ""
        else:
            rows, token = self.paged(params, acct["rules"])
        return ec2_xml("DescribeSecurityGroupRules", items("securityGroupRuleSet", (self.rule_xml(r) for r in rows)) + token)

    def do_DescribeKeyPairs(self, region, acct, params):
        return ec2_xml("DescribeKeyPairs", items("keySet", (
            f"<keyPairId>{k['id']}</keyPairId><keyName>{q(k['name'])}</keyName><keyType>{k['type']}</keyType>"
            f"<keyFingerprint>{k['fingerprint']}</keyFingerprint><createTime>{k['created']}</createTime><tagSet/>"
            for k in acct["keys"])))

    def do_DescribeVolumes(self, region, acct, params):
        rows, token = self.paged(params, acct["volumes"])
        return ec2_xml("DescribeVolumes", items("volumeSet", (
            f"<volumeId>{v['id']}</volumeId><size>{v['size']}</size><snapshotId/><availabilityZone>{v['zone']}"
            f"</availabilityZone><status>{v['state']}</status><createTime>2026-09-01T10:00:00.000Z</createTime>"
            + items("attachmentSet", (f"<volumeId>{v['id']}</volumeId><instanceId>{i}</instanceId><device>{d}</device>"
                                      "<status>attached</status>" for i, d in v["attached"]))
            + f"<volumeType>{v['type']}</volumeType><iops>{v['iops']}</iops><encrypted>true</encrypted>"
            for v in rows)) + token)

    def do_DescribeAddresses(self, region, acct, params):
        return ec2_xml("DescribeAddresses", items("addressesSet", (
            f"<publicIp>{a['ip']}</publicIp><allocationId>{a['allocation']}</allocationId><domain>vpc</domain>"
            f"<instanceId>{a['instance']}</instanceId><privateIpAddress>{a['private']}</privateIpAddress>"
            for a in acct["addresses"])))

    def do_DescribeSnapshots(self, region, acct, params):
        assert params.get("Owner.1") == "self"
        rows, token = self.paged(params, list(range(acct["snapshots"])))
        return ec2_xml("DescribeSnapshots", items("snapshotSet", (
            f"<snapshotId>snap-{n:017x}</snapshotId><ownerId>{ACCOUNT}</ownerId><volumeSize>8</volumeSize>" for n in rows))
            + token)

    def do_DescribeImages(self, region, acct, params):
        assert params.get("Owner.1") == "self"
        rows, token = self.paged(params, list(range(acct["images"])))
        return ec2_xml("DescribeImages", items("imagesSet", (f"<imageId>ami-{n:017x}</imageId>" for n in rows)) + token)

    def state_change(self, action, acct, iid, now):
        inst = next(i for i in acct["instances"] if i["id"] == iid)
        was = inst["state"]
        inst["state"] = now
        return ec2_xml(action, items("instancesSet", [
            f"<instanceId>{iid}</instanceId><currentState><code>0</code><name>{now}</name></currentState>"
            f"<previousState><code>16</code><name>{was}</name></previousState>"]))

    def do_StartInstances(self, region, acct, params):
        return self.state_change("StartInstances", acct, params["InstanceId.1"], "pending")

    def do_StopInstances(self, region, acct, params):
        inst = next(i for i in acct["instances"] if i["id"] == params["InstanceId.1"])
        if inst["root"] == "instance-store":
            return ec2_error("UnsupportedOperation", "The instance does not have an 'ebs' root device type")
        return self.state_change("StopInstances", acct, params["InstanceId.1"], "stopping")

    def do_RebootInstances(self, region, acct, params):
        return ec2_xml("RebootInstances", "<return>true</return>")

    def do_AuthorizeSecurityGroupIngress(self, region, acct, params):
        cidr4 = params.get("IpPermissions.1.IpRanges.1.CidrIp", "")
        cidr6 = params.get("IpPermissions.1.Ipv6Ranges.1.CidrIpv6", "")
        rule = {"id": f"sgr-{next(self.ids)}", "group": params["GroupId"], "egress": False,
                "protocol": params["IpPermissions.1.IpProtocol"],
                "from": int(params["IpPermissions.1.FromPort"]) if "IpPermissions.1.FromPort" in params else None,
                "to": int(params["IpPermissions.1.ToPort"]) if "IpPermissions.1.ToPort" in params else None,
                "cidr4": cidr4, "cidr6": cidr6,
                "description": params.get("IpPermissions.1.IpRanges.1.Description")
                or params.get("IpPermissions.1.Ipv6Ranges.1.Description") or ""}
        acct["rules"].append(rule)
        return ec2_xml("AuthorizeSecurityGroupIngress", "<return>true</return>" + items("securityGroupRuleSet", [self.rule_xml(rule)]))

    def do_RevokeSecurityGroupIngress(self, region, acct, params):
        before = len(acct["rules"])
        acct["rules"] = [r for r in acct["rules"] if r["id"] != params["SecurityGroupRuleId.1"]]
        if len(acct["rules"]) == before:
            return ec2_error("InvalidSecurityGroupRuleId.NotFound", "The specified security group rule does not exist.")
        return ec2_xml("RevokeSecurityGroupIngress", "<return>true</return>")

    def do_ImportKeyPair(self, region, acct, params):
        line = base64.b64decode(params["PublicKeyMaterial"]).decode()
        assert line.startswith(("ssh-ed25519 ", "ssh-rsa "))
        kid = f"key-{next(self.ids)}"
        acct["keys"].append({"id": kid, "name": params["KeyName"], "type": line.split()[0][4:], "fingerprint": "SHA256:new",
                             "created": "2026-11-11T12:00:00.000Z"})
        return ec2_xml("ImportKeyPair", f"<keyName>{q(params['KeyName'])}</keyName><keyPairId>{kid}</keyPairId>"
                                        "<keyFingerprint>SHA256:new</keyFingerprint>")

    def do_DeleteKeyPair(self, region, acct, params):
        acct["keys"] = [k for k in acct["keys"] if k["id"] != params["KeyPairId"]]
        return ec2_xml("DeleteKeyPair", f"<return>true</return><keyPairId>{params['KeyPairId']}</keyPairId>")

    # -- Route 53 ----------------------------------------------------------------------------------------------------------------
    def route53(self, record, refused):
        path, query = record["path"], dict(parse_qsl(urlsplit(record["url"]).query, keep_blank_values=True))
        record["params"] = query
        assert path.startswith("/2013-04-01/")
        if refused:
            record["action"] = "?"
            return 403, {}, r53_error(refused, "The security token included in the request is invalid.")
        rest = path[len("/2013-04-01/"):]
        if record["method"] == "GET" and rest == "hostedzone":
            record["action"] = "ListHostedZones"
            return self.list_zones(query)
        m = re.match(r"^hostedzone/([A-Z0-9]+)/rrset/?$", rest)
        if m and record["method"] == "GET":
            record["action"] = "ListResourceRecordSets"
            return self.list_sets(m.group(1), query)
        if m and record["method"] == "POST":
            record["action"] = "ChangeResourceRecordSets"
            assert rest.endswith("/rrset/") and record["headers"]["Content-Type"].startswith("text/xml")
            return self.change(m.group(1), record["body"])
        m = re.match(r"^change/([A-Z0-9]+)$", rest)
        if m and record["method"] == "GET":
            record["action"] = "GetChange"
            return 200, {}, (f'<?xml version="1.0" encoding="UTF-8"?>\n<GetChangeResponse xmlns="{NS_R53}"><ChangeInfo>'
                             f"<Id>/change/{m.group(1)}</Id><Status>INSYNC</Status><SubmittedAt>2026-11-11T12:00:00.000Z"
                             "</SubmittedAt></ChangeInfo></GetChangeResponse>").encode()
        raise AssertionError(f"the fake has no {record['method']} {path}")

    def list_zones(self, query):
        if self.throttle:  # Route 53's own "slow down": an HTTP 400 Throttling, as many times as set
            self.throttle -= 1
            return 400, {}, r53_error("Throttling", "Rate exceeded")
        if "ListHostedZones" in self.fail:
            status, code, message = self.fail["ListHostedZones"]
            return status, {}, r53_error(code, message)
        assert query.get("maxitems") == "100"
        zones = "".join(f"<HostedZone><Id>/hostedzone/{z['id']}</Id><Name>{z['name']}.</Name><CallerReference>ref"
                        f"</CallerReference><Config><Comment>{q(z['comment'])}</Comment><PrivateZone>{str(z['private']).lower()}"
                        f"</PrivateZone></Config><ResourceRecordSetCount>{len(self.rrsets[z['id']])}</ResourceRecordSetCount>"
                        "</HostedZone>" for z in self.zones)
        return 200, {}, (f'<?xml version="1.0" encoding="UTF-8"?>\n<ListHostedZonesResponse xmlns="{NS_R53}"><HostedZones>'
                         f"{zones}</HostedZones><IsTruncated>false</IsTruncated><MaxItems>100</MaxItems>"
                         "</ListHostedZonesResponse>").encode()

    @staticmethod
    def order(r):
        return (list(reversed(r["name"].split("."))), r["type"])

    def list_sets(self, zid, query):
        sets = sorted(self.rrsets[zid], key=self.order)
        if "name" in query:
            start = {"name": unquote(query["name"]).rstrip(".").replace("\\052", "*"), "type": query.get("type", "")}
            sets = [r for r in sets if self.order(r) >= self.order(start)]
        size = int(query.get("maxitems", 300))
        shown, more = sets[:size], len(sets) > size

        def one(r):
            name = r["name"].replace("*", "\\052") + "."
            if r.get("alias"):
                return (f"<ResourceRecordSet><Name>{name}</Name><Type>{r['type']}</Type><AliasTarget><HostedZoneId>Z2FDTNDATAQYW2"
                        f"</HostedZoneId><DNSName>{r['alias']}</DNSName><EvaluateTargetHealth>false</EvaluateTargetHealth>"
                        "</AliasTarget></ResourceRecordSet>")
            values = "".join(f"<ResourceRecord><Value>{q(v)}</Value></ResourceRecord>" for v in r["values"])
            return (f"<ResourceRecordSet><Name>{name}</Name><Type>{r['type']}</Type><TTL>{r['ttl']}</TTL>"
                    f"<ResourceRecords>{values}</ResourceRecords></ResourceRecordSet>")
        tail = ""
        if more:
            nxt = sets[size]
            tail = f"<NextRecordName>{nxt['name']}.</NextRecordName><NextRecordType>{nxt['type']}</NextRecordType>"
        return 200, {}, (f'<?xml version="1.0" encoding="UTF-8"?>\n<ListResourceRecordSetsResponse xmlns="{NS_R53}">'
                         f"<ResourceRecordSets>{''.join(one(r) for r in shown)}</ResourceRecordSets>"
                         f"<IsTruncated>{str(more).lower()}</IsTruncated><MaxItems>{size}</MaxItems>{tail}"
                         "</ListResourceRecordSetsResponse>").encode()

    def change(self, zid, body):
        root = ET.fromstring(body)
        assert root.tag == f"{{{NS_R53}}}ChangeResourceRecordSetsRequest"
        ns = {"r": NS_R53}
        sets = self.rrsets[zid]
        for change in root.findall("r:ChangeBatch/r:Changes/r:Change", ns):
            action = change.findtext("r:Action", namespaces=ns)
            rrs = change.find("r:ResourceRecordSet", ns)
            name = rrs.findtext("r:Name", namespaces=ns)
            assert name.endswith(".")
            new = {"name": name.rstrip(".").lower(), "type": rrs.findtext("r:Type", namespaces=ns),
                   "ttl": int(rrs.findtext("r:TTL", namespaces=ns)),
                   "values": [v.text for v in rrs.findall("r:ResourceRecords/r:ResourceRecord/r:Value", ns)]}
            at = next((i for i, r in enumerate(sets) if (r["name"], r["type"]) == (new["name"], new["type"])), None)
            if action == "UPSERT":
                if at is None:
                    sets.append(new)
                else:
                    sets[at] = new
            elif action == "DELETE":
                if at is None or sets[at].get("ttl") != new["ttl"] or sorted(sets[at]["values"]) != sorted(new["values"]):
                    return 400, {}, (f'<?xml version="1.0"?>\n<InvalidChangeBatch xmlns="{NS_R53}"><Messages><Message>'
                                     f"Tried to delete resource record set [name='{name}', type='{new['type']}'] but the "
                                     "values provided do not match the current values</Message></Messages>"
                                     "<RequestId>b25f48e8-example</RequestId></InvalidChangeBatch>").encode()
                del sets[at]
            else:
                raise AssertionError(action)
        cid = next(self.change_ids)
        self.changes[cid] = "PENDING"
        comment = root.findtext("r:ChangeBatch/r:Comment", namespaces=ns) or ""
        return 200, {}, (f'<?xml version="1.0" encoding="UTF-8"?>\n<ChangeResourceRecordSetsResponse xmlns="{NS_R53}">'
                         f"<ChangeInfo><Id>/change/{cid}</Id><Status>PENDING</Status><SubmittedAt>2026-11-11T12:00:00.000Z"
                         f"</SubmittedAt><Comment>{q(comment)}</Comment></ChangeInfo></ChangeResourceRecordSetsResponse>").encode()


class Pairs(Login):
    """A login holding pairs by name (the login app's store, as the Login interface asks it)."""

    NAMESPACE = "test"

    def __init__(self, values: dict[str, str]):
        self.pairs = {pair_name(k): v for k, v in values.items()}
        self.asked: list[str] = []

    def user(self) -> dict:
        return {"name": "tester"}

    def vector(self, name: str) -> str:
        self.asked.append(name)
        if name not in self.pairs:
            raise Unauthorized(f"no {name}", 404)
        return self.pairs[name]

    def names(self) -> set[str]:
        return set(self.pairs)


def settings_of(api: bool = True, ddns: bool = False, **more) -> dict[str, str]:
    out = {}
    if api:
        out.update({"EC2_ACCESS_KEY_ID": KEY_ID, "EC2_SECRET_ACCESS_KEY": SECRET})
    if ddns:
        out["EC2_DDNS_HOSTS"] = "home.example.com"
    out.update(more)
    return out


@pytest.fixture(autouse=True)
def _no_aws_no_network(monkeypatch, tmp_path):
    """No test reaches AWS, a resolver or this machine's settings: the HTTPS and DNS are refused, every EC2_ variable
    cleared (and AWS_ ones set, which the plugin must never read), the platform's folder the test's own."""
    def refused(*a, **k):
        raise AssertionError("a test reached for the network")
    monkeypatch.setattr(aws_mod, "https", refused)
    monkeypatch.setattr(dns_mod, "query", refused)
    for n in NAMES:
        monkeypatch.delenv(n, raising=False)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIAOTHERTOOLSKEY001")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "another-tools-secret-0123456789")
    monkeypatch.setenv("AWS_REGION", "ap-south-1")
    monkeypatch.setenv("LIMINAL_PLATFORM_DIR", str(tmp_path / "platform"))


@pytest.fixture
def env(monkeypatch):
    """Sets the plugin's variables (the EnvironmentLogin's: what the platform reads today)."""
    def put(values: dict[str, str]):
        for k, v in values.items():
            monkeypatch.setenv(k, v)
    return put


class Public:
    """This network's public address as DNS would tell it (a stand-in; `address` changed by a test)."""

    def __init__(self, address: str | None = HOME, whose: str = "OpenDNS"):
        self.address, self.whose, self.asked = address, whose, 0

    def __call__(self):
        self.asked += 1
        return self.address, (self.whose if self.address else "neither OpenDNS nor Google answered")


class PlatformApp:
    """The platform app as a plugin sees it attaching it (its NAME): only it starts the reading in the background."""

    NAME = "platform"


@pytest.fixture
def made(tmp_path):
    """A plugin over the stand-ins: (plugin, fake AWS); its folder (Dynamic DNS's ddns.json) the test's own."""
    def make(fake: FakeAws | None = None, public=(HOME, "OpenDNS"), folder=None):
        fake = fake or FakeAws()
        ask = public if callable(public) else (lambda: public)
        p = Ec2Plugin(transport=fake, public=ask, sleep=lambda s: None, folder=folder or tmp_path / "ec2")
        return p, fake
    return make
