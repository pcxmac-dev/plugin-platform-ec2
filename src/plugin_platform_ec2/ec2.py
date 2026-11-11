"""Amazon EC2's Query API (Version 2016-11-15) as the plugin asks it: a request to the region's endpoint
(https://ec2.<region>.amazonaws.com/) naming its Action and Version, its lists numbered (InstanceId.1, Filter.1.Name,
IpPermissions.1.IpRanges.1.CidrIp), signed with SigV4; its answer XML. A read is a GET (tried again on a throttle or a
server's trouble), a change a POST of a form (never sent twice).

It makes the reads in READS and the free changes in WRITES and no other action (`call` refuses one): power on, stop
(gracefully, or forced when asked twice), reboot; an inbound rule authorized or revoked; a key pair imported or deleted.
Nothing here starts a charge: no instance is launched or ended, no volume, snapshot, image or address made."""
from __future__ import annotations

import base64
import ipaddress
import re
from collections.abc import Mapping

from liminal_libs.machines.rest import RestError

from .aws import AwsClient, AwsError, flag, items, parse, query, tags_of, text

VERSION = "2016-11-15"
HOME_REGION = "us-east-1"  # where the account's regions are asked (enabled in every account)
PAGE = 100  # MaxResults of a paginated describe (EC2's larger, paginated token buckets)
PAGES_MOST = 20
COUNT_PAGES = 3  # snapshots and images are counted over at most this many pages ("300+")
READS = ("DescribeRegions", "DescribeAccountAttributes", "DescribeInstances", "DescribeInstanceTypes",
         "DescribeSecurityGroups", "DescribeSecurityGroupRules", "DescribeKeyPairs", "DescribeVolumes",
         "DescribeAddresses", "DescribeSnapshots", "DescribeImages")
WRITES = ("StartInstances", "StopInstances", "RebootInstances", "AuthorizeSecurityGroupIngress",
          "RevokeSecurityGroupIngress", "ImportKeyPair", "DeleteKeyPair")
PROTOCOLS = {"tcp": "TCP", "udp": "UDP", "icmp": "ICMP", "icmpv6": "ICMPv6", "-1": "every protocol"}
KEY_LINE = re.compile(r"^(ssh-ed25519|ssh-rsa)\s+([A-Za-z0-9+/]+={0,3})(?:\s+(.*))?$")
KEY_NAME = re.compile(r"^[ -~]{1,255}$")  # AWS: up to 255 ASCII characters


def endpoint(region: str) -> str:
    return f"https://ec2.{region}.amazonaws.com/"


class Ec2Api:
    """The EC2 API through one client (its endpoint per region; the signer reads the region off the host)."""

    def __init__(self, client: AwsClient):
        self.client = client

    # -- a request ------------------------------------------------------------------------------------------------------
    def call(self, region: str, action: str, params: Mapping[str, object] | None = None):
        """One action in `region`, its answer's XML (an AwsError in words when AWS refuses it)."""
        if action not in READS and action not in WRITES:
            raise ValueError(f"{action} is not an action this plugin makes")
        form = {"Action": action, "Version": VERSION, **{k: v for k, v in (params or {}).items() if v is not None}}
        try:
            if action in WRITES:
                answer = self.client.request("POST", endpoint(region), form={k: str(v) for k, v in form.items()})
            else:
                answer = self.client.request("GET", endpoint(region) + "?" + query(form))
        except RestError as e:
            raise AwsError.of(e, action, region) from None
        try:
            return parse(answer.body)
        except ValueError as e:
            raise AwsError(f"{action} in {region}: {e}", answer.status, action=action, region=region) from None

    def pages(self, region: str, action: str, container: str, params: Mapping[str, object] | None = None,
              most: int = PAGES_MOST) -> tuple[list, bool, object]:
        """Every <item> of `container` across a paginated describe's pages (MaxResults, NextToken): (items, more left
        after `most` pages, the first page's root)."""
        found, token, first = [], None, None
        for _ in range(max(1, most)):
            root = self.call(region, action, {**(params or {}), "MaxResults": PAGE, "NextToken": token})
            first = root if first is None else first
            found += items(root, container)
            token = text(root, "nextToken") or None
            if not token:
                return found, False, first
        return found, True, first

    # -- reads ------------------------------------------------------------------------------------------------------------
    def regions(self) -> list[dict]:
        """The regions enabled for the account (DescribeRegions without AllRegions): name, endpoint, opt-in status."""
        root = self.call(HOME_REGION, "DescribeRegions")
        return sorted(({"name": text(r, "regionName"), "endpoint": text(r, "regionEndpoint"),
                        "optIn": text(r, "optInStatus")} for r in items(root, "regionInfo")), key=lambda r: r["name"])

    def account_attributes(self, region: str) -> dict[str, list[str]]:
        """The account's attributes in `region` (default-vpc, max-elastic-ips, vpc-max-elastic-ips,
        vpc-max-security-groups-per-interface ...): name -> values."""
        root = self.call(region, "DescribeAccountAttributes")
        return {text(a, "attributeName"): [text(v, "attributeValue") for v in items(a, "attributeValueSet")]
                for a in items(root, "accountAttributeSet")}

    def instances(self, region: str) -> tuple[list[dict], str]:
        """The region's instances and the account's ID (the reservations' owner)."""
        found, _, _ = self.pages(region, "DescribeInstances", "reservationSet")
        out, owner = [], ""
        for reservation in found:
            owner = owner or text(reservation, "ownerId")
            out += [instance_of(i, region) for i in items(reservation, "instancesSet")]
        return out, owner

    def instance(self, region: str, instance: str) -> dict | None:
        """One instance, read now by its ID (None when the region has none of that ID)."""
        root = self.call(region, "DescribeInstances", {"InstanceId.1": instance})
        found = [instance_of(i, region) for r in items(root, "reservationSet") for i in items(r, "instancesSet")]
        return found[0] if found else None

    def instance_types(self, region: str, names) -> dict[str, dict]:
        """What the instance types `names` are (vCPUs, memory, instance store), by name; at most 100 asked."""
        wanted = sorted({n for n in names if n})[:100]
        if not wanted:
            return {}
        params: dict[str, object] = {f"InstanceType.{i}": n for i, n in enumerate(wanted, 1)}
        out: dict[str, dict] = {}
        token = None
        for _ in range(PAGES_MOST):
            root = self.call(region, "DescribeInstanceTypes", {**params, "NextToken": token})
            for t in items(root, "instanceTypeSet"):
                out[text(t, "instanceType")] = type_of(t)
            token = text(root, "nextToken") or None
            if not token:
                break
        return out

    def security_groups(self, region: str) -> list[dict]:
        found, _, _ = self.pages(region, "DescribeSecurityGroups", "securityGroupInfo")
        return [{"id": text(g, "groupId"), "name": text(g, "groupName"), "about": text(g, "groupDescription"),
                 "vpc": text(g, "vpcId"), "owner": text(g, "ownerId"), "region": region,
                 "inbound": len(items(g, "ipPermissions")), "outbound": len(items(g, "ipPermissionsEgress"))}
                for g in found]

    def security_group_rules(self, region: str, rule: str | None = None) -> list[dict]:
        """The region's security group rules (each one with its ID), or the one rule `rule`."""
        if rule:
            root = self.call(region, "DescribeSecurityGroupRules", {"SecurityGroupRuleId.1": rule})
            return [rule_of(r, region) for r in items(root, "securityGroupRuleSet")]
        found, _, _ = self.pages(region, "DescribeSecurityGroupRules", "securityGroupRuleSet")
        return [rule_of(r, region) for r in found]

    def key_pairs(self, region: str) -> list[dict]:
        root = self.call(region, "DescribeKeyPairs")
        return [{"id": text(k, "keyPairId"), "name": text(k, "keyName"), "type": text(k, "keyType"),
                 "fingerprint": text(k, "keyFingerprint"), "created": text(k, "createTime"), "region": region}
                for k in items(root, "keySet")]

    def volumes(self, region: str) -> list[dict]:
        found, _, _ = self.pages(region, "DescribeVolumes", "volumeSet")
        out = []
        for v in found:
            attached = [{"instance": text(a, "instanceId"), "device": text(a, "device"), "state": text(a, "status")}
                        for a in items(v, "attachmentSet")]
            out.append({"id": text(v, "volumeId"), "name": tags_of(v).get("Name", ""), "size": text(v, "size"),
                        "type": text(v, "volumeType"), "iops": text(v, "iops"), "state": text(v, "status"),
                        "zone": text(v, "availabilityZone"), "created": text(v, "createTime"),
                        "encrypted": flag(text(v, "encrypted")), "attached": attached, "region": region})
        return out

    def addresses(self, region: str) -> list[dict]:
        root = self.call(region, "DescribeAddresses")
        return [{"ip": text(a, "publicIp"), "allocation": text(a, "allocationId"), "instance": text(a, "instanceId"),
                 "interface": text(a, "networkInterfaceId"), "private": text(a, "privateIpAddress"),
                 "association": text(a, "associationId"), "name": tags_of(a).get("Name", ""), "region": region}
                for a in items(root, "addressesSet")]

    def snapshot_count(self, region: str) -> tuple[int, bool]:
        """How many EBS snapshots the account owns in `region` (counted over COUNT_PAGES pages: more left when True)."""
        found, more, _ = self.pages(region, "DescribeSnapshots", "snapshotSet", {"Owner.1": "self"}, most=COUNT_PAGES)
        return len(found), more

    def image_count(self, region: str) -> tuple[int, bool]:
        """How many AMIs the account owns in `region`."""
        found, more, _ = self.pages(region, "DescribeImages", "imagesSet", {"Owner.1": "self"}, most=COUNT_PAGES)
        return len(found), more

    # -- the free changes ---------------------------------------------------------------------------------------------------
    def start(self, region: str, instance: str) -> dict:
        return state_change(self.call(region, "StartInstances", {"InstanceId.1": instance}), instance)

    def stop(self, region: str, instance: str, force: bool = False) -> dict:
        params = {"InstanceId.1": instance, "Force": "true" if force else None}
        return state_change(self.call(region, "StopInstances", params), instance)

    def reboot(self, region: str, instance: str) -> bool:
        return flag(text(self.call(region, "RebootInstances", {"InstanceId.1": instance}), "return")) is not False

    def authorize_ingress(self, region: str, group: str, protocol: str, from_port: int | None, to_port: int | None,
                          source: str, description: str = "") -> list[dict]:
        """An inbound rule added to `group`: `protocol` (tcp, udp, icmp, icmpv6, -1 every one) from `source` (an IPv4 or
        IPv6 CIDR); its rules as AWS made them (with their IDs)."""
        params: dict[str, object] = {"GroupId": group, "IpPermissions.1.IpProtocol": protocol,
                                     "IpPermissions.1.FromPort": from_port, "IpPermissions.1.ToPort": to_port}
        net = ipaddress.ip_network(source, strict=False)
        box = "IpPermissions.1.IpRanges.1" if net.version == 4 else "IpPermissions.1.Ipv6Ranges.1"
        params[f"{box}.{'CidrIp' if net.version == 4 else 'CidrIpv6'}"] = str(net)
        if description:
            params[f"{box}.Description"] = description
        root = self.call(region, "AuthorizeSecurityGroupIngress", params)
        if flag(text(root, "return")) is False:
            raise AwsError(f"AuthorizeSecurityGroupIngress in {region}: AWS answered that it was not done",
                           action="AuthorizeSecurityGroupIngress", region=region)
        return [rule_of(r, region) for r in items(root, "securityGroupRuleSet")]

    def revoke_ingress(self, region: str, group: str, rule: str) -> bool:
        """The inbound rule `rule` (sgr-…) taken out of `group`, by its ID."""
        root = self.call(region, "RevokeSecurityGroupIngress", {"GroupId": group, "SecurityGroupRuleId.1": rule})
        unknown = items(root, "unknownIpPermissionSet")
        if flag(text(root, "return")) is False or unknown:
            raise AwsError(f"RevokeSecurityGroupIngress in {region}: AWS did not revoke {rule} (it may be gone)",
                           action="RevokeSecurityGroupIngress", region=region)
        return True

    def import_key_pair(self, region: str, name: str, public_key: str) -> dict:
        """An OpenSSH public key imported as the key pair `name` (its material base64-encoded, as the Query API takes a
        binary parameter); the key pair as AWS made it."""
        line = clean_public_key(public_key)
        material = base64.b64encode(line.encode("ascii")).decode("ascii")
        root = self.call(region, "ImportKeyPair", {"KeyName": key_name(name), "PublicKeyMaterial": material})
        return {"id": text(root, "keyPairId"), "name": text(root, "keyName"), "fingerprint": text(root, "keyFingerprint"),
                "region": region}

    def delete_key_pair(self, region: str, key_pair: str) -> bool:
        return flag(text(self.call(region, "DeleteKeyPair", {"KeyPairId": key_pair}), "return")) is not False


# -- reading the answers ------------------------------------------------------------------------------------------------------
def instance_of(item, region: str) -> dict:
    ipv6 = text(item, "ipv6Address")
    if not ipv6:
        for nic in items(item, "networkInterfaceSet"):
            for a in items(nic, "ipv6AddressesSet"):
                ipv6 = ipv6 or text(a, "ipv6Address")
    return {"id": text(item, "instanceId"), "name": tags_of(item).get("Name", ""), "state": text(item, "instanceState/name"),
            "type": text(item, "instanceType"), "zone": text(item, "placement/availabilityZone"), "region": region,
            "publicIp": text(item, "ipAddress"), "ipv6": ipv6, "privateIp": text(item, "privateIpAddress"),
            "launched": text(item, "launchTime"), "root": text(item, "rootDeviceType"), "key": text(item, "keyName"),
            "platform": text(item, "platformDetails") or text(item, "platform"), "lifecycle": text(item, "instanceLifecycle"),
            "groups": [(text(g, "groupId"), text(g, "groupName")) for g in items(item, "groupSet")],
            "reason": text(item, "stateReason/message") or text(item, "reason"), "vpc": text(item, "vpcId")}


def type_of(item) -> dict:
    try:
        memory = round(int(text(item, "memoryInfo/sizeInMiB") or 0) / 1024, 1)
    except ValueError:
        memory = None
    store = text(item, "instanceStorageInfo/totalSizeInGB")
    return {"vcpus": text(item, "vCpuInfo/defaultVCpus"), "memoryGiB": memory,
            "instanceStore": flag(text(item, "instanceStorageSupported")) is True, "storeGB": store,
            "freeTier": flag(text(item, "freeTierEligible"))}


def rule_of(item, region: str) -> dict:
    def port(name):
        value = text(item, name)
        try:
            return int(value)
        except ValueError:
            return None
    return {"id": text(item, "securityGroupRuleId"), "group": text(item, "groupId"), "region": region,
            "egress": flag(text(item, "isEgress")) is True, "protocol": text(item, "ipProtocol") or "-1",
            "from": port("fromPort"), "to": port("toPort"), "cidr4": text(item, "cidrIpv4"), "cidr6": text(item, "cidrIpv6"),
            "prefixList": text(item, "prefixListId"), "peer": text(item, "referencedGroupInfo/groupId"),
            "description": text(item, "description")}


def state_change(root, instance: str) -> dict:
    for i in items(root, "instancesSet"):
        if text(i, "instanceId") == instance or not instance:
            return {"instance": text(i, "instanceId"), "was": text(i, "previousState/name"), "now": text(i, "currentState/name")}
    return {"instance": instance, "was": "", "now": ""}


# -- what a change is given ---------------------------------------------------------------------------------------------------
def clean_public_key(text_: str) -> str:
    """An OpenSSH public key line (ssh-ed25519 or ssh-rsa, its base64 blob, a comment); ValueError otherwise (ImportKeyPair
    takes RSA and ED25519 keys alone; a private key is refused outright)."""
    line = " ".join(str(text_ or "").split())
    if "PRIVATE KEY" in line.upper():
        raise ValueError("that is a private key: only the public key (the .pub file's line) is ever imported")
    m = KEY_LINE.match(line)
    if not m:
        raise ValueError("not an OpenSSH public key: one line, ssh-ed25519 AAAA… or ssh-rsa AAAA… (the .pub file)")
    try:
        blob = base64.b64decode(m.group(2), validate=True)
    except ValueError:
        raise ValueError("the key's base64 part is not valid") from None
    if len(blob) < 4 or blob[4:4 + len(m.group(1))] != m.group(1).encode("ascii"):
        raise ValueError(f"the key's base64 part is not an {m.group(1)} key")
    return line


def key_name(name: str) -> str:
    n = str(name or "").strip()
    if not KEY_NAME.match(n):
        raise ValueError("a key pair's name is 1 to 255 ASCII characters")
    return n


def ports_of(protocol: str, ports: str | None) -> tuple[int | None, int | None]:
    """(FromPort, ToPort) of an inbound rule as typed: "22", "8000-8100" for TCP and UDP; an ICMP type ("8") or every one
    ("" -> -1, -1) for ICMP; none for every protocol (-1)."""
    p = str(protocol or "").strip().lower()
    t = str(ports or "").strip().lower().replace(" ", "")
    if p == "-1":
        if t not in ("", "all", "-1", "0-65535"):
            raise ValueError("a rule for every protocol takes no ports: it opens them all")
        return None, None
    if p in ("icmp", "icmpv6"):
        if t in ("", "all", "-1"):
            return -1, -1
        if not t.isdigit() or int(t) > 255:
            raise ValueError("an ICMP rule takes an ICMP type (0 to 255), or nothing for every type")
        return int(t), -1
    if p not in ("tcp", "udp"):
        raise ValueError(f"{protocol!r} is no protocol here: {', '.join(PROTOCOLS)}")
    if t in ("all", "*"):
        return 0, 65535
    m = re.match(r"^(\d{1,5})(?:-(\d{1,5}))?$", t)
    if not m:
        raise ValueError("ports are a port (22) or a range (8000-8100)")
    low, high = int(m.group(1)), int(m.group(2) or m.group(1))
    if not 0 <= low <= high <= 65535:
        raise ValueError("ports are 0 to 65535, the lower first")
    return low, high


def source_of(source: str) -> str:
    """A rule's source as AWS keeps it: an IPv4 or IPv6 CIDR (an address alone is its /32 or /128)."""
    s = str(source or "").strip()
    if not s:
        raise ValueError("no source given: an address range (203.0.113.7/32, 0.0.0.0/0, 2001:db8::/64)")
    try:
        net = ipaddress.ip_network(s, strict=False)
    except ValueError:
        raise ValueError(f"{s!r} is not an IPv4 or IPv6 address range (CIDR)") from None
    return str(net)


def covers(rule_from, rule_to, port: int) -> bool:
    if rule_from is None or rule_to is None:
        return True
    if rule_from == -1 and rule_to == -1:
        return False
    return rule_from <= port <= rule_to


def everywhere(cidr: str) -> bool:
    return cidr in ("0.0.0.0/0", "::/0")


def rule_words(rule: Mapping) -> str:
    """A rule in words: "TCP 22 from 0.0.0.0/0", "every protocol from sg-0abc"."""
    proto = PROTOCOLS.get(rule.get("protocol") or "-1", str(rule.get("protocol")))
    a, b = rule.get("from"), rule.get("to")
    if proto == "every protocol" or a is None:
        ports = ""
    elif rule.get("protocol") in ("icmp", "icmpv6"):
        ports = "" if a == -1 else f" type {a}"
    else:
        ports = f" {a}" if a == b else f" {a}-{b}"
    peer = rule.get("cidr4") or rule.get("cidr6") or rule.get("prefixList") or rule.get("peer") or "?"
    return f"{proto}{ports} {'to' if rule.get('egress') else 'from'} {peer}"
