"""The platform's page changes what costs nothing through the plugin's forms, each confirmed: an instance powered on,
stopped or rebooted (a forced stop, or one that erases an instance store, asked twice; an instance store-backed one never
stopped); an inbound rule authorized or revoked (one opening SSH, RDP or every port to the whole internet, or the last one
letting SSH in to an instance, asked twice); a public key imported, a key pair deleted; a Route 53 record set or removed,
one record set a change. Each hook sends exactly the request AWS's references give (its Action and parameters, its XML),
over the stand-ins alone."""
from __future__ import annotations

import base64
import inspect
import xml.etree.ElementTree as ET

import pytest

from conftest import ED25519, NS_R53, PRIVATE, ZONE, FakeAws, instance, settings_of
from plugin_platform_ec2 import ACCEPT_LOCKOUT, ACCEPT_OPEN, ACCEPT_POWER, Refusal

BASE = {"Version": "2016-11-15"}


def page_args(form: dict, values: dict, accepted=()) -> list:
    """What the platform's page sends for a form (platform.js argsOf): the fields' values in order, a field whose `when` is
    unmet or left empty null (the hook's default), a number as a number, an accept field true only once accepted."""
    now = {**{x["name"]: x.get("value") for x in form["fields"]}, **values}
    out = []
    for x in form["fields"]:
        if x["type"] == "accept":
            out.append(x["name"] in accepted)
            continue
        shown = all(str(now.get(k) or "") in [str(v) for v in vs] for k, vs in (x.get("when") or {}).items())
        v = now.get(x["name"])
        out.append(None if not shown or v in (None, "") else int(v) if x["type"] == "number" else v)
    return out


def forms_of(p) -> dict:
    return {f["id"]: f for f in p.status()["forms"]}


def ask(p, form, values, accepted=()):
    return p.ask(form["hook"], *page_args(form, values, accepted))


def sent(fake, action) -> dict:
    """The parameters of the last `action` sent (a POST's form), Action and Version taken out after checking them."""
    r = fake.last(action)
    assert r["method"] == "POST" and r["params"]["Action"] == action and r["params"]["Version"] == "2016-11-15"
    return {k: v for k, v in r["params"].items() if k not in ("Action", "Version")}


@pytest.fixture
def ready(made, env):
    env(settings_of(EC2_REGIONS="us-east-1"))
    p, fake = made()
    p.refresh()
    return p, fake


def test_every_form_asks_a_hook_with_its_arguments_in_order(ready):
    p, fake = ready
    forms = forms_of(p)
    assert sorted(forms) == sorted(["power:us-east-1:i-0web0000000000001", "power:us-east-1:i-0db00000000000002",
                                    "power:us-east-1:i-0eph0000000000003", "authorize", "revoke", "import-key", "delete-key",
                                    f"set:{ZONE}", f"remove:{ZONE}", f"set:{PRIVATE}", f"remove:{PRIVATE}"])
    hooks = p.interface()["hooks"]
    for f in forms.values():
        assert f["hook"] in hooks and f["confirm"]["title"] and f["confirm"]["yes"]
        assert [x["name"] for x in f["fields"]] == list(inspect.signature(getattr(p, f["hook"])).parameters)  # in order
        assert all(x["type"] in ("text", "number", "choice", "fixed", "accept") for x in f["fields"])
        for x in f["fields"]:
            if x["type"] == "accept":
                assert x["name"] in (ACCEPT_POWER, ACCEPT_OPEN, ACCEPT_LOCKOUT) and x["yes"] and x["words"]
    # what each instance's Power… offers follows its state; an instance store-backed one is only rebooted
    actions = {i: [c["value"] for c in next(x for x in forms[f"power:us-east-1:{i}"]["fields"] if x["name"] == "action")["choices"]]
               for i in ("i-0web0000000000001", "i-0db00000000000002", "i-0eph0000000000003")}
    assert actions == {"i-0web0000000000001": ["stop", "reboot", "force-stop"], "i-0db00000000000002": ["start"],
                       "i-0eph0000000000003": ["reboot"]}
    # a start (db is stopped) says its compute charge resumes once it runs, beside the charges that never stopped
    start = forms["power:us-east-1:i-0db00000000000002"]
    assert start["confirm"]["words"] == ("{action} db in us-east-1: once it runs, its compute charge resumes (by the second, "
                                         "a minute at least each start), beside the charges that never stopped: its EBS "
                                         "volumes and Elastic IPs.")
    assert start["confirm"].get("danger") is False  # asked once: no second confirmation for a start
    stop = forms["power:us-east-1:i-0web0000000000001"]["confirm"]["words"]  # web runs: a stop's words
    assert "stopped, an EBS-backed instance stops its compute charge; its EBS volumes and Elastic IPs still bill" in stop
    assert "resumes" not in stop and "instance store" not in stop  # t3.micro has none
    assert forms["power:us-east-1:i-0eph0000000000003"]["confirm"]["words"].endswith("a reboot keeps it running, billed as it is.")
    tables = {t["title"]: t for t in p.status()["tables"]}
    buttons = [r[-1] for r in tables["Instances"]["rows"]]
    assert {b["form"] for b in buttons} == {k for k in forms if k.startswith("power:")} and all(b["title"] == "Power…" for b in buttons)
    assert tables["Security group rules"]["actions"] == [{"form": "authorize", "title": "Authorize an inbound rule…"}]
    assert tables["Key pairs"]["actions"] == [{"form": "import-key", "title": "Import a public key…"}]
    assert tables["example.com records"]["actions"] == [{"form": f"set:{ZONE}", "title": "Set a record…"}]
    assert not any(a in fake.actions() for a in ("StartInstances", "StopInstances", "ChangeResourceRecordSets"))  # drawn only


def test_power_sends_start_stop_and_reboot_and_asks_twice_before_a_stop_that_loses_data(ready):
    p, fake = ready
    forms = forms_of(p)
    web = forms["power:us-east-1:i-0web0000000000001"]
    rep = ask(p, web, {"action": "reboot"})
    assert sent(fake, "RebootInstances") == {"InstanceId.1": "i-0web0000000000001"} and rep["said"] == "web (i-0web0000000000001): rebooting"
    rep = ask(p, web, {"action": "stop"})
    assert sent(fake, "StopInstances") == {"InstanceId.1": "i-0web0000000000001"}  # graceful: no Force
    assert rep["now"] == "stopping" and "its EBS volumes (8 GiB) still bill per GB-month" in rep["lines"][0]
    db = forms["power:us-east-1:i-0db00000000000002"]
    rep = ask(p, db, {"action": "start"})
    assert sent(fake, "StartInstances") == {"InstanceId.1": "i-0db00000000000002"} and rep["now"] == "pending"
    assert "a minute at least" in rep["lines"][0]
    # db (m5d.large) has an instance store: its stop is refused until accepted, nothing sent first
    fake.account["us-east-1"]["instances"][1]["state"] = "running"
    p.refresh()  # running now: its Power… offers a stop, whose words say what a stop erases
    assert ("its type's instance store volumes are erased by a stop (you are asked again first)"
            in forms_of(p)["power:us-east-1:i-0db00000000000002"]["confirm"]["words"])
    calls = len(fake.requests)
    with pytest.raises(Refusal, match=r"instance store volumes \(75 GB\): a stop erases their data") as refused:
        ask(p, db, {"action": "stop"})
    assert refused.value.accept == ACCEPT_POWER and "StopInstances" not in fake.actions()[calls:]
    rep = ask(p, db, {"action": "stop"}, accepted={ACCEPT_POWER})
    assert sent(fake, "StopInstances") == {"InstanceId.1": "i-0db00000000000002"}
    assert "Elastic IP (203.0.113.41) still bill" in rep["lines"][0]
    # a forced stop is asked twice too, and sent with Force
    fake.account["us-east-1"]["instances"][0]["state"] = "running"
    with pytest.raises(Refusal, match="does not flush its file systems") as refused:
        ask(p, web, {"action": "force-stop"})
    assert refused.value.accept == ACCEPT_POWER
    ask(p, web, {"action": "force-stop"}, accepted={ACCEPT_POWER})
    assert sent(fake, "StopInstances") == {"InstanceId.1": "i-0web0000000000001", "Force": "true"}
    # an instance store-backed instance is never stopped, accepted or not; a start of a running one is refused
    eph = forms["power:us-east-1:i-0eph0000000000003"]
    calls = len(fake.requests)
    with pytest.raises(Refusal, match="instance store-backed: AWS cannot stop it") as refused:
        p.power("us-east-1", "i-0eph0000000000003", "stop", accept_data_loss=True)
    assert refused.value.accept is None and "StopInstances" not in fake.actions()[calls:]
    with pytest.raises(Refusal, match="running already"):
        p.power("us-east-1", "i-0eph0000000000003", "start")
    ask(p, eph, {"action": "reboot"})
    assert sent(fake, "RebootInstances") == {"InstanceId.1": "i-0eph0000000000003"}
    # each change read the instance afresh first, by its ID (DescribeInstances InstanceId.1)
    fresh = [r for r in fake.requests if r["action"] == "DescribeInstances" and "InstanceId.1" in r["params"]]
    assert fresh and all(r["method"] == "GET" for r in fresh)


def test_an_inbound_rule_is_authorized_as_the_reference_gives_it_and_a_wide_open_one_asked_twice(ready):
    p, fake = ready
    form = forms_of(p)["authorize"]
    groups = [c["value"] for c in form["fields"][0]["choices"]]
    assert groups == ["us-east-1/sg-0web", "us-east-1/sg-0db"]
    rep = ask(p, form, {"group": "us-east-1/sg-0web", "protocol": "tcp", "ports": "8000-8100", "source": "203.0.113.0/24",
                        "description": "office"})
    assert sent(fake, "AuthorizeSecurityGroupIngress") == {
        "GroupId": "sg-0web", "IpPermissions.1.IpProtocol": "tcp", "IpPermissions.1.FromPort": "8000",
        "IpPermissions.1.ToPort": "8100", "IpPermissions.1.IpRanges.1.CidrIp": "203.0.113.0/24",
        "IpPermissions.1.IpRanges.1.Description": "office"}
    assert rep["said"] == "authorized TCP 8000-8100 from 203.0.113.0/24 in sg-0web" and rep["rules"][0].startswith("sgr-")
    rules = next(t for t in p.status()["tables"] if t["title"] == "Security group rules")["rows"]
    assert any(r[3] == "TCP 8000-8100 from 203.0.113.0/24" for r in rules)  # drawn at once, its Revoke beside it
    # SSH, RDP or every port to the whole internet: refused until accepted, nothing sent first
    for values, opens in (({"protocol": "tcp", "ports": "22", "source": "0.0.0.0/0"}, "SSH"),
                          ({"protocol": "tcp", "ports": "3389", "source": "0.0.0.0/0"}, "RDP"),
                          ({"protocol": "-1", "ports": "", "source": "::/0"}, "every port"),
                          ({"protocol": "udp", "ports": "0-65535", "source": "0.0.0.0/0"}, "every port")):
        calls = len(fake.requests)
        with pytest.raises(Refusal, match=f"opens {opens} to the whole internet") as refused:
            ask(p, form, {"group": "us-east-1/sg-0web", **values})
        assert refused.value.accept == ACCEPT_OPEN and fake.requests[calls:] == []
    ask(p, form, {"group": "us-east-1/sg-0web", "protocol": "-1", "source": "::/0"}, accepted={ACCEPT_OPEN})
    assert sent(fake, "AuthorizeSecurityGroupIngress") == {"GroupId": "sg-0web", "IpPermissions.1.IpProtocol": "-1",
                                                           "IpPermissions.1.Ipv6Ranges.1.CidrIpv6": "::/0"}
    ask(p, form, {"group": "us-east-1/sg-0db", "protocol": "icmp", "ports": "", "source": "198.51.100.7"})
    assert sent(fake, "AuthorizeSecurityGroupIngress") == {"GroupId": "sg-0db", "IpPermissions.1.IpProtocol": "icmp",
                                                           "IpPermissions.1.FromPort": "-1", "IpPermissions.1.ToPort": "-1",
                                                           "IpPermissions.1.IpRanges.1.CidrIp": "198.51.100.7/32"}
    for bad, words in (({"ports": "22-21"}, "the lower first"), ({"source": "not-a-net"}, "not an IPv4 or IPv6"),
                       ({"protocol": "gre"}, "no protocol here")):
        with pytest.raises(ValueError, match=words):
            ask(p, form, {"group": "us-east-1/sg-0web", "protocol": "tcp", "ports": "22", "source": "10.0.0.0/8", **bad})


def test_a_rule_is_revoked_by_its_id_and_the_last_one_letting_ssh_in_asked_twice(ready):
    p, fake = ready
    form = forms_of(p)["revoke"]
    rows = next(t for t in p.status()["tables"] if t["title"] == "Security group rules")["rows"]
    https_rule = next(r[-1] for r in rows if r[3] == "TCP 443 from 0.0.0.0/0")
    assert https_rule["values"] == {"group": "us-east-1/sg-0web", "rule": "sgr-0http000000000002"}
    rep = ask(p, form, https_rule["values"])
    assert sent(fake, "RevokeSecurityGroupIngress") == {"GroupId": "sg-0web", "SecurityGroupRuleId.1": "sgr-0http000000000002"}
    assert rep["said"] == "revoked TCP 443 from 0.0.0.0/0 from sg-0web"
    fresh = fake.last("DescribeSecurityGroupRules")
    assert fresh["method"] == "GET" and fresh["params"]["SecurityGroupRuleId.1"] == "sgr-0http000000000002"  # read afresh
    # sgr-0ssh… is the only rule letting SSH in to web and the instance store-backed one: asked twice
    ssh = {"group": "us-east-1/sg-0web", "rule": "sgr-0ssh0000000000001"}
    calls = len(fake.requests)
    with pytest.raises(Refusal, match=r"last rule letting SSH in to web \(i-0web0000000000001\), i-0eph0000000000003") as refused:
        ask(p, form, ssh)
    assert refused.value.accept == ACCEPT_LOCKOUT and "RevokeSecurityGroupIngress" not in fake.actions()[calls:]
    # another rule letting SSH in to them: no second question
    p.authorize_ingress("us-east-1/sg-0web", "tcp", "22", "198.51.100.0/24")
    ask(p, form, ssh)
    assert sent(fake, "RevokeSecurityGroupIngress") == {"GroupId": "sg-0web", "SecurityGroupRuleId.1": "sgr-0ssh0000000000001"}
    db_ssh = {"group": "us-east-1/sg-0db", "rule": "sgr-0dbssh00000000004"}
    with pytest.raises(Refusal, match=r"db \(i-0db00000000000002\)"):
        ask(p, form, db_ssh)
    ask(p, form, db_ssh, accepted={ACCEPT_LOCKOUT})
    assert sent(fake, "RevokeSecurityGroupIngress") == {"GroupId": "sg-0db", "SecurityGroupRuleId.1": "sgr-0dbssh00000000004"}
    with pytest.raises(Refusal, match="outbound rule"):
        p.revoke_ingress("us-east-1/sg-0web", "sgr-0out0000000000003")
    with pytest.raises(Refusal, match="no rule sgr-0gone"):
        p.revoke_ingress("us-east-1/sg-0web", "sgr-0gone")


def test_a_public_key_is_imported_and_a_key_pair_deleted(ready):
    p, fake = ready
    forms = forms_of(p)
    rep = ask(p, forms["import-key"], {"region": "us-east-1", "name": "desktop", "public_key": "  " + ED25519 + "\n"})
    params = sent(fake, "ImportKeyPair")
    assert params == {"KeyName": "desktop", "PublicKeyMaterial": base64.b64encode(ED25519.encode()).decode()}
    assert rep["said"] == "imported desktop into us-east-1" and rep["id"].startswith("key-")
    calls = len(fake.requests)
    for key, words in (("-----BEGIN OPENSSH PRIVATE KEY----- b3BlbnNzaC1rZXk=", "that is a private key"),
                       ("ssh-dss AAAAB3NzaC1kc3MAAACBAP", "not an OpenSSH public key"),
                       ("ssh-ed25519 AAAAB3NzaC1yc2EAAAADAQABAAABAQ== x", "not an ssh-ed25519 key")):
        with pytest.raises(ValueError, match=words):
            ask(p, forms["import-key"], {"region": "us-east-1", "name": "x", "public_key": key})
    with pytest.raises(Refusal, match="a key pair named laptop already"):
        ask(p, forms["import-key"], {"region": "us-east-1", "name": "laptop", "public_key": ED25519})
    assert fake.requests[calls:] == []  # refused before anything was sent
    rows = next(t for t in p.status()["tables"] if t["title"] == "Key pairs")["rows"]
    laptop = next(r[-1] for r in rows if r[0]["text"] == "laptop")
    assert laptop["values"] == {"region": "us-east-1", "key": "key-0laptop000000001", "name": "laptop"}
    rep = ask(p, forms["delete-key"], laptop["values"])
    assert sent(fake, "DeleteKeyPair") == {"KeyPairId": "key-0laptop000000001"}
    assert "keep the key they hold" in rep["lines"][0]
    assert [r[0]["text"] for r in next(t for t in p.status()["tables"] if t["title"] == "Key pairs")["rows"]] == ["desktop"]


def change_of(fake) -> list[tuple]:
    """The last ChangeResourceRecordSets' changes as sent: (Action, Name, Type, TTL, values), with its XML's layout."""
    r = fake.last("ChangeResourceRecordSets")
    assert r["body"].startswith(b'<?xml version="1.0" encoding="UTF-8"?>')
    root = ET.fromstring(r["body"])
    ns = {"r": NS_R53}
    out = []
    for c in root.findall("r:ChangeBatch/r:Changes/r:Change", ns):
        rrs = c.find("r:ResourceRecordSet", ns)
        assert [x.tag.split("}")[1] for x in rrs] == ["Name", "Type", "TTL", "ResourceRecords"]  # the reference's order
        out.append((c.findtext("r:Action", namespaces=ns), rrs.findtext("r:Name", namespaces=ns),
                    rrs.findtext("r:Type", namespaces=ns), rrs.findtext("r:TTL", namespaces=ns),
                    [v.text for v in rrs.findall("r:ResourceRecords/r:ResourceRecord/r:Value", ns)]))
    assert [x.tag.split("}")[1] for x in root.find("r:ChangeBatch", ns)] == ["Comment", "Changes"]
    return out


def test_a_record_is_set_with_one_upsert_and_every_other_record_untouched(ready):
    p, fake = ready
    forms = forms_of(p)
    set_form = forms[f"set:{ZONE}"]
    before = fake.zone_sets()
    rep = ask(p, set_form, {"name": "blog", "rtype": "A", "value": "192.0.2.55", "ttl": "120"})
    assert change_of(fake) == [("UPSERT", "blog.example.com.", "A", "120", ["192.0.2.55"])]
    assert rep["said"] == "made blog.example.com A 192.0.2.55" and rep["status"] == "PENDING" and rep["change"].startswith("C")
    assert fake.zone_sets() == [*before, ("blog.example.com", "A", 120, ("192.0.2.55",))]
    # a TXT value is added beside the set's others, quoted for Route 53; the TTL the set's own
    rep = ask(p, set_form, {"name": "@", "rtype": "TXT", "value": "google-site-verification=abc123"})
    assert change_of(fake) == [("UPSERT", "example.com.", "TXT", "300", ['"v=spf1 include:_spf.protonmail.ch ~all"',
                                                                          '"protonmail-verification=0123456789abcdef"',
                                                                          '"google-site-verification=abc123"'])]
    assert rep["said"] == "added \"google-site-verification=abc123\" to example.com TXT (3 values)"
    # an A value replaces the set's (unless added); MX added beside the others
    ask(p, set_form, {"name": "home", "rtype": "A", "value": "203.0.113.9"})
    assert change_of(fake) == [("UPSERT", "home.example.com.", "A", "60", ["203.0.113.9"])]
    ask(p, set_form, {"name": "home", "rtype": "A", "value": "203.0.113.10", "how": "add"})
    assert change_of(fake)[0][4] == ["203.0.113.9", "203.0.113.10"]
    ask(p, set_form, {"name": "@", "rtype": "MX", "value": "30 mail3.example.org"})
    assert change_of(fake)[0][4] == ["10 mail.protonmail.ch.", "20 mailsec.protonmail.ch.", "30 mail3.example.org"]
    calls = len(fake.requests)
    rep = ask(p, set_form, {"name": "@", "rtype": "MX", "value": "30 mail3.example.org."})
    assert rep["changed"] is False and "nothing sent" in rep["said"] and "ChangeResourceRecordSets" not in fake.actions()[calls:]
    # what Route 53 would refuse is refused before anything is sent
    for values, words in (({"name": "www", "rtype": "A", "value": "192.0.2.1"}, "is a CNAME"),
                          ({"name": "@", "rtype": "CNAME", "value": "example.net"}, "cannot stand for the zone's own name"),
                          ({"name": "@", "rtype": "NS", "value": "ns1.example.net"}, "own NS records are Route 53's"),
                          ({"name": "cdn", "rtype": "A", "value": "192.0.2.1"}, "alias to d111111abcdef8.cloudfront.net"),
                          ({"name": "home", "rtype": "A", "value": "not-an-ip"}, "not an IPv4 address"),
                          ({"name": "a.b.other.org.", "rtype": "A", "value": "192.0.2.1"}, "outside the zone"),
                          ({"name": "no spaces", "rtype": "A", "value": "192.0.2.1"}, "not a name in example.com")):
        calls = len(fake.requests)
        with pytest.raises(ValueError, match=words):
            ask(p, set_form, values)
        assert "ChangeResourceRecordSets" not in fake.actions()[calls:]
    # the zone's table holds the change at once, with its state
    zone = next(t for t in p.status()["tables"] if t["title"] == "example.com records")
    assert ["blog.example.com", "A", "120", "192.0.2.55", "simple"] in [r[:5] for r in zone["rows"]]
    assert "last change C" in zone["note"] and zone["note"].endswith("PENDING")
    p.refresh()  # the next read asks the change's state once
    assert fake.actions().count("GetChange") == 1
    assert next(t for t in p.status()["tables"] if t["title"] == "example.com records")["note"].endswith("INSYNC")


def test_a_record_is_removed_keeping_the_sets_other_values_or_deleted_as_it_is(ready):
    p, fake = ready
    forms = forms_of(p)
    remove = forms[f"remove:{ZONE}"]
    rows = next(t for t in p.status()["tables"] if t["title"] == "example.com records")["rows"]
    verification = next(r[-1] for r in rows if r[3] == '"protonmail-verification=0123456789abcdef"')
    assert verification["values"] == {"name": "example.com", "rtype": "TXT", "value": '"protonmail-verification=0123456789abcdef"'}
    rep = ask(p, remove, verification["values"])
    assert change_of(fake) == [("UPSERT", "example.com.", "TXT", "300", ['"v=spf1 include:_spf.protonmail.ch ~all"'])]
    assert rep["said"].startswith("removed") and rep["after"] == ['"v=spf1 include:_spf.protonmail.ch ~all"']
    rep = ask(p, remove, {"name": "home.example.com", "rtype": "A", "value": "198.51.100.20"})
    assert change_of(fake) == [("DELETE", "home.example.com.", "A", "60", ["198.51.100.20"])]  # the set exactly as it is
    assert rep["said"] == "deleted home.example.com A (its one value 198.51.100.20)" and rep["after"] == []
    assert ("home.example.com", "A") not in [(n, t) for n, t, *_ in fake.zone_sets()]
    assert ("example.com", "MX") in [(n, t) for n, t, *_ in fake.zone_sets()]  # the rest untouched
    # Route 53's own records and alias ones have no Remove, and are refused when asked
    assert all(r[-1] == "" for r in rows if r[1] in ("SOA", "NS") or r[0] == "cdn.example.com")
    for values, words in (({"name": "@", "rtype": "SOA", "value": "x"}, "Route 53's own"),
                          ({"name": "@", "rtype": "NS", "value": "ns-2048.awsdns-64.net."}, "Route 53's own"),
                          ({"name": "cdn", "rtype": "A", "value": "d111111abcdef8.cloudfront.net"}, "alias to"),
                          ({"name": "www", "rtype": "CNAME", "value": "example.org"}, "holds no value 'example.org'")):
        with pytest.raises(ValueError, match=words):
            p.remove_record(ZONE, values["name"], values["rtype"], values["value"])
    ask(p, forms[f"remove:{PRIVATE}"], {"name": "db.corp.internal", "rtype": "A", "value": "10.0.0.5"})
    assert change_of(fake) == [("DELETE", "db.corp.internal.", "A", "300", ["10.0.0.5"])]
    assert fake.last("ChangeResourceRecordSets")["path"] == f"/2013-04-01/hostedzone/{PRIVATE}/rrset/"


def test_a_type_that_cannot_be_read_makes_a_stop_asked_twice_and_an_ended_instance_has_no_power(made, env):
    env(settings_of(EC2_REGIONS="us-east-1"))
    fake = FakeAws()
    fake.fail["DescribeInstanceTypes"] = (403, "UnauthorizedOperation", "You are not authorized to perform this operation.")
    fake.account["us-east-1"]["instances"].append(instance("i-0gone000000000004", "old", state="terminated", ip=""))
    p, fake = made(fake)
    p.refresh()
    with pytest.raises(Refusal, match="whether its type t3.micro has instance store volumes could not be read") as refused:
        p.power("us-east-1", "i-0web0000000000001", "stop")
    assert refused.value.accept == ACCEPT_POWER and "StopInstances" not in fake.actions()
    p.power("us-east-1", "i-0web0000000000001", "stop", accept_data_loss=True)
    assert sent(fake, "StopInstances") == {"InstanceId.1": "i-0web0000000000001"}
    st = p.status()
    old = next(r for r in next(t for t in st["tables"] if t["title"] == "Instances")["rows"] if r[0] == {"text": "old", "sub": "i-0gone000000000004"})
    assert old[1] == "terminated" and old[-1] == "" and "power:us-east-1:i-0gone000000000004" not in {f["id"] for f in st["forms"]}


def test_a_value_typed_as_it_was_set_is_found_to_remove(ready):
    p, fake = ready
    p.set_record(ZONE, "@", "TXT", "google-site-verification=abc123")
    rep = p.remove_record(ZONE, "@", "TXT", "google-site-verification=abc123")  # typed bare, as it was set
    assert rep["after"] == ['"v=spf1 include:_spf.protonmail.ch ~all"', '"protonmail-verification=0123456789abcdef"']
    rep = p.remove_record(ZONE, "www", "CNAME", "EXAMPLE.net.")  # a host name in any case, its dot or not
    assert change_of(fake) == [("DELETE", "www.example.com.", "CNAME", "300", ["example.net"])]
