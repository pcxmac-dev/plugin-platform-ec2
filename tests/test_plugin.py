"""The plugin over the stand-ins: its settings read through the Login interface (an EnvironmentLogin not attached, the
app's login attached; EC2_* alone), its status from what was read (no request made to answer it; no value of a setting in
it), valid while the API works or is untried, the regions it reads, a region or a part it may not read said beside the
rest, errors worded with the keys scrubbed, the background reading only while attached, the command line."""
from __future__ import annotations

import json
import time

import pytest

import plugin_platform_ec2.__main__ as cli
from conftest import ACCOUNT, KEY_ID, SECRET, TOKEN, FakeAws, Pairs, settings_of
from plugin_platform_ec2 import NOT_SET, PUBLIC_IPV4, RETRY_S
from plugin_platform_ec2.aws import AwsError
from plugin_platform_ec2.settings import read


def wait_until(test, seconds=5.0):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if test():
            return True
        time.sleep(0.02)
    return False


def table(status: dict, title: str) -> dict:
    return next(t for t in status["tables"] if t["title"] == title)


def test_nothing_set_is_not_valid_and_names_the_variables_and_where_a_key_is_made(made):
    p, fake = made()
    st = p.status()
    assert st["present"] is False and st["valid"] is False and st["why"] == NOT_SET
    assert "https://console.aws.amazon.com/iam/" in st["why"] and "EC2_ACCESS_KEY_ID" in st["why"]
    assert st["tables"] == [] and st["actions"] == [] and st["forms"] == [] and fake.requests == []
    with pytest.raises(ValueError, match="the API is not set up"):
        p.refresh()
    with pytest.raises(ValueError, match="Dynamic DNS is not set up"):
        p.ddns_update()


def test_the_settings_are_read_through_the_login_by_their_pairs():
    login = Pairs(settings_of(ddns=True, EC2_SESSION_TOKEN=TOKEN, EC2_REGIONS="us-east-1, eu-west-1,us-east-1 cn-north-1",
                              EC2_DDNS_MINUTES="15"))
    c = read(login)
    assert (c.access_key, c.secret_key, c.session_token, c.regions, c.minutes) == (KEY_ID, SECRET, TOKEN,
                                                                                  ("us-east-1", "eu-west-1"), 15.0)
    assert c.api_ready and c.ddns_ready and c.hosts == "home.example.com"
    assert any("cn-north-1 is in another AWS partition" in w for w in c.problems)
    assert "ec2-secret-access-key" in login.asked and "EC2_SECRET_ACCESS_KEY" not in login.asked  # by the pairs' names
    assert SECRET not in repr(c) and TOKEN not in repr(c) and KEY_ID not in repr(c)
    halfway = read(Pairs({"EC2_ACCESS_KEY_ID": "ASIA0TEMPKEY00000001", "EC2_DDNS_HOSTS": "home.example.com"}))
    assert not halfway.api_ready and any("EC2_SECRET_ACCESS_KEY is not set" in w for w in halfway.incomplete)
    assert any("temporary key (ASIA…)" in w for w in halfway.problems)

    class Down(Pairs):
        def names(self):
            raise ConnectionError("the login app is not answering")
    assert read(Down({})).problems == ("the settings could not be read from the login: ConnectionError",)


def test_attached_it_asks_the_apps_login_and_reads_in_the_background_until_detached(made):
    p, fake = made()
    login = Pairs(settings_of())
    p.attach(object(), login)
    try:
        assert p.working and wait_until(lambda: p.status().get("readAt"))
        assert "ec2-access-key-id" in login.asked and "DescribeInstances" in fake.actions()
    finally:
        p.detach()
    assert not p.working and p.app is None and p.login is None
    calls = len(fake.requests)
    time.sleep(0.1)
    assert len(fake.requests) == calls  # detached: nothing of it runs


def test_a_refresh_draws_the_tables_and_the_status_asks_nothing_and_holds_no_value(made, env):
    env(settings_of())
    p, fake = made()
    st = p.status()
    assert st["valid"] is True and st["summary"] == "the account is read once attached" and fake.requests == []
    done = p.refresh()
    assert (done["regions"], done["instances"], done["zones"]) == (2, 3, 2)
    calls = len(fake.requests)
    st = p.status()
    assert len(fake.requests) == calls  # the status asks nothing of AWS
    assert st["valid"] is True and "problem" not in st
    assert st["summary"] == "3 instances (2 running) in 1 of 2 regions · 2 zones"
    assert st["account"] == ACCOUNT and st["regions"] == "2 enabled for the account"
    assert st["elasticIpQuota"] == "5 a region (eu-west-1)" and st["defaultVpc"] == "vpc-1 (eu-west-1)"
    assert st["prices"] == "not in EC2's API: https://aws.amazon.com/ec2/pricing/on-demand/"
    assert st["stoppedInstances"] == ("a stopped EBS-backed instance stops its compute charge; its EBS volumes and "
                                      "Elastic IPs still bill")
    assert [t["title"] for t in st["tables"]] == ["Instances", "Security groups", "Security group rules", "Key pairs",
                                                  "Volumes", "Elastic IPs", "Regions", "Hosted zones", "example.com records",
                                                  "corp.internal records (private)"]
    inst = table(st, "Instances")
    assert "https://aws.amazon.com/ec2/pricing/on-demand/" in inst["note"] and "still bill" in inst["note"]
    web = next(r for r in inst["rows"] if r[0] == {"text": "web", "sub": "i-0web0000000000001"})
    assert web[1:8] == ["running", {"text": "us-east-1", "sub": "us-east-1a"}, {"text": "t3.micro", "sub": "2 vCPU · 1 GiB"},
                        "54.194.252.215", "2001:db8:1234:1a2b::123", "2026-10-01 08:30 UTC", "EBS"]
    db = next(r for r in inst["rows"] if r[0]["text"] == "db")
    assert db[1] == {"text": "stopped", "sub": "User initiated (2026-10-02 09:00:00 GMT)"} and db[4] == "–"
    assert db[3] == {"text": "m5d.large", "sub": "2 vCPU · 8 GiB · instance store 75 GB"}
    assert all(len(r) == len(inst["columns"]) for t in st["tables"] for r in [*t["rows"]] for inst in [t])
    groups = table(st, "Security groups")["rows"]
    assert [{"text": "web", "sub": "sg-0web"}, "us-east-1", "vpc-1", "2", "1", "web, i-0eph0000000000003"] in groups
    rules = table(st, "Security group rules")
    assert ["inbound", "TCP 22 from 203.0.113.7/32", "home"] in [r[2:5] for r in rules["rows"]]
    assert rules["rows"][-1][2:4] == ["outbound", "every protocol to 0.0.0.0/0"] and rules["rows"][-1][5] == ""
    assert table(st, "Volumes")["rows"][2][:6] == ["vol-0spare0000000003", {"text": "us-east-1", "sub": "us-east-1a"}, "20",
                                                   {"text": "gp2", "sub": "100 IOPS"}, "available", "–"]
    assert table(st, "Elastic IPs")["rows"] == [["203.0.113.41", "us-east-1", "eipalloc-08229861", "i-0db00000000000002",
                                                 "10.0.0.228"]]
    assert "bills by the hour" in table(st, "Elastic IPs")["note"]
    assert table(st, "Regions")["rows"][1][:6] == ["us-east-1", "2 of 3", "3", "1", "2", "1"]
    zone = table(st, "example.com records")
    cdn = next(r for r in zone["rows"] if r[0] == "cdn.example.com")
    assert cdn[3:] == ["d111111abcdef8.cloudfront.net", "alias to d111111abcdef8.cloudfront.net", ""]  # read only
    assert next(r for r in zone["rows"] if r[0] == "*.example.com")[:4] == ["*.example.com", "A", "300", "192.0.2.10"]
    assert [a["hook"] for a in st["actions"]] == ["refresh"] and all(a["args"] == [] for a in st["actions"])
    text = json.dumps(st)
    assert KEY_ID not in text and SECRET not in text  # names of the settings, never a value


def test_the_regions_read_are_those_enabled_unless_named_and_asked_once_a_day(made, env):
    env(settings_of())
    p, fake = made()
    p.refresh()
    p.refresh()
    assert fake.actions().count("DescribeRegions") == 1  # kept a day
    asked = {r["host"] for r in fake.requests if r["action"] == "DescribeInstances"}
    assert asked == {"ec2.us-east-1.amazonaws.com", "ec2.eu-west-1.amazonaws.com"}
    env({"EC2_REGIONS": "us-east-1"})
    p.settings_changed()
    fake.requests.clear()
    p.refresh()
    assert "DescribeRegions" not in fake.actions()
    assert {r["host"] for r in fake.requests if r["host"].startswith("ec2.")} == {"ec2.us-east-1.amazonaws.com"}
    assert p.status()["regions"] == "us-east-1 (EC2_REGIONS)"


def test_a_long_list_is_read_by_its_pages(made, env):
    env(settings_of(EC2_REGIONS="us-east-1"))
    fake = FakeAws()
    fake.page = 1
    p, fake = made(fake)
    p.refresh()
    reads = [r for r in fake.requests if r["action"] == "DescribeInstances"]
    assert [r["params"].get("NextToken") for r in reads] == [None, "1", "2"] and all(r["params"]["MaxResults"] == "100"
                                                                                   for r in reads)
    assert p.status()["summary"].startswith("3 instances")


def test_a_region_or_a_part_it_may_not_read_is_said_beside_the_rest(made, env):
    env(settings_of())
    fake = FakeAws()
    fake.refuse["eu-west-1"] = (401, "OptInRequired", "You are not subscribed to this service. Please go to http://aws.amazon.com to subscribe.")
    fake.fail["DescribeSnapshots"] = (403, "UnauthorizedOperation", "You are not authorized to perform this operation.")
    p, fake = made(fake)
    p.refresh()
    eu = [r["action"] for r in fake.requests if r["host"] == "ec2.eu-west-1.amazonaws.com"]
    assert eu == ["DescribeInstances"]  # refused there: nothing more asked of that region
    st = p.status()
    assert st["valid"] is True and "eu-west-1: DescribeInstances in eu-west-1: OptInRequired" in st["problem"]
    assert "the region is not enabled for the account" in st["problem"]
    assert "us-east-1: DescribeSnapshots in us-east-1: UnauthorizedOperation" in st["problem"]
    assert "the key's IAM policy does not allow this action" in st["problem"]
    regions = table(st, "Regions")["rows"]
    assert regions[0][6]["text"].startswith("refused: DescribeInstances in eu-west-1: OptInRequired")
    assert regions[1][4] == "–" and regions[1][6]["text"] == "1 part not read"


def test_a_key_aws_refuses_is_not_valid_and_its_words_hold_no_secret(made, env):
    env(settings_of())
    fake = FakeAws(secret="the-account-holds-another-secret")  # the secret is not the key's: SignatureDoesNotMatch
    p, fake = made(fake)
    with pytest.raises(AwsError) as failed:
        p.refresh()
    words = str(failed.value)
    assert words.startswith("DescribeRegions in us-east-1: SignatureDoesNotMatch: The request signature we calculated")
    assert "(HTTP 401)" in words and "EC2_SECRET_ACCESS_KEY" in words and failed.value.status == 401
    assert "Credential=•••/" in words and KEY_ID not in words  # AWS quoting the key's ID: scrubbed
    st = p.status()
    assert st["valid"] is False and st["why"].startswith("the API: DescribeRegions in us-east-1: SignatureDoesNotMatch")
    assert "Create access key" in st["why"] and SECRET not in json.dumps(st) and KEY_ID not in json.dumps(st)
    # AWS's words quoting the secret or the token: scrubbed too
    env({"EC2_SESSION_TOKEN": TOKEN, "EC2_REGIONS": "us-east-1"})
    fake2 = FakeAws(token=TOKEN)
    fake2.fail["DescribeInstances"] = (400, "InvalidParameterValue", f"odd value {SECRET} with {TOKEN}")
    p2, fake2 = made(fake2)
    p2.refresh()
    problem = p2.status()["problem"]
    assert "InvalidParameterValue: odd value ••• with •••" in problem and SECRET not in problem and TOKEN not in problem
    # a part that failed is tried again once the platform attaches it, a quarter of an hour on
    t = [time.time()]
    p3, _ = made(FakeAws(secret="wrong-secret-0123"))
    p3._clock = lambda: t[0]
    with pytest.raises(AwsError):
        p3.refresh()
    assert p3.status()["valid"] is False
    t[0] += RETRY_S
    assert p3.status()["valid"] is True and p3.status()["summary"] == "the account is read once attached"


def test_temporary_credentials_send_their_session_token(made, env):
    env(settings_of(EC2_SESSION_TOKEN=TOKEN, EC2_REGIONS="us-east-1"))
    p, fake = made(FakeAws(token=TOKEN))
    p.refresh()
    assert all(r["headers"]["X-Amz-Security-Token"] == TOKEN for r in fake.requests)
    assert all("x-amz-security-token" in r["headers"]["Authorization"] for r in fake.requests)


def test_route53_refused_is_said_while_ec2_works(made, env):
    env(settings_of(EC2_REGIONS="us-east-1"))
    fake = FakeAws()
    fake.fail["ListHostedZones"] = (403, "AccessDenied",
                                    "User: arn:aws:iam::123456789012:user/liminal is not authorized to perform: route53:ListHostedZones")
    p, fake = made(fake)
    p.refresh()
    st = p.status()
    assert st["valid"] is True and "Route 53: ListHostedZones: AccessDenied" in st["problem"]
    zones = table(st, "Hosted zones")
    assert zones["rows"] == [] and zones["note"].startswith("ListHostedZones: AccessDenied")


def test_the_public_address_is_asked_of_the_name_servers_the_plugin_names():
    assert PUBLIC_IPV4 == (("myip.opendns.com", "a", "208.67.222.222", "OpenDNS"),
                           ("o-o.myaddr.l.google.com", "txt", "216.239.32.10", "Google"))


def test_the_command_line_reads_and_asks_yes_before_a_change(made, env):
    env(settings_of(EC2_REGIONS="us-east-1"))
    p, fake = made()
    said, told = [], []
    assert cli.main(["servers"], plugin=p, out=said.append, err=told.append) == 0
    assert any("i-0web0000000000001" in s and "running" in s and "web" in s for s in said)
    said.clear()
    assert cli.main(["domains"], plugin=p, out=said.append) == 0 and any("example.com" in s for s in said)
    said.clear()
    assert cli.main(["records", "example.com"], plugin=p, out=said.append) == 0
    assert any(s.startswith("home.example.com") and "198.51.100.20" in s for s in said)
    said.clear()
    assert cli.main(["firewalls"], plugin=p, out=said.append) == 0 and any("TCP 22 from 203.0.113.7/32" in s for s in said)
    said.clear()
    assert cli.main(["keys"], plugin=p, out=said.append) == 0 and any("laptop" in s for s in said)
    # a change: nothing done without "yes"
    calls = len(fake.requests)
    assert cli.main(["power", "web", "reboot"], plugin=p, out=said.append, ask=lambda q: "no") == 1
    assert "RebootInstances" not in fake.actions()[calls:] and said[-1] == "nothing done"
    assert cli.main(["power", "web", "reboot"], plugin=p, out=said.append, ask=lambda q: "yes") == 0
    assert fake.last("RebootInstances")["params"]["InstanceId.1"] == "i-0web0000000000001"
    # a risky one is asked twice: the stop of an instance whose type has an instance store
    fake.account["us-east-1"]["instances"][1]["state"] = "running"
    asked = []
    assert cli.main(["power", "db", "stop", "--region", "us-east-1"], plugin=p, out=said.append,
                    ask=lambda q: asked.append(q) or "yes") == 0
    assert len(asked) == 2 and "instance store" in asked[1] and fake.last("StopInstances")["params"]["InstanceId.1"] == \
        "i-0db00000000000002"
    assert cli.main(["set", "example.com", "blog", "A", "192.0.2.55"], plugin=p, out=said.append, ask=lambda q: "yes") == 0
    assert any(s == "made blog.example.com A 192.0.2.55" for s in said)
    assert cli.main(["status"], plugin=p, out=said.append) == 0 and json.loads(said[-1])["valid"] is True
    assert cli.main(["records", "nowhere.example"], plugin=p, out=said.append, err=told.append) == 1
    assert told[-1].startswith("refused: 'nowhere.example' is none of the account's hosted zones")
