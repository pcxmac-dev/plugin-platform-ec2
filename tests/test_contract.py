"""Every plugin here conforms to the class contract (plugin API 2.2): liminal_libs.sources.conformance, read from the
plugin alone (nothing runs); its API cards name the calls its clients make, their addresses answer (with
LIMINAL_VENDOR_PAGES=1), and nothing that costs is in its clients' sources."""
from __future__ import annotations

import ast
import inspect
import os
import re

import pytest

import plugin_platform_ec2 as module
from liminal_libs.sources.apis import dead_links, problems, urls
from liminal_libs.sources.conformance import assert_module_conforms
from plugin_platform_ec2 import __main__ as cli
from plugin_platform_ec2 import aws, card, ec2, route53, settings, sigv4


def test_every_plugin_here_conforms_to_the_class_contract():
    found = assert_module_conforms(module)
    assert found and all(p.api == "2.2" and not p.is_record for p in found)
    assert {p.SYSTEM for p in found} == {"platform"} and {p.KIND for p in found} == {"machine"}
    assert {(p.name, p.title, p.order, p.ICON) for p in found} == {("ec2", "Amazon EC2", 763, "ec2")}
    assert module.__version__ == "0.1.1"


def test_its_settings_are_pairs_named_by_their_variables_and_never_aws_ones():
    p = module.MACHINE
    assert [k.pair for k in p.keys] == ["ec2-access-key-id", "ec2-secret-access-key", "ec2-session-token", "ec2-regions",
                                        "ec2-ddns-hosts", "ec2-ddns-minutes"]
    assert {k.name for k in p.keys if k.secret} == {"EC2_ACCESS_KEY_ID", "EC2_SECRET_ACCESS_KEY", "EC2_SESSION_TOKEN"}
    assert all(not k.aliases for k in p.keys)  # no AWS_ACCESS_KEY_ID read beside them
    for mod in (module, settings, aws, ec2, route53, sigv4, cli):  # no string of its code names one (its words may)
        tree = ast.parse(inspect.getsource(mod))
        docs = {id(n.body[0].value) for n in ast.walk(tree)
                if isinstance(n, (ast.Module, ast.ClassDef, ast.FunctionDef)) and n.body
                and isinstance(n.body[0], ast.Expr) and isinstance(n.body[0].value, ast.Constant)}
        strings = [n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)
                   and id(n) not in docs]
        assert not [s for s in strings if re.search(r"\bAWS_[A-Z]|[~\\/]\.aws\b", s)], mod.__name__  # nor ~/.aws


def test_aws_variables_meant_for_other_tools_are_never_read(made):
    """conftest sets AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY: the plugin, with no EC2_ variable, is not set up."""
    assert os.environ.get("AWS_ACCESS_KEY_ID")
    p, fake = made()
    st = p.status()
    assert st["present"] is False and st["valid"] is False and not p.present() and fake.requests == []


def test_the_cards_conform_and_name_exactly_the_calls_its_clients_make():
    assert problems(module.MACHINE.apis) == [] and module.MACHINE.apis == card.APIS
    ec2_card, r53_card = card.APIS
    assert {c.name for c in ec2_card.used} == set(ec2.READS) | set(ec2.WRITES)
    assert {c.name for c in r53_card.used} == set(route53.READS) | set(route53.WRITES)
    assert {c.name for c in ec2_card.used if c.writes} == set(ec2.WRITES)
    assert {c.name for c in r53_card.used if c.writes} == set(route53.WRITES)
    # the one call it makes that bills: a start, resuming a stopped instance's compute charge (said when confirmed)
    assert {c.name for api in card.APIS for c in api.used if c.costs} == {"StartInstances"}
    start = next(c for c in ec2_card.calls if c.name == "StartInstances")
    assert start.writes and "starts the compute charge again" in start.about
    # every action string the EC2 client sends is one of its READS and WRITES (call() refuses another), and each is sent
    sent = set()
    for mod in (ec2, module):
        sent |= set(re.findall(r'\.(?:call|pages)\(\s*[A-Za-z_]+,\s*"([A-Za-z]+)"', inspect.getsource(mod)))
    assert sent == set(ec2.READS) | set(ec2.WRITES)
    r53_source = inspect.getsource(route53.Route53Api)
    named = set(re.findall(r'_get\("([A-Za-z]+)"', r53_source)) | set(re.findall(r'AwsError\.of\(e, "([A-Za-z]+)"', r53_source))
    assert named == set(route53.READS) | set(route53.WRITES)
    with pytest.raises(ValueError, match="not an action this plugin makes"):
        ec2.Ec2Api(None).call("us-east-1", "Run" + "Instances")
    # each covered area is the area of a call it makes; the docs are AWS's own pages
    assert {a.name for a in ec2_card.covered} >= {c.area for c in ec2_card.used}
    assert {a.name for a in r53_card.covered} >= {c.area for c in r53_card.used}
    assert all(u.startswith(("https://docs.aws.amazon.com/", "https://aws.amazon.com/", "https://console.aws.amazon.com/",
                             "https://health.aws.amazon.com/", "https://builder.aws.com/")) for u in urls(card.APIS))
    assert len(ec2_card.areas) >= 60 and len(r53_card.areas) >= 18  # every part of each API, the most not used


def test_nothing_that_costs_is_in_its_clients_sources():
    """No call that starts or raises a charge (the cards' costs=True calls) but the start it makes and confirms (a stopped
    instance's compute charge resumed), nor one that ends or deletes a billable thing, nor Cost Explorer (each of its
    requests costs), is named outside the API card."""
    costly = {c.name for api in card.APIS for c in api.calls if c.costs and not c.used}
    assert {"RunInstances", "CreateVolume", "CreateSnapshot", "AllocateAddress", "CreateHostedZone"} <= costly
    assert "StartInstances" not in costly
    never = costly | {"TerminateInstances", "DeleteVolume", "ReleaseAddress", "DeleteHostedZone", "ModifyInstanceAttribute",
                      "RegisterDomain", "GetCostAndUsage", "costexplorer", "ce.us-east-1.amazonaws.com", "AllRegions=true"}
    for mod in (module, aws, ec2, route53, sigv4, settings, cli):
        source = inspect.getsource(mod)
        found = sorted(n for n in never if n in source)
        assert found == [], f"{mod.__name__} names {found}"


def test_the_readmes_iam_policy_allows_exactly_the_actions_it_makes():
    """The README's policy (the user: "an IAM user or role whose policy allows exactly the reads and the free changes")
    names every action the clients make and no other; its "## Its API" section is there."""
    import json
    from pathlib import Path

    text = (Path(__file__).resolve().parents[1] / "README.md").read_text(encoding="utf-8")
    policy = json.loads(re.search(r"```json\n(.*?)\n\s*```", text, re.S).group(1))
    allowed = [a for s in policy["Statement"] for a in s["Action"]]
    assert sorted(allowed) == sorted(module.IAM_ACTIONS) and len(allowed) == len(set(allowed))
    assert {s["Effect"] for s in policy["Statement"]} == {"Allow"}
    writes = {f"ec2:{a}" for a in ec2.WRITES} | {f"route53:{a}" for a in route53.WRITES}
    assert set(policy["Statement"][1]["Action"]) == writes  # the second statement: the free changes alone
    assert "## Its API" in text and "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/Welcome.html" in text


def test_its_facts_are_keyed_by_its_apis_and_ask_nothing(made, env):
    from conftest import settings_of

    p, fake = made()
    assert p.api_facts() == {}
    env(settings_of())
    p.refresh()
    calls = len(fake.requests)
    facts = p.api_facts()
    assert set(facts) == {a.name for a in card.APIS} and len(fake.requests) == calls
    assert facts["Amazon EC2 API"]["Requests"].endswith("made") and facts["Amazon EC2 API"]["Account"] == "123456789012"
    assert facts["Amazon Route 53 API"]["Last answer"].startswith("HTTP 200")


def test_its_icon_is_its_makers_mark_drawn_by_the_library():
    from liminal_libs.ui import STATIC

    drawn = set(re.findall(r"^\s*([a-z0-9]+):\s*'", (STATIC / "icons.js").read_text(encoding="utf-8"), re.M))
    assert module.MACHINE.ICON == "ec2" and "ec2" in drawn


@pytest.mark.skipif(os.environ.get("LIMINAL_VENDOR_PAGES") != "1", reason="asks AWS's pages: LIMINAL_VENDOR_PAGES=1")
def test_every_address_on_its_cards_answers():
    assert dead_links(card.APIS) == []
