"""Dynamic DNS through Route 53 over the stand-ins, changing only what is its own (liminal-libs 1.49.2's Keeper; the audit
before any key went in): a host with no A record is made, one already pointing here or at the address it set last is
kept current (after a restart too: its ddns.json), and one holding another address, or several, is left as it is with a
Take over… on the page until the user takes it over; never cut to one address unasked; Update DNS now is confirmed first;
a host taken out of the settings is let go; a pass ends before a write once the plugin is detached."""
from __future__ import annotations

import json
import threading

import pytest

from conftest import HOME, ZONE, FakeAws, OneShotPlatform, Public, serving, settings_of
from liminal_libs.machines.ddns import TakeOverRefused
from plugin_platform_ec2 import Refusal
from test_forms import change_of, page_args

NEW = "93.184.216.77"  # this network's address once it moved


def ddns_table(st: dict) -> dict:
    return next(t for t in st["tables"] if t["title"] == "Dynamic DNS")


def test_a_host_holding_another_address_is_left_as_it_is_its_row_offering_take_over(made, env):
    env(settings_of(ddns=True, EC2_REGIONS="us-east-1"))  # home.example.com holds 198.51.100.20, not this network's
    p, fake = made()
    [first] = p.ddns_update(force=False)
    assert first["ok"] is False and first["foreign"] is True and first["holds"] == ["198.51.100.20"]
    assert first["result"] == "holds 198.51.100.20, not this network's address: left as it is (Take over… to point it here)"
    assert "ChangeResourceRecordSets" not in fake.actions()
    p.refresh()
    st = p.status()
    row = ddns_table(st)["rows"][0]
    assert row[:2] == ["home.example.com", "198.51.100.20"]
    assert row[-1] == {"form": "ddns-take", "title": "Take over…", "label": "Take over home.example.com",
                       "values": {"host": "home.example.com", "holds": "198.51.100.20"}}
    forms = {f["id"]: f for f in st["forms"]}
    assert forms["ddns-take"]["hook"] == "ddns_take_over" and forms["ddns-now"]["hook"] == "ddns_update"
    assert {"form": "ddns-now", "title": "Update DNS now"}.items() <= next(a for a in st["actions"] if a.get("form")).items()
    assert not any(a.get("hook") == "ddns_update" for a in st["actions"])  # never a write on one click
    # Update DNS now (its form, confirmed) leaves it too: it is not the keeper's
    [forced] = p.ask("ddns_update", *page_args(forms["ddns-now"], {}))
    assert forced["foreign"] is True and "ChangeResourceRecordSets" not in fake.actions()


def test_take_over_then_a_pass_sets_it(made, env):
    env(settings_of(ddns=True, EC2_REGIONS="us-east-1"))
    p, fake = made()
    p.refresh()
    p.ddns_update(force=False)
    take = next(f for f in p.status()["forms"] if f["id"] == "ddns-take")
    calls = len(fake.requests)
    with pytest.raises(Refusal, match="holds 198.51.100.20 now, not 203.0.113.1 as confirmed"):
        p.ddns_take_over("home.example.com", "203.0.113.1", True)  # what was confirmed is no longer what it holds
    assert "ChangeResourceRecordSets" not in fake.actions()[calls:]
    assert [x["name"] for x in take["fields"]] == ["host", "holds", "accept_take_over"]  # the hook's arguments, in order
    values = {"host": "home.example.com", "holds": "198.51.100.20"}
    done = p.ask("ddns_take_over", *page_args(take, values, accepted={"accept_take_over"}))
    assert done["ok"] and done["result"] == "set (pending) (was 198.51.100.20)"
    assert change_of(fake) == [("UPSERT", "home.example.com.", "A", "60", [HOME])]  # exactly one address, its TTL kept
    calls = len(fake.requests)
    [again] = p.ddns_update(force=False)
    assert again["result"] == "current" and "ChangeResourceRecordSets" not in fake.actions()[calls:]
    assert ddns_table(p.status())["rows"][0][-1] == ""  # its own now: no Take over…


def test_a_host_with_several_addresses_is_never_cut_to_one(made, env):
    env(settings_of(ddns=True, EC2_REGIONS="us-east-1"))
    fake = FakeAws()
    home = next(r for r in fake.rrsets[ZONE] if r["name"] == "home.example.com")
    home["values"] = [HOME, "198.51.100.21"]  # this network's among others: still not one address of its own
    p, fake = made(fake)
    for force in (False, True):
        [one] = p.ddns_update(force=force)
        assert one["foreign"] is True and one["result"].startswith(f"holds 2 addresses ({HOME}, 198.51.100.21): left as it is")
    assert "ChangeResourceRecordSets" not in fake.actions() and home["values"] == [HOME, "198.51.100.21"]


def test_its_own_old_address_is_updated_after_the_networks_address_changed(made, env, tmp_path):
    env(settings_of(EC2_REGIONS="us-east-1", EC2_DDNS_HOSTS="nas.example.com"))
    public = Public(HOME)
    p, fake = made(public=public)
    [made_] = p.ddns_update(force=False)  # no record: made, and its own from now on
    assert made_["result"] == "set (pending) (was none)" and change_of(fake) == [("UPSERT", "nas.example.com.", "A", "300", [HOME])]
    state = json.loads((tmp_path / "ec2" / "ddns.json").read_text(encoding="utf-8"))
    assert state["own"] == {"nas.example.com": HOME}
    public.address = NEW  # the network's address moved; the platform restarted (a new plugin, the same folder)
    p2, _ = made(fake, public=public)
    [moved] = p2.ddns_update(force=False)
    assert moved["ok"] and moved["result"] == f"set (pending) (was {HOME})"
    assert change_of(fake) == [("UPSERT", "nas.example.com.", "A", "300", [NEW])]
    # a host taken out of the settings is let go by the serving platform: no longer its own
    serving(p2)
    env({"EC2_DDNS_HOSTS": "home.example.com"})
    p2.settings_changed()
    p2.ddns_update(force=False)
    assert json.loads((tmp_path / "ec2" / "ddns.json").read_text(encoding="utf-8"))["own"] == {}


def test_a_pass_writes_nothing_once_the_plugin_is_detached(made, env):
    env(settings_of(EC2_REGIONS="us-east-1", EC2_DDNS_HOSTS="nas.example.com"))
    p, fake = made()
    p.domains()
    p.clients()
    hosts, _ = p.ddns_hosts(p.config())
    stop = threading.Event()
    stop.set()  # the worker's stop event, set by the detach
    assert p.keeper().run_pass(hosts, stop=stop) == []
    assert "ChangeResourceRecordSets" not in fake.actions() and "ListResourceRecordSets" not in fake.actions()


def test_a_host_outside_the_public_zones_is_said_and_an_alias_never_written_over(made, env):
    env(settings_of(EC2_REGIONS="us-east-1", EC2_DDNS_HOSTS="cdn.example.com, db.corp.internal, home.elsewhere.org"))
    p, fake = made()
    [alias] = p.ddns_update(force=True)
    assert alias["ok"] is False and "alias to d111111abcdef8.cloudfront.net" in alias["result"]
    assert "ChangeResourceRecordSets" not in fake.actions()
    p.refresh()
    problem = p.status()["problem"]
    assert "db.corp.internal is in none of the account's domains" in problem  # a private zone is never used
    assert "home.elsewhere.org is in none of the account's domains" in problem
    env({"EC2_DDNS_HOSTS": "nas.example.com"})
    p2, fake2 = made(FakeAws(), public=(None, "neither OpenDNS nor Google answered with a public IPv4 address"))
    [none] = p2.ddns_update(force=True)
    assert none["ok"] is False and "this network's address was not found" in none["result"]
    assert "ChangeResourceRecordSets" not in fake2.actions()


def test_take_over_is_asked_twice_and_counts_only_when_exactly_true(made, env):
    """Taking over sets the record at once and drops what it holds: refused, naming accept_take_over (the page's second
    confirmation), and nothing taken, until it is exactly True; "true", 1 or "yes" are refused like a missing one."""
    env(settings_of(ddns=True, EC2_REGIONS="us-east-1"))
    p, fake = made()
    p.ddns_update(force=False)
    keeper = p.keeper()
    for value in (False, "true", 1, "yes", None):
        with pytest.raises(TakeOverRefused) as refused:
            p.ddns_take_over("home.example.com", "198.51.100.20", value)
        assert refused.value.accept == "accept_take_over" and "198.51.100.20" in str(refused.value)
        assert not keeper.taken("home.example.com")
    assert "ChangeResourceRecordSets" not in fake.actions()
    done = p.ddns_take_over("home.example.com", "198.51.100.20", True)
    assert done["ok"] and done["result"] == "set (pending) (was 198.51.100.20)"
    assert keeper.own("home.example.com") == HOME and not keeper.taken("home.example.com")  # single-use: its own now
    assert change_of(fake) == [("UPSERT", "home.example.com.", "A", "60", [HOME])]


def test_a_host_taken_over_then_out_of_the_setting_is_let_go_and_left_as_it_is_when_put_back(made, env, tmp_path):
    env(settings_of(ddns=True, EC2_REGIONS="us-east-1"))
    public = Public(HOME)
    p, fake = made(public=public)
    serving(p)  # the serving platform: what settles
    p.ddns_update(force=False)
    p.ddns_take_over("home.example.com", "198.51.100.20", True)  # taken over: pointed here, its own
    keeper = p.keeper()
    assert keeper.known() == ["home.example.com"]
    env({"EC2_DDNS_HOSTS": "nas.example.com"})  # taken out of the setting
    p.settings_changed()
    p.refresh()  # the next read (its zones read): let go
    assert keeper.known() == [] and not keeper.taken("home.example.com") and keeper.own("home.example.com") is None
    state = json.loads((tmp_path / "ec2" / "ddns.json").read_text(encoding="utf-8"))
    assert state == {"own": {}, "taken": {}}
    # put back once this network moved on: the record holds the old address, no longer its own, so it is left as it is
    public.address = NEW
    env({"EC2_DDNS_HOSTS": "home.example.com"})
    p.settings_changed()
    calls = len(fake.requests)
    [back] = p.ddns_update(force=True)  # the address asked afresh (Update DNS now); still never written over
    assert back["foreign"] is True and back["result"].startswith(f"holds {HOME}, not this network's address: left as it is")
    assert "ChangeResourceRecordSets" not in fake.actions()[calls:]
    p.refresh()
    row = next(t for t in p.status()["tables"] if t["title"] == "Dynamic DNS")["rows"][0]
    assert row[-1]["form"] == "ddns-take" and row[-1]["values"] == {"host": "home.example.com", "holds": HOME}


def test_the_keeper_is_settled_only_once_the_zones_are_read(made, env):
    """Never with a list cut short by unread zones: a refresh whose zones could not be read lets nothing go."""
    env(settings_of(ddns=True, EC2_REGIONS="us-east-1"))
    p, fake = made()
    serving(p)
    p.ddns_update(force=False)
    p.ddns_take_over("home.example.com", "198.51.100.20", True)
    env({"EC2_DDNS_HOSTS": ""})
    p.settings_changed()
    fake.fail["ListHostedZones"] = (403, "AccessDenied", "not authorized to perform: route53:ListHostedZones")
    p.refresh()
    assert p.keeper().known() == ["home.example.com"]  # the zones unread: kept
    del fake.fail["ListHostedZones"]
    p.refresh()
    assert p.keeper().known() == []  # read, and the setting holds it no more: let go


def test_only_the_serving_platform_settles(made, env, tmp_path):
    """Its own command line (unattached) and a one-shot platform command run from a shell whose setting may lack
    EC2_DDNS_HOSTS: with the setting emptied, the keeper's own host is kept in ddns.json. Under the serving platform, the
    same refresh lets it go."""
    env(settings_of(EC2_REGIONS="us-east-1", EC2_DDNS_HOSTS="nas.example.com"))
    p, fake = made()
    p.ddns_update(force=False)  # unattached (the command line): made, its own
    keeper = p.keeper()
    assert keeper.own("nas.example.com") == HOME
    env({"EC2_DDNS_HOSTS": ""})  # a shell whose setting lacks the hosts
    p.settings_changed()
    p.refresh()  # unattached: the zones read, nothing settled
    assert keeper.own("nas.example.com") == HOME
    serving(p, OneShotPlatform())
    p.refresh()  # a one-shot platform command: nothing settled either
    assert keeper.own("nas.example.com") == HOME
    assert json.loads((tmp_path / "ec2" / "ddns.json").read_text(encoding="utf-8"))["own"] == {"nas.example.com": HOME}
    serving(p)
    p.refresh()  # the serving platform: let go
    assert keeper.known() == [] and json.loads((tmp_path / "ec2" / "ddns.json").read_text(encoding="utf-8"))["own"] == {}
