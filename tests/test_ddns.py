"""Dynamic DNS through Route 53 over the stand-ins: this network's address (a stand-in for asking OpenDNS and Google), each
host's A record read of its public zone (ListResourceRecordSets), an UPSERT of that one record only where it differs (or
when asked), its TTL kept; a host outside the account's public zones said, an alias A record never written over."""
from __future__ import annotations

from conftest import HOME, ZONE, FakeAws, settings_of
from test_forms import change_of


def test_a_host_is_set_to_this_networks_address_only_when_it_differs(made, env):
    env(settings_of(ddns=True, EC2_REGIONS="us-east-1"))
    p, fake = made()
    [first] = p.ddns_update(force=False)  # the zones read first, then the host
    assert first["ok"] and first["result"] == "set (pending) (was 198.51.100.20)" and first["address"] == HOME
    assert change_of(fake) == [("UPSERT", "home.example.com.", "A", "60", [HOME])]  # the record's own TTL kept
    read = [r for r in fake.requests if r["action"] == "ListResourceRecordSets"][-1]
    assert read["path"] == f"/2013-04-01/hostedzone/{ZONE}/rrset" and read["params"]["name"] == "home.example.com."
    calls = len(fake.requests)
    [again] = p.ddns_update(force=False)
    assert again["result"] == "current" and fake.actions()[calls:] == ["ListResourceRecordSets"]  # read, not written
    [forced] = p.ddns_update(force=True)  # Update DNS now: written whatever it holds
    assert forced["ok"] and fake.actions()[-1] == "ChangeResourceRecordSets"
    st = p.status()
    ddns = next(t for t in st["tables"] if t["title"] == "Dynamic DNS")
    assert ddns["rows"][0][:2] == ["home.example.com", HOME] and f"this network's address: {HOME}" in ddns["note"]
    assert [a["hook"] for a in st["actions"]] == ["refresh", "ddns_update"]
    assert st["summary"].endswith(f"home.example.com at {HOME}")


def test_a_host_with_no_record_is_made_and_one_outside_the_public_zones_said(made, env):
    env(settings_of(EC2_REGIONS="us-east-1", EC2_DDNS_HOSTS="nas.example.com, db.corp.internal, home.elsewhere.org"))
    p, fake = made()
    [made_] = p.ddns_update(force=False)
    assert made_["host"] == "nas.example.com" and made_["result"] == "set (pending) (was none)"
    assert change_of(fake) == [("UPSERT", "nas.example.com.", "A", "300", [HOME])]
    p.refresh()
    problem = p.status()["problem"]
    assert "db.corp.internal is in none of the account's domains" in problem  # a private zone is not kept
    assert "home.elsewhere.org is in none of the account's domains" in problem


def test_an_alias_record_is_never_written_over_and_no_address_no_write(made, env):
    env(settings_of(EC2_REGIONS="us-east-1", EC2_DDNS_HOSTS="cdn.example.com"))
    p, fake = made()
    [alias] = p.ddns_update(force=True)
    assert alias["ok"] is False and "alias to d111111abcdef8.cloudfront.net" in alias["result"]
    assert "ChangeResourceRecordSets" not in fake.actions()
    env({"EC2_DDNS_HOSTS": "home.example.com"})
    p2, fake2 = made(FakeAws(), public=(None, "neither OpenDNS nor Google answered with a public IPv4 address"))
    [none] = p2.ddns_update(force=True)
    assert none["ok"] is False and "this network's address was not found" in none["result"]
    assert "ChangeResourceRecordSets" not in fake2.actions()
