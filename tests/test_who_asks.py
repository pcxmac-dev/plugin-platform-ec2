"""Who may ask the plugin's changes (0.1.5; the independent review's PLT-H1 and the sweep of the plugins after it,
2026-11-25). Its changes are asked only from its page (PAGE_ONLY_HOOKS, as liminal-libs 1.66.0's apps/asking.py and
liminal-platform 0.34.0 read them): an instance's power, a security group's inbound rule authorized or revoked, a key
pair imported or deleted, a Route 53 value set or removed, a Dynamic DNS pass and a host taken over. Another plugin's ask
is refused, and so is an ask that names no one; over HTTP the platform also asks its login whether you are at the page.
Before, any program on this PC asked them of the platform with a header anyone can send, and the access key did the rest:
a stopped instance started (its compute charge resumed), SSH opened to the whole internet and the last rule letting SSH
in revoked (each second confirmation being only an argument), a host's record replaced with no second question at all.
Its reads are asked only from its page too since 0.1.6 (closed by default: the account's key makes them; `present` and
`status` alone are anyone's). Asked through the library's own App (its ask names who asks as the platform's
does), over the stand-in AWS: nothing reaches AWS or the network."""
from __future__ import annotations

import pytest

pytest.importorskip("liminal_libs.apps.asking", reason="no hook is asked only from its page before liminal-libs 1.66.0")

from conftest import ED25519, HOME, ZONE, settings_of  # noqa: E402 - after the skip, as each of these
from liminal_libs import internal  # noqa: E402
from liminal_libs.apps import App, EnvironmentLogin, asking  # noqa: E402
from liminal_libs.machines.plugin import MachinePlugin  # noqa: E402
from plugin_platform_ec2 import MACHINE  # noqa: E402

CHANGES = ("power", "authorize_ingress", "revoke_ingress", "import_key", "delete_key", "set_record", "remove_record",
           "ddns_update", "ddns_take_over")
READS = ("present", "status", "refresh", "regions", "servers", "firewalls", "key_pairs", "domains", "records", "change")
# 0.1.6, closed by default (the user, 2026-11-26: "Page-only"): the reads made with the account's key are its
# page's alone too; the contract's own two stay anyone's
OPEN_READS = ("present", "status")
PAGE_READS = tuple(h for h in READS if h not in OPEN_READS)
READ_ARGS = {'records': ('example.com',), 'change': ('C1',)}  # the argument a read takes, as another program words it
HOSTS = "new.example.com,home.example.com"  # Dynamic DNS's: one with no record yet, one holding another address
ASKED = {  # each change as another program worded it: the hook's arguments, a second confirmation said where it has one
    "power": ("us-east-1", "i-0db00000000000002", "start", False, True),  # its compute charge resumed, "accepted"
    "authorize_ingress": ("us-east-1/sg-0db", "tcp", "22", "0.0.0.0/0", None, True),  # SSH, to the whole internet
    "revoke_ingress": ("us-east-1/sg-0web", "sgr-0ssh0000000000001", True),  # the one rule letting SSH in to web
    "import_key": ("us-east-1", "another", ED25519),
    "delete_key": ("us-east-1", "key-0laptop000000001", "laptop"),
    "set_record": (ZONE, "www", "CNAME", "example.org"),  # the site's name, pointed at another's
    "remove_record": (ZONE, "@", "TXT", "v=spf1 include:_spf.protonmail.ch ~all"),
    "ddns_update": (),
    "ddns_take_over": ("home.example.com", None, True),  # a name holding another address pointed at this network
}
SENT = [  # what the same asks send from the page, in CHANGES' order
    "StartInstances", "AuthorizeSecurityGroupIngress", "RevokeSecurityGroupIngress", "ImportKeyPair", "DeleteKeyPair",
    "ChangeResourceRecordSets", "ChangeResourceRecordSets",
    "ChangeResourceRecordSets",  # Update DNS now: new.example.com made, home.example.com left as it is
    "ChangeResourceRecordSets",  # home.example.com taken over
]


def writes(fake) -> list[str]:
    """The actions sent that change something (EC2's and Route 53's reads are Describe…, List… and Get…)."""
    return [a for a in fake.actions() if not a.startswith(("Describe", "List", "Get"))]


class Neighbour(MachinePlugin):
    """Another plugin of the platform, asking EC2's through its app as any plugin may (a container plugin, or the MCP
    plugin for a local agent)."""

    name, title = "neighbour", "Neighbour"

    def wants(self, hook, *args):
        """Not a hook: one of EC2's asked through the app."""
        return self.app.ask("ec2", hook, *args)


class Platform(App):
    """The library's App asking as the platform does: from its page's route, the page named in so many words, or from
    its own code, no one named. It holds the plugin as the platform's one-shot commands do (`once`): the plugin's
    background reads and Dynamic DNS passes are not started, so every request the stand-in sees is an ask's."""

    NAME, TITLE, ICON = "platform", "Platform", "chip"
    once = True

    def from_page(self, hook, *args):
        """As the page's route asks a hook."""
        with asking.asking(asking.PAGE):
            return self.ask("ec2", hook, *args)

    def on_its_own(self, hook, *args):
        """As the app's own code asks a hook."""
        return self.ask("ec2", hook, *args)


@pytest.fixture
def attached(made):
    """The plugin over the stand-in AWS, attached with another plugin to an app whose login holds its settings (the
    access key and two Dynamic DNS hosts); let go after."""
    plugin, fake = made()
    neighbour = Neighbour()
    app = Platform(log=lambda m: None, login=EnvironmentLogin(env=settings_of(EC2_DDNS_HOSTS=HOSTS)))
    app.attach(plugin)
    app.attach(neighbour)
    yield app, plugin, neighbour, fake
    app.detach(neighbour.name)
    app.detach(plugin.name)


def test_its_changes_are_said_to_be_asked_only_from_its_page_and_its_reads_with_the_key_too():
    assert set(internal.page_only(MACHINE)) == {*CHANGES, *PAGE_READS}  # what the platform reads
    assert internal.plugin_only(MACHINE) == ()
    assert internal.problems(MACHINE) == []  # each a hook of its own, and someone may ask it
    assert set(CHANGES) | set(READS) == set(MACHINE.interface()["hooks"]) and set(ASKED) == set(CHANGES)
    for hook in (*CHANGES, *PAGE_READS):
        assert asking.refusal(MACHINE, hook, asking.PAGE) == ""
        assert asking.refusal(MACHINE, hook, "neighbour") == (f"ec2's {hook} is asked only from its page, "
                                                              "never by another plugin: neighbour asked it.")
        assert asking.refusal(MACHINE, hook, None).endswith("This ask names no asker: neither the page nor a plugin.")
    for hook in OPEN_READS:
        assert {asking.refusal(MACHINE, hook, who) for who in (asking.PAGE, "neighbour", None)} == {""}


def test_another_plugin_or_no_one_asking_a_change_sends_nothing_and_its_page_does(attached):
    app, plugin, neighbour, fake = attached
    for hook in CHANGES:
        for ask in (neighbour.wants, app.on_its_own):
            with pytest.raises(asking.AskRefused, match=f"ec2's {hook} is asked only from its page"):
                ask(hook, *ASKED[hook])
    for hook in PAGE_READS:  # 0.1.6: a read made with the key is refused them too, and nothing is sent for it
        for ask in (neighbour.wants, app.on_its_own):
            with pytest.raises(asking.AskRefused, match=f"ec2's {hook} is asked only from its page"):
                ask(hook, *READ_ARGS.get(hook, ()))
    assert fake.requests == []  # nothing sent, nor read: not the read a change makes first
    assert neighbour.wants("present") is True and neighbour.wants("status")["valid"] is True  # the contract's reads, anyone's as before
    assert [i["name"] for i in app.from_page("servers")["us-east-1"]] == ["web", "db", ""]
    assert len(app.from_page("records", ZONE)["records"]) == 8 and app.from_page("refresh") is not None
    assert writes(fake) == []
    for hook in CHANGES:  # the same asks from its page: each one sent
        sent = len(writes(fake))
        assert app.from_page(hook, *ASKED[hook]) is not None
        assert len(writes(fake)) == sent + 1, hook
    assert writes(fake) == SENT
    assert fake.last("StartInstances")["params"]["InstanceId.1"] == "i-0db00000000000002"
    assert ("home.example.com", "A", 60, (HOME,)) in fake.zone_sets()


def test_its_own_code_asks_nothing_of_the_app_and_runs_as_before(attached):
    """The background's Dynamic DNS pass and the command line call the plugin's code themselves: not an ask, so no asker
    is named and none is needed."""
    app, plugin, neighbour, fake = attached
    assert asking.asker() is None
    new, home = plugin.ddns_update(force=False)
    assert new["ok"] is True and home["foreign"] is True
    assert writes(fake) == ["ChangeResourceRecordSets"]


def test_no_hook_is_left_undeclared():
    """0.1.6, closed by default (liminal-libs 1.107.0): every hook it answers says who may ask it, so none is left to
    the default and the library's conformance has no warning. Read from its words, so it holds on an older library."""
    from liminal_libs.sources import conformance

    said = {h for word in ("READ_HOOKS", "SERVICE_HOOKS", "PLUGIN_ONLY_HOOKS", "PAGE_ONLY_HOOKS")
            for h in internal.declared(MACHINE, word)}
    own = [h for h in MACHINE.interface()["hooks"] if h not in ("setup", "run", "scan")]
    assert own and [h for h in own if h not in said] == []
    assert set(PAGE_READS) <= set(internal.declared(MACHINE, "PAGE_ONLY_HOOKS"))
    assert not set(PAGE_READS) & set(internal.declared(MACHINE, "READ_HOOKS"))  # none is opened again as a read
    warnings = getattr(conformance, "warnings", None)  # liminal-libs 1.107.0
    assert warnings is None or warnings(MACHINE) == []
