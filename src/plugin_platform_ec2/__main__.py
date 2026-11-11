"""`python -m plugin_platform_ec2 ...`: the plugin from the command line, its settings read from the environment (an
EnvironmentLogin: EC2_* as this shell has them; never AWS_*).

    status                                   the account read, then the plugin's status (JSON)
    regions                                  the regions enabled for the account
    servers                                  each region's instances
    firewalls                                each region's security groups and rules
    keys                                     each region's key pairs
    domains                                  the Route 53 hosted zones
    records ZONE                             a zone's records (its ID or its name)
    ddns [--now]                             a Dynamic DNS pass: an UPSERT where a host differs (--now: every host)
    power INSTANCE start|stop|reboot [--force] [--region R]
                                             an instance (its ID or its Name tag) powered on, stopped or rebooted
    set ZONE NAME TYPE VALUE [--ttl N] [--add | --replace]
                                             a record set in a zone, every other record untouched
    remove ZONE NAME TYPE VALUE              a value taken out of a record set (the set deleted with its last)
    change ID                                a Route 53 change's state (PENDING, INSYNC)

A change asks "yes" on the terminal first, and once more for a risky one. --json prints the answer as JSON."""
from __future__ import annotations

import argparse
import json
import sys

from . import MACHINE, Refusal
from .aws import AwsError
from .ec2 import rule_words


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m plugin_platform_ec2", description="Amazon EC2 and Route 53 for Liminal")
    p.add_argument("--json", action="store_true", help="print the answer as JSON")
    sub = p.add_subparsers(dest="what")
    for name, words in (("status", "the account read, then the plugin's status"), ("regions", "the regions enabled"),
                        ("servers", "each region's instances"), ("firewalls", "each region's security groups and rules"),
                        ("keys", "each region's key pairs"), ("domains", "the Route 53 hosted zones")):
        sub.add_parser(name, help=words)
    r = sub.add_parser("records", help="a zone's records")
    r.add_argument("zone")
    d = sub.add_parser("ddns", help="a Dynamic DNS pass")
    d.add_argument("--now", action="store_true", help="an UPSERT for every host, whether it differs or not")
    w = sub.add_parser("power", help="an instance powered on, stopped or rebooted")
    w.add_argument("instance")
    w.add_argument("action", choices=("start", "stop", "reboot", "on", "off"))
    w.add_argument("--force", action="store_true", help="a forced stop (without flushing the file systems)")
    w.add_argument("--region", help="its region (else found among the regions read)")
    s = sub.add_parser("set", help="a record set in a zone")
    for a in ("zone", "name", "type", "value"):
        s.add_argument(a)
    s.add_argument("--ttl", type=int)
    how = s.add_mutually_exclusive_group()
    how.add_argument("--add", action="store_true", help="the value added beside the set's others")
    how.add_argument("--replace", action="store_true", help="the set holds this value alone")
    m = sub.add_parser("remove", help="a value taken out of a record set")
    for a in ("zone", "name", "type", "value"):
        m.add_argument(a)
    c = sub.add_parser("change", help="a Route 53 change's state")
    c.add_argument("id")
    return p


def confirmed(ask, words: str) -> bool:
    return str(ask(f"{words} Type yes to go on: ") or "").strip().lower() == "yes"


def changing(do, ask, say, words: str):
    """A change asked once ("yes"), and once more when the plugin refuses it naming what accepts it."""
    if not confirmed(ask, words):
        say("nothing done")
        return None
    try:
        return do({})
    except Refusal as e:
        if not e.accept:
            raise
        if not confirmed(ask, f"{e}\nAsked again:"):
            say("nothing done")
            return None
        return do({e.accept: True})


def find_region(p, instance: str) -> str:
    for region, found in p.servers().items():
        if isinstance(found, list) and any(i["id"] == instance or i["name"] == instance for i in found):
            return region
    raise ValueError(f"no instance {instance!r} in the regions read (give --region)")


def main(argv: list[str] | None = None, plugin=None, out=None, err=None, ask=None) -> int:
    p = plugin if plugin is not None else MACHINE
    say = out or (lambda s: print(s))
    tell = err or (lambda s: print(s, file=sys.stderr))
    ask = ask or input
    args = parser().parse_args(sys.argv[1:] if argv is None else argv)
    what = args.what or "status"
    try:
        if what == "status":
            if p.config().api_ready:
                try:
                    p.refresh()
                except AwsError:
                    pass  # the status says it
            say(json.dumps(p.status(), indent=1))
            return 0
        if what == "regions":
            answer = p.regions()
            lines = [f"{r['name']:<16} {r['endpoint']:<32} {r['optIn']}" for r in answer]
        elif what in ("servers", "firewalls", "keys"):
            answer = {"servers": p.servers, "firewalls": p.firewalls, "keys": p.key_pairs}[what]()
            lines = []
            for region, found in answer.items():
                if isinstance(found, dict) and "error" in found:
                    lines.append(f"{region}: {found['error']}")
                elif what == "servers":
                    lines += [f"{region:<15} {i['id']:<20} {i['state']:<10} {i['type']:<12} {i['publicIp'] or '-':<15} "
                              f"{i['name']}" for i in found]
                elif what == "firewalls":
                    names = {g["id"]: g["name"] for g in found["groups"]}
                    lines += [f"{region:<15} {g['id']:<21} {g['name']}" for g in found["groups"]]
                    lines += [f"{region:<15}   {names.get(x['group'], x['group'])}: {rule_words(x)} ({x['id']})"
                              for x in found["rules"]]
                else:
                    lines += [f"{region:<15} {k['id']:<22} {k['type']:<8} {k['name']}" for k in found]
            lines = lines or ["nothing in the regions read"]
        elif what == "domains":
            answer = p.domains()
            lines = [f"{z['id']:<22} {z['name']:<32} {'private' if z['private'] else 'public'}" for z in answer]
            lines = lines or ["no hosted zones"]
        elif what == "records":
            answer = p.records(args.zone)
            lines = [f"{r['name']:<36} {r['type']:<6} {r['ttl'] if r['ttl'] is not None else '-':<6} "
                     f"{', '.join(r['values']) or r['kind']}" for r in answer["records"]]
        elif what == "ddns":
            answer = p.ddns_update(force=args.now)
            lines = [f"{h['host']:<32} {h['address'] or '-':<16} {h['result']}" for h in answer]
        elif what == "change":
            answer = p.change(args.id)
            lines = [f"{answer['id']}: {answer['status']} (submitted {answer['submitted'] or '-'})"]
        elif what == "power":
            action = {"on": "start", "off": "stop"}.get(args.action, args.action)
            if args.force and action == "stop":
                action = "force-stop"
            region = args.region or find_region(p, args.instance)
            answer = changing(lambda more: p.power(region, args.instance, action, **more), ask, say,
                              f"{action} {args.instance} in {region}?")
            if answer is None:
                return 1
            lines = [answer["said"], *(f"  {x}" for x in answer["lines"])]
        else:  # set, remove
            how = "add" if getattr(args, "add", False) else "replace" if getattr(args, "replace", False) else None
            if what == "set":
                answer = changing(lambda more: p.set_record(args.zone, args.name, args.type, args.value, ttl=args.ttl, how=how),
                                  ask, say, f"set {args.name} {args.type.upper()} {args.value} in {args.zone}?")
            else:
                answer = changing(lambda more: p.remove_record(args.zone, args.name, args.type, args.value), ask, say,
                                  f"remove {args.name} {args.type.upper()} {args.value} from {args.zone}?")
            if answer is None:
                return 1
            lines = [answer["said"], *(f"  {x}" for x in answer["lines"])]
    except AwsError as e:
        tell(f"aws: {e}")
        return 1
    except (ValueError, RuntimeError) as e:  # a refusal, a setting not set, a pass under way
        tell(f"refused: {e}")
        return 1
    if args.json:
        say(json.dumps(answer, indent=1, default=str))
    else:
        for line in lines:
            say(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
