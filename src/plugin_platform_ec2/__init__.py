"""Amazon EC2 for Liminal (the user, 2026-11-11: "lets roll plugins for EC2, vultr, azure and google cloud"; "Free changes
only"): the account's EC2 instances in every region it reads (their state, type, public IPv4 and IPv6 addresses, launch
time, Name tag), their security groups and rules, key pairs, EBS volumes and Elastic IPs, and its Route 53 hosted zones
and records; and the changes that cost nothing, each confirmed on the platform's page first: an instance started (asked
twice: its compute charge resumes), stopped (a forced stop, or a stop that erases an instance store, asked twice; an
Auto Scaling group's instance never) or rebooted; a Route 53 record set or removed, one record set a change, every other
record of the zone untouched; an inbound security group rule authorized or revoked (one opening SSH, RDP or every port
to the whole internet, or the last one letting SSH or RDP in to an instance, asked twice); a public key imported or a key
pair deleted. Dynamic DNS keeps hosts of the account's public zones at this network's address (an UPSERT of the host's A
record to that one address), changing only what is its own: a host holding another address, or several, is left as it
is until the user takes it over on the page. Nothing that makes a billable thing: no instance launched, resized or
ended, no volume, snapshot, image, address or zone made. EC2's API gives no prices: the page links the pricing pages,
and says that a stopped EBS-backed instance stops its compute charge while its EBS volumes and Elastic IPs still bill.

Its settings are pairs asked of the login of the app it is attached to (settings.py: EC2_ACCESS_KEY_ID,
EC2_SECRET_ACCESS_KEY, EC2_SESSION_TOKEN, EC2_REGIONS, EC2_DDNS_HOSTS, EC2_DDNS_MINUTES), never a file, never AWS_*. While
attached to the platform it reads the account every quarter of an hour and checks the Dynamic DNS hosts every few minutes
in a thread of its own; detached, nothing of it runs. Its status is what was read last (no request answers it).

    python -m plugin_platform_ec2 status | regions | servers | firewalls | keys | domains | records ZONE | ddns [--now]
        | power INSTANCE start|stop|reboot [--force] | set ZONE NAME TYPE VALUE [--ttl N] [--add] | remove ZONE NAME TYPE VALUE
        | change ID
"""
from __future__ import annotations

import json
import os
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

from liminal_libs.machines.ddns import NOW_FORM, Host, Keeper, hosts_of
from liminal_libs.machines.plugin import MachinePlugin

from . import ec2 as ec2_mod
from . import route53 as r53
from . import settings as settings_mod
from .aws import AwsClient, AwsError, route53_throttled
from .card import APIS, EBS_PRICING, EC2_NAME, IPV4_PRICING, PRICING, ROUTE53_NAME, STOPPED_COSTS
from .ec2 import Ec2Api, covers, everywhere, rule_words
from .route53 import ChangeInfo, RecordSet, Route53Api, Zone
from .settings import ACCESS_KEY, DDNS_HOSTS, IAM_CONSOLE, KEYS, NAMES, REGIONS, SECRET_KEY, Config
from .sigv4 import Signer

__version__ = "0.1.1"
REFRESH_S = 900.0  # the account read again at most this often while attached (or by Refresh)
REGIONS_S = 86400.0  # the regions enabled for the account asked again after a day
CONFIG_S = 30.0  # the settings asked of the login again after this long
RETRY_S = 900.0  # a part that failed is taken as untried after this long while detached
ZONES_MAX = 20  # the hosted zones whose records a refresh reads (the rest: `records ZONE`)
REGION_WORKERS = 4  # regions read at once (EC2's limits are each region's own)
ENDED = ("terminated", "shutting-down")  # an instance ended (shown for the hour EC2 lists it, never changed)
DDNS_TTL = 300  # an A record Dynamic DNS makes (one it finds keeps its own TTL)
PUBLIC_IPV4 = (("myip.opendns.com", "a", "208.67.222.222", "OpenDNS"),
               ("o-o.myaddr.l.google.com", "txt", "216.239.32.10", "Google"))
ACCEPT_POWER = "accept_data_loss"  # a stop erasing an instance store, a forced stop
ACCEPT_OPEN = "accept_open"  # an inbound rule opening SSH, RDP or every port to the whole internet
ACCEPT_LOCKOUT = "accept_lockout"  # a revoke taking away the last rule letting SSH (RDP to Windows) in to an instance
ACCEPT_COSTS = "accept_costs"  # a start: the instance's compute charge resumes once it runs
DIR_VAR = "LIMINAL_PLATFORM_DIR"  # the platform's own folder (its app's variable): Dynamic DNS's state under it
REFUSED_KEY = frozenset({"AuthFailure", "InvalidClientTokenId", "SignatureDoesNotMatch", "OptInRequired", "RequestExpired",
                         "ExpiredToken", "InvalidToken", "MissingAuthenticationToken", "Blocked", "PendingVerification"})
SSH, RDP = 22, 3389
HOW_TO = (f"make an access key for an IAM user (IAM console {IAM_CONSOLE} > Users > the user > Security credentials > "
          "Create access key) whose policy allows the reads and the free changes alone (the README writes it out), and "
          f"enter {ACCESS_KEY} and {SECRET_KEY}")
NOT_SET = f"not set up: {HOW_TO}"
# every action the plugin makes, as its IAM policy names them (the README's policy allows these and nothing else)
IAM_ACTIONS = (*(f"ec2:{a}" for a in (*ec2_mod.READS, *ec2_mod.WRITES)), *(f"route53:{a}" for a in (*r53.READS, *r53.WRITES)))
IAM_WORDS = ("ec2: " + ", ".join(ec2_mod.READS) + " (reads); " + ", ".join(ec2_mod.WRITES) + " (free changes) · route53: "
             + ", ".join(r53.READS) + " (reads); " + ", ".join(r53.WRITES) + " (records)")
BILLING = "a stopped EBS-backed instance stops its compute charge; its EBS volumes and Elastic IPs still bill"
START_WORDS = ("once it runs, its compute charge resumes (by the second, a minute at least each start), beside the charges "
               "that never stopped: its EBS volumes and Elastic IPs")
STOP_WORDS = "stopped, an EBS-backed instance stops its compute charge; its EBS volumes and Elastic IPs still bill"
POWER = {"start": "Start", "stop": "Stop (a graceful shutdown)", "reboot": "Reboot",
         "force-stop": "Force stop (without flushing its file systems)"}
PROTOCOL_CHOICES = (("tcp", "TCP"), ("udp", "UDP"), ("icmp", "ICMP"), ("icmpv6", "ICMPv6"), ("-1", "Every protocol"))
RECORD_TYPES = {
    "A": "an IPv4 address; replaces the set's addresses unless added",
    "AAAA": "an IPv6 address; replaces the set's addresses unless added",
    "CNAME": "a host name the name stands for (it holds nothing else; the zone's own name takes none)",
    "TXT": 'text (SPF, DKIM, DMARC, a verification), quoted for Route 53; added beside the set\'s others',
    "MX": "a preference and a mail server: 10 mail.example.com; added beside the others",
    "NS": "a subdomain's name server; added beside the others",
    "CAA": 'flags, tag and value: 0 issue "letsencrypt.org"; added beside the others',
    "SRV": "priority, weight, port and target: 10 5 5060 sip.example.com; added beside the others",
}


class Refusal(ValueError):
    """A change not made, and why: nothing was sent to AWS. `accept`: the argument that, set, makes it anyway (the
    platform's page asks it as a second, explicit confirmation)."""

    def __init__(self, message: str, accept: str | None = None):
        super().__init__(message)
        self.accept = accept


def accepted(value) -> bool:
    """A second confirmation, honoured only when it is exactly True (the page sends JSON true): "false", "yes" or 1 from a
    local program is refused like a missing one."""
    return value is True


def platform_dir() -> Path:
    """The platform's own folder: LIMINAL_PLATFORM_DIR, else the data folder's platform/ (where Namecheap keeps its own)."""
    named = (os.environ.get(DIR_VAR) or "").strip()
    if named:
        return Path(named).expanduser()
    from liminal_libs import layout

    return layout.data_dir() / "platform"


def host_names(text: str) -> set[str]:
    """The hosts of EC2_DDNS_HOSTS as names (home.example.com; @.example.com is example.com), whatever zones are known."""
    out = set()
    for part in re.split(r"[,;\s]+", str(text or "")):
        n = part.strip().rstrip(".").lower()
        if n:
            out.add(n[2:] if n.startswith("@.") else n)
    return out


def asg_words(label: str, group: str) -> str:
    """Why an Auto Scaling group's instance is not stopped here (its aws:autoscaling:groupName tag names the group)."""
    return (f"{label} belongs to the Auto Scaling group {group}: stopped, it fails the group's health check, and the group "
            "ends it (its root volume with it, when set to go) and launches another instance in its place, which bills. "
            "Nothing was sent: change the group instead, in the EC2 console's Auto Scaling groups (its desired capacity; or "
            f"put {label} in standby first, which the group's health checks leave alone).")


def when(t: float | None) -> str:
    return "–" if not t else time.strftime("%b %d %H:%M", time.localtime(t))


def iso_words(value: str) -> str:
    """An AWS time (2018-05-08T16:46:19.000Z) as "2018-05-08 16:46 UTC"."""
    v = (value or "").strip()
    return f"{v[:10]} {v[11:16]} UTC" if len(v) >= 16 and v[10] == "T" else v or "–"


def plural(n: int, word: str) -> str:
    return f"{n:,} {word}{'' if n == 1 else 's'}"


def cell(text, sub: str | None = None):
    return {"text": text, "sub": sub} if sub else text


def count_words(found) -> str:
    if not found:
        return "–"
    n, more = found
    return f"{n:,}+" if more else f"{n:,}"


@dataclass
class RegionRead:
    """What a refresh read of a region; `errors`: each part that failed, in words; `refused`: the key was refused there."""

    name: str
    instances: list = field(default_factory=list)
    types: dict = field(default_factory=dict)
    groups: list = field(default_factory=list)
    rules: list = field(default_factory=list)
    keys: list = field(default_factory=list)
    volumes: list = field(default_factory=list)
    addresses: list = field(default_factory=list)
    snapshots: tuple | None = None
    images: tuple | None = None
    attributes: dict = field(default_factory=dict)
    account: str = ""
    errors: dict = field(default_factory=dict)
    refused: bool = False
    read_at: float | None = None


class _Runtime:
    """What the plugin read and holds, shared by its copies (the registry's with_ makes them)."""

    def __init__(self):
        self.lock = threading.Lock()
        self.config: tuple[float, Config] | None = None
        self.clients: tuple[str, Ec2Api, Route53Api] | None = None
        self.regions: tuple[float, list[str]] | None = None  # DescribeRegions' answer, when asked
        self.reads: dict[str, RegionRead] = {}
        self.account = ""
        self.zones: list[Zone] | None = None
        self.zones_error = ""
        self.records: dict[str, tuple[list[RecordSet], bool] | str] = {}  # zone id -> (sets, more) or why not read
        self.changes: dict[str, ChangeInfo] = {}  # zone id -> its last change
        self.ttls: dict[str, int] = {}  # a Dynamic DNS host -> its A record's TTL as read
        self.refreshed_at: float | None = None
        self.api_ok: bool | None = None
        self.api_error = ""
        self.api_error_at: float | None = None
        self.api_print = ""
        self.keeper: Keeper | None = None
        self.ddns_print = ""
        self.ddns_at: float | None = None
        self.worker: threading.Thread | None = None
        self.stop: threading.Event | None = None
        self.wake = threading.Event()
        self.refreshing = threading.Lock()


class Ec2Plugin(MachinePlugin):
    """Amazon EC2 and Route 53: the account read in the background while attached, free changes confirmed on the page."""

    name = "ec2"
    title = "Amazon EC2"
    about = ("Your AWS account's EC2 instances, security groups, key pairs, volumes and Elastic IPs in each region, and "
             "its Route 53 zones and records; free changes only, each confirmed: power, records, inbound rules, keys; "
             "Dynamic DNS through Route 53")
    api = "2.2"
    order = 763
    ICON = "ec2"  # the EC2 mark (liminal-libs 1.49.0's icons.js)
    HOOKS = (*MachinePlugin.HOOKS, "refresh", "regions", "servers", "firewalls", "key_pairs", "domains", "records", "power",
             "authorize_ingress", "revoke_ingress", "import_key", "delete_key", "set_record", "remove_record", "change",
             "ddns_update", "ddns_take_over")
    keys = KEYS
    signup = IAM_CONSOLE
    limits = ("EC2: per account and region, a describe 100 at once and 20 a second, a change 50 and 5 (StartInstances 5 and "
              "2); Route 53: 50 requests at once and 10 a second for the account")
    apis = APIS

    def __init__(self, transport=None, public=None, clock=None, sleep=None, folder: Path | None = None):
        self._transport = transport  # (method, url, headers, body, timeout) -> (status, headers, body): a test's
        self._public = public  # () -> (address, whose): a test's stand-in for asking DNS this network's address
        self._clock = clock or time.time
        self._sleep = sleep  # how a client waits out a rate limit and spaces Route 53's requests (a test's: no wait)
        self._folder = Path(folder) if folder is not None else None  # its folder (a test's), else the platform's ec2/
        self._rt = _Runtime()

    @property
    def folder(self) -> Path:
        """Where it keeps what is its own: the platform's folder's ec2/ (Dynamic DNS's ddns.json)."""
        return self._folder if self._folder is not None else platform_dir() / self.name

    # -- the settings and the clients -------------------------------------------------------------------------------------
    def config(self, fresh: bool = False, login=None) -> Config:
        """The settings, asked of the login (`login`, else the attached app's, else the environment's); kept CONFIG_S."""
        now = time.monotonic()
        with self._rt.lock:
            kept = self._rt.config
        if kept is not None and not fresh and now - kept[0] < CONFIG_S:
            return kept[1]
        cfg = settings_mod.read(login if login is not None else self.login)
        with self._rt.lock:
            self._rt.config = (now, cfg)
        return cfg

    def settings_changed(self) -> None:
        """Its settings were just entered (the platform's Settings…): read anew at once, a failed part tried again."""
        with self._rt.lock:
            self._rt.config = None

    def _ready(self) -> Config:
        cfg = self.config()
        if not cfg.api_ready:
            raise ValueError("the API is not set up: " + ("; ".join(cfg.incomplete) or HOW_TO))
        return cfg

    def clients(self) -> tuple[Ec2Api, Route53Api]:
        """EC2's and Route 53's APIs with the settings as they are (ValueError when they are not set)."""
        return self._clients_for(self._ready())

    def _clients_for(self, cfg: Config) -> tuple[Ec2Api, Route53Api]:
        """The clients of these settings (made once for them; a pass asks no setting again)."""
        if not cfg.api_ready:
            raise ValueError("the API is not set up: " + ("; ".join(cfg.incomplete) or HOW_TO))
        with self._rt.lock:
            held = self._rt.clients
        if held is not None and held[0] == cfg.api_print:
            return held[1], held[2]
        signer = Signer(cfg.credentials, clock=self._clock)
        options = {"transport": self._transport, "secrets": cfg.secrets, "clock": self._clock}
        if self._sleep is not None:
            options["sleep"] = self._sleep
        made = (cfg.api_print, Ec2Api(AwsClient(ec2_mod.endpoint(ec2_mod.HOME_REGION), signer=signer, **options)),
                Route53Api(AwsClient(r53.BASE, signer=signer, throttled=route53_throttled, **options),
                           **({"sleep": self._sleep} if self._sleep is not None else {})))
        with self._rt.lock:
            self._rt.clients = made
        return made[1], made[2]

    def keeper(self) -> Keeper:
        """Dynamic DNS's keeper: it changes only what is its own (liminal-libs 1.49.2), kept in the folder's ddns.json."""
        with self._rt.lock:
            if self._rt.keeper is None:
                self._rt.keeper = Keeper(read=self._ddns_read, write=self._ddns_write, servers=PUBLIC_IPV4,
                                         public=self._public, clock=self._clock, state=self.folder / "ddns.json")
            return self._rt.keeper

    def _held(self) -> tuple[Ec2Api, Route53Api]:
        """The clients made last (a pass under way asks no setting again: once detached, nothing reads the process's
        environment); made now when there are none."""
        with self._rt.lock:
            held = self._rt.clients
        return (held[1], held[2]) if held is not None else self.clients()

    def present(self) -> bool:
        """Whether anything of it is set."""
        return bool(self.config().present)

    # -- reading --------------------------------------------------------------------------------------------------------------
    def region_names(self, cfg: Config, api: Ec2Api, fresh: bool = False) -> list[str]:
        """The regions read: EC2_REGIONS when set, else those DescribeRegions says are enabled (asked once a day)."""
        if cfg.regions:
            return list(cfg.regions)
        now = self._clock()
        with self._rt.lock:
            held = self._rt.regions
        if held is not None and not fresh and now - held[0] < REGIONS_S:
            return list(held[1])
        found = [r["name"] for r in api.regions() if r["name"]]
        with self._rt.lock:
            self._rt.regions = (now, found)
        return found

    def refresh(self) -> dict:
        """The account read again now: each region's instances, groups and rules, key pairs, volumes, Elastic IPs and
        counts, and Route 53's zones and their records (at most ZONES_MAX); what the status shows until the next."""
        cfg = self.config(fresh=True)
        if not cfg.api_ready:
            raise ValueError("the API is not set up: " + ("; ".join(cfg.incomplete) or HOW_TO))
        if not self._rt.refreshing.acquire(timeout=120):
            raise RuntimeError("a refresh is under way")
        try:
            return self._refresh(cfg)
        finally:
            self._rt.refreshing.release()

    def _failed(self, cfg: Config, now: float, words: str) -> None:
        with self._rt.lock:
            rt = self._rt
            rt.api_ok, rt.api_error, rt.api_error_at, rt.api_print = False, words, now, cfg.api_print

    def _refresh(self, cfg: Config, stop: threading.Event | None = None) -> dict:
        """A refresh with these settings (asked of no login again); `stop` set (the plugin detached) ends it before its
        next request, and nothing it read is kept."""
        now = self._clock()
        try:
            ec2api, r53api = self._clients_for(cfg)
            regions = self.region_names(cfg, ec2api)
        except (AwsError, ValueError) as e:
            self._failed(cfg, now, str(e))
            raise
        reads: dict[str, RegionRead] = {}
        if regions:
            with ThreadPoolExecutor(max_workers=min(REGION_WORKERS, len(regions)), thread_name_prefix="ec2-region") as pool:
                pending = [(region, pool.submit(self._read_region, ec2api, region, i == 0, stop))
                           for i, region in enumerate(regions)]
                for region, done in pending:
                    reads[region] = done.result()
        if stop is not None and stop.is_set():
            return {"regions": len(regions), "stopped": True}
        if regions and all(r.refused for r in reads.values()):
            words = next(iter(reads.values())).errors.get("instances", "every region refused the key")
            self._failed(cfg, now, words)
            raise AwsError(words)
        zones, zones_error, records = self._read_zones(r53api, stop)
        if stop is not None and stop.is_set():
            return {"regions": len(regions), "stopped": True}
        account = next((r.account for r in reads.values() if r.account), "")
        with self._rt.lock:
            rt = self._rt
            rt.reads, rt.zones, rt.zones_error, rt.records, rt.refreshed_at = reads, zones, zones_error, records, now
            rt.account = account or rt.account
            rt.api_ok, rt.api_error, rt.api_error_at, rt.api_print = True, "", None, cfg.api_print
        return {"regions": len(regions), "instances": sum(len(r.instances) for r in reads.values()),
                "zones": len(zones or []), "refreshedAt": when(now)}

    def _read_region(self, api: Ec2Api, region: str, attributes: bool = False,
                     stop: threading.Event | None = None) -> RegionRead:
        """One region read, each part on its own (a part the key may not read is said, the rest read); `stop` set ends it
        before its next request."""
        rr = RegionRead(region, read_at=self._clock())
        if stop is not None and stop.is_set():
            return rr
        try:
            rr.instances, rr.account = api.instances(region)
        except AwsError as e:
            rr.errors["instances"] = str(e)
            if e.code in REFUSED_KEY:  # the key is refused in this region (or the region is not enabled): no more asked
                rr.refused = True
                return rr
        parts = (("types", lambda: api.instance_types(region, [i["type"] for i in rr.instances]) if rr.instances else {}),
                 ("groups", lambda: api.security_groups(region)), ("rules", lambda: api.security_group_rules(region)),
                 ("keys", lambda: api.key_pairs(region)), ("volumes", lambda: api.volumes(region)),
                 ("addresses", lambda: api.addresses(region)), ("snapshots", lambda: api.snapshot_count(region)),
                 ("images", lambda: api.image_count(region)))
        for part, read in parts:
            if stop is not None and stop.is_set():
                return rr
            try:
                setattr(rr, part, read())
            except AwsError as e:
                rr.errors[part] = str(e)
        if attributes and not (stop is not None and stop.is_set()):
            try:
                rr.attributes = api.account_attributes(region)
            except AwsError as e:
                rr.errors["attributes"] = str(e)
        if not rr.account:
            rr.account = next((g["owner"] for g in rr.groups if g.get("owner")), "")
        return rr

    def _read_zones(self, api: Route53Api, stop: threading.Event | None = None) -> tuple[list[Zone] | None, str, dict]:
        try:
            zones = api.zones()
        except AwsError as e:
            return None, str(e), {}
        records: dict = {}
        ordered = sorted(zones, key=lambda z: (z.private, z.name))
        for z in ordered[:ZONES_MAX]:
            if stop is not None and stop.is_set():
                return zones, "", records
            try:
                records[z.id] = api.records(z.id)
            except AwsError as e:
                records[z.id] = str(e)
        for z in ordered[ZONES_MAX:]:
            records[z.id] = f"not read with the rest (more than {ZONES_MAX} zones): records {z.name}"
        with self._rt.lock:
            pending = [(zid, c) for zid, c in self._rt.changes.items() if c.status == "PENDING"]
        for zid, c in pending:
            try:
                got = api.get_change(c.id)
            except AwsError:
                continue
            with self._rt.lock:
                self._rt.changes[zid] = got
        return zones, "", records

    def regions(self) -> list[dict]:
        """The regions enabled for the account, asked now (DescribeRegions)."""
        api, _ = self.clients()
        found = api.regions()
        with self._rt.lock:
            self._rt.regions = (self._clock(), [r["name"] for r in found])
        return found

    def _each_region(self, read) -> dict[str, object]:
        cfg = self._ready()
        api, _ = self.clients()
        out: dict[str, object] = {}
        for region in self.region_names(cfg, api):
            try:
                out[region] = read(api, region)
            except AwsError as e:
                out[region] = {"error": str(e)}
        return out

    def servers(self) -> dict[str, object]:
        """Each region's instances, read now."""
        return self._each_region(lambda api, region: api.instances(region)[0])

    def firewalls(self) -> dict[str, object]:
        """Each region's security groups and their rules, read now."""
        return self._each_region(lambda api, region: {"groups": api.security_groups(region),
                                                      "rules": api.security_group_rules(region)})

    def key_pairs(self) -> dict[str, object]:
        """Each region's key pairs, read now."""
        return self._each_region(lambda api, region: api.key_pairs(region))

    def domains(self) -> list[dict]:
        """The account's Route 53 hosted zones, read now."""
        _, api = self.clients()
        zones = api.zones()
        with self._rt.lock:
            self._rt.zones, self._rt.zones_error = zones, ""
        return [z.__dict__.copy() for z in zones]

    def records(self, zone: str) -> dict:
        """A zone's record sets (by its ID or its name), read now."""
        z = self._zone(zone)
        _, api = self.clients()
        found = api.records(z.id)
        with self._rt.lock:
            self._rt.records[z.id] = found
        return {"zone": z.id, "name": z.name, "private": z.private, "more": found[1],
                "records": [{"name": r.name, "type": r.type, "ttl": r.ttl, "values": list(r.values), "kind": r.kind_words}
                            for r in found[0]]}

    def change(self, change: str) -> dict:
        """A Route 53 change's state, asked now (GetChange: PENDING, or INSYNC once every name server has it)."""
        _, api = self.clients()
        got = api.get_change(change)
        with self._rt.lock:
            for zid, c in list(self._rt.changes.items()):
                if c.id == got.id:
                    self._rt.changes[zid] = got
        return {"id": got.id, "status": got.status, "submitted": got.submitted}

    # -- the changes: instances -----------------------------------------------------------------------------------------------
    def _region(self, region: str) -> str:
        r = str(region or "").strip().lower()
        if not settings_mod.REGION.match(r):
            raise ValueError(f"{region!r} is not a region name (us-east-1)")
        return r

    def _instance_now(self, api: Ec2Api, region: str, instance: str) -> dict:
        """An instance read now (DescribeInstances by its ID, or found by its Name tag among those read)."""
        iid = str(instance or "").strip()
        if not iid.startswith("i-"):
            with self._rt.lock:
                rr = self._rt.reads.get(region)
                held = list(rr.instances) if rr else None
            named = [i for i in (held if held is not None else api.instances(region)[0]) if i["name"] == iid]
            if len(named) != 1:
                raise ValueError(f"no one instance named {iid!r} in {region} (give its ID: i-…)")
            iid = named[0]["id"]
        found = api.instance(region, iid)
        if found is None:
            raise ValueError(f"{iid} is not an instance in {region}")
        return found

    def power(self, region: str, instance: str, action: str, accept_data_loss: bool = False,
              accept_costs: bool = False) -> dict:
        """An instance started, stopped (gracefully; `force-stop` without flushing its file systems), or rebooted, read
        afresh first. A start (its compute charge resumes) is refused unless `accept_costs`; a stop that erases an instance
        store, or a forced one, unless `accept_data_loss` (each honoured only when exactly True); the stop of an Auto
        Scaling group's instance is refused outright (the group would end it and launch another)."""
        region = self._region(region)
        act = str(action or "").strip().lower().replace(" ", "-").replace("_", "-")
        act = {"on": "start", "off": "stop", "power-on": "start", "shutdown": "stop", "force": "force-stop"}.get(act, act)
        if act not in POWER:
            raise ValueError(f"{action!r} is none of {', '.join(POWER)}")
        api, _ = self.clients()
        inst = self._instance_now(api, region, instance)
        label = f"{inst['name']} ({inst['id']})" if inst["name"] else inst["id"]
        state = inst["state"]
        lines: list[str] = []
        if act == "start":
            if state in ("running", "pending"):
                raise Refusal(f"{label} is {state} already")
            if state != "stopped":
                raise Refusal(f"{label} is {state}: only a stopped instance is started")
            if not accepted(accept_costs):
                raise Refusal(f"Starting {label} resumes its compute charge: once it runs, its type {inst['type']} bills by "
                              "the second (a minute at least each start), beside its EBS volumes and Elastic IPs, which "
                              "never stopped billing. Nothing was sent: asked again, it is started.", accept=ACCEPT_COSTS)
            done = api.start(region, inst["id"])
            lines.append("once it runs its compute charge resumes, by the second (a minute at least), beside the charges "
                         "that never stopped (its EBS volumes and Elastic IPs); its public IPv4 address is a new one "
                         "unless it holds an Elastic IP")
        elif act == "reboot":
            if state != "running":
                raise Refusal(f"{label} is {state}: only a running instance is rebooted")
            api.reboot(region, inst["id"])
            done = {"instance": inst["id"], "was": state, "now": "rebooting"}
            lines.append("a reboot is queued: AWS reboots it hard if its system does not shut down within a few minutes")
        else:
            if inst["root"] == "instance-store":
                raise Refusal(f"{label} is instance store-backed: AWS cannot stop it (only reboot it; ending it, which this "
                              "plugin never does, loses its root volume)")
            if state in ("stopped", "terminated", "shutting-down"):
                raise Refusal(f"{label} is {state} already")
            if act == "stop" and state == "stopping":
                raise Refusal(f"{label} is stopping already (a forced stop is for one stuck in stopping)")
            if inst.get("asg"):
                raise Refusal(asg_words(label, inst["asg"]))
            try:
                kind = self._type_of(api, region, inst["type"])
            except AwsError as e:  # not known: taken as having one (asked twice), and said why
                kind = {"instanceStore": True, "storeGB": "", "unknown": str(e)}
            risks = []
            if kind.get("unknown"):
                risks.append(f"whether its type {inst['type']} has instance store volumes could not be read "
                             f"({kind['unknown'][:160]}): if it has, a stop erases their data")
            elif kind.get("instanceStore"):
                size = f" ({kind['storeGB']} GB)" if kind.get("storeGB") else ""
                risks.append(f"its type {inst['type']} has instance store volumes{size}: a stop erases their data "
                             "(its EBS volumes keep theirs)")
            if act == "force-stop":
                risks.append("a forced stop does not flush its file systems: unsaved data may be lost, and they need a "
                             "check and repair after it")
            if risks and not accepted(accept_data_loss):
                raise Refusal(f"Stopping {label} may lose data: " + "; ".join(risks) + ". Nothing was sent: asked again, "
                              "it is stopped anyway.", accept=ACCEPT_POWER)
            done = api.stop(region, inst["id"], force=(act == "force-stop"))
            lines.append(f"once stopped its compute charge ends; {self._still_billing(region, inst['id'])}")
        with self._rt.lock:
            rr = self._rt.reads.get(region)
            for i in (rr.instances if rr else []):
                if i["id"] == inst["id"] and done.get("now"):
                    i["state"] = done["now"]
        said = {"start": "started", "stop": "stopping", "force-stop": "stopping (forced)", "reboot": "rebooting"}[act]
        return {"instance": inst["id"], "name": inst["name"], "region": region, "action": act, "was": done.get("was") or state,
                "now": done.get("now") or "", "said": f"{label}: {said}", "lines": lines}

    def _type_of(self, api: Ec2Api, region: str, name: str) -> dict:
        with self._rt.lock:
            rr = self._rt.reads.get(region)
            kept = (rr.types if rr else {}).get(name)
        if kept is not None:
            return kept
        return api.instance_types(region, [name]).get(name, {})

    def _still_billing(self, region: str, instance: str) -> str:
        with self._rt.lock:
            rr = self._rt.reads.get(region)
            volumes = [v for v in (rr.volumes if rr else []) if any(a["instance"] == instance for a in v["attached"])]
            eips = [a for a in (rr.addresses if rr else []) if a["instance"] == instance]
        size = sum(int(v["size"]) for v in volumes if str(v["size"]).isdigit())
        bits = [f"its EBS volumes ({size:,} GiB) still bill per GB-month" if volumes else "its EBS volumes still bill"]
        if eips:
            bits.append(f"its Elastic IP{'s' if len(eips) > 1 else ''} ({', '.join(a['ip'] for a in eips)}) still bill by the hour")
        else:
            bits.append("an Elastic IP it holds still bills")
        return "; ".join(bits)

    # -- the changes: security groups ---------------------------------------------------------------------------------------------
    @staticmethod
    def _group(group: str) -> tuple[str, str]:
        region, _, gid = str(group or "").strip().partition("/")
        if not gid.startswith("sg-") or not settings_mod.REGION.match(region):
            raise ValueError(f"{group!r} is not a security group as region/sg-…")
        return region, gid

    def authorize_ingress(self, group: str, protocol: str, ports: str | None, source: str, description: str | None = None,
                          accept_open: bool = False) -> dict:
        """An inbound rule added to a security group (`group`: region/sg-…): `protocol` (tcp, udp, icmp, icmpv6, -1 every
        one), `ports` (22, 8000-8100), from `source` (a CIDR). One opening SSH, RDP or every port to the whole internet
        (0.0.0.0/0, ::/0) is refused unless `accept_open`."""
        region, gid = self._group(group)
        proto = str(protocol or "").strip().lower()
        proto = {"all": "-1", "every": "-1", "any": "-1"}.get(proto, proto)
        low, high = ec2_mod.ports_of(proto, ports)
        cidr = ec2_mod.source_of(source)
        desc = " ".join(str(description or "").split())
        if len(desc) > 255:
            raise ValueError("a rule's description is at most 255 characters")
        rule = {"protocol": proto, "from": low, "to": high, "cidr4": cidr if ":" not in cidr else "",
                "cidr6": cidr if ":" in cidr else "", "egress": False}
        opens = self._opens(rule)
        if everywhere(cidr) and opens and not accepted(accept_open):
            raise Refusal(f"{rule_words(rule)} opens {opens} to the whole internet: anyone may try to sign in or reach "
                          "every service. Nothing was sent: asked again, it is authorized anyway.", accept=ACCEPT_OPEN)
        api, _ = self.clients()
        made = api.authorize_ingress(region, gid, proto, low, high, cidr, desc)
        with self._rt.lock:
            rr = self._rt.reads.get(region)
            if rr is not None:
                rr.rules = [*rr.rules, *made]
        return {"group": gid, "region": region, "said": f"authorized {rule_words(rule)} in {gid}",
                "rules": [r["id"] for r in made], "lines": ["rule changes reach the group's instances within moments"]}

    @staticmethod
    def _opens(rule: dict) -> str:
        """What of note an inbound rule opens ("SSH", "RDP", "every port"), or ""."""
        proto = rule.get("protocol")
        if proto == "-1":
            return "every port"
        if proto not in ("tcp", "udp"):
            return ""
        low, high = rule.get("from"), rule.get("to")
        if (low, high) in ((0, 65535), (1, 65535)):
            return "every port"
        found = [w for w, p in (("SSH", SSH), ("RDP", RDP)) if proto == "tcp" and covers(low, high, p)]
        return " and ".join(found)

    def revoke_ingress(self, group: str, rule: str, accept_lockout: bool = False) -> dict:
        """An inbound rule (`rule`: sgr-…) revoked from a security group (`group`: region/sg-…), it and the region's rules
        read afresh first. The last rule letting SSH in to an instance of the group (RDP to a Windows one) is refused unless
        `accept_lockout` (honoured only when exactly True)."""
        region, gid = self._group(group)
        rid = str(rule or "").strip()
        if not rid.startswith("sgr-"):
            raise ValueError(f"{rule!r} is not a security group rule ID (sgr-…)")
        api, _ = self.clients()
        fresh = [r for r in api.security_group_rules(region, rid) if r["id"] == rid]
        if not fresh:
            raise Refusal(f"{gid} has no rule {rid} (read again: it may be gone)")
        r = fresh[0]
        if r["group"] != gid:
            raise Refusal(f"{rid} is a rule of {r['group']}, not of {gid}")
        if r["egress"]:
            raise Refusal(f"{rid} is an outbound rule: only inbound rules are revoked here")
        rules = api.security_group_rules(region)  # what lets each instance in now, not as last read
        lost = self._way_in_lost(region, gid, r, rules)
        if lost and not accepted(accept_lockout):
            raise Refusal(f"{rule_words(r)} is the last rule letting {' and '.join(lost)}: revoking it may leave no way in. "
                          "Nothing was sent: asked again, it is revoked anyway.", accept=ACCEPT_LOCKOUT)
        api.revoke_ingress(region, gid, rid)
        with self._rt.lock:
            rr = self._rt.reads.get(region)
            if rr is not None:
                rr.rules = [x for x in rules if x["id"] != rid]
        return {"group": gid, "region": region, "rule": rid, "said": f"revoked {rule_words(r)} from {gid}", "lines": []}

    def _way_in_lost(self, region: str, gid: str, rule: dict, rules: list[dict]) -> list[str]:
        """What `rule` is the last way in to, in words ("SSH in to web (i-…)", "RDP in to win (i-…)"): each instance of the
        group (RDP for a Windows one, SSH for the rest) that no other inbound rule of its groups (`rules`, read now) lets
        in once `rule` is gone."""
        if rule.get("protocol") not in ("tcp", "-1"):
            return []
        with self._rt.lock:
            rr = self._rt.reads.get(region)
            instances = [i for i in (rr.instances if rr else []) if i["state"] not in ENDED]
        lost: dict[str, list[str]] = {}
        for inst in instances:
            groups = {g for g, _ in inst["groups"]}
            way, port = ("RDP", RDP) if "windows" in str(inst.get("platform") or "").lower() else ("SSH", SSH)
            if gid not in groups or not covers(rule.get("from"), rule.get("to"), port):
                continue
            others = [x for x in rules if x["id"] != rule["id"] and not x["egress"] and x["group"] in groups
                      and x["protocol"] in ("tcp", "-1") and covers(x["from"], x["to"], port)]
            if not others:
                lost.setdefault(way, []).append(f"{inst['name']} ({inst['id']})" if inst["name"] else inst["id"])
        return [f"{way} in to {', '.join(names)}" for way, names in lost.items()]

    # -- the changes: key pairs -------------------------------------------------------------------------------------------------
    def import_key(self, region: str, name: str, public_key: str) -> dict:
        """An OpenSSH public key (ssh-ed25519 or ssh-rsa) imported as the key pair `name` in `region`."""
        region = self._region(region)
        n = ec2_mod.key_name(name)
        line = ec2_mod.clean_public_key(public_key)
        with self._rt.lock:
            rr = self._rt.reads.get(region)
            taken = any(k["name"] == n for k in (rr.keys if rr else []))
        if taken:
            raise Refusal(f"{region} has a key pair named {n} already")
        api, _ = self.clients()
        made = api.import_key_pair(region, n, line)
        with self._rt.lock:
            rr = self._rt.reads.get(region)
            if rr is not None:
                rr.keys = [*rr.keys, {"id": made["id"], "name": made["name"] or n, "type": line.split()[0].replace("ssh-", ""),
                                      "fingerprint": made["fingerprint"], "created": "", "region": region}]
        return {"region": region, "name": n, "id": made["id"], "fingerprint": made["fingerprint"],
                "said": f"imported {n} into {region}", "lines": ["new instances in the region may be launched with it"]}

    def delete_key(self, region: str, key: str, name: str | None = None) -> dict:
        """A key pair deleted (`key`: its ID, key-…). Instances launched with it keep the key they hold."""
        region = self._region(region)
        kid = str(key or "").strip()
        if not kid.startswith("key-"):
            raise ValueError(f"{key!r} is not a key pair ID (key-…)")
        api, _ = self.clients()
        api.delete_key_pair(region, kid)
        with self._rt.lock:
            rr = self._rt.reads.get(region)
            if rr is not None:
                rr.keys = [k for k in rr.keys if k["id"] != kid]
        return {"region": region, "id": kid, "said": f"deleted {name or kid} from {region}",
                "lines": ["instances launched with it keep the key they hold; it can no longer be chosen at a launch"]}

    # -- the changes: Route 53 ----------------------------------------------------------------------------------------------------
    def _zone(self, zone: str) -> Zone:
        """A hosted zone by its ID (Z…) or its name, among those read (read now when none are)."""
        z = str(zone or "").strip().rstrip(".")
        with self._rt.lock:
            zones = self._rt.zones
        if zones is None:
            self.domains()
            with self._rt.lock:
                zones = self._rt.zones or []
        by_id = [x for x in zones if x.id == z.rsplit("/", 1)[-1]]
        if by_id:
            return by_id[0]
        named = [x for x in zones if x.name == z.lower()]
        if len(named) == 1:
            return named[0]
        if len(named) > 1:
            raise ValueError(f"{len(named)} zones are named {z} (a public and a private one): give its ID")
        raise ValueError(f"{zone!r} is none of the account's hosted zones")

    def _keep_sets(self, zone: Zone, before: RecordSet | None, after: RecordSet | None, info: ChangeInfo) -> None:
        with self._rt.lock:
            self._rt.changes[zone.id] = info
            held = self._rt.records.get(zone.id)
            if isinstance(held, tuple):
                sets = [r for r in held[0] if not (before is not None and r.name == before.name and r.type == before.type
                                                   and r.simple)]
                if after is not None:
                    sets.append(after)
                sets.sort(key=lambda r: (list(reversed(r.name.split("."))), r.type))
                self._rt.records[zone.id] = (sets, held[1])

    def set_record(self, zone: str, name: str, rtype: str, value: str, ttl=None, how: str | None = None) -> dict:
        """A value set in a record set of `zone` (an UPSERT of that one record set; the rest of the zone untouched): an A,
        AAAA or CNAME replaces the set's values unless `how` is "add"; a TXT, MX, NS, CAA or SRV value is added beside the
        others unless `how` is "replace". The set is read afresh first."""
        z = self._zone(zone)
        _, api = self.clients()
        full = r53.fqdn(name, z.name)
        current = api.at(z.id, full)
        was, after, words = r53.plan_set(current, z, name, rtype, value, ttl=ttl, how=how)
        if was is not None and was.values == after.values and was.ttl == after.ttl:
            return {"zone": z.id, "name": full, "type": after.type, "changed": False, "said": f"{words}: nothing sent",
                    "lines": []}
        info = api.change(z.id, [("UPSERT", after)], comment=f"Liminal: {words}"[:256])
        self._keep_sets(z, was, after, info)
        return {"zone": z.id, "name": full, "type": after.type, "changed": True, "said": words,
                "before": list(was.values) if was else [], "after": list(after.values), "change": info.id,
                "status": info.status, "lines": [f"Route 53 change {info.id}: {info.status} (it reaches every Route 53 "
                                                 "name server within about a minute)"]}

    def remove_record(self, zone: str, name: str, rtype: str, value: str) -> dict:
        """A value taken out of a record set of `zone`: the set kept with its other values (an UPSERT), or deleted when it
        was its last (a DELETE naming the set exactly as it is); the rest of the zone untouched."""
        z = self._zone(zone)
        _, api = self.clients()
        full = r53.fqdn(name, z.name)
        current = api.at(z.id, full)
        was, after, words = r53.plan_remove(current, z, name, rtype, value)
        info = api.change(z.id, [("UPSERT", after)] if after is not None else [("DELETE", was)],
                          comment=f"Liminal: {words}"[:256])
        self._keep_sets(z, was, after, info)
        return {"zone": z.id, "name": full, "type": was.type, "changed": True, "said": words,
                "before": list(was.values), "after": list(after.values) if after else [], "change": info.id,
                "status": info.status, "lines": [f"Route 53 change {info.id}: {info.status}"]}

    # -- Dynamic DNS ----------------------------------------------------------------------------------------------------------------
    def _public_zone(self, name: str) -> Zone:
        with self._rt.lock:
            zones = [z for z in (self._rt.zones or []) if not z.private and z.name == name]
        if len(zones) != 1:
            raise ValueError(f"{len(zones)} public zones are named {name}" if zones else f"no public zone is named {name}")
        return zones[0]

    def _ddns_read(self, host: Host) -> list[str] | None:
        """The addresses the host's A record holds (Route 53's record set read now); one with an alias target or a routing
        policy is never Dynamic DNS's: said, and never written."""
        zone = self._public_zone(host.zone)
        _, api = self._held()
        found = api.record_set(zone.id, host.fqdn, "A")
        if found is None:
            return []
        if not found.simple:
            raise ValueError(f"its A record is {found.kind_words}: Dynamic DNS keeps a simple record alone")
        with self._rt.lock:
            if found.ttl is not None:
                self._rt.ttls[host.fqdn] = found.ttl
        return list(found.values)

    def _ddns_write(self, host: Host, ip: str) -> str:
        """The host's A record set to exactly `ip` (an UPSERT of that one record set). The keeper asks it only of a record
        that is its own (none, already this network's, the address it set last) or that the user let it take over."""
        zone = self._public_zone(host.zone)
        _, api = self._held()
        with self._rt.lock:
            ttl = self._rt.ttls.get(host.fqdn, DDNS_TTL)
        after = RecordSet(name=host.fqdn, type="A", ttl=ttl, values=(ip,))
        info = api.change(zone.id, [("UPSERT", after)], comment=f"Liminal Dynamic DNS: {host.fqdn} at {ip}")
        self._keep_sets(zone, RecordSet(name=host.fqdn, type="A"), after, info)
        return f"set ({info.status.lower()})"

    def ddns_hosts(self, cfg: Config) -> tuple[list[Host], list[str]]:
        """The Dynamic DNS hosts among the account's public zones, and the entries that are in none, in words."""
        with self._rt.lock:
            zones = self._rt.zones
        if zones is None:
            return [], []
        return hosts_of(cfg.hosts, [z.name for z in zones if not z.private])

    def _let_go(self, cfg: Config) -> None:
        """The hosts taken out of EC2_DDNS_HOSTS are no longer the keeper's (neither its own nor taken over), whatever
        zones are read: those it holds in its state file and those it kept in this run."""
        keeper = self.keeper()
        wanted = host_names(cfg.hosts)
        held: set[str] = {s.fqdn for s in keeper.states()}
        try:
            data = json.loads((self.folder / "ddns.json").read_text(encoding="utf-8"))
            held |= {str(k).lower() for k in (data.get("own") or {})} | {str(x).lower() for x in (data.get("taken") or [])}
        except (OSError, ValueError, AttributeError):
            pass
        for fqdn in sorted(held - wanted):
            keeper.let_go(fqdn)

    def _ddns_ready(self) -> tuple[Config, list[Host]]:
        cfg = self.config(fresh=True)
        if not cfg.ddns_ready:
            raise ValueError("Dynamic DNS is not set up: " + ("; ".join(cfg.incomplete) or
                                                              f"{DDNS_HOSTS}, with {ACCESS_KEY} and {SECRET_KEY}"))
        self.clients()  # the clients of the settings as they are now
        with self._rt.lock:
            known = self._rt.zones is not None
        if not known:
            self.domains()
        hosts, wrong = self.ddns_hosts(cfg)
        if not hosts:
            raise ValueError("no Dynamic DNS host is in a public zone of the account: " + ("; ".join(wrong) or DDNS_HOSTS))
        self._let_go(cfg)
        return cfg, hosts

    def ddns_update(self, force: bool = True) -> list[dict]:
        """A Dynamic DNS pass now (the page's Update DNS now, once confirmed: `force`, an UPSERT of every host that is its
        own whether it differs or not; never one holding another address: that one is taken over first). The command
        line's `ddns` without --now writes only where it differs."""
        cfg, hosts = self._ddns_ready()
        out = self.keeper().run_pass(hosts, force=force is True)
        with self._rt.lock:
            self._rt.ddns_print, self._rt.ddns_at = cfg.ddns_print, self._clock()
        return out

    def ddns_take_over(self, host: str, holds: str | None = None) -> dict:
        """A host holding another address taken over (the page's Take over…, once confirmed: `holds`, what its record
        held as the confirmation said), then a pass for it: its A record set to this network's address. Refused, nothing
        changed, when the record holds something else by now."""
        cfg, hosts = self._ddns_ready()
        name = str(host or "").strip().rstrip(".").lower()
        found = next((h for h in hosts if h.fqdn == name), None)
        if found is None:
            raise ValueError(f"{host!r} is none of the Dynamic DNS hosts set ({DDNS_HOSTS})")
        keeper = self.keeper()
        st = keeper.state(found.fqdn)
        now = ", ".join(st.holds) if st is not None else ""
        if holds is not None and now and str(holds).strip() != now:
            raise Refusal(f"{found.fqdn} holds {now} now, not {holds} as confirmed: look again before taking it over")
        keeper.take_over(found.fqdn)
        out = keeper.run_pass([found], force=False)
        with self._rt.lock:
            self._rt.ddns_print, self._rt.ddns_at = cfg.ddns_print, self._clock()
        return out[0] if out else {"host": found.fqdn, "result": "taken over: set on the next pass"}

    # -- what it learned of its APIs ----------------------------------------------------------------------------------------------
    def api_facts(self) -> dict:
        """What the plugin learned of EC2's and Route 53's APIs while it ran (the requests, the last answer), asking nothing."""
        with self._rt.lock:
            held, refreshed, regions, account = self._rt.clients, self._rt.refreshed_at, list(self._rt.reads), self._rt.account
        if held is None:
            return {}
        ec2_facts = held[1].client.facts()
        r53_facts = held[2].client.facts()
        if refreshed:
            ec2_facts["Last read"] = when(refreshed)
            r53_facts["Last read"] = when(refreshed)
        if regions:
            ec2_facts["Regions read"] = f"{len(regions)}: {', '.join(regions[:6])}" + ("…" if len(regions) > 6 else "")
        if account:
            ec2_facts["Account"] = account
        return {EC2_NAME: ec2_facts, ROUTE53_NAME: r53_facts}

    # -- attached: the reading in the background -----------------------------------------------------------------------------------
    def attach(self, app, login=None) -> dict:
        """Attached: its settings asked of the app's login from now on. Only the platform's attaching starts the reading in
        the background (the account, the Dynamic DNS hosts): the charts app run alone attaches every plugin it finds, and
        starts nothing of this one."""
        interface = super().attach(app, login)
        with self._rt.lock:
            self._rt.config = None
        if self.reading:
            self._start()
        return interface

    @property
    def reading(self) -> bool:
        """Whether it reads in the background: attached by the platform (its app's NAME), and only then."""
        return self.app is not None and getattr(self.app, "NAME", "") == "platform" and not getattr(self.app, "once", False)  # never a one-shot command's

    def detach(self) -> None:
        """Detached (the platform ending, the plugin disabled or not valid): the background reading ends."""
        self._stop()
        super().detach()
        with self._rt.lock:
            self._rt.config = None

    @property
    def working(self) -> bool:
        with self._rt.lock:
            t = self._rt.worker
        return t is not None and t.is_alive()

    def _start(self) -> None:
        with self._rt.lock:
            if self._rt.worker is not None and self._rt.worker.is_alive():
                return
            stop = threading.Event()
            t = threading.Thread(target=self._work, args=(stop,), name="ec2", daemon=True)
            self._rt.worker, self._rt.stop = t, stop
            self._rt.wake.clear()
        t.start()

    def _stop(self) -> None:
        with self._rt.lock:
            t, stop = self._rt.worker, self._rt.stop
            self._rt.worker = self._rt.stop = None
        if stop is not None:
            stop.set()
            self._rt.wake.set()
        if t is not None and t is not threading.current_thread():
            t.join(timeout=10)

    def _work(self, stop: threading.Event) -> None:
        """The background: the account read every REFRESH_S, the Dynamic DNS hosts checked every EC2_DDNS_MINUTES (after
        the zones are read); nothing done for what is not set."""
        next_api = next_ddns = 0.0
        while not stop.is_set():
            now = time.monotonic()
            cfg = None
            try:
                login = self.login
                if stop.is_set() or login is None:  # detached: no setting is read of the process's environment
                    break
                cfg = self.config(login=login)
                if cfg.api_ready and now >= next_api:
                    next_api = now + REFRESH_S
                    if self._rt.refreshing.acquire(blocking=False):  # Refresh asked meanwhile: that one is enough
                        try:
                            self._refresh(cfg, stop)
                        except Exception:  # noqa: BLE001 - kept as its outcome (api_error), shown by the status
                            pass
                        finally:
                            self._rt.refreshing.release()
                if cfg.ddns_ready and now >= next_ddns and not stop.is_set():
                    next_ddns = now + cfg.minutes * 60.0
                    hosts, _ = self.ddns_hosts(cfg)
                    if hosts:
                        try:
                            self._let_go(cfg)
                            self.keeper().run_pass(hosts, force=False, wait=0.5, stop=stop)  # ends before a write once detached
                            with self._rt.lock:
                                self._rt.ddns_print, self._rt.ddns_at = cfg.ddns_print, self._clock()
                        except Exception:  # noqa: BLE001 - a pass under way (Update DNS now), or its trouble kept by the hosts
                            pass
            except Exception:  # noqa: BLE001 - the background never ends on a trouble; the status says it
                pass
            due = [t for t, on in ((next_api, cfg is not None and cfg.api_ready),
                                   (next_ddns, cfg is not None and cfg.ddns_ready)) if on]
            wait = min([60.0, *(t - time.monotonic() for t in due)])
            self._rt.wake.wait(max(1.0, wait))
            self._rt.wake.clear()

    # -- what the platform's page shows ------------------------------------------------------------------------------------------
    def status(self) -> dict:
        """What was read last, asking nothing of AWS: the settings set (by name), the summary, valid (the API set up and
        working or untried) and why not, the facts, the tables, the actions and the forms."""
        cfg = self.config()
        if not cfg.present:
            return {"present": False, "valid": False, "why": NOT_SET, "summary": "not set up",
                    "settingsNotSet": ", ".join(NAMES), "tables": [], "actions": [], "forms": []}
        rt, now, attached = self._rt, self._clock(), self.reading  # read in the background only under the platform
        with rt.lock:
            reads, zones, zones_error = dict(rt.reads), rt.zones, rt.zones_error
            records, changes, account = dict(rt.records), dict(rt.changes), rt.account
            refreshed_at, api_ok, api_error, api_error_at = rt.refreshed_at, rt.api_ok, rt.api_error, rt.api_error_at
            api_print, ddns_print, keeper, regions_held = rt.api_print, rt.ddns_print, rt.keeper, rt.regions
        out: dict = {"present": True, "settingsSet": ", ".join(n for n in NAMES if n in cfg.present)}
        missing = [n for n in NAMES if n not in cfg.present]
        if missing:
            out["settingsNotSet"] = ", ".join(missing)
        if not cfg.api_ready:
            out.update({"valid": False, "why": "; ".join([*cfg.incomplete, *cfg.problems]) or NOT_SET,
                        "summary": "set up halfway", "tables": [], "actions": [], "forms": []})
            return out
        works = api_ok if api_print == cfg.api_print else None
        if works is False and not attached and api_error_at is not None and now - api_error_at >= RETRY_S:
            works = None  # tried again once the platform attaches it
        hosts, wrong = self.ddns_hosts(cfg) if cfg.ddns_ready else ([], [])
        states = {s.fqdn: s for s in (keeper.states() if keeper is not None else [])}
        troubles, notes = [], [*cfg.problems, *wrong]
        if works is False:
            troubles.append(f"the API: {api_error}")
        if works is True:
            failed = sorted({f"{r.name}: {w}" for r in reads.values() for w in r.errors.values()})
            notes += failed[:6] + ([f"and {len(failed) - 6} more of the regions' parts not read"] if len(failed) > 6 else [])
            if zones_error:
                notes.append(f"Route 53: {zones_error}")
        tried = [states[h.fqdn] for h in hosts if h.fqdn in states and states[h.fqdn].ok is not None]
        if cfg.ddns_ready and ddns_print == cfg.ddns_print and tried and not any(s.ok for s in tried):
            notes.append("Dynamic DNS: " + "; ".join(f"{s.fqdn}: {s.result}" for s in tried if s.ok is False))
        valid = works is not False
        out["valid"] = valid
        out["summary"] = self._summary(cfg, works, api_error, reads, zones, hosts, states, attached)
        if not valid:
            out["why"] = "; ".join(troubles) + f" ({HOW_TO})"
        elif troubles or notes:
            out["problem"] = "; ".join([*troubles, *notes])
        if account:
            out["account"] = account
        if cfg.regions:
            out["regions"] = f"{', '.join(cfg.regions)} ({REGIONS})"
        elif regions_held:
            out["regions"] = f"{len(regions_held[1])} enabled for the account"
        if refreshed_at:
            out["readAt"] = when(refreshed_at)
        first = next(iter(reads.values()), None)
        if first is not None and first.attributes:
            eips = (first.attributes.get("vpc-max-elastic-ips") or first.attributes.get("max-elastic-ips") or [""])[0]
            vpc = (first.attributes.get("default-vpc") or [""])[0]
            if eips:
                out["elasticIpQuota"] = f"{eips} a region ({first.name})"
            if vpc:
                out["defaultVpc"] = f"{vpc} ({first.name})"
        out["prices"] = f"not in EC2's API: {PRICING}"
        out["stoppedInstances"] = BILLING
        out["iamActions"] = IAM_WORDS
        if cfg.ddns_ready:
            out["ddnsEvery"] = f"every {cfg.minutes:g} min" + ("" if attached else ", once attached")
        out["tables"] = self._tables(cfg, reads, zones, zones_error, records, changes, hosts, attached)
        out["forms"] = self._forms(reads, zones, records)
        out["actions"] = [{"hook": "refresh", "args": [], "title": "Refresh",
                           "note": "every region and the Route 53 zones read again now (about ten requests a region)"}]
        if cfg.ddns_ready:
            keeper = self.keeper()
            out["forms"] += [keeper.take_form(), keeper.now_form()]
            out["actions"].append({"form": NOW_FORM, "title": "Update DNS now",
                                   "note": ("each host that is Dynamic DNS's own set to this network's address now, once "
                                            "confirmed (a host holding another address is left as it is)")})
        return out

    def _summary(self, cfg, works, api_error, reads, zones, hosts, states, attached) -> str:
        bits = []
        if works is True:
            instances = [i for r in reads.values() for i in r.instances]
            running = sum(1 for i in instances if i["state"] == "running")
            used = sum(1 for r in reads.values() if r.instances)
            bits.append(plural(len(instances), "instance") + (f" ({running} running)" if instances else "") +
                        f" in {used} of {plural(len(reads), 'region')}")
            if zones is not None:
                bits.append(plural(len(zones), "zone"))
        elif works is None:
            bits.append("reading the account…" if attached else "the account is read once attached")
        else:
            bits.append(f"the API: {api_error[:100]}")
        if cfg.ddns_ready and hosts:
            mine = [states[h.fqdn] for h in hosts if h.fqdn in states]
            if len(hosts) == 1 and mine and mine[0].ok:
                bits.append(f"{mine[0].fqdn} at {mine[0].address}")
            elif any(s.ok is not None for s in mine):
                bits.append(f"Dynamic DNS: {sum(1 for s in mine if s.ok)} of {plural(len(hosts), 'host')} current")
            else:
                bits.append("Dynamic DNS: the first check is under way" if attached else "Dynamic DNS: checked once attached")
        return " · ".join(bits)

    # -- the tables ----------------------------------------------------------------------------------------------------------------
    def _tables(self, cfg, reads, zones, zones_error, records, changes, hosts, attached) -> list[dict]:
        out = []
        if cfg.ddns_ready:
            table = self.keeper().table(hosts, cfg.minutes, attached=attached, when=when, take=True)
            if zones is None:
                table["empty"] = "The Route 53 zones are read first (Refresh)."
            out.append(table)
        if not reads:
            return out
        out.append(self._instances_table(reads))
        out += self._firewall_tables(reads)
        out.append(self._keys_table(reads))
        out.append(self._volumes_table(reads))
        out.append(self._addresses_table(reads))
        out.append(self._regions_table(reads))
        out += self._zone_tables(zones, zones_error, records, changes)
        return out

    def _instances_table(self, reads) -> dict:
        rows = []
        for r in reads.values():
            for i in sorted(r.instances, key=lambda x: (x["name"].lower() or "~", x["id"])):
                kind = r.types.get(i["type"], {})
                hw = " · ".join(x for x in (f"{kind['vcpus']} vCPU" if kind.get("vcpus") else "",
                                            f"{kind['memoryGiB']:g} GiB" if kind.get("memoryGiB") else "",
                                            (f"instance store {kind['storeGB']} GB" if kind.get("storeGB") else "instance store")
                                            if kind.get("instanceStore") else "") if x)
                state = i["state"] + (" (Spot)" if i["lifecycle"] == "spot" else "")
                rows.append([cell(i["name"] or i["id"], i["id"] if i["name"] else None),
                             cell(state, i["reason"][:80] if i["reason"] and i["state"] != "running" else None),
                             cell(i["region"], i["zone"] or None), cell(i["type"], hw or None), i["publicIp"] or "–",
                             i["ipv6"] or "–", iso_words(i["launched"]),
                             "EBS" if i["root"] == "ebs" else "instance store" if i["root"] == "instance-store" else i["root"] or "–",
                             {"form": f"power:{r.name}:{i['id']}", "title": "Power…", "label": f"Power {i['name'] or i['id']}",
                              "values": {}} if i["state"] not in ENDED else ""])
        return {"title": "Instances",
                "note": (f"prices are not in EC2's API: {PRICING} · {BILLING} ({STOPPED_COSTS}); every public IPv4 address "
                         f"bills by the hour ({IPV4_PRICING})"),
                "columns": [{"title": "Instance"}, {"title": "State"}, {"title": "Region"}, {"title": "Type"},
                            {"title": "Public IPv4"}, {"title": "IPv6"}, {"title": "Launched"}, {"title": "Root"},
                            {"title": ""}],
                "rows": rows, "empty": "No instances in the regions read."}

    def _firewall_tables(self, reads) -> list[dict]:
        attached: dict[tuple[str, str], list[str]] = {}
        for r in reads.values():
            for i in r.instances:
                for gid, _ in (i["groups"] if i["state"] not in ENDED else ()):
                    attached.setdefault((r.name, gid), []).append(i["name"] or i["id"])
        groups, rules = [], []
        names = {}
        for r in reads.values():
            for g in sorted(r.groups, key=lambda g: (g["name"].lower(), g["id"])):
                names[(r.name, g["id"])] = g["name"]
                on = attached.get((r.name, g["id"]), [])
                groups.append([cell(g["name"], g["id"]), r.name, g["vpc"] or "–", str(g["inbound"]), str(g["outbound"]),
                               cell(", ".join(on[:4]) + (f" +{len(on) - 4}" if len(on) > 4 else ""), None) if on else "–"])
            for x in sorted(r.rules, key=lambda x: (names.get((r.name, x["group"]), x["group"]).lower(), x["egress"],
                                                     str(x["from"]), x["id"])):
                row = [cell(names.get((r.name, x["group"]), x["group"]), x["group"]), r.name,
                       "outbound" if x["egress"] else "inbound", rule_words(x), x["description"] or "–"]
                row.append({"form": "revoke", "title": "Revoke", "label": f"Revoke {rule_words(x)}",
                            "values": {"group": f"{r.name}/{x['group']}", "rule": x["id"]}} if not x["egress"] else "")
                rules.append(row)
        return [
            {"title": "Security groups", "note": "the instances' firewalls, by region (a group belongs to one VPC)",
             "columns": [{"title": "Group"}, {"title": "Region"}, {"title": "VPC"}, {"title": "Inbound", "num": True},
                         {"title": "Outbound", "num": True}, {"title": "Instances"}],
             "rows": groups, "empty": "No security groups read."},
            {"title": "Security group rules",
             "note": ("inbound rules authorized and revoked here, each confirmed (one opening SSH, RDP or every port to the "
                      "whole internet, or the last letting SSH in to an instance, asked twice); outbound rules read only"),
             "columns": [{"title": "Group"}, {"title": "Region"}, {"title": "Direction"}, {"title": "Rule"},
                         {"title": "Description"}, {"title": ""}],
             "rows": rules, "empty": "No rules read.", "actions": [{"form": "authorize", "title": "Authorize an inbound rule…"}]},
        ]

    def _keys_table(self, reads) -> dict:
        rows = []
        for r in reads.values():
            for k in sorted(r.keys, key=lambda k: k["name"].lower()):
                rows.append([cell(k["name"], k["id"]), r.name, k["type"] or "–", cell(k["fingerprint"][:47] or "–"),
                             iso_words(k["created"]),
                             {"form": "delete-key", "title": "Delete", "label": f"Delete {k['name']}",
                              "values": {"region": r.name, "key": k["id"], "name": k["name"]}}])
        return {"title": "Key pairs", "note": "SSH public keys instances are launched with; imported and deleted here",
                "columns": [{"title": "Key pair"}, {"title": "Region"}, {"title": "Type"}, {"title": "Fingerprint"},
                            {"title": "Made"}, {"title": ""}],
                "rows": rows, "empty": "No key pairs.", "actions": [{"form": "import-key", "title": "Import a public key…"}]}

    def _volumes_table(self, reads) -> dict:
        rows = []
        for r in reads.values():
            for v in sorted(r.volumes, key=lambda v: v["id"]):
                on = ", ".join(f"{a['instance']} {a['device']}".strip() for a in v["attached"]) or "–"
                rows.append([cell(v["id"], v["name"] or None), cell(r.name, v["zone"] or None), v["size"] or "–",
                             cell(v["type"] or "–", f"{v['iops']} IOPS" if v["iops"] else None), v["state"] or "–", on,
                             "yes" if v["encrypted"] else "no" if v["encrypted"] is False else "–", iso_words(v["created"])])
        return {"title": "Volumes", "note": f"EBS volumes bill per GB-month until they are deleted, attached or not ({EBS_PRICING})",
                "columns": [{"title": "Volume"}, {"title": "Region"}, {"title": "GiB", "num": True}, {"title": "Type"},
                            {"title": "State"}, {"title": "Attached to"}, {"title": "Encrypted"}, {"title": "Made"}],
                "rows": rows, "empty": "No EBS volumes."}

    def _addresses_table(self, reads) -> dict:
        rows = []
        for r in reads.values():
            for a in sorted(r.addresses, key=lambda a: a["ip"]):
                rows.append([cell(a["ip"], a["name"] or None), r.name, a["allocation"] or "–",
                             a["instance"] or (a["interface"] or "nothing (it still bills)"), a["private"] or "–"])
        return {"title": "Elastic IPs", "note": f"each public IPv4 address bills by the hour, attached or not ({IPV4_PRICING})",
                "columns": [{"title": "Address"}, {"title": "Region"}, {"title": "Allocation"}, {"title": "Attached to"},
                            {"title": "Private IP"}],
                "rows": rows, "empty": "No Elastic IPs."}

    def _regions_table(self, reads) -> dict:
        rows = []
        for r in reads.values():
            running = sum(1 for i in r.instances if i["state"] == "running")
            read = ("refused: " + r.errors.get("instances", "")[:120]) if r.refused else \
                (f"{len(r.errors)} part{'s' if len(r.errors) != 1 else ''} not read" if r.errors else "read")
            rows.append([r.name, f"{running} of {len(r.instances)}" if r.instances else "0", str(len(r.volumes)),
                         str(len(r.addresses)), count_words(r.snapshots), count_words(r.images), cell(read, when(r.read_at))])
        return {"title": "Regions", "note": "each region read (snapshots and AMIs bill per GB-month of their storage)",
                "columns": [{"title": "Region"}, {"title": "Running"}, {"title": "Volumes", "num": True},
                            {"title": "Elastic IPs", "num": True}, {"title": "Snapshots", "num": True},
                            {"title": "AMIs", "num": True}, {"title": "Read"}],
                "rows": rows, "empty": "No regions read."}

    def _zone_tables(self, zones, zones_error, records, changes) -> list[dict]:
        if zones is None:
            return [{"title": "Hosted zones", "note": zones_error or "not read yet", "columns": [{"title": "Zone"}],
                     "rows": [], "empty": "Not read."}]
        out = [{"title": "Hosted zones", "note": "Route 53 zones (each bills by the month); records set and removed below",
                "columns": [{"title": "Zone"}, {"title": "Kind"}, {"title": "Records", "num": True}, {"title": "Comment"}],
                "rows": [[cell(z.name, z.id), "private" if z.private else "public",
                          "–" if z.records is None else str(z.records), z.comment or "–"]
                         for z in sorted(zones, key=lambda z: (z.private, z.name))],
                "empty": "No hosted zones."}]
        for z in sorted(zones, key=lambda z: (z.private, z.name)):
            held = records.get(z.id)
            if held is None:
                continue
            title = f"{z.name} records" + (" (private)" if z.private else "")
            if isinstance(held, str):
                out.append({"title": title, "note": held, "columns": [{"title": "Name"}], "rows": [], "empty": "Not read."})
                continue
            sets, more = held
            rows = []
            for rs in sets:
                writable = rs.simple and rs.type in r53.WRITABLE and not (rs.type == "NS" and rs.name == z.name)
                values = rs.values or ((rs.alias,) if rs.alias else ())
                for v in values or ("",):
                    short = v if len(v) <= 72 else v[:71] + "…"
                    row = [rs.name, rs.type, "–" if rs.ttl is None else str(rs.ttl), cell(short or "–"),
                           "simple" if rs.simple else rs.kind_words]
                    row.append({"form": f"remove:{z.id}", "title": "Remove", "label": f"Remove {rs.name} {rs.type} {short}",
                                "values": {"name": rs.name, "rtype": rs.type, "value": v}} if writable and v else "")
                    rows.append(row)
            change = changes.get(z.id)
            note = ("set and removed here, one record set a change (every other record untouched); alias and routing "
                    "policy records are read only") + (f" · the first {len(sets):,} record sets" if more else "")
            if change is not None:
                note += f" · last change {change.id}: {change.status}"
            out.append({"title": title, "note": note,
                        "columns": [{"title": "Name"}, {"title": "Type"}, {"title": "TTL", "num": True}, {"title": "Value"},
                                    {"title": "Routing"}, {"title": ""}],
                        "rows": rows, "empty": "No records.", "actions": [{"form": f"set:{z.id}", "title": "Set a record…"}]})
        return out

    # -- the forms ---------------------------------------------------------------------------------------------------------------
    def _forms(self, reads, zones, records) -> list[dict]:
        out = []
        for r in reads.values():
            for i in r.instances:
                if i["state"] not in ENDED:
                    out.append(self._power_form(r, i))
        groups = [(r.name, g) for r in reads.values() for g in r.groups]
        if groups:
            out.append(self._authorize_form(groups))
        if any(not x["egress"] for r in reads.values() for x in r.rules):
            out.append(self._revoke_form())
        usable = [r.name for r in reads.values() if not r.refused]
        if usable:
            out.append(self._import_form(usable))
        if any(r.keys for r in reads.values()):
            out.append(self._delete_key_form())
        for z in sorted(zones or [], key=lambda z: (z.private, z.name)):
            if isinstance(records.get(z.id), tuple):
                out += self._record_forms(z)
        return out

    @staticmethod
    def _power_form(r: RegionRead, i: dict) -> dict:
        state = i["state"]
        if state == "stopped":
            choices = ["start"]
        elif state == "running":
            choices = ["stop", "reboot", "force-stop"]
        elif state == "stopping":
            choices = ["force-stop"]
        else:
            choices = ["start", "stop", "reboot", "force-stop"]
        if i["root"] == "instance-store" or i.get("asg"):  # never stopped here: AWS cannot, or its group would replace it
            choices = [c for c in choices if c not in ("stop", "force-stop")] or ["reboot"]
        kind = r.types.get(i["type"], {})
        label = i["name"] or i["id"]
        said = []
        if "start" in choices:
            said.append(START_WORDS + " (you are asked again first)")
        if "stop" in choices or "force-stop" in choices:
            said.append(STOP_WORDS + ("; its type's instance store volumes are erased by a stop (you are asked again "
                                      "first)" if kind.get("instanceStore") else ""))
        if choices == ["reboot"]:
            said.append("a reboot keeps it running, billed as it is")
        note = f"{label} is {state} in {r.name} ({i['type']})."
        if i.get("asg"):
            note += (f" It belongs to the Auto Scaling group {i['asg']}: it is not stopped here (the group would end it and "
                     "launch another); change the group instead.")
        return {"id": f"power:{r.name}:{i['id']}", "hook": "power", "title": f"Power: {label}", "note": note,
                "fields": [{"name": "region", "label": "Region", "type": "fixed", "value": r.name},
                           {"name": "instance", "label": "Instance", "type": "fixed", "value": i["id"]},
                           {"name": "action", "label": "Action", "type": "choice", "value": choices[0],
                            "choices": [{"value": c, "title": POWER[c]} for c in choices]},
                           {"name": ACCEPT_POWER, "type": "accept", "title": "Stop anyway?", "yes": "Stop anyway",
                            "words": ("Stopping {instance} may lose data, as said: an instance store's data is erased by "
                                      "a stop, and a forced stop does not flush the file systems.")},
                           {"name": ACCEPT_COSTS, "type": "accept", "title": "Start it, and its charge?", "yes": "Start it",
                            "words": ("Started, {instance} bills again: once it runs, its compute charge resumes by the "
                                      "second (a minute at least each start), beside its EBS volumes and Elastic IPs, "
                                      "which never stopped billing.")}],
                "submit": "Review",
                "confirm": {"title": f"{label}: {{action}}?",
                            "words": "{action} " + f"{label} in {r.name}: " + "; ".join(said) + ".",
                            "yes": "Do it", "danger": state == "running"}}

    @staticmethod
    def _authorize_form(groups) -> dict:
        return {"id": "authorize", "hook": "authorize_ingress", "title": "Authorize an inbound rule",
                "note": "a rule added to a security group: every instance of the group lets that traffic in",
                "fields": [{"name": "group", "label": "Security group", "type": "choice", "value": f"{groups[0][0]}/{groups[0][1]['id']}",
                            "choices": [{"value": f"{region}/{g['id']}", "title": f"{g['name']} ({g['id']}, {region})",
                                         "note": g["about"]} for region, g in groups]},
                           {"name": "protocol", "label": "Protocol", "type": "choice", "value": "tcp",
                            "choices": [{"value": v, "title": t} for v, t in PROTOCOL_CHOICES]},
                           {"name": "ports", "label": "Ports", "type": "text", "placeholder": "22, 443, 8000-8100",
                            "note": "a port or a range; for ICMP its type, or empty for every one; none for every protocol",
                            "when": {"protocol": ["tcp", "udp", "icmp", "icmpv6"]}},
                           {"name": "source", "label": "Source", "type": "text", "required": True,
                            "placeholder": "203.0.113.7/32, 2001:db8::/64", "note": "0.0.0.0/0 and ::/0 are the whole internet"},
                           {"name": "description", "label": "Description", "type": "text", "placeholder": "optional"},
                           {"name": ACCEPT_OPEN, "type": "accept", "title": "Open it to the whole internet?",
                            "yes": "Open it anyway",
                            "words": ("The rule lets anyone on the internet reach SSH, RDP or every port of the group's "
                                      "instances from {source}.")}],
                "submit": "Review the rule",
                "confirm": {"title": "Authorize this inbound rule?",
                            "words": "{protocol} {ports} from {source} is let in to {group}.", "yes": "Authorize"}}

    @staticmethod
    def _revoke_form() -> dict:
        return {"id": "revoke", "hook": "revoke_ingress", "title": "Revoke an inbound rule",
                "fields": [{"name": "group", "label": "Security group", "type": "fixed"},
                           {"name": "rule", "label": "Rule", "type": "fixed"},
                           {"name": ACCEPT_LOCKOUT, "type": "accept", "title": "Revoke the last SSH rule?",
                            "yes": "Revoke it anyway",
                            "words": ("{rule} is the last rule letting SSH in to an instance of {group}: once revoked, "
                                      "SSH to it is refused until a rule lets it in again.")}],
                "confirm": {"title": "Revoke this rule?",
                            "words": "{rule} is revoked from {group}: the traffic it lets in is refused from then on.",
                            "yes": "Revoke", "danger": True}}

    @staticmethod
    def _import_form(regions) -> dict:
        return {"id": "import-key", "hook": "import_key", "title": "Import a public key",
                "note": "an OpenSSH public key (the .pub file's line); the private key never leaves your machine",
                "fields": [{"name": "region", "label": "Region", "type": "choice", "value": regions[0],
                            "choices": [{"value": r, "title": r} for r in regions]},
                           {"name": "name", "label": "Name", "type": "text", "required": True, "placeholder": "laptop-2026"},
                           {"name": "public_key", "label": "Public key", "type": "text", "required": True,
                            "placeholder": "ssh-ed25519 AAAA… you@machine"}],
                "submit": "Review", "confirm": {"title": "Import this key?",
                                                "words": "{name} is imported into {region} as a key pair.", "yes": "Import"}}

    @staticmethod
    def _delete_key_form() -> dict:
        return {"id": "delete-key", "hook": "delete_key", "title": "Delete a key pair",
                "fields": [{"name": "region", "label": "Region", "type": "fixed"},
                           {"name": "key", "label": "Key pair", "type": "fixed"},
                           {"name": "name", "label": "Name", "type": "fixed"}],
                "confirm": {"title": "Delete this key pair?",
                            "words": ("{name} ({key}) is deleted from {region}. Instances launched with it keep the key "
                                      "they hold; it can no longer be chosen at a launch."),
                            "yes": "Delete", "danger": True}}

    @staticmethod
    def _record_forms(z: Zone) -> list[dict]:
        zone = {"name": "zone", "label": "Zone", "type": "fixed", "value": z.id}
        kept = f"Every other record of {z.name} is untouched: one record set is written (an UPSERT)."
        return [
            {"id": f"set:{z.id}", "hook": "set_record", "title": f"Set a record in {z.name}",
             "note": ("an A, AAAA or CNAME value replaces the set's values unless added; a TXT, MX, NS, CAA or SRV value is "
                      "added beside them unless replaced"),
             "fields": [zone,
                        {"name": "name", "label": "Name", "type": "text", "required": True, "placeholder": "@, www, home",
                         "note": f"@ is {z.name} itself; home is home.{z.name}"},
                        {"name": "rtype", "label": "Type", "type": "choice", "value": "A",
                         "choices": [{"value": t, "title": t, "note": w} for t, w in RECORD_TYPES.items()]},
                        {"name": "value", "label": "Value", "type": "text", "required": True,
                         "placeholder": "an address, a host name or text, as its type says"},
                        {"name": "ttl", "label": "TTL (seconds)", "type": "number", "min": 0, "max": r53.TTL_MOST,
                         "placeholder": str(r53.TTL_DEFAULT), "empty": f"the set's own, else {r53.TTL_DEFAULT}"},
                        {"name": "how", "label": "Existing values", "type": "choice", "value": "",
                         "choices": [{"value": "", "title": "As the type says"},
                                     {"value": "replace", "title": "Replace them"},
                                     {"value": "add", "title": "Add beside them"}]}],
             "submit": "Review the change",
             "confirm": {"title": f"Set this record in {z.name}?",
                         "words": "{name} {rtype} {value} is set in " + f"{z.name}. " + kept, "yes": "Set the record"}},
            {"id": f"remove:{z.id}", "hook": "remove_record", "title": f"Remove a record from {z.name}",
             "fields": [zone, {"name": "name", "label": "Name", "type": "fixed"}, {"name": "rtype", "label": "Type", "type": "fixed"},
                        {"name": "value", "label": "Value", "type": "fixed"}],
             "confirm": {"title": f"Remove this record from {z.name}?",
                         "words": ("{name} {rtype} {value} is removed from " + f"{z.name}: the set keeps its other values, "
                                   "or is deleted when it held this one alone. " + kept),
                         "yes": "Remove the record", "danger": True}},
        ]


MACHINE = Ec2Plugin()
