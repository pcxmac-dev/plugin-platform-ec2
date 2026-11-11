"""The plugin's settings, read through the library's Login interface and nothing else (the user, 2026-11-08: "again, all
the settings are stored on a login-app db"; "but we are not integrating login-app right now"). Each setting is a pair named
by its variable (EC2_SECRET_ACCESS_KEY is the pair `ec2-secret-access-key`: apps.authorization.pair_name), asked of the
login of the app the plugin is attached to: the platform's EnvironmentLogin today, the login app's pairs once the platform
binds it. Not attached (the command line), an EnvironmentLogin of its own. No settings file: a value is never written
anywhere, never shown, and only the names of the settings set are said.

The variables carry the plugin's name on purpose (the user, 2026-11-11): it never picks up AWS_ACCESS_KEY_ID,
AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN, AWS_PROFILE or ~/.aws meant for other tools, nor do they pick up its key."""
from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass, field

from liminal_libs.apps import EnvironmentLogin, Login
from liminal_libs.machines.ddns import MINUTES, minutes_of
from liminal_libs.sources.keys import KeyVar

from .sigv4 import Credentials

ACCESS_KEY = "EC2_ACCESS_KEY_ID"
SECRET_KEY = "EC2_SECRET_ACCESS_KEY"
SESSION_TOKEN = "EC2_SESSION_TOKEN"
REGIONS = "EC2_REGIONS"
DDNS_HOSTS = "EC2_DDNS_HOSTS"
DDNS_MINUTES = "EC2_DDNS_MINUTES"
IAM_CONSOLE = "https://console.aws.amazon.com/iam/"

# what the login app's "Pairs your plugins ask for" lists, once it lists the platform's plugins
KEYS = (
    KeyVar(ACCESS_KEY, label="Access key ID",
           hint="an IAM user's access key ID (AKIA…): IAM console > Users > the user > Security credentials > Create access key"),
    KeyVar(SECRET_KEY, label="Secret access key",
           hint="the secret shown once beside the access key ID when the key is made"),
    KeyVar(SESSION_TOKEN, label="Session token",
           hint="optional: the session token of temporary credentials (an ASIA… key); they expire, and are entered anew"),
    KeyVar(REGIONS, label="Regions", secret=False,
           hint="optional: the regions read, comma separated (us-east-1, eu-west-1); every region enabled for the account unless set"),
    KeyVar(DDNS_HOSTS, label="Dynamic DNS hosts", secret=False,
           hint="hosts in your Route 53 public zones kept at this network's address, comma separated: home.example.com, "
                "@.example.com (the zone's own name)"),
    KeyVar(DDNS_MINUTES, label="Dynamic DNS minutes", secret=False,
           hint="optional: minutes between Dynamic DNS checks, 1 to 1440 (5 unless set)"),
)
NAMES = tuple(k.name for k in KEYS)

KEY_ID = re.compile(r"^[A-Z0-9]{16,128}$")
REGION = re.compile(r"^[a-z]{2}(?:-[a-z]+)+-\d{1,2}$")
OTHER_PARTITIONS = ("cn-", "us-gov-", "us-iso")  # China, GovCloud, the isolated regions: other endpoints, other keys


@dataclass(frozen=True)
class Config:
    """The settings as read (`present`: the names of those set; `problems`: what was set but could not be taken, in words
    that never hold a secret)."""

    access_key: str = field(default="", repr=False)
    secret_key: str = field(default="", repr=False)
    session_token: str = field(default="", repr=False)
    regions: tuple[str, ...] = ()  # as set (EC2_REGIONS); () every region enabled for the account
    hosts: str = ""  # EC2_DDNS_HOSTS as typed (split against the account's public zones once they are read)
    minutes: float = MINUTES[2]
    present: frozenset = frozenset()
    problems: tuple[str, ...] = ()

    @property
    def api_ready(self) -> bool:
        return bool(self.access_key and self.secret_key)

    @property
    def ddns_ready(self) -> bool:
        return self.api_ready and bool(self.hosts.strip())

    @property
    def incomplete(self) -> tuple[str, ...]:
        """What a part set halfway lacks, in words."""
        out = []
        if bool(self.access_key) != bool(self.secret_key):
            out.append(f"{SECRET_KEY if self.access_key else ACCESS_KEY} is not set (a request is signed with both)")
        if self.hosts.strip() and not self.api_ready:
            out.append(f"{DDNS_HOSTS} is set, but Dynamic DNS writes through Route 53 with {ACCESS_KEY} and {SECRET_KEY}")
        if self.session_token and not self.api_ready:
            out.append(f"{SESSION_TOKEN} is set without {ACCESS_KEY} and {SECRET_KEY}")
        return tuple(out)

    @property
    def credentials(self) -> Credentials:
        return Credentials(self.access_key, self.secret_key, self.session_token)

    @property
    def secrets(self) -> tuple[str, ...]:
        """The values scrubbed from every message the plugin gives (the key's ID too: an error may quote the scope)."""
        return tuple(v for v in (self.secret_key, self.session_token, self.access_key) if v)

    def print_of(self, *names: str) -> str:
        """A fingerprint of these settings' values (kept in memory to notice a change; never shown nor written)."""
        values = {ACCESS_KEY: self.access_key, SECRET_KEY: self.secret_key, SESSION_TOKEN: self.session_token,
                  REGIONS: ",".join(self.regions), DDNS_HOSTS: self.hosts, DDNS_MINUTES: str(self.minutes)}
        return hashlib.sha256("\0".join(f"{n}={values[n]}" for n in names).encode("utf-8")).hexdigest()

    @property
    def api_print(self) -> str:
        return self.print_of(ACCESS_KEY, SECRET_KEY, SESSION_TOKEN, REGIONS)

    @property
    def ddns_print(self) -> str:
        return self.print_of(ACCESS_KEY, SECRET_KEY, SESSION_TOKEN, DDNS_HOSTS)


def regions_of(text: str) -> tuple[tuple[str, ...], list[str]]:
    """The regions of EC2_REGIONS (comma or space separated, each once, in order) and, in words, the entries refused."""
    found: list[str] = []
    wrong: list[str] = []
    for part in re.split(r"[,;\s]+", str(text or "").strip().lower()):
        if not part:
            continue
        if part.startswith(OTHER_PARTITIONS):
            wrong.append(f"{part} is in another AWS partition (China, GovCloud or an isolated region): not read by this plugin")
        elif not REGION.match(part):
            wrong.append(f"{part!r} is not a region name (us-east-1, eu-west-2, ap-southeast-1)")
        elif part not in found:
            found.append(part)
    return tuple(found), wrong


def parse(values: Mapping[str, str]) -> Config:
    """The settings from their values by variable (those not set left out or empty)."""
    v = {n: str(values.get(n) or "").strip() for n in NAMES}
    present = frozenset(n for n in NAMES if v[n])
    problems: list[str] = []
    access = v[ACCESS_KEY]
    if access and not KEY_ID.match(access):
        problems.append(f"{ACCESS_KEY} does not look like an access key ID (capitals and digits, AKIA… or ASIA…)")
    if access.startswith("ASIA") and not v[SESSION_TOKEN]:
        problems.append(f"{ACCESS_KEY} is a temporary key (ASIA…): it is signed with {SESSION_TOKEN} too, which is not set")
    regions, wrong = regions_of(v[REGIONS])
    problems += wrong
    if v[REGIONS] and not regions:
        problems.append(f"no region of {REGIONS} can be read: every region enabled for the account is read instead")
    minutes = minutes_of(v[DDNS_MINUTES])
    if v[DDNS_MINUTES]:
        try:
            float(v[DDNS_MINUTES])
        except ValueError:
            problems.append(f"{DDNS_MINUTES} is not a number of minutes: {MINUTES[2]:g} is used")
    return Config(access_key=access, secret_key=v[SECRET_KEY], session_token=v[SESSION_TOKEN], regions=regions,
                  hosts=v[DDNS_HOSTS], minutes=minutes, present=present, problems=tuple(problems))


def read(login: Login | None = None) -> Config:
    """The settings as `login` furnishes them (the login of the app the plugin is attached to), else an EnvironmentLogin's:
    the variables set, by their pairs' names; a login that cannot be asked furnishes none, and says so."""
    asked = login if login is not None else EnvironmentLogin()
    try:
        values = asked.variables(NAMES)
    except Exception as e:  # noqa: BLE001 - a login that cannot be asked: nothing set, and why
        return Config(problems=(f"the settings could not be read from the login: {type(e).__name__}",))
    return parse(values)
