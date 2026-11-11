# Changelog

## 0.1.1 (2026-11-11)

What the audit of the six cloud plugins found before any key went in (session 87405e6a, "the cloud plugins and today's
platform code: an audit before 8780's restart"; eight reviewers, a skeptic per finding), fixed. Needs liminal-libs>=1.49.2.

- **Dynamic DNS changes only what is its own** (liminal-libs 1.49.2's Keeper): a host with no A record is made, one
  already pointing here or at the address it set last kept current, one holding another address, or several, left as it
  is with a **Take over…** on the page (`ddns_take_over(host, holds)`, confirmed; refused when the record changed since);
  never cut to one address unasked; the address asked again just before a write. What is its own is kept in the
  platform's folder's `ec2/ddns.json`, so it is known after a restart; a host taken out of EC2_DDNS_HOSTS is let go.
  Before, a pass replaced a host's whole A record set with this network's address, whatever it held.
- **Update DNS now is confirmed** (its form, `ddns-now`), no longer a write on one click.
- **A start is asked twice** (`accept_costs`): it resumes the instance's compute charge, which its words say.
- **An Auto Scaling group's instance is never stopped here**: stopped, the group ends it and launches another, which
  bills, while the dialog said its charge stopped. Its Power… offers no stop, and a stop asked anyway is refused, naming
  the group (its `aws:autoscaling:groupName` tag) and saying to change the group instead.
- **A second confirmation counts only when it is exactly true** (`accept_costs`, `accept_data_loss`, `accept_open`,
  `accept_lockout`): "false", "yes" or 1 from a local program is refused like a missing one.
- **The background reading starts only when the platform attaches the plugin**: the charts app run alone attaches every
  plugin it finds, and now starts nothing of this one.
- **A pass ends once the plugin is detached**: a refresh stops before its next request and keeps nothing; a Dynamic DNS
  pass writes nothing after the detach; the worker reads no setting again (never the process's environment).
- The revoke's lockout check reads the region's rules afresh (it used those of the last read), and covers RDP to a
  Windows instance as well as SSH to the rest.
- Route 53's throttling (HTTP 400 Throttling, PriorRequestNotComplete) is waited out and asked again, and its requests are
  spaced 0.15 s apart so twenty zones' reads never go out in a burst; its XML change is sent with the library's `data=`
  (no more of the plugin's own way round RestClient).
- A private key pasted into "Import a public key…" was written to the platform's log by the platform's logging of every
  change with its arguments: liminal-platform 0.20.1 logs a change without its values; the plugin still refuses the key
  without saying it back.

## 0.1.0 (2026-11-11)

The first release (the user: "lets roll plugins for EC2, vultr, azure and google cloud"; "Free changes only"; "each plugin
should reflect the the API its attached to, and present links that provide documentation"):

- the settings read through the library's Login interface alone, as pairs named by their variables
  (`ec2-secret-access-key` for EC2_SECRET_ACCESS_KEY): EC2_ACCESS_KEY_ID, EC2_SECRET_ACCESS_KEY, EC2_SESSION_TOKEN,
  EC2_REGIONS, EC2_DDNS_HOSTS, EC2_DDNS_MINUTES; no settings file, never a value shown; never AWS_* nor ~/.aws, which are
  other tools';
- AWS Signature Version 4 written in the plugin with hashlib and hmac, tested against AWS's published examples (the S3
  User Guide's four, their canonical requests, strings to sign and signatures); the requests sent through liminal-libs'
  RestClient with the signer as its `auth=` and a reader of AWS's XML errors as its `error=` (each with what to do, the
  key, secret and token scrubbed);
- EC2's Query API (2016-11-15) in each region enabled for the account (DescribeRegions, asked once a day) or those
  EC2_REGIONS names: instances (state, type with its vCPUs, memory and instance store, public IPv4 and IPv6, launch time,
  Name tag), security groups and their rules, key pairs, EBS volumes, Elastic IPs, the account's snapshots and AMIs
  counted, the default VPC and Elastic IP quota; a region or a part the key may not read said beside the rest;
- Route 53's API (2013-04-01): the hosted zones and each one's record sets (at most 20 zones a refresh);
- EC2's API gives no prices: the page links the pricing pages, and says that a stopped EBS-backed instance stops its
  compute charge while its EBS volumes and Elastic IPs still bill; Cost Explorer, whose requests cost, is never asked;
- free changes only, each a form the platform's page confirms: start, stop and reboot (a start asked once, its
  confirmation saying the compute charge resumes once it runs beside the volumes and Elastic IPs that never stopped
  billing, StartInstances marked as costing on the card; a forced stop, or the stop of an instance whose type has an
  instance store, asked twice; an instance store-backed instance never stopped); an inbound
  rule authorized or revoked by its ID (one opening SSH, RDP or every port to the whole internet, or the last one letting
  SSH in to an instance, asked twice); a public key imported, a key pair deleted; a Route 53 record set or removed, one
  record set a change (an UPSERT, or a DELETE naming the set exactly), every other record of the zone untouched, the
  change's state asked at the next read; nothing that starts a charge, its calls not even named outside the API card;
- Dynamic DNS through Route 53: this network's address asked of OpenDNS and Google's name servers, each host's A record
  read, an UPSERT where it differs (Update DNS now: every host), its TTL kept; alias records never written over;
- the API cards (plugin API 2.2): Amazon EC2's (every action group of EC2, EBS, VPC and the services its API holds; the
  calls made beside the notable rest, those that cost said so; its limits and costs) and Amazon Route 53's, with AWS's
  own pages, each address checked; `api_facts()` from the clients' own counts;
- while attached to the platform: the account read every quarter of an hour and the hosts checked every
  EC2_DDNS_MINUTES (5) in a thread of its own; detached, nothing runs;
- `python -m plugin_platform_ec2 status | regions | servers | firewalls | keys | domains | records | ddns | power | set |
  remove | change`, a change asking "yes" first (twice for a risky one).
