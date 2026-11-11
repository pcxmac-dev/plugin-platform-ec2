# plugin-platform-ec2

Amazon EC2 for Liminal's platform: your AWS account's instances, security groups, key pairs, EBS volumes and Elastic
IPs in each region, and its Route 53 hosted zones and records, through AWS's own APIs; the changes that cost nothing,
each confirmed on the platform's page first; and Dynamic DNS keeping hosts at this network's address through Route 53.

The user's words (2026-11-11): "lets roll plugins for EC2, vultr, azure and google cloud"; for the cloud plugins, "Free
changes only"; and "each plugin should reflect the the API its attached to, and present links that provide
documentation".

## What it shows

A machine plugin of the platform (`liminal_libs.machines.MachinePlugin`, plugin API 2.2, its icon the EC2 mark):

- **Instances** in every region read: the Name tag (and the ID), the state (and why it changed), the region and zone,
  the type with its vCPUs, memory and instance store, the public IPv4 and IPv6 addresses, the launch time, the root
  device (EBS or instance store).
- **Security groups** (their VPC, their inbound and outbound rule counts, the instances in each) and **their rules**,
  each with its ID.
- **Key pairs**, **EBS volumes** (size, type, state, what each is attached to) and **Elastic IPs**.
- **Regions**: what each holds, the account's own snapshots and AMIs counted, whether each was read.
- **Route 53**: the hosted zones (public and private) and each zone's record sets (simple, alias and routing policy
  ones alike).
- The account's ID, its default VPC and its Elastic IP quota, among the facts beside the tables.

EC2's API gives **no prices**: the page links AWS's pricing pages instead
([On-Demand](https://aws.amazon.com/ec2/pricing/on-demand/), [public IPv4](https://aws.amazon.com/vpc/pricing/),
[EBS](https://aws.amazon.com/ebs/pricing/)), and says what AWS's page on stopping says
([costs](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/how-ec2-instance-stop-start-works.html)): **stopping an
EBS-backed instance stops its compute charge, but its EBS volumes and Elastic IPs still bill.** Each start bills a
minute at least, then by the second.

While attached to the platform app it reads the account every quarter of an hour and checks the Dynamic DNS hosts every
`EC2_DDNS_MINUTES` (5), in a thread of its own. Only the platform's attaching starts that: the charts app run alone,
which attaches every plugin it finds, starts nothing of it. Detached, nothing of it runs: a pass under way ends before
its next request, and reads no setting again. Its status is what was read last: no
request is made to answer it. **Refresh** reads everything again now.

## What it changes (free changes only)

Every change is a form on the platform's page, sent only once you confirm it; the risky ones are refused first, and the
page then asks a second, explicit time.

- **Power…** on each instance: **Start**, **Stop** (a graceful shutdown), **Reboot**, and **Force stop** (for one stuck
  in stopping: its file systems are not flushed). A forced stop, and the stop of an instance whose type has instance
  store volumes (a stop erases their data), are asked twice. An instance store-backed instance cannot be stopped at all
  (AWS only reboots it), and an Auto Scaling group's instance (its `aws:autoscaling:groupName` tag) is never stopped
  here: stopped, it fails the group's health check, and the group ends it and launches another, which bills; the
  refusal names the group, to change instead. Each one is read afresh before it is changed. A start is asked twice: its
  compute charge resumes once it runs, beside the charges that never stopped (its EBS volumes and Elastic IPs).
  A second confirmation counts only when it is exactly `true` (what the page sends).
- **Authorize an inbound rule…** (a security group, a protocol, ports, a source address range, a description) and a
  **Revoke** on each inbound rule (by its rule ID, read afresh first). A rule opening SSH (22), RDP (3389) or every port
  to the whole internet (0.0.0.0/0, ::/0), and the revoke of the last rule letting SSH in to an instance (RDP to a
  Windows one), judged over the region's rules read afresh, are asked twice.
  Outbound rules are shown, not changed.
- **Import a public key…** (an OpenSSH `ssh-ed25519` or `ssh-rsa` line, the `.pub` file; a private key is refused
  outright) and a **Delete** on each key pair (instances launched with it keep the key they hold).
- **Set a record…** in each zone and a **Remove** on each value: one record set a change (an `UPSERT` of that set, or a
  `DELETE` naming it exactly as it is when its last value goes), so every other record of the zone is untouched. An A,
  AAAA or CNAME value replaces the set's values unless added; a TXT, MX, NS, CAA or SRV value is added beside the
  others unless replaced. TXT text is quoted for Route 53. The zone's SOA and its own NS records, and alias and routing
  policy records, are read only (changed in Route 53's console). The answer names the Route 53 change and its state
  (PENDING, then INSYNC, asked once at the next read).

## What it never does

Nothing that makes a billable thing: no instance is launched, resized or ended, no volume, snapshot, image, Elastic IP,
hosted zone or health check is made, no domain registered. Its clients' sources do not even name those calls (a test
checks): only its API card does, to say what the API offers. The one change that bills is a start, which resumes a
stopped instance's compute charge (the card marks StartInstances so, and the confirmation says it). It never asks **Cost Explorer**, each of whose requests
costs money. It never reads `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_PROFILE` or `~/.aws`: those are other
tools', and its own variables carry its name.

## Setting it up

1. **An IAM user for it**, with an access key: the [IAM console](https://console.aws.amazon.com/iam/) > Users > Create
   user (no console access), then the user > Security credentials > Create access key
   ([AWS's steps](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-keys-admin-managed.html)). The secret is shown
   once. Temporary credentials (a role's, IAM Identity Center's) work too, with their session token, until they expire.
2. **Its policy**, allowing exactly the reads and the free changes (attach it to the user as an inline or customer
   managed policy):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "LiminalReads",
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeRegions",
        "ec2:DescribeAccountAttributes",
        "ec2:DescribeInstances",
        "ec2:DescribeInstanceTypes",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeSecurityGroupRules",
        "ec2:DescribeKeyPairs",
        "ec2:DescribeVolumes",
        "ec2:DescribeAddresses",
        "ec2:DescribeSnapshots",
        "ec2:DescribeImages",
        "route53:ListHostedZones",
        "route53:ListResourceRecordSets",
        "route53:GetChange"
      ],
      "Resource": "*"
    },
    {
      "Sid": "LiminalFreeChanges",
      "Effect": "Allow",
      "Action": [
        "ec2:StartInstances",
        "ec2:StopInstances",
        "ec2:RebootInstances",
        "ec2:AuthorizeSecurityGroupIngress",
        "ec2:RevokeSecurityGroupIngress",
        "ec2:ImportKeyPair",
        "ec2:DeleteKeyPair",
        "route53:ChangeResourceRecordSets"
      ],
      "Resource": "*"
    }
  ]
}
```

   Without the second statement the plugin reads everything and AWS refuses its changes (said in words). The second
   statement's `Resource` can be narrowed to the instances, security groups, key pairs and hosted zones you want changed
   from here: [EC2's](https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazonec2.html) and
   [Route 53's](https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazonroute53.html) entries in
   the Service Authorization Reference list the resource types and condition keys each action takes.
3. **Enter the settings**: on the platform's page, the plugin's **Settings…** asks for each one, the key and secret
   typed hidden; no value is ever shown back. They are pairs the plugin asks of the login of the app it is attached to,
   each named by its variable (`EC2_SECRET_ACCESS_KEY` is the pair `ec2-secret-access-key`): today the platform's login
   keeps them as your user environment variables, read at once. The plugin keeps no settings file.

| Variable | | |
|---|---|---|
| `EC2_ACCESS_KEY_ID` | the API (secret) | the IAM user's access key ID (`AKIA…`, or `ASIA…` for temporary credentials) |
| `EC2_SECRET_ACCESS_KEY` | the API (secret) | its secret access key |
| `EC2_SESSION_TOKEN` | optional (secret) | the session token of temporary credentials |
| `EC2_REGIONS` | optional | the regions read, comma separated (`us-east-1, eu-west-1`); every region enabled for the account unless set (fewer regions, fewer requests) |
| `EC2_DDNS_HOSTS` | Dynamic DNS | hosts in your Route 53 public zones kept at this network's address, comma separated: `home.example.com`, `@.example.com` (the zone's own name) |
| `EC2_DDNS_MINUTES` | optional | minutes between Dynamic DNS checks, 1 to 1440 (5 unless set) |

The plugin is valid while its key is set and the last read worked, or has not been tried yet. A region the key may not
read (one not enabled for the account), or a part of one its policy does not allow, is said beside the rest.

## Dynamic DNS

This network's public IPv4 address is asked of DNS (`myip.opendns.com` of OpenDNS's resolver, else Google's
`o-o.myaddr.l.google.com`, each asked by its IPv4 address), then each host's A record of its Route 53 public zone
(ListResourceRecordSets). It changes only what is its own (liminal-libs' Keeper): a host with no A record is made, and
one already pointing at this network, or at the address it set last, is kept current with an `UPSERT` of that one
record set to exactly one address (ChangeResourceRecordSets), keeping its TTL (300 s for one it makes). A host holding
another address, or several, is left as it is and said so, with a **Take over…** on its row: taken over (confirmed,
naming what it holds and that whatever answers there stops answering), it is pointed here on the next pass. Several
addresses are never cut to one unasked. Just before a write the address is asked again, so a stale one is never written
back. What is its own is kept in the platform's folder (`LIMINAL_PLATFORM_DIR`, else the data folder's `platform/`),
`ec2/ddns.json`, so it is known after a restart; a host taken out of `EC2_DDNS_HOSTS` is let go. **Update DNS now** is
confirmed first, and sets its own hosts whatever they hold. A host in no public zone of the account is said, a private
zone is never used, and an alias or routing policy A record is never written over.

## Its API

It attaches to two AWS APIs, both signed with AWS Signature Version 4, written in the plugin (`sigv4.py`, hashlib and
hmac) and tested against AWS's published examples:

- **Amazon EC2's Query API**, Version 2016-11-15: `https://ec2.<region>.amazonaws.com/`, an `Action` and its
  parameters, answered in XML ([API Reference](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/Welcome.html),
  [actions by service](https://docs.aws.amazon.com/ec2/latest/devguide/OperationList-query.html),
  [query requests](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/Query-Requests.html),
  [throttling](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/throttling.html),
  [error codes](https://docs.aws.amazon.com/ec2/latest/devguide/errors-overview.html)). A read is a GET, tried again on
  a throttle; a change a POST, never sent twice. EC2 throttles each account and region by token buckets (a describe 100
  at once and 20 a second; paginated, as here, 100 a second; a change 50 and 5; StartInstances 5 and 2): a refresh asks
  each region about ten times.
- **Amazon Route 53's API**, Version 2013-04-01: `https://route53.amazonaws.com/2013-04-01/`, XML both ways, signed for
  us-east-1 ([API Reference](https://docs.aws.amazon.com/Route53/latest/APIReference/Welcome.html),
  [ChangeResourceRecordSets](https://docs.aws.amazon.com/Route53/latest/APIReference/API_ChangeResourceRecordSets.html),
  [quotas](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/DNSLimitations.html),
  [throttling](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/throttling-api-requests.html),
  [pricing](https://aws.amazon.com/route53/pricing/)): 50 requests at once and 10 a second for the account.

The platform's page draws both APIs' cards (`card.py`): every part of each API (EC2's sixty-odd action groups across
EC2, EBS, VPC and the services its API holds; Route 53's zones, records, changes, health checks, traffic policies and
the rest), the parts the plugin uses first, the calls it makes beside the notable ones it never makes (those that start
a charge said so), the limits, the costs, and the links: the references, guides, IAM, pricing, the
[AWS Health Dashboard](https://health.aws.amazon.com/health/status), the consoles and the CLI. What it learned of them
while it ran (the requests made, the last answer, the account, the regions) is its `api_facts()`.

## Its hooks

`present`, `status` (the summary, the facts, `tables`, `actions`, `forms`), `refresh()`, `regions()`, `servers()`,
`firewalls()`, `key_pairs()`, `domains()`, `records(zone)`, `change(id)`,
`power(region, instance, action, accept_data_loss=False)`,
`authorize_ingress(group, protocol, ports, source, description=None, accept_open=False)`,
`revoke_ingress(group, rule, accept_lockout=False)`, `import_key(region, name, public_key)`,
`delete_key(region, key, name=None)`, `set_record(zone, name, rtype, value, ttl=None, how=None)`,
`remove_record(zone, name, rtype, value)`, `ddns_update(force=True)`, `ddns_take_over(host, holds=None)`;
`power` takes `accept_costs=False` after `accept_data_loss` too. A refusal names the argument that accepts it
(`Refusal.accept`), which the page asks as its second confirmation.

## From the command line

Its settings read from the environment (as this shell has them):

```
python -m plugin_platform_ec2 status
python -m plugin_platform_ec2 regions | servers | firewalls | keys | domains
python -m plugin_platform_ec2 records example.com
python -m plugin_platform_ec2 ddns [--now]
python -m plugin_platform_ec2 power web reboot
python -m plugin_platform_ec2 power i-0123456789abcdef0 stop --region eu-west-1
python -m plugin_platform_ec2 set example.com home A 203.0.113.7 --ttl 300
python -m plugin_platform_ec2 set example.com @ TXT "google-site-verification=..."
python -m plugin_platform_ec2 remove example.com @ TXT "\"google-site-verification=...\""
python -m plugin_platform_ec2 change C2682N5HXP0BZ4
```

A change asks `yes` on the terminal first, and once more for a risky one. `--json` before the command prints the answer
as JSON.

## Install

```
pip install "plugin-platform-ec2 @ git+https://github.com/pcxmac-dev/plugin-platform-ec2@main"
```

or, for the platform's preview, a checkout in the plugin directory (`LIMINAL_PLUGINS`). Its tests use stand-ins for
AWS alone (`python -m pytest`): none reaches AWS or the network; `LIMINAL_VENDOR_PAGES=1` also checks that every address
on its cards answers.
