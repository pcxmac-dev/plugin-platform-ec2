"""What the plugin attaches to (plugin API 2.2; the user, 2026-11-11: "each plugin should reflect the the API its attached
to, and present links that provide documentation ... it should also expose more of what the API is about"): Amazon EC2's
Query API and, as an API of its own, Amazon Route 53's. Every address is one of AWS's own pages, read on the day said
(`verified`); every part of each API is listed, the parts used first on the page, and the calls the plugin makes beside
the notable ones it never makes (those that start a charge said so). This module is the only one of the plugin that names
a call that costs: the clients' sources hold none (tests/test_contract.py)."""
from __future__ import annotations

from liminal_libs.sources.apis import Api, Area, Call, Link

VERIFIED = "2026-11-11"
EC2_DOCS = "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/"
DEVGUIDE = "https://docs.aws.amazon.com/ec2/latest/devguide/"
R53_DOCS = "https://docs.aws.amazon.com/Route53/latest/APIReference/"
R53_GUIDE = "https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/"
EC2_NAME = "Amazon EC2 API"
ROUTE53_NAME = "Amazon Route 53 API"
PRICING = "https://aws.amazon.com/ec2/pricing/on-demand/"
STOPPED_COSTS = "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/how-ec2-instance-stop-start-works.html"
IPV4_PRICING = "https://aws.amazon.com/vpc/pricing/"
EBS_PRICING = "https://aws.amazon.com/ebs/pricing/"
STATUS = "https://health.aws.amazon.com/health/status"


def ec2_page(action: str) -> str:
    return f"{EC2_DOCS}API_{action}.html"


def r53_page(action: str) -> str:
    return f"{R53_DOCS}API_{action}.html"


def _area(name: str, about: str, action: str | None = None, page: str | None = None, covered: str = "") -> Area:
    return Area(name, about, page or (ec2_page(action) if action else ""), covered)


def _call(name: str, about: str, area: str, used: str = "", writes: bool = False, costs: bool = False) -> Call:
    return Call(name, about, area, used, ec2_page(name), writes, costs)


def _r53(name: str, about: str, area: str, used: str = "", writes: bool = False, costs: bool = False) -> Call:
    return Call(name, about, area, used, r53_page(name), writes, costs)


EC2_API = Api(
    name=EC2_NAME,
    maker="Amazon Web Services",
    about=("Amazon EC2's own API: one Query API (an Action and its parameters, answered in XML) for the account's virtual "
           "machines in each region and everything around them, their disks (EBS), networks (VPC), addresses, firewalls "
           "(security groups) and SSH keys. Every region has its own endpoint and its own resources; a request is signed "
           "for the region it is sent to."),
    kind="query",
    base="https://ec2.<region>.amazonaws.com/ (Action=…&Version=2016-11-15)",
    version="2016-11-15",
    auth=("AWS Signature Version 4 (AWS4-HMAC-SHA256) with an IAM access key: EC2_ACCESS_KEY_ID and EC2_SECRET_ACCESS_KEY "
          "(and EC2_SESSION_TOKEN for temporary credentials), each request signed for its region and the ec2 service; what "
          "the key may do is its IAM policy's (the README's allows the reads and the free changes alone)"),
    limits=("token buckets per account and region: a describe 100 at once, refilled 20 a second (DescribeInstances, "
            "DescribeSecurityGroups and DescribeVolumes asked unpaginated: 50 and 10; paginated, as here: 100 and 100); a "
            "change 50 and 5 (StartInstances 5 and 2; AuthorizeSecurityGroupIngress, RevokeSecurityGroupIngress 50 and 5); "
            "RequestLimitExceeded beyond. A refresh asks each region about ten times, every quarter of an hour"),
    costs=("the requests are free; what they run bills: an instance by the second while it runs (a minute at least each "
           "start), its EBS volumes and snapshots per GB-month whether it runs or not, every public IPv4 address "
           "$0.005 an hour (an Elastic IP too, attached or not). The API gives no prices (the pricing pages do). Stopping an "
           "EBS-backed instance ends its compute charge; its EBS volumes and Elastic IPs still bill. Cost Explorer, which "
           "would say the bill, charges for each request: the plugin never asks it"),
    links=(
        Link("Amazon EC2 API Reference", f"{EC2_DOCS}Welcome.html", "docs"),
        Link("Actions (A to Z)", f"{EC2_DOCS}API_Operations.html", "reference"),
        Link("Actions by service and resource", f"{DEVGUIDE}OperationList-query.html", "reference"),
        Link("Query requests (GET or POST, parameters, pagination)", f"{EC2_DOCS}Query-Requests.html", "guide"),
        Link("Using the API for Amazon EC2", f"{DEVGUIDE}ec2-low-level-api.html", "guide"),
        Link("Service endpoints", f"{DEVGUIDE}ec2-endpoints.html", "guide"),
        Link("Error codes", f"{DEVGUIDE}errors-overview.html", "reference"),
        Link("Create a signed AWS API request (Signature Version 4)",
             "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html", "auth"),
        Link("Actions, resources and condition keys for EC2 (IAM)",
             "https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazonec2.html", "auth"),
        Link("Access keys for an IAM user",
             "https://docs.aws.amazon.com/IAM/latest/UserGuide/access-keys-admin-managed.html", "auth"),
        Link("Request throttling", f"{EC2_DOCS}throttling.html", "limits"),
        Link("On-Demand pricing", PRICING, "pricing"),
        Link("EC2 pricing (every way to buy)", "https://aws.amazon.com/ec2/pricing/", "pricing"),
        Link("What a stopped instance costs", STOPPED_COSTS, "pricing"),
        Link("Public IPv4 address pricing (VPC pricing)", IPV4_PRICING, "pricing"),
        Link("EBS pricing", EBS_PRICING, "pricing"),
        Link("AWS Health Dashboard", STATUS, "status"),
        Link("EC2 console", "https://console.aws.amazon.com/ec2/", "console"),
        Link("IAM console (users and access keys)", "https://console.aws.amazon.com/iam/", "console"),
        Link("Service Quotas: EC2's limits", "https://console.aws.amazon.com/servicequotas/home/services/ec2/quotas/",
             "console"),
        Link("AWS CLI: aws ec2", "https://docs.aws.amazon.com/cli/latest/reference/ec2/", "tool"),
        Link("AWS Tools for PowerShell: EC2 cmdlets",
             "https://docs.aws.amazon.com/powershell/v5/reference/items/EC2_cmdlets.html", "tool"),
        Link("AWS SDKs and tools", "https://builder.aws.com/build/tools", "sdk"),
    ),
    areas=(
        # Amazon EC2's own actions (Actions by service: Amazon EC2 actions)
        _area("Instances", "virtual machines: describe, launch, start, stop, reboot, terminate, their attributes",
              "DescribeInstances", covered="the Instances table; start, stop (graceful, or forced when asked twice), reboot"),
        _area("Instance types", "what each type is: vCPUs, memory, instance store, network, the regions offering it",
              "DescribeInstanceTypes", covered="the instances' types: vCPUs, memory, instance store (a stop erases it)"),
        _area("Regions and Zones", "the regions enabled for the account and their Availability Zones", "DescribeRegions",
              covered="the regions read: those enabled for the account, unless EC2_REGIONS names them"),
        _area("Account attributes", "the default VPC and the account's quotas in a region", "DescribeAccountAttributes",
              covered="the default VPC and the Elastic IP quota, in the regions table"),
        _area("Security groups", "the instances' firewalls: groups and their inbound and outbound rules",
              "DescribeSecurityGroups",
              covered="the Security groups and Rules tables; inbound rules authorized and revoked (risky ones asked twice)"),
        _area("Key pairs", "SSH public keys an instance is launched with", "DescribeKeyPairs",
              covered="the Key pairs table; public keys imported and key pairs deleted"),
        _area("Elastic IP addresses", "static public IPv4 addresses (each bills by the hour)", "DescribeAddresses",
              covered="the Elastic IPs table, read only (none allocated or released)"),
        _area("AMIs", "machine images: registered, copied, shared, deprecated", "DescribeImages",
              covered="the account's own AMIs counted per region (they bill through their snapshots)"),
        _area("Tags", "labels on every resource", "DescribeTags", covered="each resource's Name tag, read with it (none written)"),
        _area("AFIs", "FPGA images for F-family instances", "DescribeFpgaImages"),
        _area("AWS Marketplace", "Marketplace product codes on instances", "ConfirmProductInstance"),
        _area("Bundle tasks", "instance store-backed Windows instances bundled into AMIs", "DescribeBundleTasks"),
        _area("BYOIP", "bringing your own IP address ranges to AWS", "DescribeByoipCidrs"),
        _area("Capacity Reservations", "capacity held in a zone, and Capacity Blocks for ML", "DescribeCapacityReservations"),
        _area("Declarative policies reports", "the account status reports of declarative policies",
              "DescribeDeclarativePoliciesReports"),
        _area("Dedicated Hosts", "physical servers for your instances alone", "DescribeHosts"),
        _area("EC2 Fleet", "fleets of On-Demand and Spot instances launched together", "DescribeFleets"),
        _area("EC2 Instance Connect Endpoints", "SSH and RDP to private instances without a public address",
              "DescribeInstanceConnectEndpoints"),
        _area("EC2 topology", "where instances sit in AWS's network", "DescribeInstanceTopology"),
        _area("Elastic Graphics", "graphics accelerators (ended January 2024)", "DescribeElasticGpus"),
        _area("Event notifications", "the tags included in scheduled-event notifications",
              "DescribeInstanceEventNotificationAttributes"),
        _area("Event windows", "when scheduled maintenance may happen", "DescribeInstanceEventWindows"),
        _area("Launch templates", "saved launch settings", "DescribeLaunchTemplates"),
        _area("Nitro TPM", "an instance's TPM endorsement key", "GetInstanceTpmEkPub"),
        _area("Placement groups", "how instances are placed on hardware", "DescribePlacementGroups"),
        _area("Reserved Instances", "discounts for a term commitment", "DescribeReservedInstances"),
        _area("Resource IDs", "the long ID formats", "DescribeIdFormat"),
        _area("Serial console", "the account's EC2 serial console access", "GetSerialConsoleAccessStatus"),
        _area("Scheduled Instances", "instances on a recurring schedule", "DescribeScheduledInstances"),
        _area("Spot Instances", "spare capacity at a discount, and its price history", "DescribeSpotInstanceRequests"),
        _area("Spot Fleet", "fleets of Spot Instances", "DescribeSpotFleetRequests"),
        # Amazon EBS's actions in the EC2 API
        _area("EBS volumes", "block storage attached to instances (bills per GB-month)", "DescribeVolumes",
              covered="the Volumes table, read only (none made, resized or deleted)"),
        _area("EBS snapshots", "point-in-time copies of volumes (bill per GB-month)", "DescribeSnapshots",
              covered="the account's own snapshots counted per region"),
        _area("EBS encryption", "encryption by default and its KMS key", "GetEbsEncryptionByDefault"),
        _area("EBS fast snapshot restores", "snapshots restored at full speed at once", "DescribeFastSnapshotRestores"),
        # Amazon VPC's actions in the EC2 API
        _area("VPCs", "the private networks instances run in", "DescribeVpcs"),
        _area("Subnets", "a VPC's address ranges in each zone", "DescribeSubnets"),
        _area("Route tables", "a VPC's routes", "DescribeRouteTables"),
        _area("Internet gateways", "a VPC's way to the internet", "DescribeInternetGateways"),
        _area("NAT gateways", "outbound internet for private subnets (bills by the hour)", "DescribeNatGateways"),
        _area("Network ACLs", "subnet-level firewalls", "DescribeNetworkAcls"),
        _area("Elastic network interfaces", "an instance's network cards and their addresses", "DescribeNetworkInterfaces"),
        _area("DHCP options", "a VPC's DHCP settings", "DescribeDhcpOptions"),
        _area("Managed prefix lists", "named sets of address ranges for rules and routes", "DescribeManagedPrefixLists"),
        _area("VPC peering", "connections between VPCs", "DescribeVpcPeeringConnections"),
        _area("VPC flow logs", "a record of the traffic in a VPC", "DescribeFlowLogs"),
        _area("Traffic Mirroring", "copies of network traffic", "DescribeTrafficMirrorSessions"),
        _area("Route servers", "BGP route servers in a VPC", "DescribeRouteServers"),
        _area("VPC Block Public Access", "the account's block on internet traffic to VPCs",
              "DescribeVpcBlockPublicAccessOptions"),
        # the other services whose actions the EC2 API holds (Actions by service)
        _area("AWS Client VPN", "managed VPN for clients", page=f"{DEVGUIDE}OperationList-query-cvpn.html"),
        _area("AWS Site-to-Site VPN", "VPN connections from your network", page=f"{DEVGUIDE}OperationList-query-s2s.html"),
        _area("AWS Transit Gateway", "a hub joining VPCs and networks", page=f"{DEVGUIDE}operation-list-tgw.html"),
        _area("AWS PrivateLink", "VPC endpoints and endpoint services", page=f"{DEVGUIDE}operation-list-privatelink.html"),
        _area("Amazon VPC IPAM", "IP address management", page=f"{DEVGUIDE}operation-list-ipam.html"),
        _area("AWS Verified Access", "access to applications without a VPN",
              page=f"{DEVGUIDE}operation-list-verified-access.html"),
        _area("AWS Network Manager", "global networks", page=f"{DEVGUIDE}OperationList-query-networkmanager.html"),
        _area("AWS Nitro Enclaves", "isolated environments on instances", page=f"{DEVGUIDE}operation-list-enclave.html"),
        _area("AWS Outposts", "AWS hardware on your premises", page=f"{DEVGUIDE}operation-list-outposts.html"),
        _area("AWS Wavelength", "zones at the edge of carriers' 5G networks",
              page=f"{DEVGUIDE}operation-list-wavelength.html"),
        _area("Recycle Bin", "deleted snapshots and AMIs kept for a while", page=f"{DEVGUIDE}operation-list-rbin.html"),
        _area("Secondary networks", "secondary networks for instances",
              page=f"{DEVGUIDE}operation-list-secondary-network.html"),
        _area("VM Import/Export", "virtual machine images brought in and out", page=f"{DEVGUIDE}OperationList-query-vmie.html"),
    ),
    calls=(
        _call("DescribeRegions", "the regions enabled for the account (AllRegions: every one)", "Regions and Zones",
              used="the regions read (those enabled), asked again once a day"),
        _call("DescribeAccountAttributes", "the default VPC and the account's quotas", "Account attributes",
              used="the default VPC and the Elastic IP quota"),
        _call("DescribeInstances", "the instances, by pages", "Instances",
              used="the Instances table: state, type, public IPv4 and IPv6, launch time, Name tag"),
        _call("DescribeInstanceTypes", "instance types' hardware", "Instance types",
              used="the instances' vCPUs, memory and instance store"),
        _call("DescribeSecurityGroups", "the security groups", "Security groups", used="the Security groups table"),
        _call("DescribeSecurityGroupRules", "the rules, each with its ID", "Security groups",
              used="the Rules table (a revoke names the rule by its ID)"),
        _call("DescribeKeyPairs", "the key pairs", "Key pairs", used="the Key pairs table"),
        _call("DescribeVolumes", "the EBS volumes, by pages", "EBS volumes", used="the Volumes table"),
        _call("DescribeAddresses", "the Elastic IP addresses", "Elastic IP addresses", used="the Elastic IPs table"),
        _call("DescribeSnapshots", "EBS snapshots (Owner self: the account's own)", "EBS snapshots",
              used="the snapshots counted per region"),
        _call("DescribeImages", "AMIs (Owner self: the account's own)", "AMIs", used="the AMIs counted per region"),
        _call("StartInstances", "starts stopped EBS-backed instances (each start bills a minute at least)", "Instances",
              used="Power… > Start", writes=True),
        _call("StopInstances", "stops EBS-backed instances (Force: without the file systems flushed)", "Instances",
              used="Power… > Stop; Force stop only when asked twice", writes=True),
        _call("RebootInstances", "reboots instances (a hard reboot if the OS does not shut down)", "Instances",
              used="Power… > Reboot", writes=True),
        _call("AuthorizeSecurityGroupIngress", "adds inbound rules", "Security groups",
              used="Authorize an inbound rule… (to the whole internet on SSH, RDP or every port: asked twice)", writes=True),
        _call("RevokeSecurityGroupIngress", "removes inbound rules (by rule ID or by their values)", "Security groups",
              used="a rule's Revoke (the one letting SSH in to an instance: asked twice)", writes=True),
        _call("ImportKeyPair", "imports an RSA or ED25519 public key", "Key pairs", used="Import a public key…",
              writes=True),
        _call("DeleteKeyPair", "deletes a key pair (instances keep the key they hold)", "Key pairs",
              used="a key pair's Delete", writes=True),
        _call("RunInstances", "launches instances: starts a charge", "Instances", writes=True, costs=True),
        _call("TerminateInstances", "ends instances for good (their volumes set to go with them too)", "Instances",
              writes=True),
        _call("ModifyInstanceAttribute", "changes an instance's attributes, its type too (a resize)", "Instances",
              writes=True, costs=True),
        _call("DescribeInstanceStatus", "status checks and scheduled events", "Instances"),
        _call("GetConsoleOutput", "an instance's console output", "Instances"),
        _call("DescribeAvailabilityZones", "the zones of a region", "Regions and Zones"),
        _call("DescribeSpotPriceHistory", "Spot prices: the only prices the API gives", "Spot Instances"),
        _call("RequestSpotInstances", "asks for Spot Instances: starts a charge", "Spot Instances", writes=True, costs=True),
        _call("CreateKeyPair", "AWS makes a key pair and hands back its private key (here a key is imported instead)",
              "Key pairs", writes=True),
        _call("AuthorizeSecurityGroupEgress", "adds outbound rules", "Security groups", writes=True),
        _call("RevokeSecurityGroupEgress", "removes outbound rules", "Security groups", writes=True),
        _call("ModifySecurityGroupRules", "changes rules in place", "Security groups", writes=True),
        _call("CreateSecurityGroup", "makes a security group", "Security groups", writes=True),
        _call("AllocateAddress", "allocates an Elastic IP: bills by the hour", "Elastic IP addresses", writes=True,
              costs=True),
        _call("ReleaseAddress", "releases an Elastic IP", "Elastic IP addresses", writes=True),
        _call("AssociateAddress", "attaches an Elastic IP to an instance", "Elastic IP addresses", writes=True),
        _call("CreateVolume", "makes an EBS volume: bills per GB-month", "EBS volumes", writes=True, costs=True),
        _call("ModifyVolume", "resizes or retypes a volume", "EBS volumes", writes=True, costs=True),
        _call("DeleteVolume", "deletes a volume and its data", "EBS volumes", writes=True),
        _call("CreateSnapshot", "snapshots a volume: bills per GB-month", "EBS snapshots", writes=True, costs=True),
        _call("CreateImage", "makes an AMI of an instance (and snapshots of its volumes)", "AMIs", writes=True, costs=True),
        _call("CreateTags", "tags resources", "Tags", writes=True),
        _call("DescribeVpcs", "the VPCs", "VPCs"),
        _call("DescribeSubnets", "the subnets", "Subnets"),
        _call("CreateNatGateway", "makes a NAT gateway: bills by the hour", "NAT gateways", writes=True, costs=True),
        _call("PurchaseReservedInstancesOffering", "buys Reserved Instances", "Reserved Instances", writes=True, costs=True),
    ),
    verified=VERIFIED,
)

ROUTE53_API = Api(
    name=ROUTE53_NAME,
    maker="Amazon Web Services",
    about=("Route 53's API: AWS's DNS service, global rather than regional. The account's hosted zones (public ones for the "
           "internet, private ones for its VPCs) hold record sets, changed in batches applied all at once; it also checks "
           "health, routes by policy and logs queries. Its domain registration and its resolvers are APIs of their own."),
    kind="xml",
    base="https://route53.amazonaws.com/2013-04-01/",
    version="2013-04-01",
    auth=("AWS Signature Version 4 with the same IAM access key, signed for us-east-1 and the route53 service; the IAM "
          "policy allows route53:ListHostedZones, ListResourceRecordSets, GetChange and ChangeResourceRecordSets"),
    limits=("per account: 50 requests at once, refilled 10 a second, across every action (and each action's own bucket); "
            "record changes 1,500 at once and 100 a second (an UPSERT counts 2); Throttling (HTTP 400) beyond; a zone takes "
            "one change at a time (PriorRequestNotComplete); a change batch at most 1,000 records and 32,000 characters"),
    costs=("$0.50 a hosted zone a month for the first 25 ($0.10 after), $0.40 per million standard queries; the pricing "
           "page names no charge for the API's requests. Making a hosted zone or a health check starts a charge (never "
           "done here); records cost nothing to set"),
    links=(
        Link("Amazon Route 53 API Reference", f"{R53_DOCS}Welcome.html", "docs"),
        Link("Actions", f"{R53_DOCS}API_Operations_Amazon_Route_53.html", "reference"),
        Link("Amazon Route 53 Developer Guide", R53_GUIDE, "guide"),
        Link("ChangeResourceRecordSets (UPSERT, DELETE, a batch all or none)", r53_page("ChangeResourceRecordSets"),
             "reference"),
        Link("Actions, resources and condition keys for Route 53 (IAM)",
             "https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazonroute53.html", "auth"),
        Link("Quotas", f"{R53_GUIDE}DNSLimitations.html", "limits"),
        Link("Throttling for Route 53 API requests", f"{R53_GUIDE}throttling-api-requests.html", "limits"),
        Link("Route 53 pricing", "https://aws.amazon.com/route53/pricing/", "pricing"),
        Link("AWS Health Dashboard", STATUS, "status"),
        Link("Service Quotas: Route 53's limits",
             "https://console.aws.amazon.com/servicequotas/home?region=us-east-1#!/services/route53/quotas", "console"),
        Link("AWS CLI: change-resource-record-sets",
             "https://docs.aws.amazon.com/goto/cli2/route53-2013-04-01/ChangeResourceRecordSets", "tool"),
    ),
    areas=(
        Area("Hosted zones", "public and private zones, each with its four name servers", r53_page("ListHostedZones"),
             "the Hosted zones table (none made or deleted: a zone bills by the month)"),
        Area("Records", "a zone's record sets: simple, alias, weighted, latency, failover, geolocation, multivalue",
             r53_page("ListResourceRecordSets"),
             "each zone's records; simple ones set and removed one record set a change (the rest untouched); Dynamic DNS"),
        Area("Changes", "whether a change batch has reached every name server", r53_page("GetChange"),
             "a change's state after a write (PENDING, then INSYNC), asked once at the next read"),
        Area("Health checks", "endpoints watched from around the world (each bills by the month)", r53_page("ListHealthChecks")),
        Area("Traffic policies", "routing configurations applied as policy records", r53_page("ListTrafficPolicies")),
        Area("Reusable delegation sets", "one set of name servers for many zones", r53_page("ListReusableDelegationSets")),
        Area("DNSSEC", "zone signing and its key-signing keys", r53_page("GetDNSSEC")),
        Area("Query logging", "the DNS queries a zone answers, logged", r53_page("ListQueryLoggingConfigs")),
        Area("VPC associations", "the VPCs a private zone answers in", r53_page("ListHostedZonesByVPC")),
        Area("CIDR collections", "address ranges for IP-based routing", r53_page("ListCidrCollections")),
        Area("Tags", "labels on zones and health checks", r53_page("ListTagsForResource")),
        Area("Limits", "the account's and a zone's quotas", r53_page("GetAccountLimit")),
        Area("Geolocations", "the places geolocation routing knows", r53_page("ListGeoLocations")),
        Area("DNS answer test", "what Route 53 would answer for a name", r53_page("TestDNSAnswer")),
        Area("Domain registration", "Route 53 Domains: registering and renewing domains (an API of its own, billed by TLD)",
             f"{R53_DOCS}Welcome.html#Welcome_Amazon_Route_53_Domains"),
        Area("Resolver", "DNS for VPCs and forwarding to and from your network (an API of its own, per region)",
             f"{R53_DOCS}Welcome.html#Welcome_Amazon_Route_53_Resolver"),
        Area("Profiles", "DNS settings shared with VPCs and accounts (an API of its own)",
             f"{R53_DOCS}Welcome.html#Welcome_Route_53_Profiles"),
        Area("Global Resolver", "a public resolver for your domains (an API of its own)",
             f"{R53_DOCS}Welcome.html#Welcome_Amazon_Route_53_Global_Resolver"),
    ),
    calls=(
        _r53("ListHostedZones", "the account's zones, 100 a page", "Hosted zones", used="the Hosted zones table"),
        _r53("ListResourceRecordSets", "a zone's record sets, 300 a page, from a name and type", "Records",
             used="each zone's records; a record set read afresh before each change; Dynamic DNS's A record"),
        _r53("ChangeResourceRecordSets", "a batch of CREATE, DELETE and UPSERT changes, applied all at once", "Records",
             used="Set a record… and a record's Remove (an UPSERT or a DELETE of one record set); Dynamic DNS's UPSERT",
             writes=True),
        _r53("GetChange", "a change's state: PENDING or INSYNC", "Changes", used="a change's state after a write"),
        _r53("GetHostedZone", "a zone, its name servers and VPCs", "Hosted zones"),
        _r53("ListHostedZonesByName", "the zones in name order", "Hosted zones"),
        _r53("CreateHostedZone", "makes a zone: bills by the month", "Hosted zones", writes=True, costs=True),
        _r53("DeleteHostedZone", "deletes an empty zone", "Hosted zones", writes=True),
        _r53("ListHealthChecks", "the health checks", "Health checks"),
        _r53("CreateHealthCheck", "makes a health check: bills by the month", "Health checks", writes=True, costs=True),
        _r53("CreateTrafficPolicyInstance", "applies a traffic policy as a policy record: bills by the month",
             "Traffic policies", writes=True, costs=True),
        _r53("EnableHostedZoneDNSSEC", "signs a zone with DNSSEC", "DNSSEC", writes=True),
        _r53("GetAccountLimit", "an account quota and what is used of it", "Limits"),
        _r53("TestDNSAnswer", "the answer Route 53 would give a query", "DNS answer test"),
        _r53("ChangeTagsForResource", "tags a zone or a health check", "Tags", writes=True),
    ),
    verified=VERIFIED,
)

APIS = (EC2_API, ROUTE53_API)
