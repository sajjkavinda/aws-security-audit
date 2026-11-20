# Network security and compute resources checks
import json
import re
import shlex

from botocore.exceptions import ClientError

from common import as_list, finding

SENSITIVE_PORTS = {
    22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL", 1433: "MSSQL", 1521: "Oracle",
    27017: "MongoDB", 6379: "Redis", 9200: "Elasticsearch", 5601: "Kibana", 11211: "Memcached",
    2049: "NFS", 10250: "Kubelet", 2375: "Docker API", 9092: "Kafka", 2379: "etcd",
}
WEB_PORTS = {80, 443}
MODERN_TLS_PREFIXES = ("ELBSecurityPolicy-TLS13", "ELBSecurityPolicy-TLS-1-2", "ELBSecurityPolicy-FS-1-2",
                       "ELBSecurityPolicy-FS-1-3")
SECRET_NAME = re.compile(r"(PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|CREDENTIAL|ACCESS_?KEY)", re.I)
MAX_LIST = 50


def _code(e):
    return e.response.get("Error", {}).get("Code", "")


def _world(perm):
    return (any(r.get("CidrIp") == "0.0.0.0/0" for r in perm.get("IpRanges", [])) or
            any(r.get("CidrIpv6") == "::/0" for r in perm.get("Ipv6Ranges", [])))


# EC2 / VPC
def scan_ec2_vpc(ctx, region):
    ec2 = ctx.client("ec2", region)
    attached = set()
    for eni in ec2.get_paginator("describe_network_interfaces").paginate().search("NetworkInterfaces[]"):
        attached.update(g["GroupId"] for g in eni.get("Groups", []))

    for sg in ec2.get_paginator("describe_security_groups").paginate().search("SecurityGroups[]"):
        gid, gname = sg["GroupId"], sg.get("GroupName", "")
        in_use = gid in attached
        if gname == "default" and (sg.get("IpPermissions") or sg.get("IpPermissionsEgress")):
            if sg.get("IpPermissions"):
                ctx.add(finding(
                    service="VPC", check_id="SG-DEFAULT-HAS-RULES", severity="LOW", resource=gid, region=region,
                    title=f"Default security group {gid} has inbound rules",
                    description="Default SGs should have no rules; they are easy to attach by accident.",
                    remediation="Remove all rules from default SGs and use purpose-built groups.",
                    fix_commands=[f"aws ec2 describe-security-groups --group-ids {gid} --region {region}"]))
        for perm in sg.get("IpPermissions", []):
            if not _world(perm):
                continue
            proto = perm.get("IpProtocol")
            lo, hi = perm.get("FromPort"), perm.get("ToPort")
            if proto == "-1":
                sev, what = "CRITICAL", "ALL traffic on ALL ports"
            elif lo is None:
                continue
            else:
                hits = sorted(p for p in SENSITIVE_PORTS if lo <= p <= hi)
                if hits:
                    what = ", ".join(f"{p}/{SENSITIVE_PORTS[p]}" for p in hits[:6])
                    sev = "CRITICAL" if (hi - lo) > 1000 or hits[0] in (22, 3389) else "HIGH"
                elif (lo, hi) in ((80, 80), (443, 443)) or (lo in WEB_PORTS and hi in WEB_PORTS):
                    continue  # public web ports are expected on ALB SGs
                else:
                    sev, what = "MEDIUM", f"ports {lo}-{hi}/{proto}"
            if not in_use and sev != "CRITICAL":
                sev = "LOW"
            rev = {"IpProtocol": proto, "IpRanges": [r for r in perm.get("IpRanges", []) if r["CidrIp"] == "0.0.0.0/0"],
                   "Ipv6Ranges": [r for r in perm.get("Ipv6Ranges", []) if r["CidrIpv6"] == "::/0"]}
            if proto != "-1":
                rev.update(FromPort=lo, ToPort=hi)
            rev = {k: v for k, v in rev.items() if v != []}
            cmds = [f"aws ec2 revoke-security-group-ingress --region {region} --group-id {gid} "
                    f"--ip-permissions {shlex.quote(json.dumps(rev))}"]
            if lo in (22, 3389) or proto == "-1":
                cmds.append("# Prefer AWS Systems Manager Session Manager (no inbound port needed), or restrict to a VPN/office CIDR:")
            if proto != "-1":
                cmds.append(f"aws ec2 authorize-security-group-ingress --region {region} --group-id {gid} "
                            f"--protocol {proto} --port {lo if lo == hi else f'{lo}-{hi}'} --cidr <TRUSTED_CIDR>/32")
            ctx.add(finding(
                service="VPC", check_id="SG-OPEN-INGRESS", severity=sev, resource=f"{gid} ({gname})", region=region,
                title=f"Security group {gid} allows the internet to reach {what}",
                description=f"0.0.0.0/0 or ::/0 is allowed on {what}. Attached to a network interface: {'yes' if in_use else 'no'}.",
                remediation="Replace the world-open rule with specific CIDRs, a source security group (e.g. the ALB's SG), "
                            "or remove the need (SSM Session Manager for SSH/RDP, private endpoints for databases).",
                fix_commands=cmds))

    # EC2 instances
    imds, public_ip = [], []
    for res in ec2.get_paginator("describe_instances").paginate(
            Filters=[{"Name": "instance-state-name", "Values": ["running"]}]):
        for r in res["Reservations"]:
            for i in r["Instances"]:
                if i.get("MetadataOptions", {}).get("HttpTokens") != "required":
                    imds.append(i["InstanceId"])
                if i.get("PublicIpAddress"):
                    public_ip.append(i["InstanceId"])
    if imds:
        ctx.add(finding(
            service="EC2", check_id="EC2-IMDSV2", severity="MEDIUM", resource=f"{len(imds)} instance(s)", region=region,
            title=f"{len(imds)} running instance(s) allow IMDSv1",
            description="IMDSv1 enables credential theft through SSRF. Instances: " + ", ".join(imds[:MAX_LIST]),
            remediation="Require IMDSv2. For EKS worker nodes/containers keep hop limit 2; test old SDKs/agents first.",
            fix_commands=[f"for i in {' '.join(imds[:MAX_LIST])}; do aws ec2 modify-instance-metadata-options "
                          f"--region {region} --instance-id $i --http-tokens required --http-endpoint enabled; done",
                          "# Make it the default for new instances:",
                          f"aws ec2 modify-instance-metadata-defaults --region {region} --http-tokens required"],
            details={"instances": imds[:MAX_LIST]}))
    if public_ip:
        ctx.add(finding(
            service="EC2", check_id="EC2-PUBLIC-IP", severity="LOW", resource=f"{len(public_ip)} instance(s)", region=region,
            title=f"{len(public_ip)} running instance(s) have public IPs",
            description="App instances behind an ALB normally need no public IP. Instances: " + ", ".join(public_ip[:MAX_LIST]),
            remediation="Move them to private subnets (NAT/VPC endpoints for outbound) and expose only the ALB.",
            fix_commands=[], details={"instances": public_ip[:MAX_LIST]}))


    # EBS
    unenc = [v["VolumeId"] for v in ec2.get_paginator("describe_volumes").paginate(
        Filters=[{"Name": "encrypted", "Values": ["false"]}]).search("Volumes[]")]
    if unenc:
        ctx.add(finding(
            service="EC2", check_id="EBS-UNENCRYPTED", severity="MEDIUM", resource=f"{len(unenc)} volume(s)", region=region,
            title=f"{len(unenc)} unencrypted EBS volume(s)",
            description="Volumes: " + ", ".join(unenc[:MAX_LIST]),
            remediation="Snapshot, copy the snapshot with encryption, and recreate the volume; enable encryption by default.",
            fix_commands=[f"aws ec2 enable-ebs-encryption-by-default --region {region}",
                          f"aws ec2 create-snapshot --region {region} --volume-id <VOL_ID>",
                          f"aws ec2 copy-snapshot --region {region} --source-region {region} --source-snapshot-id <SNAP_ID> --encrypted"]))
    if not ec2.get_ebs_encryption_by_default().get("EbsEncryptionByDefault"):
        ctx.add(finding(
            service="EC2", check_id="EBS-DEFAULT-ENCRYPTION", severity="LOW", resource=region, region=region,
            title="EBS encryption by default is off",
            description="New volumes are not encrypted automatically.", remediation="Enable it per region.",
            fix_commands=[f"aws ec2 enable-ebs-encryption-by-default --region {region}"]))
    pub_snaps = [s["SnapshotId"] for s in ec2.get_paginator("describe_snapshots").paginate(
        OwnerIds=["self"], RestorableByUserIds=["all"]).search("Snapshots[]")]

    if pub_snaps:
        ctx.add(finding(
            service="EC2", check_id="EBS-PUBLIC-SNAPSHOT", severity="CRITICAL", resource=", ".join(pub_snaps[:10]), region=region,
            title=f"{len(pub_snaps)} publicly shared EBS snapshot(s)",
            description="Anyone can copy these snapshots and read their data.",
            remediation="Make them private immediately.",
            fix_commands=[f"aws ec2 modify-snapshot-attribute --region {region} --snapshot-id {s} "
                          "--attribute createVolumePermission --operation-type remove --group-names all"
                          for s in pub_snaps[:MAX_LIST]]))
    pub_amis = [a["ImageId"] for a in ec2.describe_images(
        Owners=["self"], Filters=[{"Name": "is-public", "Values": ["true"]}])["Images"]]
    if pub_amis:
        ctx.add(finding(
            service="EC2", check_id="AMI-PUBLIC", severity="HIGH", resource=", ".join(pub_amis[:10]), region=region,
            title=f"{len(pub_amis)} public AMI(s)", description="AMIs may contain secrets, keys or proprietary code.",
            remediation="Make AMIs private.",
            fix_commands=[f"aws ec2 modify-image-attribute --region {region} --image-id {a} "
                          "--launch-permission 'Remove=[{Group=all}]'" for a in pub_amis[:MAX_LIST]]))

    # VPC flow logs
    covered = {f["ResourceId"] for f in ec2.get_paginator("describe_flow_logs").paginate().search("FlowLogs[]")}
    no_logs = [v["VpcId"] for v in ec2.get_paginator("describe_vpcs").paginate().search("Vpcs[]")
               if v["VpcId"] not in covered]
    if no_logs:
        ctx.add(finding(
            service="VPC", check_id="VPC-NO-FLOWLOGS", severity="LOW", resource=", ".join(no_logs), region=region,
            title=f"{len(no_logs)} VPC(s) without flow logs",
            description="No network traffic visibility for incident response.",
            remediation="Enable VPC flow logs to S3 or CloudWatch Logs.",
            fix_commands=[f"aws ec2 create-flow-logs --region {region} --resource-type VPC --resource-ids {v} "
                          "--traffic-type ALL --log-destination-type s3 --log-destination arn:aws:s3:::<LOG_BUCKET>/flow-logs/"
                          for v in no_logs[:10]]))


# ALB / NLB
def scan_load_balancers(ctx, region, alb_log_bucket="<LOG_BUCKET>"):
    elb = ctx.client("elbv2", region)
    waf = ctx.client("wafv2", region)
    for lb in elb.get_paginator("describe_load_balancers").paginate().search("LoadBalancers[]"):
        arn, name, typ = lb["LoadBalancerArn"], lb["LoadBalancerName"], lb["Type"]
        public = lb.get("Scheme") == "internet-facing"
        attrs = {a["Key"]: a["Value"] for a in elb.describe_load_balancer_attributes(LoadBalancerArn=arn)["Attributes"]}
        if attrs.get("access_logs.s3.enabled") != "true":
            ctx.add(finding(
                service="ELB", check_id="ELB-NO-ACCESS-LOGS", severity="LOW", resource=name, region=region,
                title=f"Load balancer '{name}' has access logging disabled",
                description="No request logs for investigations.",
                remediation="Enable access logs to an S3 bucket with the proper ELB log-delivery policy.",
                fix_commands=[f"aws elbv2 modify-load-balancer-attributes --region {region} --load-balancer-arn {arn} "
                              f"--attributes Key=access_logs.s3.enabled,Value=true Key=access_logs.s3.bucket,Value={alb_log_bucket}"]))
        if typ == "application" and attrs.get("routing.http.drop_invalid_header_fields.enabled") != "true":
            ctx.add(finding(
                service="ELB", check_id="ALB-DROP-INVALID-HEADERS", severity="LOW", resource=name, region=region,
                title=f"ALB '{name}' does not drop invalid HTTP headers",
                description="Mitigates HTTP desync/request smuggling.",
                remediation="Enable drop_invalid_header_fields.",
                fix_commands=[f"aws elbv2 modify-load-balancer-attributes --region {region} --load-balancer-arn {arn} "
                              "--attributes Key=routing.http.drop_invalid_header_fields.enabled,Value=true"]))
        if typ == "application" and public:
            try:
                if not waf.get_web_acl_for_resource(ResourceArn=arn).get("WebACL"):
                    ctx.add(finding(
                        service="ELB", check_id="ALB-NO-WAF", severity="LOW", resource=name, region=region,
                        title=f"Internet-facing ALB '{name}' has no AWS WAF web ACL",
                        description="No managed protection against common web exploits and bots.",
                        remediation="Associate a WAFv2 web ACL (e.g. AWS managed Common + KnownBadInputs rule groups).",
                        fix_commands=[f"aws wafv2 associate-web-acl --region {region} --web-acl-arn <WEB_ACL_ARN> --resource-arn {arn}"]))
            except ClientError:
                pass
        for l in elb.get_paginator("describe_listeners").paginate(LoadBalancerArn=arn).search("Listeners[]"):
            la = l["ListenerArn"]
            if l["Protocol"] == "HTTP":
                redirect = any(a["Type"] == "redirect" and a.get("RedirectConfig", {}).get("Protocol") == "HTTPS"
                               for a in l.get("DefaultActions", []))
                if not redirect and public:
                    ctx.add(finding(
                        service="ELB", check_id="ELB-HTTP-NO-REDIRECT", severity="MEDIUM", resource=la, region=region,
                        title=f"'{name}' serves plain HTTP on port {l['Port']} without redirecting to HTTPS",
                        description="Traffic can be intercepted or downgraded.",
                        remediation="Redirect HTTP to HTTPS.",
                        fix_commands=[f"aws elbv2 modify-listener --region {region} --listener-arn {la} --default-actions "
                                      "'Type=redirect,RedirectConfig={Protocol=HTTPS,Port=443,StatusCode=HTTP_301}'"]))
            elif l["Protocol"] in ("HTTPS", "TLS"):
                pol = l.get("SslPolicy", "")
                if pol and not pol.startswith(MODERN_TLS_PREFIXES):
                    ctx.add(finding(
                        service="ELB", check_id="ELB-WEAK-TLS-POLICY", severity="MEDIUM", resource=la, region=region,
                        title=f"'{name}' listener {l['Port']} uses legacy TLS policy {pol}",
                        description="Allows TLS 1.0/1.1 and/or weak ciphers.",
                        remediation="Use a TLS 1.2+/1.3 policy (verify client compatibility).",
                        fix_commands=[f"aws elbv2 modify-listener --region {region} --listener-arn {la} "
                                      "--ssl-policy ELBSecurityPolicy-TLS13-1-2-2021-06"]))


# EKS
def scan_eks(ctx, region):
    eks = ctx.client("eks", region)
    for cname in eks.get_paginator("list_clusters").paginate().search("clusters[]"):
        c = eks.describe_cluster(name=cname)["cluster"]
        vpc = c.get("resourcesVpcConfig", {})
        arn = c["arn"]
        if vpc.get("endpointPublicAccess") and "0.0.0.0/0" in vpc.get("publicAccessCidrs", ["0.0.0.0/0"]):
            ctx.add(finding(
                service="EKS", check_id="EKS-PUBLIC-ENDPOINT", severity="HIGH", resource=arn, region=region,
                title=f"EKS cluster '{cname}' API endpoint is open to the internet",
                description="Public endpoint allows 0.0.0.0/0 (Jenkins/Bitbucket runners and admins can be pinned to CIDRs).",
                remediation="Restrict public access CIDRs to your CI/VPN egress IPs, or disable public access and use private endpoint.",
                fix_commands=[f"aws eks update-cluster-config --region {region} --name {cname} --resources-vpc-config "
                              "endpointPublicAccess=true,publicAccessCidrs=<CI_EGRESS_IP>/32,<VPN_CIDR>,endpointPrivateAccess=true"]))
        enabled = {t for l in c.get("logging", {}).get("clusterLogging", []) if l.get("enabled") for t in l["types"]}
        missing = {"api", "audit", "authenticator"} - enabled
        if missing:
            ctx.add(finding(
                service="EKS", check_id="EKS-CONTROL-PLANE-LOGS", severity="MEDIUM", resource=arn, region=region,
                title=f"EKS cluster '{cname}': control plane logs disabled ({', '.join(sorted(missing))})",
                description="Audit/API logs are needed to detect abuse of the cluster.",
                remediation="Enable api, audit, authenticator (and ideally all) log types.",
                fix_commands=[f"aws eks update-cluster-config --region {region} --name {cname} --logging "
                              "'{\"clusterLogging\":[{\"types\":[\"api\",\"audit\",\"authenticator\",\"controllerManager\",\"scheduler\"],\"enabled\":true}]}'"]))
        if not any("secrets" in e.get("resources", []) for e in c.get("encryptionConfig", [])):
            ctx.add(finding(
                service="EKS", check_id="EKS-SECRETS-ENCRYPTION", severity="MEDIUM", resource=arn, region=region,
                title=f"EKS cluster '{cname}': Kubernetes secrets not envelope-encrypted with KMS",
                description="Secrets are stored without a customer-managed KMS key.",
                remediation="Associate a KMS key (cannot be removed afterwards).",
                fix_commands=[f"aws eks associate-encryption-config --region {region} --cluster-name {cname} "
                              "--encryption-config '[{\"resources\":[\"secrets\"],\"provider\":{\"keyArn\":\"<KMS_KEY_ARN>\"}}]'"]))
        for ng in eks.get_paginator("list_nodegroups").paginate(clusterName=cname).search("nodegroups[]"):
            d = eks.describe_nodegroup(clusterName=cname, nodegroupName=ng)["nodegroup"]
            ra = d.get("remoteAccess")
            if ra and ra.get("ec2SshKey") and not ra.get("sourceSecurityGroups"):
                ctx.add(finding(
                    service="EKS", check_id="EKS-NODEGROUP-SSH-OPEN", severity="HIGH", resource=d["nodegroupArn"], region=region,
                    title=f"Node group '{ng}' allows SSH from anywhere",
                    description="Remote access is enabled with an SSH key and no source security group, which opens port 22 to 0.0.0.0/0.",
                    remediation="Disable remote access and use SSM Session Manager, or restrict to a bastion SG. "
                                "Requires a new node group (cannot be changed in place).",
                    fix_commands=["# Create a replacement node group without remoteAccess, then drain/delete the old one"]))


# Lambda scanning Lambda
def scan_lambda(ctx, region):
    lam = ctx.client("lambda", region)
    for fn in lam.get_paginator("list_functions").paginate().search("Functions[]"):
        name, arn = fn["FunctionName"], fn["FunctionArn"]
        names = sorted(k for k in (fn.get("Environment", {}).get("Variables") or {}) if SECRET_NAME.search(k))
        if names:
            ctx.add(finding(
                service="Lambda", check_id="LAMBDA-ENV-SECRETS", severity="MEDIUM", resource=arn, region=region,
                title=f"Lambda '{name}' may keep secrets in environment variables",
                description=f"Suspicious variable NAMES (values not read): {', '.join(names)}.",
                remediation="Move secrets to Secrets Manager / SSM Parameter Store SecureString and fetch at runtime.",
                fix_commands=["aws secretsmanager create-secret --name <NAME> --secret-string <VALUE>"]))
        try:
            for cfg in lam.list_function_url_configs(FunctionName=name).get("FunctionUrlConfigs", []):
                if cfg["AuthType"] == "NONE":
                    ctx.add(finding(
                        service="Lambda", check_id="LAMBDA-URL-NO-AUTH", severity="HIGH", resource=arn, region=region,
                        title=f"Lambda '{name}' has a public function URL (AuthType NONE)",
                        description="Anyone on the internet can invoke it.",
                        remediation="Use AWS_IAM auth or put the function behind API Gateway/ALB with authentication.",
                        fix_commands=[f"aws lambda update-function-url-config --region {region} --function-name {name} --auth-type AWS_IAM"]))
        except ClientError:
            pass
        try:
            pol = json.loads(lam.get_policy(FunctionName=name)["Policy"])
            for st in as_list(pol.get("Statement")):
                pr = st.get("Principal")
                if st.get("Effect") == "Allow" and not st.get("Condition") and (
                        pr == "*" or (isinstance(pr, dict) and "*" in as_list(pr.get("AWS")))):
                    ctx.add(finding(
                        service="Lambda", check_id="LAMBDA-POLICY-PUBLIC", severity="HIGH", resource=arn, region=region,
                        title=f"Lambda '{name}' resource policy allows any principal",
                        description=f"Statement {st.get('Sid')} has Principal '*' with no condition.",
                        remediation="Restrict the principal or add aws:SourceArn / aws:SourceAccount conditions.",
                        fix_commands=[f"aws lambda remove-permission --region {region} --function-name {name} --statement-id {st.get('Sid')}"]))
        except ClientError as e:
            if _code(e) != "ResourceNotFoundException":
                raise


# Detective controls
def scan_cloudtrail(ctx):
    ct = ctx.client("cloudtrail")
    ok = False
    for t in ct.describe_trails(includeShadowTrails=True)["trailList"]:
        if t.get("IsMultiRegionTrail") and ct.get_trail_status(Name=t["TrailARN"]).get("IsLogging"):
            ok = True
    if not ok:
        ctx.add(finding(
            service="CloudTrail", check_id="CLOUDTRAIL-NOT-ENABLED", severity="HIGH", resource="account",
            title="No active multi-region CloudTrail trail",
            description="API activity is not fully recorded; also required for Access Analyzer policy generation.",
            remediation="Create a multi-region trail with log file validation, delivered to a locked-down S3 bucket.",
            fix_commands=["aws cloudtrail create-trail --name org-trail --s3-bucket-name <TRAIL_BUCKET> "
                          "--is-multi-region-trail --enable-log-file-validation",
                          "aws cloudtrail start-logging --name org-trail"]))


def scan_guardduty(ctx, region):
    if not ctx.client("guardduty", region).list_detectors().get("DetectorIds"):
        ctx.add(finding(
            service="GuardDuty", check_id="GUARDDUTY-DISABLED", severity="MEDIUM", resource=region, region=region,
            title=f"GuardDuty is not enabled in {region}",
            description="No managed threat detection for this region.",
            remediation="Enable GuardDuty (include EKS audit log and runtime monitoring if you run EKS).",
            fix_commands=[f"aws guardduty create-detector --region {region} --enable"]))
