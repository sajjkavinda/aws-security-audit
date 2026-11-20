# S3 checks: public access, ACLs, bucket policies, TLS, encryption, versioning, logging
import json
import shlex

from botocore.exceptions import ClientError

from common import as_list, finding

PAB_KEYS = ["BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"]
PUBLIC_GROUPS = ("AllUsers", "AuthenticatedUsers")

TLS_DENY_STATEMENT = {
    "Sid": "DenyInsecureTransport", "Effect": "Deny", "Principal": "*",
    "Action": "s3:*",
    "Resource": ["arn:aws:s3:::BUCKET", "arn:aws:s3:::BUCKET/*"],
    "Condition": {"Bool": {"aws:SecureTransport": "false"}},
}


def _code(e):
    return e.response.get("Error", {}).get("Code", "")


def _bucket_region(s3, name):
    loc = s3.get_bucket_location(Bucket=name).get("LocationConstraint")
    return {None: "us-east-1", "": "us-east-1", "EU": "eu-west-1"}.get(loc, loc)


def scan(ctx):
    _account_pab(ctx)
    s3 = ctx.client("s3")
    buckets = ctx.safe("s3:list-buckets", lambda: s3.list_buckets()["Buckets"]) or []
    for b in buckets:
        ctx.safe(f"s3:{b['Name']}", _check_bucket, ctx, b["Name"])


def _account_pab(ctx):
    sc = ctx.client("s3control")
    try:
        cfg = sc.get_public_access_block(AccountId=ctx.account_id)["PublicAccessBlockConfiguration"]
        missing = [k for k in PAB_KEYS if not cfg.get(k)]
    except ClientError as e:
        if _code(e) != "NoSuchPublicAccessBlockConfiguration":
            ctx.errors.append({"check": "s3:account-pab", "error": _code(e), "message": ""})
            return
        missing = PAB_KEYS
    if missing:
        ctx.add(finding(
            service="S3", check_id="S3-ACCOUNT-PAB", severity="MEDIUM", resource=f"account/{ctx.account_id}",
            title="Account-level S3 Block Public Access is not fully enabled",
            description=f"Disabled settings: {', '.join(missing)}.",
            remediation="Enable all four account-level Block Public Access settings (safety net for every bucket).",
            fix_commands=[f"aws s3control put-public-access-block --account-id {ctx.account_id} "
                          "--public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,"
                          "BlockPublicPolicy=true,RestrictPublicBuckets=true"]))


def _check_bucket(ctx, name):
    region = _bucket_region(ctx.client("s3"), name)
    c = ctx.client("s3", region)
    res = f"arn:aws:s3:::{name}"
    q = shlex.quote(name)

    # --- public access block
    try:
        pab = c.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
        missing = [k for k in PAB_KEYS if not pab.get(k)]
    except ClientError as e:
        if _code(e) != "NoSuchPublicAccessBlockConfiguration":
            raise
        missing = PAB_KEYS
    if missing:
        ctx.add(finding(
            service="S3", check_id="S3-BUCKET-PAB", severity="MEDIUM", resource=res, region=region,
            title=f"Bucket '{name}': Block Public Access not fully enabled",
            description=f"Disabled settings: {', '.join(missing)}.",
            remediation="Enable all four settings unless the bucket is an intentional public website "
                        "(prefer CloudFront with Origin Access Control instead).",
            fix_commands=[f"aws s3api put-public-access-block --bucket {q} --public-access-block-configuration "
                          "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"]))

    # policy: public status, wildcard principals, TLS enforcement
    policy = None
    try:
        policy = json.loads(c.get_bucket_policy(Bucket=name)["Policy"])
    except ClientError as e:
        if _code(e) != "NoSuchBucketPolicy":
            raise
    try:
        if c.get_bucket_policy_status(Bucket=name)["PolicyStatus"]["IsPublic"]:
            ctx.add(finding(
                service="S3", check_id="S3-POLICY-PUBLIC", severity="CRITICAL", resource=res, region=region,
                title=f"Bucket '{name}' is public through its bucket policy",
                description="S3 evaluates the bucket policy as granting public access.",
                remediation="Remove wildcard principals or add conditions (aws:SourceVpce, aws:PrincipalOrgID, "
                            "aws:SourceArn). Serve public content via CloudFront + OAC.",
                fix_commands=[f"aws s3api get-bucket-policy --bucket {q}  # review, then edit",
                              f"aws s3api delete-bucket-policy --bucket {q}  # only if the policy is not needed"]))
    except ClientError as e:
        if _code(e) != "NoSuchBucketPolicy":
            raise
    if policy:
        has_tls_deny = False
        for st in as_list(policy.get("Statement")):
            cond = st.get("Condition") or {}
            if st.get("Effect") == "Deny" and "false" in json.dumps(cond.get("Bool", {})).lower() \
                    and "securetransport" in json.dumps(cond).lower():
                has_tls_deny = True
            principal = st.get("Principal")
            if st.get("Effect") == "Allow" and not cond and (
                    principal == "*" or (isinstance(principal, dict) and "*" in as_list(principal.get("AWS")))):
                ctx.add(finding(
                    service="S3", check_id="S3-POLICY-WILDCARD-PRINCIPAL", severity="HIGH", resource=res, region=region,
                    title=f"Bucket '{name}': Allow statement for Principal '*' without conditions",
                    description=f"Statement {st.get('Sid', '(no Sid)')} allows everyone: actions={as_list(st.get('Action'))}.",
                    remediation="Name explicit principals or add restricting conditions.",
                    fix_commands=[f"aws s3api get-bucket-policy --bucket {q}"]))
        if has_tls_deny:
            policy = {"_tls": True}
    if not (policy and policy.get("_tls")):
        stmt = json.loads(json.dumps(TLS_DENY_STATEMENT).replace("BUCKET", name))
        ctx.add(finding(
            service="S3", check_id="S3-NO-TLS-ENFORCEMENT", severity="MEDIUM", resource=res, region=region,
            title=f"Bucket '{name}' does not deny non-TLS requests",
            description="No Deny statement on aws:SecureTransport=false was found.",
            remediation="Add the statement (suggested_policy) to the bucket policy, merging with existing statements.",
            fix_commands=[f"aws s3api get-bucket-policy --bucket {q} > current.json  # merge the statement, then:",
                          f"aws s3api put-bucket-policy --bucket {q} --policy file://merged-policy.json"],
            suggested_policy={"Version": "2012-10-17", "Statement": [stmt]}))

    # ACLs
    acl = c.get_bucket_acl(Bucket=name)
    bad = [g["Grantee"]["URI"].rsplit("/", 1)[-1] for g in acl.get("Grants", [])
           if g.get("Grantee", {}).get("URI", "").rsplit("/", 1)[-1] in PUBLIC_GROUPS]
    if bad:
        ctx.add(finding(
            service="S3", check_id="S3-ACL-PUBLIC", severity="HIGH", resource=res, region=region,
            title=f"Bucket '{name}' ACL grants access to {', '.join(sorted(set(bad)))}",
            description="Bucket ACL gives access to everyone or any authenticated AWS user.",
            remediation="Disable ACLs by setting Object Ownership to BucketOwnerEnforced.",
            fix_commands=[f"aws s3api put-bucket-ownership-controls --bucket {q} "
                          "--ownership-controls 'Rules=[{ObjectOwnership=BucketOwnerEnforced}]'"]))

    # encryption
    try:
        rules = c.get_bucket_encryption(Bucket=name)["ServerSideEncryptionConfiguration"]["Rules"]
        algo = rules[0]["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"]
    except ClientError as e:
        if _code(e) != "ServerSideEncryptionConfigurationNotFoundError":
            raise
        algo = None
    if algo is None:
        ctx.add(finding(
            service="S3", check_id="S3-NO-ENCRYPTION", severity="MEDIUM", resource=res, region=region,
            title=f"Bucket '{name}' has no default encryption",
            description="Objects may be stored without server-side encryption.",
            remediation="Enable default SSE-KMS (or at least SSE-S3).",
            fix_commands=[f"aws s3api put-bucket-encryption --bucket {q} --server-side-encryption-configuration "
                          "'{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"aws:kms\"},\"BucketKeyEnabled\":true}]}'"]))
    elif algo == "AES256":
        ctx.add(finding(
            service="S3", check_id="S3-SSE-S3-ONLY", severity="INFO", resource=res, region=region,
            title=f"Bucket '{name}' uses SSE-S3 (not KMS)",
            description="Fine for most data; SSE-KMS adds key policy control and CloudTrail visibility.",
            remediation="Consider SSE-KMS for sensitive data.", fix_commands=[]))

    # versioning & logging
    if c.get_bucket_versioning(Bucket=name).get("Status") != "Enabled":
        ctx.add(finding(
            service="S3", check_id="S3-NO-VERSIONING", severity="LOW", resource=res, region=region,
            title=f"Bucket '{name}': versioning disabled",
            description="Overwrites/deletes (including by ransomware or mistakes) cannot be undone.",
            remediation="Enable versioning (plus a lifecycle rule for noncurrent versions).",
            fix_commands=[f"aws s3api put-bucket-versioning --bucket {q} --versioning-configuration Status=Enabled"]))
    if not c.get_bucket_logging(Bucket=name).get("LoggingEnabled"):
        ctx.add(finding(
            service="S3", check_id="S3-NO-ACCESS-LOGS", severity="LOW", resource=res, region=region,
            title=f"Bucket '{name}': server access logging disabled",
            description="No access logs for forensics. (CloudTrail data events are an alternative.)",
            remediation="Enable access logging to a dedicated log bucket.",
            fix_commands=[f"aws s3api put-bucket-logging --bucket {q} --bucket-logging-status "
                          "'{\"LoggingEnabled\":{\"TargetBucket\":\"<LOG_BUCKET>\",\"TargetPrefix\":\"" + name + "/\"}}'"]))
