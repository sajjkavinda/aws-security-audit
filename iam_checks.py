# IAM access analyser
import csv
import io
import json
import re
import shlex
import time
from datetime import datetime, timezone

from common import SEV_RANK, as_list, finding

RISKY_AWS_MANAGED = {
    "AdministratorAccess": "CRITICAL",
    "PowerUserAccess": "HIGH",
    "IAMFullAccess": "HIGH",
}

PRIV_ESC_ACTIONS = {
    "iam:passrole", "iam:createpolicyversion", "iam:setdefaultpolicyversion",
    "iam:attachuserpolicy", "iam:attachrolepolicy", "iam:attachgrouppolicy",
    "iam:putuserpolicy", "iam:putrolepolicy", "iam:putgrouppolicy",
    "iam:createaccesskey", "iam:createloginprofile", "iam:updateloginprofile",
    "iam:updateassumerolepolicy", "sts:assumerole",
}

# Services where ACTION_LEVEL tracking covers management actions only
PARTIAL_TRACKING = {"s3", "lambda"}
KEY_MAX_AGE_DAYS = 90
ROLE_IDLE_DAYS = 90       # flag roles unused for this many days
ROLE_NEW_GRACE_DAYS = 30  # don't flag brand-new roles that have never been assumed yet

ENTITY_API = {
    "role": dict(list="list_roles", key="Roles", name="RoleName",
                 attached="list_attached_role_policies", inline_names="list_role_policies",
                 inline_get="get_role_policy", attach="attach-role-policy",
                 detach="detach-role-policy", delete_inline="delete-role-policy",
                 flag="--role-name"),
    "user": dict(list="list_users", key="Users", name="UserName",
                 attached="list_attached_user_policies", inline_names="list_user_policies",
                 inline_get="get_user_policy", attach="attach-user-policy",
                 detach="detach-user-policy", delete_inline="delete-user-policy",
                 flag="--user-name"),
    "group": dict(list="list_groups", key="Groups", name="GroupName",
                  attached="list_attached_group_policies", inline_names="list_group_policies",
                  inline_get="get_group_policy", attach="attach-group-policy",
                  detach="detach-group-policy", delete_inline="delete-group-policy",
                  flag="--group-name"),
}


#  Policy analysis
def analyze_policy_document(doc):
    # Return a list of {severity, code, message} for risky Allow statements
    issues = []
    for i, st in enumerate(as_list((doc or {}).get("Statement"))):
        if st.get("Effect") != "Allow":
            continue
        sid = st.get("Sid") or f"#{i}"
        actions = [str(a) for a in as_list(st.get("Action"))]
        resources = [str(r) for r in as_list(st.get("Resource"))]
        res_star = "*" in resources
        scope = "on all resources" if res_star else "on the listed resources"

        if st.get("NotAction") is not None:
            issues.append({"severity": "HIGH", "code": "ALLOW_NOTACTION",
                           "message": f"Statement {sid}: Allow + NotAction grants everything except the listed actions."})
        for a in actions:
            al = a.lower()
            if al == "*":
                issues.append({"severity": "CRITICAL" if res_star else "HIGH", "code": "ACTION_STAR",
                               "message": f"Statement {sid}: Action '*' {scope} (full admin)."})
            elif al.endswith(":*"):
                issues.append({"severity": "HIGH" if res_star else "MEDIUM", "code": "SERVICE_WILDCARD",
                               "message": f"Statement {sid}: '{a}' grants every {a.split(':')[0]} action {scope}."})
        esc = sorted({a for a in actions if a.lower() in PRIV_ESC_ACTIONS})
        if esc and res_star:
            issues.append({"severity": "HIGH", "code": "PRIV_ESCALATION",
                           "message": f"Statement {sid}: {', '.join(esc)} on '*' can allow privilege escalation."})
        if res_star and not st.get("Condition") and any(
                a.lower() in ("iam:passrole",) for a in actions):
            issues.append({"severity": "HIGH", "code": "PASSROLE_STAR",
                           "message": f"Statement {sid}: iam:PassRole on '*' without conditions."})
    # de-duplicate
    seen, out = set(), []
    for it in issues:
        k = (it["code"], it["message"])
        if k not in seen:
            seen.add(k)
            out.append(it)
    return out


def _trust_issues(role, account_id):
    doc = role.get("AssumeRolePolicyDocument") or {}
    out = []
    for st in as_list(doc.get("Statement")):
        if st.get("Effect") != "Allow":
            continue
        principal = st.get("Principal", {})
        cond = st.get("Condition") or {}
        cond_keys = {k.lower() for op in cond.values() if isinstance(op, dict) for k in op}
        aws, fed = [], []
        if principal == "*":
            aws = ["*"]
        elif isinstance(principal, dict):
            aws, fed = as_list(principal.get("AWS")), as_list(principal.get("Federated"))

        if "*" in aws:
            out.append(("CRITICAL" if not cond else "HIGH", "TRUST_WILDCARD",
                        "Trust policy allows ANY AWS principal to assume this role."))
        for a in aws:
            m = re.search(r"(\d{12})", str(a))
            if m and m.group(1) != account_id and not (
                    {"sts:externalid", "aws:principalorgid"} & cond_keys):
                out.append(("MEDIUM", "TRUST_CROSS_ACCOUNT",
                            f"Trusts external account {m.group(1)} without sts:ExternalId or aws:PrincipalOrgID."))
        for f in fed:
            if "oidc-provider" in str(f):
                sub_vals = [v for op in cond.values() if isinstance(op, dict)
                            for k, val in op.items() if k.lower().endswith(":sub")
                            for v in as_list(val)]
                if not sub_vals:
                    out.append(("HIGH", "TRUST_OIDC_NO_SUB",
                                "OIDC/IRSA trust has no ':sub' condition, so any service account/identity "
                                "from that provider can assume the role."))
                elif any("*" in str(v) for v in sub_vals):
                    out.append(("MEDIUM", "TRUST_OIDC_WILDCARD_SUB",
                                "OIDC/IRSA trust uses a wildcard ':sub'; pin it to one namespace:serviceaccount."))
    return out


def _role_last_used(role):
    """Return (last_used_datetime_or_None, region_or_None) from RoleLastUsed."""
    rlu = role.get("RoleLastUsed") or {}
    last = rlu.get("LastUsedDate")
    region = rlu.get("Region")
    return last, region


# Least privilege
def _collect_last_accessed(iam, job_id):
    services, marker = [], None
    while True:
        kw = {"JobId": job_id}
        if marker:
            kw["Marker"] = marker
        r = iam.get_service_last_accessed_details(**kw)
        services.extend(r.get("ServicesLastAccessed", []))
        if r.get("IsTruncated"):
            marker = r.get("Marker")
        else:
            return services


def fetch_last_accessed(iam, arns, deadline):
    jobs, results = {}, {}
    for arn in arns:
        try:
            jobs[arn] = iam.generate_service_last_accessed_details(
                Arn=arn, Granularity="ACTION_LEVEL")["JobId"]
        except Exception:  # noqa: BLE001
            continue
    pending = dict(jobs)
    while pending and time.time() < deadline:
        for arn, job in list(pending.items()):
            try:
                r = iam.get_service_last_accessed_details(JobId=job)
            except Exception:  # noqa: BLE001
                del pending[arn]
                continue
            if r["JobStatus"] == "COMPLETED":
                results[arn] = _collect_last_accessed(iam, job)
                del pending[arn]
            elif r["JobStatus"] == "FAILED":
                del pending[arn]
        if pending:
            time.sleep(2)
    return results


def build_least_privilege(services):
    tracked, review, unused = set(), set(), []
    for s in services:
        ns = s["ServiceNamespace"]
        if not s.get("LastAuthenticated"):
            unused.append(ns)
            continue
        acts = [t["ActionName"] for t in s.get("TrackedActionsLastAccessed", [])
                if t.get("LastAccessedTime")]
        for a in acts:
            tracked.add(a if ":" in a else f"{ns}:{a}")
        if not acts or ns in PARTIAL_TRACKING:
            review.add(ns)
    statements = []
    if tracked:
        statements.append({"Sid": "ObservedActions", "Effect": "Allow",
                           "Action": sorted(tracked),
                           "Resource": "*"})
    if review:
        statements.append({"Sid": "ReviewAndNarrowThese", "Effect": "Allow",
                           "Action": sorted(f"{ns}:*" for ns in review), "Resource": "*"})
    notes = [
        "Resource is '*' in this draft - scope each statement to the real ARNs (buckets, queues, secrets, ...).",
        "Actions were derived from IAM service-last-accessed data. Data-plane actions "
        "(e.g. s3:GetObject, sqs:SendMessage) are not tracked at action level.",
    ]
    if review:
        notes.append("Statement 'ReviewAndNarrowThese' is service-level because action-level data was "
                     f"unavailable for: {', '.join(sorted(review))}. Replace it with exact actions using the "
                     "Access Analyzer policy generation output (see README).")
    if unused:
        notes.append(f"Services allowed but NOT used in the tracking period (removed): {', '.join(sorted(unused)[:40])}")
    if not statements:
        notes.append("No service usage found in the tracking period - consider deleting this identity.")
        return None, notes
    return {"Version": "2012-10-17", "Statement": statements}, notes


# Main scan in IAM
def _paginate(iam, op, key, **kw):
    return list(iam.get_paginator(op).paginate(**kw).search(f"{key}[]"))


def _managed_doc(iam, arn, cache):
    if arn not in cache:
        p = iam.get_policy(PolicyArn=arn)["Policy"]
        cache[arn] = iam.get_policy_version(
            PolicyArn=arn, VersionId=p["DefaultVersionId"])["PolicyVersion"]["Document"]
    return cache[arn]


def _entity_issues(iam, api, name, cache):
    results = []
    for p in _paginate(iam, api["attached"], "AttachedPolicies", **{api["name"]: name}):
        pname, parn = p["PolicyName"], p["PolicyArn"]
        if parn.startswith("arn:aws:iam::aws:policy/"):
            sev = RISKY_AWS_MANAGED.get(pname) or ("MEDIUM" if pname.endswith("FullAccess") else None)
            if sev:
                results.append({"policy": pname, "type": "managed", "arn": parn, "severity": sev,
                                "message": f"AWS managed policy '{pname}' is broader than a workload normally needs."})
            continue
        for it in analyze_policy_document(_managed_doc(iam, parn, cache)):
            results.append({"policy": pname, "type": "managed", "arn": parn, **it})
    for pname in _paginate(iam, api["inline_names"], "PolicyNames", **{api["name"]: name}):
        doc = getattr(iam, api["inline_get"])(**{api["name"]: name, "PolicyName": pname})["PolicyDocument"]
        for it in analyze_policy_document(doc):
            results.append({"policy": pname, "type": "inline", "arn": None, **it})
    return results


def _safe_policy_name(name):
    return re.sub(r"[^A-Za-z0-9+=,.@_-]", "-", name)[:100] + "-least-privilege"


def _check_role_usage(ctx, role, now):
    """Emit IAM-ROLE-UNUSED or IAM-ROLE-IDLE findings based on RoleLastUsed."""
    name = role["RoleName"]
    arn  = role["Arn"]
    created = role.get("CreateDate")
    if hasattr(created, "astimezone"):
        created = created.astimezone(timezone.utc)
    last_used, last_region = _role_last_used(role)
    if hasattr(last_used, "astimezone"):
        last_used = last_used.astimezone(timezone.utc)

    age_days = (now - created).days if created else None

    if last_used is None:
        # Never assumed — only flag if the role is older than the grace period
        if age_days is not None and age_days > ROLE_NEW_GRACE_DAYS:
            ctx.add(finding(
                service="IAM", check_id="IAM-ROLE-UNUSED", severity="MEDIUM",
                resource=arn,
                title=f"Role '{name}' has never been assumed ({age_days} days old)",
                description=(
                    f"The role was created {age_days} days ago and has no recorded assumption. "
                    "It may be orphaned or waiting on a workload that was never deployed."
                ),
                remediation="If the role is no longer needed, delete it. Otherwise verify the workload is "
                            "actually using it and check CloudTrail for sts:AssumeRole events.",
                fix_commands=[
                    f"# Verify no recent usage in CloudTrail first",
                    f"aws iam delete-role --role-name {shlex.quote(name)}",
                ]))
    else:
        idle_days = (now - last_used).days
        if idle_days > ROLE_IDLE_DAYS:
            ctx.add(finding(
                service="IAM", check_id="IAM-ROLE-IDLE", severity="MEDIUM",
                resource=arn,
                title=f"Role '{name}' has not been assumed for {idle_days} days",
                description=(
                    f"Last assumed {idle_days} days ago"
                    + (f" from region {last_region}" if last_region else "")
                    + f" (on {last_used.strftime('%Y-%m-%d')}). "
                    "Stale roles with broad permissions are a common lateral-movement path."
                ),
                remediation="Confirm the workload that uses this role is still active. If not, delete the role "
                            "or at minimum remove its policies until it is needed again.",
                fix_commands=[
                    f"# Check CloudTrail for recent sts:AssumeRole events before deleting",
                    f"aws iam delete-role --role-name {shlex.quote(name)}",
                ]))


def scan(ctx, max_analysis=25, deadline=None, aa_cfg=None):
    iam = ctx.client("iam")
    deadline = deadline or time.time() + 300
    cache, entities = {}, []
    now = datetime.now(timezone.utc)

    # Collect all roles upfront so we can run last-used checks on every role
    all_roles = {}

    for kind, api in ENTITY_API.items():
        items = ctx.safe(f"iam:list-{kind}s", _paginate, iam, api["list"], api["key"]) or []
        for ent in items:
            path = ent.get("Path", "")
            if path.startswith("/aws-service-role/") or path.startswith("/aws-reserved/"):
                continue
            name, arn = ent[api["name"]], ent["Arn"]

            # Track all roles for usage checks
            if kind == "role":
                all_roles[arn] = ent

            issues = ctx.safe(f"iam:policies:{kind}:{name}", _entity_issues, iam, api, name, cache) or []
            trust = _trust_issues(ent, ctx.account_id) if kind == "role" else []
            if issues or trust:
                entities.append({"kind": kind, "name": name, "arn": arn, "api": api,
                                 "issues": issues, "trust": trust, "raw": ent})

    # Role last-used checks — runs on every customer role regardless of policy issues
    for arn, role in all_roles.items():
        ctx.safe(f"iam:role-usage:{role['RoleName']}", _check_role_usage, ctx, role, now)

    # Least privilege suggestions — analyse ALL entities with policy issues, not just the top N
    perm_entities = [e for e in entities if e["issues"] and e["kind"] in ("role", "user")]
    perm_entities.sort(key=lambda e: min(SEV_RANK[i["severity"]] for i in e["issues"]))

    # Honour max_analysis as a cap but default is now higher (set to 100 in lambda_function.py)
    to_analyse = perm_entities[:max_analysis]
    last = fetch_last_accessed(iam, [e["arn"] for e in to_analyse], deadline) if to_analyse else {}
    if aa_cfg and to_analyse:
        from access_analyzer import start_generation
        start_generation(ctx, [e["arn"] for e in to_analyse], aa_cfg["trail_arn"], aa_cfg["role_arn"])

    for e in entities:
        api, name, kind = e["api"], e["name"], e["kind"]
        if e["issues"]:
            sev = min((i["severity"] for i in e["issues"]), key=SEV_RANK.get)
            pol_name = _safe_policy_name(name)
            suggestion, notes = None, []

            # Enrich description with last-used info for roles
            last_used_line = ""
            if kind == "role":
                last_used, last_region = _role_last_used(e["raw"])
                if last_used:
                    if hasattr(last_used, "astimezone"):
                        last_used = last_used.astimezone(timezone.utc)
                    idle = (now - last_used).days
                    last_used_line = (
                        f"\nRole last assumed: {last_used.strftime('%Y-%m-%d')}"
                        + (f" from {last_region}" if last_region else "")
                        + f" ({idle} days ago)."
                    )
                else:
                    last_used_line = "\nRole last assumed: never."

            if e["arn"] in last:
                suggestion, notes = build_least_privilege(last[e["arn"]])
                if suggestion:
                    ctx.suggested_policies[pol_name] = {"entity": e["arn"], "policy": suggestion, "notes": notes}
            else:
                notes = ["No usage data was retrieved (analysis limit/time reached or access denied). "
                         "Re-run with a higher MAX_POLICY_ANALYSIS or use Access Analyzer generation."]
            cmds = []
            if suggestion:
                cmds += [
                    f"# 1) Review/scope the suggested policy (saved as policies/{pol_name}.json), then create it",
                    f"aws iam create-policy --policy-name {shlex.quote(pol_name)} --policy-document file://{pol_name}.json",
                    f"aws iam {api['attach']} {api['flag']} {shlex.quote(name)} --policy-arn arn:aws:iam::{ctx.account_id}:policy/{pol_name}",
                    "# 2) Watch CloudTrail for AccessDenied, then remove the over-permissive policies:",
                ]
            for pi in {(i["policy"], i["type"], i["arn"]) for i in e["issues"]}:
                if pi[1] == "managed":
                    cmds.append(f"aws iam {api['detach']} {api['flag']} {shlex.quote(name)} --policy-arn {pi[2]}")
                else:
                    cmds.append(f"aws iam {api['delete_inline']} {api['flag']} {shlex.quote(name)} --policy-name {shlex.quote(pi[0])}")
            lines = [f"[{i['severity']}] {i['policy']} ({i['type']}): {i['message']}" for i in e["issues"]]
            ctx.add(finding(
                service="IAM", check_id="IAM-LEAST-PRIVILEGE", severity=sev,
                resource=e["arn"],
                title=f"{kind.capitalize()} '{name}' has over-permissive policies",
                description="\n".join(lines) + last_used_line,
                remediation=("Replace the broad policies with a least-privilege policy based on what this identity "
                             "actually uses. Attach the new policy first, validate, then detach the old ones."),
                fix_commands=cmds, suggested_policy=suggestion,
                details={"notes": notes, "suggested_policy_name": pol_name if suggestion else None,
                         "access_analyzer_job_id": ctx.access_analyzer_jobs.get(e["arn"])}))
        for sev, code, msg in e["trust"]:
            ctx.add(finding(
                service="IAM", check_id=f"IAM-{code}", severity=sev, resource=e["arn"],
                title=f"Role '{name}': risky trust policy",
                description=msg,
                remediation="Restrict the trusted principal and add conditions "
                            "(sts:ExternalId / aws:PrincipalOrgID for cross-account, exact ':sub' for IRSA).",
                fix_commands=[f"aws iam update-assume-role-policy --role-name {shlex.quote(name)} --policy-document file://trust-fixed.json"]))

    ctx.safe("iam:credential-report", _credential_report, ctx, iam)
    ctx.safe("iam:password-policy", _password_policy, ctx, iam)

# Services where ACTION_LEVEL tracking covers management actions only
PARTIAL_TRACKING = {"s3", "lambda"}
KEY_MAX_AGE_DAYS = 90

ENTITY_API = {
    "role": dict(list="list_roles", key="Roles", name="RoleName",
                 attached="list_attached_role_policies", inline_names="list_role_policies",
                 inline_get="get_role_policy", attach="attach-role-policy",
                 detach="detach-role-policy", delete_inline="delete-role-policy",
                 flag="--role-name"),
    "user": dict(list="list_users", key="Users", name="UserName",
                 attached="list_attached_user_policies", inline_names="list_user_policies",
                 inline_get="get_user_policy", attach="attach-user-policy",
                 detach="detach-user-policy", delete_inline="delete-user-policy",
                 flag="--user-name"),
    "group": dict(list="list_groups", key="Groups", name="GroupName",
                  attached="list_attached_group_policies", inline_names="list_group_policies",
                  inline_get="get_group_policy", attach="attach-group-policy",
                  detach="detach-group-policy", delete_inline="delete-group-policy",
                  flag="--group-name"),
}


#  Policy analysis
def analyze_policy_document(doc):
    # Return a list of {severity, code, message} for risky Allow statements
    issues = []
    for i, st in enumerate(as_list((doc or {}).get("Statement"))):
        if st.get("Effect") != "Allow":
            continue
        sid = st.get("Sid") or f"#{i}"
        actions = [str(a) for a in as_list(st.get("Action"))]
        resources = [str(r) for r in as_list(st.get("Resource"))]
        res_star = "*" in resources
        scope = "on all resources" if res_star else "on the listed resources"

        if st.get("NotAction") is not None:
            issues.append({"severity": "HIGH", "code": "ALLOW_NOTACTION",
                           "message": f"Statement {sid}: Allow + NotAction grants everything except the listed actions."})
        for a in actions:
            al = a.lower()
            if al == "*":
                issues.append({"severity": "CRITICAL" if res_star else "HIGH", "code": "ACTION_STAR",
                               "message": f"Statement {sid}: Action '*' {scope} (full admin)."})
            elif al.endswith(":*"):
                issues.append({"severity": "HIGH" if res_star else "MEDIUM", "code": "SERVICE_WILDCARD",
                               "message": f"Statement {sid}: '{a}' grants every {a.split(':')[0]} action {scope}."})
        esc = sorted({a for a in actions if a.lower() in PRIV_ESC_ACTIONS})
        if esc and res_star:
            issues.append({"severity": "HIGH", "code": "PRIV_ESCALATION",
                           "message": f"Statement {sid}: {', '.join(esc)} on '*' can allow privilege escalation."})
        if res_star and not st.get("Condition") and any(
                a.lower() in ("iam:passrole",) for a in actions):
            issues.append({"severity": "HIGH", "code": "PASSROLE_STAR",
                           "message": f"Statement {sid}: iam:PassRole on '*' without conditions."})
    # de-duplicate
    seen, out = set(), []
    for it in issues:
        k = (it["code"], it["message"])
        if k not in seen:
            seen.add(k)
            out.append(it)
    return out


def _trust_issues(role, account_id):
    doc = role.get("AssumeRolePolicyDocument") or {}
    out = []
    for st in as_list(doc.get("Statement")):
        if st.get("Effect") != "Allow":
            continue
        principal = st.get("Principal", {})
        cond = st.get("Condition") or {}
        cond_keys = {k.lower() for op in cond.values() if isinstance(op, dict) for k in op}
        aws, fed = [], []
        if principal == "*":
            aws = ["*"]
        elif isinstance(principal, dict):
            aws, fed = as_list(principal.get("AWS")), as_list(principal.get("Federated"))

        if "*" in aws:
            out.append(("CRITICAL" if not cond else "HIGH", "TRUST_WILDCARD",
                        "Trust policy allows ANY AWS principal to assume this role."))
        for a in aws:
            m = re.search(r"(\d{12})", str(a))
            if m and m.group(1) != account_id and not (
                    {"sts:externalid", "aws:principalorgid"} & cond_keys):
                out.append(("MEDIUM", "TRUST_CROSS_ACCOUNT",
                            f"Trusts external account {m.group(1)} without sts:ExternalId or aws:PrincipalOrgID."))
        for f in fed:
            if "oidc-provider" in str(f):
                sub_vals = [v for op in cond.values() if isinstance(op, dict)
                            for k, val in op.items() if k.lower().endswith(":sub")
                            for v in as_list(val)]
                if not sub_vals:
                    out.append(("HIGH", "TRUST_OIDC_NO_SUB",
                                "OIDC/IRSA trust has no ':sub' condition, so any service account/identity "
                                "from that provider can assume the role."))
                elif any("*" in str(v) for v in sub_vals):
                    out.append(("MEDIUM", "TRUST_OIDC_WILDCARD_SUB",
                                "OIDC/IRSA trust uses a wildcard ':sub'; pin it to one namespace:serviceaccount."))
    return out


# Least privilege
def _collect_last_accessed(iam, job_id):
    services, marker = [], None
    while True:
        kw = {"JobId": job_id}
        if marker:
            kw["Marker"] = marker
        r = iam.get_service_last_accessed_details(**kw)
        services.extend(r.get("ServicesLastAccessed", []))
        if r.get("IsTruncated"):
            marker = r.get("Marker")
        else:
            return services


def fetch_last_accessed(iam, arns, deadline):
    jobs, results = {}, {}
    for arn in arns:
        try:
            jobs[arn] = iam.generate_service_last_accessed_details(
                Arn=arn, Granularity="ACTION_LEVEL")["JobId"]
        except Exception:  # noqa: BLE001
            continue
    pending = dict(jobs)
    while pending and time.time() < deadline:
        for arn, job in list(pending.items()):
            try:
                r = iam.get_service_last_accessed_details(JobId=job)
            except Exception:  # noqa: BLE001
                del pending[arn]
                continue
            if r["JobStatus"] == "COMPLETED":
                results[arn] = _collect_last_accessed(iam, job)
                del pending[arn]
            elif r["JobStatus"] == "FAILED":
                del pending[arn]
        if pending:
            time.sleep(2)
    return results


def build_least_privilege(services):
    tracked, review, unused = set(), set(), []
    for s in services:
        ns = s["ServiceNamespace"]
        if not s.get("LastAuthenticated"):
            unused.append(ns)
            continue
        acts = [t["ActionName"] for t in s.get("TrackedActionsLastAccessed", [])
                if t.get("LastAccessedTime")]
        for a in acts:
            tracked.add(a if ":" in a else f"{ns}:{a}")
        if not acts or ns in PARTIAL_TRACKING:
            review.add(ns)
    statements = []
    if tracked:
        statements.append({"Sid": "ObservedActions", "Effect": "Allow",
                           "Action": sorted(tracked),
                           "Resource": "*"})
    if review:
        statements.append({"Sid": "ReviewAndNarrowThese", "Effect": "Allow",
                           "Action": sorted(f"{ns}:*" for ns in review), "Resource": "*"})
    notes = [
        "Resource is '*' in this draft - scope each statement to the real ARNs (buckets, queues, secrets, ...).",
        "Actions were derived from IAM service-last-accessed data. Data-plane actions "
        "(e.g. s3:GetObject, sqs:SendMessage) are not tracked at action level.",
    ]
    if review:
        notes.append("Statement 'ReviewAndNarrowThese' is service-level because action-level data was "
                     f"unavailable for: {', '.join(sorted(review))}. Replace it with exact actions using the "
                     "Access Analyzer policy generation output (see README).")
    if unused:
        notes.append(f"Services allowed but NOT used in the tracking period (removed): {', '.join(sorted(unused)[:40])}")
    if not statements:
        notes.append("No service usage found in the tracking period - consider deleting this identity.")
        return None, notes
    return {"Version": "2012-10-17", "Statement": statements}, notes


# Main scan in IAM
def _paginate(iam, op, key, **kw):
    return list(iam.get_paginator(op).paginate(**kw).search(f"{key}[]"))


def _managed_doc(iam, arn, cache):
    if arn not in cache:
        p = iam.get_policy(PolicyArn=arn)["Policy"]
        cache[arn] = iam.get_policy_version(
            PolicyArn=arn, VersionId=p["DefaultVersionId"])["PolicyVersion"]["Document"]
    return cache[arn]


def _entity_issues(iam, api, name, cache):
    results = []
    for p in _paginate(iam, api["attached"], "AttachedPolicies", **{api["name"]: name}):
        pname, parn = p["PolicyName"], p["PolicyArn"]
        if parn.startswith("arn:aws:iam::aws:policy/"):
            sev = RISKY_AWS_MANAGED.get(pname) or ("MEDIUM" if pname.endswith("FullAccess") else None)
            if sev:
                results.append({"policy": pname, "type": "managed", "arn": parn, "severity": sev,
                                "message": f"AWS managed policy '{pname}' is broader than a workload normally needs."})
            continue
        for it in analyze_policy_document(_managed_doc(iam, parn, cache)):
            results.append({"policy": pname, "type": "managed", "arn": parn, **it})
    for pname in _paginate(iam, api["inline_names"], "PolicyNames", **{api["name"]: name}):
        doc = getattr(iam, api["inline_get"])(**{api["name"]: name, "PolicyName": pname})["PolicyDocument"]
        for it in analyze_policy_document(doc):
            results.append({"policy": pname, "type": "inline", "arn": None, **it})
    return results


def _safe_policy_name(name):
    return re.sub(r"[^A-Za-z0-9+=,.@_-]", "-", name)[:100] + "-least-privilege"


def scan(ctx, max_analysis=25, deadline=None, aa_cfg=None):
    iam = ctx.client("iam")
    deadline = deadline or time.time() + 300
    cache, entities = {}, []

    for kind, api in ENTITY_API.items():
        items = ctx.safe(f"iam:list-{kind}s", _paginate, iam, api["list"], api["key"]) or []
        for ent in items:
            path = ent.get("Path", "")
            if path.startswith("/aws-service-role/") or path.startswith("/aws-reserved/"):
                continue
            name, arn = ent[api["name"]], ent["Arn"]
            issues = ctx.safe(f"iam:policies:{kind}:{name}", _entity_issues, iam, api, name, cache) or []
            trust = _trust_issues(ent, ctx.account_id) if kind == "role" else []
            if issues or trust:
                entities.append({"kind": kind, "name": name, "arn": arn, "api": api,
                                 "issues": issues, "trust": trust})

    # Least privilege suggestions for the worst offenders
    perm_entities = [e for e in entities if e["issues"] and e["kind"] in ("role", "user")]
    perm_entities.sort(key=lambda e: min(SEV_RANK[i["severity"]] for i in e["issues"]))
    to_analyse = perm_entities[:max_analysis]
    last = fetch_last_accessed(iam, [e["arn"] for e in to_analyse], deadline) if to_analyse else {}
    if aa_cfg and to_analyse:
        from access_analyzer import start_generation
        start_generation(ctx, [e["arn"] for e in to_analyse], aa_cfg["trail_arn"], aa_cfg["role_arn"])

    for e in entities:
        api, name, kind = e["api"], e["name"], e["kind"]
        if e["issues"]:
            sev = min((i["severity"] for i in e["issues"]), key=SEV_RANK.get)
            pol_name = _safe_policy_name(name)
            suggestion, notes = None, []
            if e["arn"] in last:
                suggestion, notes = build_least_privilege(last[e["arn"]])
                if suggestion:
                    ctx.suggested_policies[pol_name] = {"entity": e["arn"], "policy": suggestion, "notes": notes}
            else:
                notes = ["No usage data was retrieved (analysis limit/time reached or access denied). "
                         "Re-run with a higher MAX_POLICY_ANALYSIS or use Access Analyzer generation."]
            cmds = []
            if suggestion:
                cmds += [
                    f"# 1) Review/scope the suggested policy (saved as policies/{pol_name}.json), then create it",
                    f"aws iam create-policy --policy-name {shlex.quote(pol_name)} --policy-document file://{pol_name}.json",
                    f"aws iam {api['attach']} {api['flag']} {shlex.quote(name)} --policy-arn arn:aws:iam::{ctx.account_id}:policy/{pol_name}",
                    "# 2) Watch CloudTrail for AccessDenied, then remove the over-permissive policies:",
                ]
            for pi in {(i["policy"], i["type"], i["arn"]) for i in e["issues"]}:
                if pi[1] == "managed":
                    cmds.append(f"aws iam {api['detach']} {api['flag']} {shlex.quote(name)} --policy-arn {pi[2]}")
                else:
                    cmds.append(f"aws iam {api['delete_inline']} {api['flag']} {shlex.quote(name)} --policy-name {shlex.quote(pi[0])}")
            lines = [f"[{i['severity']}] {i['policy']} ({i['type']}): {i['message']}" for i in e["issues"]]
            ctx.add(finding(
                service="IAM", check_id="IAM-LEAST-PRIVILEGE", severity=sev,
                resource=e["arn"],
                title=f"{kind.capitalize()} '{name}' has over-permissive policies",
                description="\n".join(lines),
                remediation=("Replace the broad policies with a least-privilege policy based on what this identity "
                             "actually uses. Attach the new policy first, validate, then detach the old ones."),
                fix_commands=cmds, suggested_policy=suggestion,
                details={"notes": notes, "suggested_policy_name": pol_name if suggestion else None,
                         "access_analyzer_job_id": ctx.access_analyzer_jobs.get(e["arn"])}))
        for sev, code, msg in e["trust"]:
            ctx.add(finding(
                service="IAM", check_id=f"IAM-{code}", severity=sev, resource=e["arn"],
                title=f"Role '{name}': risky trust policy",
                description=msg,
                remediation="Restrict the trusted principal and add conditions "
                            "(sts:ExternalId / aws:PrincipalOrgID for cross-account, exact ':sub' for IRSA).",
                fix_commands=[f"aws iam update-assume-role-policy --role-name {shlex.quote(name)} --policy-document file://trust-fixed.json"]))

    ctx.safe("iam:credential-report", _credential_report, ctx, iam)
    ctx.safe("iam:password-policy", _password_policy, ctx, iam)


def _parse_dt(s):
    if not s or s in ("N/A", "no_information", "not_supported"):
        return None
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def _credential_report(ctx, iam):
    for _ in range(15):
        if iam.generate_credential_report()["State"] == "COMPLETE":
            break
        time.sleep(2)
    content = iam.get_credential_report()["Content"].decode("utf-8")
    now = datetime.now(timezone.utc)
    for row in csv.DictReader(io.StringIO(content)):
        user = row["user"]
        if user == "<root_account>":
            if row.get("access_key_1_active") == "true" or row.get("access_key_2_active") == "true":
                ctx.add(finding(service="IAM", check_id="IAM-ROOT-KEYS", severity="CRITICAL",
                                resource="root", title="Root account has active access keys",
                                description="Root access keys give unrestricted, un-scopable access.",
                                remediation="Delete the root access keys; use IAM roles/Identity Center instead.",
                                fix_commands=["# Sign in as root > Security credentials > delete access keys"]))
            if row.get("mfa_active") != "true":
                ctx.add(finding(service="IAM", check_id="IAM-ROOT-MFA", severity="CRITICAL",
                                resource="root", title="Root account has no MFA",
                                description="The root user is not protected by MFA.",
                                remediation="Enable a hardware or virtual MFA device on the root user.",
                                fix_commands=["# Sign in as root > Security credentials > Assign MFA device"]))
            continue
        arn = row["arn"]
        if row.get("password_enabled") == "true" and row.get("mfa_active") != "true":
            ctx.add(finding(service="IAM", check_id="IAM-USER-NO-MFA", severity="HIGH", resource=arn,
                            title=f"Console user '{user}' has no MFA",
                            description="User can sign in to the console with a password only.",
                            remediation="Require MFA (attach a policy that denies actions unless aws:MultiFactorAuthPresent) "
                                        "or move users to IAM Identity Center.",
                            fix_commands=[f"aws iam create-virtual-mfa-device --virtual-mfa-device-name {shlex.quote(user)} "
                                          "--outfile qr.png --bootstrap-method QRCodePNG"]))
        for n in ("1", "2"):
            if row.get(f"access_key_{n}_active") != "true":
                continue
            rotated = _parse_dt(row.get(f"access_key_{n}_last_rotated"))
            used = _parse_dt(row.get(f"access_key_{n}_last_used_date"))
            age = (now - rotated).days if rotated else None
            idle = (now - used).days if used else None
            if age is not None and age > KEY_MAX_AGE_DAYS:
                ctx.add(finding(service="IAM", check_id="IAM-KEY-OLD", severity="MEDIUM", resource=arn,
                                title=f"Access key {n} of '{user}' is {age} days old",
                                description=f"Keys should be rotated at least every {KEY_MAX_AGE_DAYS} days.",
                                remediation="Create a new key, update the consumer (Jenkins/Bitbucket variables), "
                                            "then deactivate and delete the old key. Prefer OIDC/roles over long-lived keys.",
                                fix_commands=[f"aws iam create-access-key --user-name {shlex.quote(user)}",
                                              f"aws iam update-access-key --user-name {shlex.quote(user)} --access-key-id <OLD_KEY_ID> --status Inactive"]))
            if used is None and age is not None and age > 30:
                ctx.add(finding(service="IAM", check_id="IAM-KEY-UNUSED", severity="LOW", resource=arn,
                                title=f"Access key {n} of '{user}' was never used",
                                description="Active key that has never been used.",
                                remediation="Delete the key if not needed.",
                                fix_commands=[f"aws iam delete-access-key --user-name {shlex.quote(user)} --access-key-id <KEY_ID>"]))
            elif idle is not None and idle > KEY_MAX_AGE_DAYS:
                ctx.add(finding(service="IAM", check_id="IAM-KEY-IDLE", severity="MEDIUM", resource=arn,
                                title=f"Access key {n} of '{user}' unused for {idle} days",
                                description="Dormant credentials are a common compromise path.",
                                remediation="Deactivate then delete the key.",
                                fix_commands=[f"aws iam update-access-key --user-name {shlex.quote(user)} --access-key-id <KEY_ID> --status Inactive"]))


def _password_policy(ctx, iam):
    try:
        pp = iam.get_account_password_policy()["PasswordPolicy"]
    except iam.exceptions.NoSuchEntityException:
        ctx.add(finding(service="IAM", check_id="IAM-PWD-POLICY", severity="MEDIUM", resource="account",
                        title="No account password policy configured",
                        description="Default AWS password rules are weak.",
                        remediation="Set a strong password policy.",
                        fix_commands=["aws iam update-account-password-policy --minimum-password-length 14 "
                                      "--require-symbols --require-numbers --require-uppercase-characters "
                                      "--require-lowercase-characters --max-password-age 90 --password-reuse-prevention 24"]))
        return
    if pp.get("MinimumPasswordLength", 0) < 14:
        ctx.add(finding(service="IAM", check_id="IAM-PWD-LENGTH", severity="LOW", resource="account",
                        title=f"Minimum password length is {pp.get('MinimumPasswordLength')}",
                        description="Recommended minimum is 14.",
                        remediation="Increase the minimum password length.",
                        fix_commands=["aws iam update-account-password-policy --minimum-password-length 14"]))
