"""AWS security audit Lambda (read-only). Entry point: lambda_function.lambda_handler

Environment variables
  REPORT_BUCKET            (required) bucket for reports, must be in the Lambda's region
  REGIONS                  comma list, default = Lambda's region
  MAX_POLICY_ANALYSIS      identities to analyse for least-privilege policies (default 25)
  PRESIGN_SECONDS          >0 returns a temporary link to report.html (default 0 = off)
  ACCESS_ANALYZER_ROLE_ARN + CLOUDTRAIL_ARN   optional CloudTrail-based policy generation

Event (all optional): {"regions": ["eu-west-2"], "skip": ["s3","iam","lambda"], "max_policy_analysis": 10}
Event to fetch Access Analyzer output: {"action": "fetch_generated_policy", "job_id": "..."}
"""
import json
import logging
import os
import time
import uuid
from datetime import datetime, timezone

import boto3
from botocore.config import Config

import access_analyzer
import iam_checks
import infra_checks
import report
import s3_checks
from common import Context

log = logging.getLogger()
log.setLevel(logging.INFO)


def _remaining(context):
    try:
        return context.get_remaining_time_in_millis() / 1000
    except Exception:  # noqa: BLE001  (local runs)
        return 600


def lambda_handler(event, context):
    event = event or {}
    bucket = os.environ["REPORT_BUCKET"]
    home = os.environ.get("AWS_REGION", "us-west-1")
    s3 = boto3.client("s3", region_name=home, config=Config(signature_version="s3v4"))

    if event.get("action") == "fetch_generated_policy":
        aa = boto3.client("accessanalyzer", region_name=home)
        result = access_analyzer.fetch_generated_policy(aa, event["job_id"])
        key = f"access-analyzer/{event['job_id']}.json"
        report._put(s3, bucket, key, json.dumps(result, indent=2), "application/json", None)
        return {"status": result["status"], "s3_key": key if result["policies"] else None}

    regions = event.get("regions") or [r.strip() for r in os.environ.get("REGIONS", "eu-west-1,eu-west-2,us-east-1,us-east-2,us-west-2,ap-south-1").split(",") if r.strip()]
    skip = {x.lower() for x in event.get("skip", [])}
    max_analysis = int(event.get("max_policy_analysis") or os.environ.get("MAX_POLICY_ANALYSIS", 100))
    run_id = f"{datetime.now(timezone.utc):%H%M%S}-{uuid.uuid4().hex[:8]}"
    ctx = Context(regions, home)
    t0 = time.time()
    deadline = t0 + _remaining(context) - 120   # keep 2 min to write the report

    # network / compute / detective controls (per region)
    for region in regions:
        for name, fn in (("ec2", infra_checks.scan_ec2_vpc), ("elb", infra_checks.scan_load_balancers),
                         ("eks", infra_checks.scan_eks), ("lambda", infra_checks.scan_lambda),
                         ("guardduty", infra_checks.scan_guardduty)):
            if name not in skip:
                ctx.safe(f"{name}:{region}", fn, ctx, region)
    if "cloudtrail" not in skip:
        ctx.safe("cloudtrail", infra_checks.scan_cloudtrail, ctx)

    # S3
    if "s3" not in skip:
        s3_checks.scan(ctx)

    # IAM last (it waits on IAM background jobs)
    if "iam" not in skip:
        aa_cfg = None
        if os.environ.get("ACCESS_ANALYZER_ROLE_ARN") and os.environ.get("CLOUDTRAIL_ARN"):
            aa_cfg = {"role_arn": os.environ["ACCESS_ANALYZER_ROLE_ARN"], "trail_arn": os.environ["CLOUDTRAIL_ARN"]}
        iam_checks.scan(ctx, max_analysis=max_analysis, deadline=deadline, aa_cfg=aa_cfg)

    rep = report.build_report(ctx, run_id, regions)
    base, files = report.upload(s3, bucket, rep)
    log.info("audit done in %.0fs: %s", time.time() - t0, json.dumps(rep["summary"]["by_severity"]))

    out = {"status": "ok", "run_id": run_id, "summary": rep["summary"],
           "report": {"bucket": bucket, "prefix": base, "files": files},
           "coverage_errors": len(rep["coverage_errors"])}
    presign = int(os.environ.get("PRESIGN_SECONDS", 0))
    if presign > 0:
        out["html_url"] = s3.generate_presigned_url(
            "get_object", Params={"Bucket": bucket, "Key": f"{base}/report.html"}, ExpiresIn=presign)
    return out
