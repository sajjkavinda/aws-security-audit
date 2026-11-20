# Checks resource-scoped least-privilege policies via IAM Access Analyzer + CloudTrail
import json
from datetime import datetime, timedelta, timezone


def start_generation(ctx, principal_arns, trail_arn, access_role_arn, days=90):
    aa = ctx.client("accessanalyzer")
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    for arn in principal_arns:
        r = ctx.safe(f"accessanalyzer:start:{arn}", aa.start_policy_generation,
                     policyGenerationDetails={"principalArn": arn},
                     cloudTrailDetails={"trails": [{"cloudTrailArn": trail_arn, "allRegions": True}],
                                        "accessRole": access_role_arn,
                                        "startTime": start, "endTime": end})
        if r:
            ctx.access_analyzer_jobs[arn] = r["jobId"]


def fetch_generated_policy(client, job_id):
    r = client.get_generated_policy(jobId=job_id, includeResourcePlaceholders=True,
                                    includeServiceLevelTemplate=True)
    status = r["jobDetails"]["status"]
    if status != "SUCCEEDED":
        return {"status": status, "policies": []}
    result = r["generatedPolicyResult"]
    return {"status": status,
            "policies": [json.loads(p["policy"]) for p in result.get("generatedPolicies", [])],
            "properties": json.loads(json.dumps(result.get("properties", {}), default=str))}
