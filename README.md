# AWS Security Audit Lambda

Read-only Lambda that audits IAM (least privilege, trust policies, keys, MFA), S3, security groups,
EC2/EBS, ALB/NLB, EKS, Lambda, CloudTrail and GuardDuty, then writes `report.html`, `report.json`,
`findings.csv` and suggested least-privilege policies (`policies/*.json`) to a locked-down S3 bucket.
It never changes anything in your account. Fixes are printed as commands for you to review and run.

## Files
| File | Purpose |
|---|---|
| `lambda_function.py` | Handler (`lambda_function.lambda_handler`) |
| `iam_checks.py` | Policy analysis, trust policies, credential report, least-privilege generation |
| `access_analyzer.py` | Optional CloudTrail-based, resource-scoped policy generation |
| `s3_checks.py`, `infra_checks.py` | S3, SG/EC2/EBS/VPC, ALB, EKS, Lambda, CloudTrail, GuardDuty |
| `report.py`, `common.py` | Report building/upload, shared helpers |
| `lambda-execution-policy.json`, `lambda-trust-policy.json`, `report-bucket-policy.json` | IAM/S3 policy templates |

## Setup (AWS CLI; replace the UPPERCASE values; use the region you want to run in)
```bash
export AWS_REGION=eu-west-2
export ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text --profile dev)
export REPORT_BUCKET=security-audit-reports-$ACCOUNT_ID


# 1) Locked-down report bucket
aws s3api create-bucket --bucket $REPORT_BUCKET --region $AWS_REGION \
  --create-bucket-configuration LocationConstraint=$AWS_REGION      # omit the flag in us-east-1
aws s3api put-public-access-block --bucket $REPORT_BUCKET --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
aws s3api put-bucket-ownership-controls --bucket $REPORT_BUCKET \
  --ownership-controls 'Rules=[{ObjectOwnership=BucketOwnerEnforced}]'
aws s3api put-bucket-versioning --bucket $REPORT_BUCKET --versioning-configuration Status=Enabled
sed "s/REPORT_BUCKET/$REPORT_BUCKET/g" report-bucket-policy.json > /tmp/bucket-policy.json
aws s3api put-bucket-policy --bucket $REPORT_BUCKET --policy file:///tmp/bucket-policy.json
aws s3api put-bucket-lifecycle-configuration --bucket $REPORT_BUCKET --lifecycle-configuration \
  '{"Rules":[{"ID":"expire-old-reports","Status":"Enabled","Filter":{"Prefix":"reports/"},"Expiration":{"Days":365},"NoncurrentVersionExpiration":{"NoncurrentDays":30}}]}'

# 2) Execution role
aws iam create-role --role-name security-audit-lambda --assume-role-policy-document file://lambda-trust-policy.json
aws iam attach-role-policy --role-name security-audit-lambda \
  --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
sed -e "s/REPORT_BUCKET/$REPORT_BUCKET/g" -e "s/ACCOUNT_ID/$ACCOUNT_ID/g" \
  lambda-execution-policy.json > /tmp/exec-policy.json
aws iam put-role-policy --role-name security-audit-lambda --policy-name audit-permissions --policy-document file:///tmp/exec-policy.json

# 3) Package + create the function (no third-party dependencies; boto3 is in the runtime)
zip -r audit.zip *.py
aws lambda create-function --function-name security-audit --runtime python3.12 --architectures arm64 \
  --handler lambda_function.lambda_handler --timeout 900 --memory-size 512 \
  --role arn:aws:iam::$ACCOUNT_ID:role/security-audit-lambda --zip-file fileb://audit.zip \
  --environment "Variables={REPORT_BUCKET=$REPORT_BUCKET,REGIONS=eu-west-1,eu-west-2,us-east-1,us-east-2,us-west-2,ap-south-1,MAX_POLICY_ANALYSIS=100}"
# (wait ~10s after creating the role the first time)

# 4) Run it on demand
aws lambda invoke --function-name security-audit --cli-read-timeout 900 --payload '{}' --cli-binary-format raw-in-base64-out out.json && cat out.json

# 5) Read the report
aws s3 ls s3://$REPORT_BUCKET/reports/ --recursive
aws s3 cp s3://$REPORT_BUCKET/reports/<date>/<run-id>/report.html .
```
Updating code later: `zip -r audit.zip *.py && aws lambda update-function-code --function-name security-audit --zip-file fileb://audit.zip`

Event options: `{"regions":["eu-west-2","us-east-1"],"skip":["lambda","guardduty"],"max_policy_analysis":10}`.
Set `REGIONS` (comma separated) to cover every region where you run EC2/EKS/ALB.

## Rolling out a least-privilege policy safely
1. Open the IAM finding and the `policies/<name>-least-privilege.json` file.
2. Scope `Resource` to real ARNs and replace the `ReviewAndNarrowThese` statement with exact actions
   (see the optional step below).
3. `create-policy`, attach it to the role **alongside** the old policies, deploy via Jenkins/Bitbucket in a non-prod environment.
4. Check CloudTrail for `AccessDenied` for that role, then detach the old policies (commands are in the finding).
For CodeDeploy, EKS node and IRSA roles, test a full deployment before detaching.

## Optional: resource-scoped policies with IAM Access Analyzer
Needs a CloudTrail trail (add S3 data events for object-level actions). Create a role
`AccessAnalyzerMonitorServiceRole-Audit` that trusts `access-analyzer.amazonaws.com` and can read the trail's S3 bucket
(plus `cloudtrail:GetTrail`/`DescribeTrails`), then set `ACCESS_ANALYZER_ROLE_ARN` and `CLOUDTRAIL_ARN` env vars.
The next run starts a generation job per flagged identity (job IDs are listed in the report). A few minutes later:
```bash
aws lambda invoke --function-name security-audit --cli-binary-format raw-in-base64-out \
  --payload '{"action":"fetch_generated_policy","job_id":"<JOB_ID>"}' out.json
```
The generated policy is written to `s3://$REPORT_BUCKET/access-analyzer/<job>.json`.

## Security notes
- The report lists your weaknesses: grant `s3:GetObject` on the bucket to a small admin/security role only, and keep KMS key access equally narrow.
- Env var **values**, secrets and credentials are never read into the report (only variable names).
- `PRESIGN_SECONDS` (default 0 = off) can return a temporary link; leave it off unless you need to share.
- Findings are point-in-time. Some are expected (e.g. a public ALB with ports 80/443 open; an intentionally public website bucket).
- Single account only. For multiple accounts, deploy per account or assume a read-only audit role in each.
- Limits: least-privilege drafts use IAM last-accessed data (management actions for EC2/IAM/Lambda/S3 only), hence the review step above.
