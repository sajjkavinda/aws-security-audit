# Shared helpers: finding factory and Context (cached boto3 clients, findings, errors)
import logging

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

log = logging.getLogger()

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

_BOTO_CFG = Config(
    retries={"max_attempts": 8, "mode": "adaptive"},
    user_agent_extra="security-audit-lambda",
)


def as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def finding(*, service, check_id, severity, resource, title, description,
            remediation, region="global", fix_commands=None,
            suggested_policy=None, details=None):

    return {
        "service": service,
        "check_id": check_id,
        "severity": severity,
        "region": region,
        "resource": resource,
        "title": title,
        "description": description,
        "remediation": remediation,
        "fix_commands": fix_commands or [],
        "suggested_policy": suggested_policy,
        "details": details or {},
    }


class Context:

    def __init__(self, regions, home_region):
        self.regions = regions
        self.home_region = home_region
        self.session = boto3.session.Session()
        self._clients = {}
        self.findings = []
        self.errors = []
        self.suggested_policies = {}   # policy name -> {"entity", "policy", "notes"}
        self.access_analyzer_jobs = {}  # principal arn -> job id
        self.account_id = self.client("sts").get_caller_identity()["Account"]

    def client(self, service, region=None):
        region = region or self.home_region
        key = (service, region)
        if key not in self._clients:
            self._clients[key] = self.session.client(
                service, region_name=region, config=_BOTO_CFG)
        return self._clients[key]

    def add(self, f):
        self.findings.append(f)

    # Error handling
    def safe(self, label, fn, *args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except ClientError as e:
            err = e.response.get("Error", {})
            self.errors.append({"check": label, "error": err.get("Code", "ClientError"),
                                "message": str(err.get("Message", ""))[:300]})
        except Exception as e:  # noqa: BLE001
            log.exception("check failed: %s", label)
            self.errors.append({"check": label, "error": type(e).__name__,
                                "message": str(e)[:300]})
        return None
