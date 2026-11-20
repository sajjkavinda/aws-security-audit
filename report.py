# Build JSON / HTML / CSV reports and store them securely in S3
import csv
import html
import io
import json
from collections import Counter
from datetime import datetime, timezone

from common import SEV_RANK, SEVERITIES

SEV_COLOR = {"CRITICAL": "#b00020", "HIGH": "#d84315", "MEDIUM": "#ef8f00", "LOW": "#1565c0", "INFO": "#607d8b"}


def build_report(ctx, run_id, regions):
    findings = sorted(ctx.findings, key=lambda f: (SEV_RANK[f["severity"]], f["service"], f["resource"]))
    for n, f in enumerate(findings, 1):
        f["id"] = f"F-{n:03d}"
    sev = Counter(f["severity"] for f in findings)
    return {
        "metadata": {"run_id": run_id, "account_id": ctx.account_id, "regions": regions,
                     "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds")},
        "summary": {"total": len(findings),
                    "by_severity": {s: sev.get(s, 0) for s in SEVERITIES},
                    "by_service": dict(Counter(f["service"] for f in findings))},
        "findings": findings,
        "suggested_policies": ctx.suggested_policies,
        "access_analyzer_jobs": ctx.access_analyzer_jobs,
        "coverage_errors": ctx.errors,
    }


def _e(x):
    return html.escape(str(x), quote=True)


def render_html(rep):
    m, s = rep["metadata"], rep["summary"]
    out = ["<!doctype html><html lang='en'><head><meta charset='utf-8'>",
           "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; style-src 'unsafe-inline'\">",
           "<meta name='viewport' content='width=device-width,initial-scale=1'>",
           f"<title>AWS Security Audit {_e(m['run_id'])}</title><style>",
           "body{font-family:system-ui,sans-serif;margin:2rem auto;max-width:1000px;padding:0 1rem;color:#1b1b1b}"
           "h1{margin-bottom:0}.muted{color:#666}.cards{display:flex;gap:.6rem;flex-wrap:wrap;margin:1rem 0}"
           ".card{padding:.6rem 1rem;border-radius:8px;color:#fff;min-width:90px;text-align:center}"
           ".card b{display:block;font-size:1.6rem}.f{border:1px solid #ddd;border-left-width:6px;border-radius:6px;"
           "padding:.8rem 1rem;margin:.8rem 0}pre{background:#f4f4f4;padding:.6rem;overflow:auto;border-radius:4px;font-size:.82rem}"
           ".tag{display:inline-block;color:#fff;border-radius:4px;padding:0 .5rem;font-size:.8rem;margin-right:.4rem}"
           "summary{cursor:pointer;font-weight:600;margin:.4rem 0}table{border-collapse:collapse}td,th{border:1px solid #ddd;padding:.3rem .6rem}"
           "</style></head><body>",
           "<h1>AWS Security Audit</h1>",
           f"<p class='muted'>Account {_e(m['account_id'])} &middot; Regions: {_e(', '.join(m['regions']))} &middot; "
           f"{_e(m['generated_at'])} &middot; Run {_e(m['run_id'])}</p>",
           "<p><b>Confidential:</b> this report describes weaknesses in your environment. Restrict access.</p>",
           "<div class='cards'>"]
    for sev in SEVERITIES:
        out.append(f"<div class='card' style='background:{SEV_COLOR[sev]}'><b>{s['by_severity'][sev]}</b>{sev}</div>")
    out.append("</div>")
    if s["by_service"]:
        out.append("<table><tr><th>Service</th><th>Findings</th></tr>" + "".join(
            f"<tr><td>{_e(k)}</td><td>{v}</td></tr>" for k, v in sorted(s["by_service"].items())) + "</table>")
    out.append("<h2>Findings</h2>")
    for f in rep["findings"]:
        c = SEV_COLOR[f["severity"]]
        out.append(f"<div class='f' style='border-left-color:{c}'><span class='tag' style='background:{c}'>{f['severity']}</span>"
                   f"<b>{_e(f['id'])} &middot; {_e(f['title'])}</b>"
                   f"<div class='muted'>{_e(f['service'])} &middot; {_e(f['region'])} &middot; {_e(f['resource'])}</div>"
                   f"<p style='white-space:pre-wrap'>{_e(f['description'])}</p>"
                   f"<p><b>Solution:</b> {_e(f['remediation'])}</p>")
        for n in f.get("details", {}).get("notes", []):
            out.append(f"<p class='muted'>&#9432; {_e(n)}</p>")
        if f["fix_commands"]:
            out.append("<details><summary>Fix commands</summary><pre>" + _e("\n".join(f["fix_commands"])) + "</pre></details>")
        if f.get("suggested_policy"):
            out.append("<details><summary>Suggested policy</summary><pre>" +
                       _e(json.dumps(f["suggested_policy"], indent=2)) + "</pre></details>")
        out.append("</div>")
    if rep["access_analyzer_jobs"]:
        out.append("<h2>Access Analyzer policy generation jobs</h2><p>Fetch results later with "
                   "<code>{\"action\":\"fetch_generated_policy\",\"job_id\":\"&lt;id&gt;\"}</code></p><table><tr><th>Principal</th><th>Job ID</th></tr>" +
                   "".join(f"<tr><td>{_e(a)}</td><td>{_e(j)}</td></tr>" for a, j in rep["access_analyzer_jobs"].items()) + "</table>")
    if rep["coverage_errors"]:
        out.append("<h2>Coverage gaps</h2><p>These checks could not run (usually missing permissions), so related issues may be missing.</p><table><tr><th>Check</th><th>Error</th></tr>" +
                   "".join(f"<tr><td>{_e(e['check'])}</td><td>{_e(e['error'])}</td></tr>" for e in rep["coverage_errors"]) + "</table>")
    out.append("</body></html>")
    return "".join(out)


def _csv_safe(v):
    v = str(v)
    return "'" + v if v[:1] in ("=", "+", "-", "@", "\t", "\r") else v


def render_csv(rep):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["id", "severity", "service", "region", "resource", "title", "description", "remediation", "fix_commands"])
    for f in rep["findings"]:
        w.writerow([_csv_safe(x) for x in (f["id"], f["severity"], f["service"], f["region"], f["resource"],
                                           f["title"], f["description"], f["remediation"], "\n".join(f["fix_commands"]))])
    return buf.getvalue()


def _put(s3, bucket, key, body, ctype, kms_key):
    args = {"Bucket": bucket, "Key": key, "Body": body.encode("utf-8"), "ContentType": ctype,
            "CacheControl": "no-store"}
    if kms_key:
        args.update(ServerSideEncryption="aws:kms", SSEKMSKeyId=kms_key, BucketKeyEnabled=True)
    else:
        args["ServerSideEncryption"] = "AES256"
    s3.put_object(**args)


def upload(s3, bucket, rep, kms_key=None, prefix="reports"):
    d = datetime.now(timezone.utc)
    base = f"{prefix}/{d:%Y/%m/%d}/{rep['metadata']['run_id']}"
    files = {
        f"{base}/report.json": (json.dumps(rep, indent=2, default=str), "application/json"),
        f"{base}/report.html": (render_html(rep), "text/html; charset=utf-8"),
        f"{base}/findings.csv": (render_csv(rep), "text/csv"),
    }
    for pname, p in rep["suggested_policies"].items():
        files[f"{base}/policies/{pname}.json"] = (json.dumps(p["policy"], indent=2), "application/json")
    for key, (body, ctype) in files.items():
        _put(s3, bucket, key, body, ctype, kms_key)
    return base, sorted(files)
