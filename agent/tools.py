import ipaddress
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import boto3
from config import (
    ALERT_SEVERITIES,
    BUCKET_NAME,
    REGION,
    REPORTS_PREFIX,
    SNS_TOPIC_ARN,
)

s3 = boto3.client("s3")
sns = boto3.client("sns", region_name=REGION)

SENSITIVE_APIS = {
    "CreateUser", "AttachUserPolicy", "CreateAccessKey", "PutUserPolicy",
    "AddUserToGroup", "StopLogging", "DisableKey", "CreateRole",
    "AssumeRole", "DeleteBucket",
}

KNOWN_INTERNAL_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]

COMPANY_OFFICE_RANGES = [
    ipaddress.ip_network("203.0.113.0/24"),
]


def _load_s3_json(key, default):
    try:
        obj = s3.get_object(Bucket=BUCKET_NAME, Key=key)
        return json.loads(obj["Body"].read())
    except s3.exceptions.NoSuchKey:
        return default


def get_behavior_baseline(user_name: str) -> dict:
    if not user_name:
        return {"error": "user_name is required"}

    baselines = _load_s3_json("baselines/per_user_baselines.json", {})
    user = baselines.get(user_name.lower())

    if not user:
        return {
            "user": user_name,
            "found": False,
            "message": f"No baseline exists for user '{user_name}'. This user may be new to the account.",
        }

    hours = user.get("typical_hours", [0])
    return {
        "user": user_name,
        "found": True,
        "baseline_period": user.get("baseline_period"),
        "total_baseline_events": user.get("total_events"),
        "typical_ips": user.get("typical_ips", []),
        "typical_hours_utc": sorted(hours),
        "typical_regions": user.get("typical_regions", []),
        "top_apis": user.get("top_apis", [])[:10],
        "average_calls_per_day": user.get("average_calls_per_day"),
        "ever_called_sensitive_api": user.get("ever_called_sensitive_api", False),
        "summary": (
            f"{user_name} normally makes ~{int(user.get('average_calls_per_day', 0))} API calls per day "
            f"from {len(user.get('typical_ips', []))} known IP(s), "
            f"during hours {min(hours)}-{max(hours)} UTC, "
            f"calling {len(user.get('top_apis', []))} distinct APIs."
        ),
    }


def check_threat_intel(ip_address: str) -> dict:
    if not ip_address:
        return {"error": "ip_address is required"}

    try:
        ip = ipaddress.ip_address(ip_address)
    except ValueError:
        return {"ip": ip_address, "error": "Invalid IP address"}

    if any(ip in net for net in KNOWN_INTERNAL_RANGES):
        classification = "internal"
    elif any(ip in net for net in COMPANY_OFFICE_RANGES):
        classification = "company_office"
    elif ip.is_loopback or ip.is_link_local:
        classification = "loopback_or_link_local"
    else:
        classification = "external"

    feed = _load_s3_json("threat-intel/known_bad_ips.json", {})
    threat_record = feed.get(ip_address)

    risk_score = 0
    findings = []

    if classification == "company_office":
        findings.append("IP is in the known company office range (203.0.113.0/24).")
    elif classification == "internal":
        findings.append("IP is in a private/internal range (RFC1918).")
    else:
        findings.append("IP is external (public internet).")
        risk_score += 30

    if threat_record:
        risk_score += int(threat_record.get("confidence", 50))
        findings.append(
            f"IP is on the threat intelligence feed: {threat_record.get('category', 'unknown')} "
            f"(first reported {threat_record.get('first_seen', 'unknown')}, "
            f"confidence {threat_record.get('confidence', 'unknown')}/100)."
        )
    else:
        findings.append("IP is not on the internal threat intelligence feed.")

    risk_score = min(risk_score, 100)
    severity = "high" if risk_score >= 70 else "medium" if risk_score >= 40 else "low"

    return {
        "ip": ip_address,
        "classification": classification,
        "on_threat_feed": bool(threat_record),
        "threat_record": threat_record,
        "risk_score": risk_score,
        "severity": severity,
        "findings": findings,
    }


def get_deployment_events(event_time: str, window_minutes: int = 60) -> dict:
    if not event_time:
        return {"error": "event_time is required (ISO 8601)"}

    try:
        target = datetime.fromisoformat(event_time.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return {"error": f"Could not parse event_time '{event_time}' (expected ISO 8601)"}

    window_start = target - timedelta(minutes=window_minutes)
    window_end = target + timedelta(minutes=window_minutes)

    deployments = _load_s3_json("deployments/events.json", [])
    matches = []
    for dep in deployments:
        try:
            dep_time = datetime.fromisoformat(dep["timestamp"].replace("Z", "+00:00"))
        except (KeyError, ValueError):
            continue
        if window_start <= dep_time <= window_end:
            matches.append({
                "timestamp": dep["timestamp"],
                "name": dep.get("name"),
                "owner": dep.get("owner"),
                "type": dep.get("type", "deployment"),
                "minutes_from_event": round((dep_time - target).total_seconds() / 60, 1),
            })

    return {
        "event_time": event_time,
        "window_minutes": window_minutes,
        "deployments_found": len(matches),
        "deployments": matches,
        "explanation": (
            f"Found {len(matches)} scheduled deployment(s) within ±{window_minutes} min."
            if matches else
            f"No scheduled deployments found within ±{window_minutes} min — "
            "the activity is unlikely to be explained by routine maintenance."
        ),
    }


def write_incident_report(title: str, severity: str, affected_user: str,
                          narrative: str, reasoning: str, evidence: str,
                          recommendations: str, anomaly_score: str = "n/a") -> dict:
    required = {"title": title, "severity": severity, "affected_user": affected_user,
                "narrative": narrative, "reasoning": reasoning, "evidence": evidence,
                "recommendations": recommendations}
    missing = [k for k, v in required.items() if not v]
    if missing:
        return {"error": f"Missing required fields: {', '.join(missing)}"}

    severity_l = severity.lower()
    if severity_l not in {"low", "medium", "high", "critical"}:
        return {"error": "severity must be one of: low, medium, high, critical"}

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    body = (
        f"# Incident Report — {title}\n\n"
        f"**Generated:** {now}\n"
        f"**Severity:** {severity_l.upper()}\n"
        f"**Affected user:** {affected_user}\n"
        f"**Anomaly score:** {anomaly_score}\n\n"
        f"## What happened\n\n{narrative}\n\n"
        f"## Why this looks suspicious\n\n{reasoning}\n\n"
        f"## Evidence\n\n{evidence}\n\n"
        f"## Recommended next steps\n\n{recommendations}\n"
    )

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safe_user = "".join(c if c.isalnum() else "_" for c in affected_user)
    key = f"{REPORTS_PREFIX}/{timestamp}_{safe_user}_{severity_l}.md"

    s3.put_object(
        Bucket=BUCKET_NAME,
        Key=key,
        Body=body.encode("utf-8"),
        ContentType="text/markdown",
    )

    s3_uri = f"s3://{BUCKET_NAME}/{key}"
    console_url = f"https://s3.console.aws.amazon.com/s3/object/{BUCKET_NAME}?prefix={key}"

    alert_sent = False
    if severity_l in ALERT_SEVERITIES:
        try:
            short_recs = "\n".join(recommendations.strip().splitlines()[:6])
            email_body = (
                f"SEVERITY: {severity_l.upper()}\n"
                f"USER:     {affected_user}\n"
                f"SCORE:    {anomaly_score}\n\n"
                f"WHAT HAPPENED\n{'-' * 60}\n{narrative}\n\n"
                f"WHY THIS LOOKS SUSPICIOUS\n{'-' * 60}\n{reasoning}\n\n"
                f"RECOMMENDED ACTIONS\n{'-' * 60}\n{short_recs}\n\n"
                f"FULL REPORT\n{'-' * 60}\n"
                f"S3:      {s3_uri}\n"
                f"Console: {console_url}\n"
            )
            sns.publish(
                TopicArn=SNS_TOPIC_ARN,
                Subject=f"[{severity_l.upper()}] {title[:90]}",
                Message=email_body,
            )
            alert_sent = True
        except Exception as e:
            alert_sent = f"failed: {type(e).__name__}: {e}"

    return {
        "status": "written",
        "s3_uri": s3_uri,
        "severity": severity_l,
        "title": title,
        "console_url": console_url,
        "alert_sent": alert_sent,
    }


TOOL_SCHEMAS = [
    {
        "name": "get_behavior_baseline",
        "description": (
            "Look up a user's normal behavior profile: typical IPs, working hours, regions, "
            "most-used APIs, average daily call rate, and whether they have ever called a "
            "sensitive API. Use this to determine whether an observed event is unusual for "
            "this specific user."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "user_name": {
                    "type": "string",
                    "description": "IAM username to look up (e.g. 'alice')",
                },
            },
            "required": ["user_name"],
        },
    },
    {
        "name": "check_threat_intel",
        "description": (
            "Check an IP address against the internal threat intelligence feed and classify "
            "it as internal / company_office / external. Returns a risk score (0-100) and "
            "severity. Use this when an event came from an unfamiliar IP."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "ip_address": {
                    "type": "string",
                    "description": "IPv4 address to check (e.g. '198.51.100.99')",
                },
            },
            "required": ["ip_address"],
        },
    },
    {
        "name": "get_deployment_events",
        "description": (
            "Look up scheduled deployments and maintenance events near the time of an "
            "observed anomaly. Use this to rule out legitimate maintenance as the cause "
            "of unusual activity."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "event_time": {
                    "type": "string",
                    "description": "ISO 8601 UTC timestamp of the anomalous event "
                                   "(e.g. '2024-02-25T02:14:33Z')",
                },
                "window_minutes": {
                    "type": "integer",
                    "description": "How many minutes before/after to search. Default 60.",
                },
            },
            "required": ["event_time"],
        },
    },
    {
        "name": "write_incident_report",
        "description": (
            "Write the final incident report to S3 as Markdown. Call this LAST, after "
            "you have gathered enough evidence from the other tools. The report is what "
            "a human security analyst will read."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "title": {"type": "string", "description": "Short headline for the incident"},
                "severity": {
                    "type": "string",
                    "enum": ["low", "medium", "high", "critical"],
                    "description": "Overall severity assessment",
                },
                "affected_user": {"type": "string", "description": "Username at risk"},
                "anomaly_score": {
                    "type": "string",
                    "description": "The ML anomaly score that triggered the alert",
                },
                "narrative": {
                    "type": "string",
                    "description": "Plain-English description of what happened (2-4 sentences)",
                },
                "reasoning": {
                    "type": "string",
                    "description": "Why this looks suspicious — cite the specific deviations "
                                   "from baseline (2-4 sentences)",
                },
                "evidence": {
                    "type": "string",
                    "description": "Bullet list of the concrete facts gathered from the "
                                   "investigation tools (4-6 bullets)",
                },
                "recommendations": {
                    "type": "string",
                    "description": "Numbered list of concrete next actions a human should "
                                   "take (3-5 items)",
                },
            },
            "required": ["title", "severity", "affected_user", "narrative",
                         "reasoning", "evidence", "recommendations"],
        },
    },
]


TOOL_DISPATCH = {
    "get_behavior_baseline": get_behavior_baseline,
    "check_threat_intel": check_threat_intel,
    "get_deployment_events": get_deployment_events,
    "write_incident_report": write_incident_report,
}


def run_tool(name: str, arguments: dict) -> dict:
    fn = TOOL_DISPATCH.get(name)
    if fn is None:
        return {"error": f"Unknown tool: {name}"}
    try:
        return fn(**arguments)
    except TypeError as e:
        return {"error": f"Bad arguments for {name}: {e}"}
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}
