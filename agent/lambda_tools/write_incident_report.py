import json
import os
from datetime import datetime, timezone
import boto3

s3 = boto3.client("s3")

BUCKET = os.environ.get("BUCKET_NAME")
REPORTS_PREFIX = os.environ.get("REPORTS_PREFIX", "incident-reports")


def parse_parameters(event):
    return {p["name"]: p["value"] for p in event.get("parameters", [])}


def bedrock_response(event, body):
    return {
        "messageVersion": "1.0",
        "response": {
            "actionGroup": event.get("actionGroup"),
            "function": event.get("function"),
            "functionResponse": {
                "responseBody": {
                    "TEXT": {"body": json.dumps(body)}
                }
            },
        },
    }


def build_markdown(p):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    return (
        f"# Incident Report — {p.get('title', 'Untitled')}\n\n"
        f"**Generated:** {now}\n"
        f"**Severity:** {p.get('severity', 'unknown').upper()}\n"
        f"**Affected user:** {p.get('affected_user', 'unknown')}\n"
        f"**Anomaly score:** {p.get('anomaly_score', 'n/a')}\n\n"
        f"## What happened\n\n{p.get('narrative', 'No narrative provided.')}\n\n"
        f"## Why this looks suspicious\n\n{p.get('reasoning', 'No reasoning provided.')}\n\n"
        f"## Evidence\n\n{p.get('evidence', 'No evidence provided.')}\n\n"
        f"## Recommended next steps\n\n{p.get('recommendations', 'No recommendations provided.')}\n"
    )


def lambda_handler(event, context):
    params = parse_parameters(event)

    required = ["title", "severity", "affected_user", "narrative",
                "reasoning", "evidence", "recommendations"]
    missing = [r for r in required if not params.get(r)]
    if missing:
        return bedrock_response(event, {
            "error": f"Missing required parameters: {', '.join(missing)}"
        })

    severity = params.get("severity", "").lower()
    if severity not in {"low", "medium", "high", "critical"}:
        return bedrock_response(event, {
            "error": "severity must be one of: low, medium, high, critical"
        })

    body = build_markdown(params)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safe_user = "".join(c if c.isalnum() else "_" for c in params["affected_user"])
    key = f"{REPORTS_PREFIX}/{timestamp}_{safe_user}_{severity}.md"

    s3.put_object(
        Bucket=BUCKET,
        Key=key,
        Body=body.encode("utf-8"),
        ContentType="text/markdown",
    )

    return bedrock_response(event, {
        "status": "written",
        "s3_uri": f"s3://{BUCKET}/{key}",
        "severity": severity,
        "title": params["title"],
        "console_url": f"https://s3.console.aws.amazon.com/s3/object/{BUCKET}?prefix={key}",
    })
