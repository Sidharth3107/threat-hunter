import json
import os
from datetime import datetime, timedelta
import boto3

s3 = boto3.client("s3")

BUCKET = os.environ.get("BUCKET_NAME")
DEPLOYMENTS_KEY = os.environ.get("DEPLOYMENTS_KEY", "deployments/events.json")


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


def load_deployments():
    try:
        obj = s3.get_object(Bucket=BUCKET, Key=DEPLOYMENTS_KEY)
        return json.loads(obj["Body"].read())
    except s3.exceptions.NoSuchKey:
        return []


def parse_time(ts):
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def lambda_handler(event, context):
    params = parse_parameters(event)
    event_time = params.get("event_time")
    window_minutes = int(params.get("window_minutes", "60"))

    if not event_time:
        return bedrock_response(event, {"error": "event_time parameter is required (ISO 8601)"})

    try:
        target = parse_time(event_time)
    except (ValueError, AttributeError):
        return bedrock_response(event, {
            "error": f"Could not parse event_time '{event_time}' (expected ISO 8601)"
        })

    window_start = target - timedelta(minutes=window_minutes)
    window_end = target + timedelta(minutes=window_minutes)

    deployments = load_deployments()
    matches = []
    for dep in deployments:
        try:
            dep_time = parse_time(dep["timestamp"])
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

    return bedrock_response(event, {
        "event_time": event_time,
        "window_minutes": window_minutes,
        "deployments_found": len(matches),
        "deployments": matches,
        "explanation": (
            f"Found {len(matches)} scheduled deployment(s) within ±{window_minutes} min of the event."
            if matches else
            f"No scheduled deployments found within ±{window_minutes} min — "
            "the activity is unlikely to be explained by routine maintenance."
        ),
    })
