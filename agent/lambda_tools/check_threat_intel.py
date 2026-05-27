import ipaddress
import json
import os
import boto3

s3 = boto3.client("s3")

BUCKET = os.environ.get("BUCKET_NAME")
THREAT_FEED_KEY = os.environ.get("THREAT_FEED_KEY", "threat-intel/known_bad_ips.json")

KNOWN_INTERNAL_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]

COMPANY_OFFICE_RANGES = [
    ipaddress.ip_network("203.0.113.0/24"),
]


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


def load_threat_feed():
    try:
        obj = s3.get_object(Bucket=BUCKET, Key=THREAT_FEED_KEY)
        return json.loads(obj["Body"].read())
    except s3.exceptions.NoSuchKey:
        return {}


def classify_ip(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return "invalid"

    if any(ip in net for net in KNOWN_INTERNAL_RANGES):
        return "internal"
    if any(ip in net for net in COMPANY_OFFICE_RANGES):
        return "company_office"
    if ip.is_private or ip.is_loopback or ip.is_link_local:
        return "private"
    return "external"


def lambda_handler(event, context):
    params = parse_parameters(event)
    ip = params.get("ip_address", "").strip()

    if not ip:
        return bedrock_response(event, {"error": "ip_address parameter is required"})

    classification = classify_ip(ip)
    feed = load_threat_feed()
    threat_record = feed.get(ip)

    risk_score = 0
    findings = []

    if classification == "invalid":
        return bedrock_response(event, {"ip": ip, "error": "Invalid IP address"})

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

    return bedrock_response(event, {
        "ip": ip,
        "classification": classification,
        "on_threat_feed": bool(threat_record),
        "threat_record": threat_record,
        "risk_score": risk_score,
        "severity": severity,
        "findings": findings,
    })
