import json
import gzip
import os
import sys
import tempfile
import uuid
import random
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import boto3
import numpy as np
from datetime import datetime, timedelta
from config import BUCKET_NAME, CLOUDTRAIL_PREFIX, ACCOUNT_ID

USERS = [
    {"name": "alice", "id": "AIDA100000000000001A", "ips": ["203.0.113.10", "203.0.113.11"]},
    {"name": "bob",   "id": "AIDA200000000000002B", "ips": ["203.0.113.20", "203.0.113.21"]},
    {"name": "carol", "id": "AIDA300000000000003C", "ips": ["203.0.113.30"]},
    {"name": "dave",  "id": "AIDA400000000000004D", "ips": ["203.0.113.40", "203.0.113.41"]},
    {"name": "eve",   "id": "AIDA500000000000005E", "ips": ["203.0.113.50"]},
]

NORMAL_API_CALLS = [
    ("s3.amazonaws.com",         "GetObject",              True),
    ("s3.amazonaws.com",         "PutObject",              False),
    ("s3.amazonaws.com",         "ListObjectsV2",          True),
    ("ec2.amazonaws.com",        "DescribeInstances",      True),
    ("ec2.amazonaws.com",        "DescribeSecurityGroups", True),
    ("iam.amazonaws.com",        "GetUser",                True),
    ("iam.amazonaws.com",        "ListRoles",              True),
    ("cloudwatch.amazonaws.com", "GetMetricData",          True),
    ("logs.amazonaws.com",       "DescribeLogGroups",      True),
    ("sts.amazonaws.com",        "GetCallerIdentity",      True),
]

SENSITIVE_API_CALLS = [
    ("iam.amazonaws.com",        "CreateUser",         False),
    ("iam.amazonaws.com",        "AttachUserPolicy",   False),
    ("iam.amazonaws.com",        "CreateAccessKey",    False),
    ("iam.amazonaws.com",        "PutUserPolicy",      False),
    ("iam.amazonaws.com",        "AddUserToGroup",     False),
    ("cloudtrail.amazonaws.com", "StopLogging",        False),
    ("kms.amazonaws.com",        "DisableKey",         False),
    ("iam.amazonaws.com",        "CreateRole",         False),
    ("sts.amazonaws.com",        "AssumeRole",         False),
    ("s3.amazonaws.com",         "DeleteBucket",       False),
]


def build_event(user, source, name, read_only, timestamp, ip, region="us-east-1", error_code=None, is_anomaly=0):
    return {
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": user["id"],
            "arn": f"arn:aws:iam::{ACCOUNT_ID}:user/{user['name']}",
            "accountId": ACCOUNT_ID,
            "userName": user["name"]
        },
        "eventTime": timestamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "eventSource": source,
        "eventName": name,
        "awsRegion": region,
        "sourceIPAddress": ip,
        "userAgent": random.choice([
            "aws-cli/2.9.0 Python/3.11.0",
            "Boto3/1.34.0 Python/3.10.0",
            "console.amazonaws.com"
        ]),
        "errorCode": error_code,
        "requestParameters": {},
        "responseElements": None,
        "requestID": uuid.uuid4().hex.upper()[:20],
        "eventID": str(uuid.uuid4()),
        "readOnly": read_only,
        "eventType": "AwsApiCall",
        "is_anomaly": is_anomaly
    }


def generate_normal_day(date, calls_per_user=60):
    records = []
    for user in USERS:
        is_travel_day = random.random() < 0.05
        travel_ip = f"203.0.113.{random.randint(100, 200)}" if is_travel_day else None

        for _ in range(calls_per_user):
            if random.random() < 0.08:
                hour = random.choice([7, 8, 18, 19, 20])
            else:
                hour = random.randint(9, 17)

            ts = date.replace(hour=hour, minute=random.randint(0, 59), second=random.randint(0, 59))

            if is_travel_day and random.random() < 0.4:
                ip = travel_ip
            else:
                ip = random.choice(user["ips"])

            source, name, read_only = random.choice(NORMAL_API_CALLS)

            if user["name"] == "carol" and random.random() < 0.04:
                source, name, read_only = random.choice(SENSITIVE_API_CALLS)

            error_code = None
            if random.random() < 0.03:
                error_code = random.choice(["AccessDenied", "ThrottlingException", "ValidationError"])

            records.append(build_event(user, source, name, read_only, ts, ip,
                                       error_code=error_code, is_anomaly=0))
    return records


def generate_attack_day(date):
    records = []
    victim = USERS[0]
    attacker_ip = "198.51.100.99"

    for i in range(25):
        ts = date.replace(hour=2, minute=i, second=random.randint(0, 59))
        source, name, read_only = random.choice([c for c in NORMAL_API_CALLS if c[2]])
        records.append(build_event(victim, source, name, read_only, ts, attacker_ip, is_anomaly=1))

    for i in range(20):
        ts = date.replace(hour=2, minute=30 + i, second=random.randint(0, 59))
        source, name, read_only = random.choice(SENSITIVE_API_CALLS)
        records.append(build_event(victim, source, name, read_only, ts, attacker_ip, error_code="AccessDenied", is_anomaly=1))

    for i, (source, name, read_only) in enumerate(SENSITIVE_API_CALLS[:6]):
        ts = date.replace(hour=3, minute=i * 4, second=0)
        records.append(build_event(victim, source, name, read_only, ts, attacker_ip, is_anomaly=1))

    for i in range(60):
        ts = date.replace(hour=3, minute=30 + (i // 60), second=i % 60)
        records.append(build_event(victim, "s3.amazonaws.com", "GetObject", True, ts, attacker_ip, region="eu-west-1", is_anomaly=1))

    return records


def upload_to_s3(records, date):
    payload = {"Records": records}
    filename = f"{uuid.uuid4().hex[:12]}_CloudTrail_us-east-1.json.gz"
    local_path = os.path.join(tempfile.gettempdir(), filename)
    date_path = date.strftime("%Y/%m/%d")

    with gzip.open(local_path, "wt", encoding="utf-8") as f:
        json.dump(payload, f)

    s3_key = f"{CLOUDTRAIL_PREFIX}/AWSLogs/{ACCOUNT_ID}/CloudTrail/us-east-1/{date_path}/{filename}"
    boto3.client("s3").upload_file(local_path, BUCKET_NAME, s3_key)
    os.remove(local_path)
    print(f"{date.strftime('%Y-%m-%d')} — {len(records)} events → s3://{BUCKET_NAME}/{s3_key}")


if __name__ == "__main__":
    random.seed(42)
    np.random.seed(42)

    start_date = datetime(2024, 1, 1)

    for day in range(60):
        current = start_date + timedelta(days=day)
        daily = generate_normal_day(current)

        if day >= 55:
            daily.extend(generate_attack_day(current))

        upload_to_s3(daily, current)

    print("\nDone — 60 days uploaded. Days 56-60 contain planted attack scenarios.")