import io
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import boto3
import pandas as pd
from config import BUCKET_NAME, FEATURES_PREFIX

s3 = boto3.client("s3")

SENSITIVE_APIS = {
    "CreateUser", "AttachUserPolicy", "CreateAccessKey", "PutUserPolicy",
    "AddUserToGroup", "StopLogging", "DisableKey", "CreateRole",
    "AssumeRole", "DeleteBucket",
}


def load_features():
    body = s3.get_object(Bucket=BUCKET_NAME, Key=f"{FEATURES_PREFIX}/features.parquet")["Body"].read()
    return pd.read_parquet(io.BytesIO(body))


def build_per_user_baselines(df, baseline_days=50):
    cutoff = df["event_time"].min() + pd.Timedelta(days=baseline_days)
    baseline = df[df["event_time"] < cutoff]
    period_start = baseline["event_time"].min().strftime("%Y-%m-%d")
    period_end = baseline["event_time"].max().strftime("%Y-%m-%d")

    baselines = {}
    for user, group in baseline.groupby("user_name"):
        api_counts = group["event_name"].value_counts()
        top_apis = [
            {"name": name, "count": int(count)}
            for name, count in api_counts.head(15).items()
        ]
        baselines[user.lower()] = {
            "baseline_period": f"{period_start} to {period_end}",
            "total_events": int(len(group)),
            "typical_ips": sorted(group["source_ip"].unique().tolist()),
            "typical_hours": sorted({int(h) for h in group["hour_of_day"].unique()}),
            "typical_regions": sorted(group["region"].unique().tolist()),
            "top_apis": top_apis,
            "average_calls_per_day": round(len(group) / baseline_days, 1),
            "ever_called_sensitive_api": bool(
                group["event_name"].isin(SENSITIVE_APIS).any()
            ),
        }
    return baselines


def upload_json(key, data):
    s3.put_object(
        Bucket=BUCKET_NAME,
        Key=key,
        Body=json.dumps(data, indent=2).encode("utf-8"),
        ContentType="application/json",
    )
    print(f"  → s3://{BUCKET_NAME}/{key}")


def main():
    print("Building per-user baselines from features.parquet...")
    df = load_features()
    baselines = build_per_user_baselines(df)
    print(f"  Built baselines for {len(baselines)} users")
    upload_json("baselines/per_user_baselines.json", baselines)

    print("\nSeeding threat intelligence feed...")
    threat_feed = {
        "198.51.100.99": {
            "category": "credential-theft / known-attacker",
            "first_seen": "2024-02-25",
            "last_seen": "2024-02-29",
            "confidence": 85,
            "sources": ["internal-honeypot", "shared-threat-feed-v2"],
            "notes": "Documented IP range (RFC5737 TEST-NET-2) used in this project to simulate an external attacker.",
        }
    }
    upload_json("threat-intel/known_bad_ips.json", threat_feed)

    print("\nSeeding deployment events...")
    deployments = [
        {
            "timestamp": "2024-01-15T14:30:00Z",
            "name": "payments-service v2.4.1",
            "owner": "bob",
            "type": "deployment",
        },
        {
            "timestamp": "2024-01-22T10:15:00Z",
            "name": "auth-service hotfix",
            "owner": "carol",
            "type": "deployment",
        },
        {
            "timestamp": "2024-02-05T16:00:00Z",
            "name": "Q1 IAM cleanup",
            "owner": "carol",
            "type": "maintenance",
        },
        {
            "timestamp": "2024-02-12T11:45:00Z",
            "name": "data-pipeline v1.8.0",
            "owner": "dave",
            "type": "deployment",
        },
        {
            "timestamp": "2024-02-20T15:20:00Z",
            "name": "internal-tools refresh",
            "owner": "eve",
            "type": "deployment",
        },
    ]
    upload_json("deployments/events.json", deployments)

    print("\nBootstrap data complete.")
    print("\nPreview — alice's baseline:")
    print(json.dumps(baselines.get("alice", {}), indent=2)[:600] + "...")


if __name__ == "__main__":
    main()