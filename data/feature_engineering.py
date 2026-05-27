import gzip
import io
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import boto3
import pandas as pd
from config import BUCKET_NAME, CLOUDTRAIL_PREFIX, FEATURES_PREFIX, ACCOUNT_ID

s3 = boto3.client("s3")

SENSITIVE_EVENT_NAMES = {
    "CreateUser", "AttachUserPolicy", "CreateAccessKey", "PutUserPolicy",
    "AddUserToGroup", "StopLogging", "DisableKey", "CreateRole",
    "AssumeRole", "DeleteBucket",
}


def list_log_keys():
    paginator = s3.get_paginator("list_objects_v2")
    prefix = f"{CLOUDTRAIL_PREFIX}/AWSLogs/{ACCOUNT_ID}/CloudTrail/"
    for page in paginator.paginate(Bucket=BUCKET_NAME, Prefix=prefix):
        for obj in page.get("Contents", []):
            if obj["Key"].endswith(".json.gz"):
                yield obj["Key"]


def read_log_file(key):
    body = s3.get_object(Bucket=BUCKET_NAME, Key=key)["Body"].read()
    with gzip.GzipFile(fileobj=io.BytesIO(body)) as f:
        return json.load(f)["Records"]


def flatten_event(event):
    user = event.get("userIdentity", {})
    ts = pd.to_datetime(event["eventTime"])
    name = event.get("eventName", "")
    return {
        "event_time": ts,
        "user_name": user.get("userName", "unknown"),
        "event_source": event.get("eventSource", ""),
        "event_name": name,
        "source_ip": event.get("sourceIPAddress", ""),
        "region": event.get("awsRegion", ""),
        "read_only": int(bool(event.get("readOnly", False))),
        "has_error": int(event.get("errorCode") is not None),
        "is_sensitive": int(name in SENSITIVE_EVENT_NAMES),
        "hour_of_day": ts.hour,
        "day_of_week": ts.dayofweek,
        "is_business_hours": int(9 <= ts.hour <= 17),
        "is_anomaly": int(event.get("is_anomaly", 0)),
    }


def add_user_context(df, baseline_days=50):
    cutoff = df["event_time"].min() + pd.Timedelta(days=baseline_days)
    baseline = df[df["event_time"] < cutoff]

    user_ips = baseline.groupby("user_name")["source_ip"].agg(set).to_dict()
    user_hours = baseline.groupby("user_name")["hour_of_day"].agg(set).to_dict()
    user_apis = baseline.groupby("user_name")["event_name"].agg(set).to_dict()
    user_regions = baseline.groupby("user_name")["region"].agg(set).to_dict()

    df["ip_is_known"] = [
        int(ip in user_ips.get(u, set()))
        for u, ip in zip(df["user_name"], df["source_ip"])
    ]
    df["hour_is_typical"] = [
        int(h in user_hours.get(u, set()))
        for u, h in zip(df["user_name"], df["hour_of_day"])
    ]
    df["api_is_typical"] = [
        int(n in user_apis.get(u, set()))
        for u, n in zip(df["user_name"], df["event_name"])
    ]
    df["region_is_typical"] = [
        int(r in user_regions.get(u, set()))
        for u, r in zip(df["user_name"], df["region"])
    ]
    df["baseline_violations"] = (
        (1 - df["ip_is_known"])
        + (1 - df["hour_is_typical"])
        + (1 - df["api_is_typical"])
        + (1 - df["region_is_typical"])
    )
    return df


def encode_categoricals(df):
    for col in ["user_name", "event_source", "event_name", "source_ip", "region"]:
        df[f"{col}_id"] = df[col].astype("category").cat.codes
    return df


def add_burst_feature(df):
    df = df.sort_values(["user_name", "event_time"]).reset_index(drop=True)
    df["events_last_5min"] = (
        df.groupby("user_name")
        .rolling("5min", on="event_time")["event_name"]
        .count()
        .reset_index(level=0, drop=True)
        .astype(int)
        .values
    )
    df["events_last_1hour"] = (
        df.groupby("user_name")
        .rolling("1h", on="event_time")["event_name"]
        .count()
        .reset_index(level=0, drop=True)
        .astype(int)
        .values
    )
    return df


def main():
    print("Discovering CloudTrail logs in S3...")
    keys = list(list_log_keys())
    print(f"Found {len(keys)} log files")

    print("Reading and flattening events...")
    events = []
    for i, key in enumerate(keys, 1):
        events.extend(flatten_event(e) for e in read_log_file(key))
        if i % 10 == 0:
            print(f"  {i}/{len(keys)} files processed")

    df = pd.DataFrame(events).sort_values("event_time").reset_index(drop=True)
    print(f"Total events: {len(df)} | Planted anomalies: {df['is_anomaly'].sum()}")

    print("Engineering per-user baseline features...")
    df = add_user_context(df)

    print("Engineering burst-rate features...")
    df = add_burst_feature(df)

    print("Encoding categorical columns...")
    df = encode_categoricals(df)

    output_key = f"{FEATURES_PREFIX}/features.parquet"
    buffer = io.BytesIO()
    df.to_parquet(buffer, engine="pyarrow", index=False)
    s3.put_object(Bucket=BUCKET_NAME, Key=output_key, Body=buffer.getvalue())

    print(f"\nFeatures saved → s3://{BUCKET_NAME}/{output_key}")
    print(f"Shape: {df.shape}")
    print(f"Columns: {list(df.columns)}")


if __name__ == "__main__":
    main()
