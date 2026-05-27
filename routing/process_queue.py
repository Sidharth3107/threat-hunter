import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import boto3
from config import ACCOUNT_ID, REGION

from agent.run_agent import investigate

QUEUE_NAME = "threat-hunter-investigations"

sqs = boto3.client("sqs", region_name=REGION)


def get_queue_url():
    return sqs.get_queue_url(QueueName=QUEUE_NAME)["QueueUrl"]


def cloudtrail_to_event_dict(detail: dict) -> dict:
    user = detail.get("userIdentity", {})
    name = detail.get("eventName", "")
    SENSITIVE = {
        "CreateUser", "AttachUserPolicy", "CreateAccessKey", "PutUserPolicy",
        "AddUserToGroup", "StopLogging", "DisableKey", "CreateRole",
        "AssumeRole", "DeleteBucket",
    }
    return {
        "event_time": detail.get("eventTime"),
        "user_name": user.get("userName") or user.get("type", "unknown"),
        "event_source": detail.get("eventSource", ""),
        "event_name": name,
        "source_ip": detail.get("sourceIPAddress", ""),
        "region": detail.get("awsRegion", ""),
        "read_only": int(bool(detail.get("readOnly", False))),
        "has_error": int(detail.get("errorCode") is not None),
        "is_sensitive": int(name in SENSITIVE),
        "baseline_violations": "unknown (realtime — no rolling baseline computed)",
        "events_last_5min": "unknown (realtime)",
        "events_last_1hour": "unknown (realtime)",
    }


def process_message(msg):
    body = json.loads(msg["Body"])
    detail = body.get("detail", body)

    print("\n" + "=" * 80)
    print(f"NEW EVENT from SQS")
    print(f"  source:     {body.get('source', 'n/a')}")
    print(f"  event_name: {detail.get('eventName', 'n/a')}")
    print(f"  user:       {detail.get('userIdentity', {}).get('userName', 'unknown')}")
    print(f"  ip:         {detail.get('sourceIPAddress', 'n/a')}")
    print(f"  errorCode:  {detail.get('errorCode', 'none')}")
    print("=" * 80)

    event = cloudtrail_to_event_dict(detail)
    result = investigate(event, verbose=False)

    report = result.get("final_report") or {}
    if report:
        print(f"  → severity: {report.get('severity', 'unknown').upper()}")
        print(f"  → title:    {report.get('title', '')}")
        print(f"  → s3:       {report.get('s3_uri', '')}")
        print(f"  → tokens:   in={result['input_tokens']}, out={result['output_tokens']}")
    else:
        print("  → no incident report written")


def main():
    queue_url = get_queue_url()
    print(f"Polling {queue_url}")
    print("Waiting for events... (Ctrl+C to stop)\n")

    while True:
        try:
            resp = sqs.receive_message(
                QueueUrl=queue_url,
                MaxNumberOfMessages=1,
                WaitTimeSeconds=20,
                MessageAttributeNames=["All"],
            )
        except KeyboardInterrupt:
            print("\nStopping.")
            break

        messages = resp.get("Messages", [])
        if not messages:
            print(".", end="", flush=True)
            continue

        for msg in messages:
            try:
                process_message(msg)
                sqs.delete_message(
                    QueueUrl=queue_url,
                    ReceiptHandle=msg["ReceiptHandle"],
                )
            except Exception as e:
                print(f"[!] Failed to process message: {type(e).__name__}: {e}")


if __name__ == "__main__":
    main()