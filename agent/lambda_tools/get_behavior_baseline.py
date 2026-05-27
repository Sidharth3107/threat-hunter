import json
import os
import boto3

s3 = boto3.client("s3")

BUCKET = os.environ.get("BUCKET_NAME")
BASELINES_KEY = os.environ.get("BASELINES_KEY", "baselines/per_user_baselines.json")


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


def load_baselines():
    obj = s3.get_object(Bucket=BUCKET, Key=BASELINES_KEY)
    return json.loads(obj["Body"].read())


def lambda_handler(event, context):
    params = parse_parameters(event)
    user_name = params.get("user_name", "").lower()

    if not user_name:
        return bedrock_response(event, {"error": "user_name parameter is required"})

    baselines = load_baselines()
    user = baselines.get(user_name)

    if not user:
        return bedrock_response(event, {
            "user": user_name,
            "found": False,
            "message": f"No baseline exists for user '{user_name}'. This user may be new to the account.",
        })

    summary = {
        "user": user_name,
        "found": True,
        "baseline_period": user.get("baseline_period"),
        "total_baseline_events": user.get("total_events"),
        "typical_ips": user.get("typical_ips", []),
        "typical_hours_utc": sorted(user.get("typical_hours", [])),
        "typical_regions": user.get("typical_regions", []),
        "top_apis": user.get("top_apis", [])[:10],
        "average_calls_per_day": user.get("average_calls_per_day"),
        "ever_called_sensitive_api": user.get("ever_called_sensitive_api", False),
        "summary": (
            f"{user_name} normally makes ~{int(user.get('average_calls_per_day', 0))} API calls per day "
            f"from {len(user.get('typical_ips', []))} known IP(s), "
            f"during hours {min(user.get('typical_hours', [0]))}-{max(user.get('typical_hours', [0]))} UTC, "
            f"calling {len(user.get('top_apis', []))} distinct APIs."
        ),
    }
    return bedrock_response(event, summary)
