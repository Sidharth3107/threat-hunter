import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import boto3
from botocore.exceptions import ClientError
from config import ACCOUNT_ID, REGION

QUEUE_NAME = "threat-hunter-investigations"
DLQ_NAME = "threat-hunter-investigations-dlq"
RULE_NAME = "threat-hunter-suspicious-cloudtrail"

SENSITIVE_IAM_EVENTS = [
    "CreateUser", "DeleteUser", "AttachUserPolicy", "DetachUserPolicy",
    "PutUserPolicy", "CreateAccessKey", "AddUserToGroup", "CreateRole",
    "AttachRolePolicy", "PutRolePolicy", "CreatePolicyVersion",
]

CLOUDTRAIL_TAMPER_EVENTS = ["StopLogging", "DeleteTrail", "UpdateTrail"]

KMS_TAMPER_EVENTS = ["DisableKey", "ScheduleKeyDeletion"]

EVENT_PATTERN = {
    "source": ["aws.iam", "aws.cloudtrail", "aws.kms", "aws.sts"],
    "detail-type": ["AWS API Call via CloudTrail"],
    "detail": {
        "$or": [
            {"eventName": SENSITIVE_IAM_EVENTS + CLOUDTRAIL_TAMPER_EVENTS + KMS_TAMPER_EVENTS},
            {"errorCode": [{"exists": True}]},
        ]
    },
}


def create_dlq(sqs):
    try:
        url = sqs.get_queue_url(QueueName=DLQ_NAME)["QueueUrl"]
        print(f"DLQ already exists: {url}")
    except ClientError as e:
        if e.response["Error"]["Code"] != "AWS.SimpleQueueService.NonExistentQueue":
            raise
        url = sqs.create_queue(
            QueueName=DLQ_NAME,
            Attributes={"MessageRetentionPeriod": "1209600"},
        )["QueueUrl"]
        print(f"Created DLQ: {url}")
    return sqs.get_queue_attributes(
        QueueUrl=url, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]


def create_queue(sqs, dlq_arn):
    # After 3 failed receives a message moves to the DLQ instead of looping
    # forever — each retry would otherwise re-run a paid agent investigation.
    redrive = json.dumps({"deadLetterTargetArn": dlq_arn, "maxReceiveCount": "3"})
    try:
        url = sqs.get_queue_url(QueueName=QUEUE_NAME)["QueueUrl"]
        print(f"Queue already exists: {url}")
        sqs.set_queue_attributes(QueueUrl=url, Attributes={"RedrivePolicy": redrive})
        return url
    except ClientError as e:
        if e.response["Error"]["Code"] != "AWS.SimpleQueueService.NonExistentQueue":
            raise

    resp = sqs.create_queue(
        QueueName=QUEUE_NAME,
        Attributes={
            "MessageRetentionPeriod": "345600",
            "VisibilityTimeout": "120",
            "ReceiveMessageWaitTimeSeconds": "20",
            "RedrivePolicy": redrive,
        },
    )
    print(f"Created queue: {resp['QueueUrl']}")
    return resp["QueueUrl"]


def queue_arn(account_id, region, name):
    return f"arn:aws:sqs:{region}:{account_id}:{name}"


def grant_eventbridge_to_send_to_queue(sqs, queue_url, queue_arn_val, rule_arn):
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowEventBridge",
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue_arn_val,
                "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
            }
        ],
    }
    sqs.set_queue_attributes(
        QueueUrl=queue_url,
        Attributes={"Policy": json.dumps(policy)},
    )
    print("Applied SQS resource policy permitting EventBridge to deliver messages")


def create_rule_and_target(events, queue_arn_val):
    rule = events.put_rule(
        Name=RULE_NAME,
        EventPattern=json.dumps(EVENT_PATTERN),
        State="ENABLED",
        Description="Routes suspicious CloudTrail events to the threat-hunter investigation queue",
    )
    rule_arn = rule["RuleArn"]
    print(f"Created/updated EventBridge rule: {rule_arn}")

    events.put_targets(
        Rule=RULE_NAME,
        Targets=[{"Id": "ThreatHunterQueue", "Arn": queue_arn_val}],
    )
    print(f"Wired rule → SQS target")
    return rule_arn


def main():
    sqs = boto3.client("sqs", region_name=REGION)
    events = boto3.client("events", region_name=REGION)

    dlq_arn = create_dlq(sqs)
    queue_url = create_queue(sqs, dlq_arn)
    queue_arn_val = queue_arn(ACCOUNT_ID, REGION, QUEUE_NAME)

    rule_arn = create_rule_and_target(events, queue_arn_val)

    grant_eventbridge_to_send_to_queue(sqs, queue_url, queue_arn_val, rule_arn)

    print("\nRouting infrastructure ready.")
    print(f"  Rule:  {rule_arn}")
    print(f"  Queue: {queue_url}")
    print("\nThe rule fires on:")
    print(f"  - Sensitive IAM events ({len(SENSITIVE_IAM_EVENTS)}): {', '.join(SENSITIVE_IAM_EVENTS[:5])}, ...")
    print(f"  - CloudTrail tampering: {', '.join(CLOUDTRAIL_TAMPER_EVENTS)}")
    print(f"  - KMS tampering: {', '.join(KMS_TAMPER_EVENTS)}")
    print(f"  - ANY event with an errorCode (AccessDenied, etc.)")
    print("\nRun `python routing\\process_queue.py` to start consuming and investigating.")


if __name__ == "__main__":
    main()