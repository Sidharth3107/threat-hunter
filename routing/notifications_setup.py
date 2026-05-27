import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import boto3
from config import ALERT_EMAIL, REGION, SNS_TOPIC_NAME


def main():
    if not ALERT_EMAIL:
        raise RuntimeError("ALERT_EMAIL is not set in .env")

    sns = boto3.client("sns", region_name=REGION)

    topic = sns.create_topic(Name=SNS_TOPIC_NAME)
    topic_arn = topic["TopicArn"]
    print(f"SNS topic: {topic_arn}")

    existing_subs = sns.list_subscriptions_by_topic(TopicArn=topic_arn)["Subscriptions"]
    already_subscribed = any(
        s["Endpoint"] == ALERT_EMAIL and s["Protocol"] == "email"
        for s in existing_subs
    )

    if already_subscribed:
        confirmed = any(
            s["Endpoint"] == ALERT_EMAIL
            and s["Protocol"] == "email"
            and s["SubscriptionArn"] != "PendingConfirmation"
            for s in existing_subs
        )
        if confirmed:
            print(f"Email {ALERT_EMAIL} is already subscribed and confirmed.")
        else:
            print(f"Email {ALERT_EMAIL} is subscribed but NOT confirmed.")
            print("Check your inbox (and spam folder) for an AWS Notification confirmation email.")
    else:
        sns.subscribe(TopicArn=topic_arn, Protocol="email", Endpoint=ALERT_EMAIL)
        print(f"\nSubscription request sent to: {ALERT_EMAIL}")
        print("\n  ACTION REQUIRED:")
        print("  1. Check your inbox (and spam folder) for an email from 'AWS Notifications'.")
        print(f"  2. Subject: 'AWS Notification - Subscription Confirmation'.")
        print(f"  3. Click the 'Confirm subscription' link inside.")
        print(f"  4. Until you click it, NO emails will be delivered.\n")

    print("Done.")


if __name__ == "__main__":
    main()