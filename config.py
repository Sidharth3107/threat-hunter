import os
import boto3
from dotenv import load_dotenv

load_dotenv()

REGION = "us-east-1"
ACCOUNT_ID = boto3.client("sts").get_caller_identity()["Account"]

BUCKET_NAME = f"threat-hunter-{ACCOUNT_ID}"
CLOUDTRAIL_PREFIX = "cloudtrail-logs"
FEATURES_PREFIX = "features"
MODELS_PREFIX = "models"
REPORTS_PREFIX = "incident-reports"

SAGEMAKER_ROLE_NAME = "SageMakerExecutionRole"
SAGEMAKER_ROLE_ARN = f"arn:aws:iam::{ACCOUNT_ID}:role/{SAGEMAKER_ROLE_NAME}"

PIPELINE_NAME = "threat-hunter-retrain-pipeline"
MODEL_PACKAGE_GROUP = "ThreatHunterModelGroup"
ENDPOINT_NAME = "threat-hunter-endpoint"
MONITOR_SCHEDULE_NAME = "threat-hunter-monitor"

BEDROCK_AGENT_NAME = "threat-hunter-agent"
BEDROCK_MODEL_ID = "anthropic.claude-3-sonnet-20240229-v1:0"
KNOWLEDGE_BASE_NAME = "threat-intel-kb"

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY")
ANTHROPIC_MODEL = "claude-sonnet-4-6"
ANTHROPIC_MAX_TOKENS = 4096

ALERT_EMAIL = os.environ.get("ALERT_EMAIL")
SNS_TOPIC_NAME = "threat-hunter-alerts"
SNS_TOPIC_ARN = f"arn:aws:sns:{REGION}:{ACCOUNT_ID}:{SNS_TOPIC_NAME}"
ALERT_SEVERITIES = {"high", "critical"}

ANOMALY_SCORE_THRESHOLD = -0.09
