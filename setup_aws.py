import boto3
import json
from config import REGION, ACCOUNT_ID, BUCKET_NAME, CLOUDTRAIL_PREFIX, SAGEMAKER_ROLE_NAME, SAGEMAKER_ROLE_ARN

def create_s3_bucket():
    s3 = boto3.client("s3", region_name=REGION)

    existing_buckets = [b["Name"] for b in s3.list_buckets()["Buckets"]]
    if BUCKET_NAME in existing_buckets:
        print(f"Bucket already exists: {BUCKET_NAME}")
        return

    if REGION == "us-east-1":
        s3.create_bucket(Bucket=BUCKET_NAME)
    else:
        s3.create_bucket(
            Bucket=BUCKET_NAME,
            CreateBucketConfiguration={"LocationConstraint": REGION}
        )

    s3.put_bucket_versioning(
        Bucket=BUCKET_NAME,
        VersioningConfiguration={"Status": "Enabled"}
    )

    s3.put_bucket_encryption(
        Bucket=BUCKET_NAME,
        ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
        }
    )

    s3.put_public_access_block(
        Bucket=BUCKET_NAME,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        }
    )

    print(f"Created S3 bucket: s3://{BUCKET_NAME}")


def apply_cloudtrail_bucket_policy():
    s3 = boto3.client("s3")

    trail_arn = f"arn:aws:cloudtrail:{REGION}:{ACCOUNT_ID}:trail/threat-hunter-trail"
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AWSCloudTrailAclCheck",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:GetBucketAcl",
                "Resource": f"arn:aws:s3:::{BUCKET_NAME}",
                "Condition": {
                    "StringEquals": {"aws:SourceArn": trail_arn}
                }
            },
            {
                "Sid": "AWSCloudTrailWrite",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": f"arn:aws:s3:::{BUCKET_NAME}/{CLOUDTRAIL_PREFIX}/AWSLogs/{ACCOUNT_ID}/*",
                "Condition": {
                    "StringEquals": {
                        "s3:x-amz-acl": "bucket-owner-full-control",
                        "aws:SourceArn": trail_arn,
                    }
                }
            }
        ]
    }

    s3.put_bucket_policy(Bucket=BUCKET_NAME, Policy=json.dumps(policy))
    print("CloudTrail bucket policy applied")


def create_cloudtrail():
    ct = boto3.client("cloudtrail", region_name=REGION)

    trails = [t["Name"] for t in ct.describe_trails()["trailList"]]
    if "threat-hunter-trail" in trails:
        print("CloudTrail trail already exists")
        return

    ct.create_trail(
        Name="threat-hunter-trail",
        S3BucketName=BUCKET_NAME,
        S3KeyPrefix=CLOUDTRAIL_PREFIX,
        IsMultiRegionTrail=False,
        EnableLogFileValidation=True
    )

    ct.start_logging(Name="threat-hunter-trail")
    print("CloudTrail trail created and logging started")


def create_sagemaker_role():
    iam = boto3.client("iam")

    try:
        role = iam.get_role(RoleName=SAGEMAKER_ROLE_NAME)
        print(f"SageMaker role already exists: {role['Role']['Arn']}")
        return
    except iam.exceptions.NoSuchEntityException:
        pass

    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "sagemaker.amazonaws.com"},
            "Action": "sts:AssumeRole"
        }]
    }

    iam.create_role(
        RoleName=SAGEMAKER_ROLE_NAME,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Description="SageMaker execution role for Threat Hunter project"
    )

    iam.attach_role_policy(
        RoleName=SAGEMAKER_ROLE_NAME,
        PolicyArn="arn:aws:iam::aws:policy/AmazonSageMakerFullAccess",
    )

    # S3 access is scoped to the project bucket only — never account-wide.
    project_s3_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
            "Resource": [
                f"arn:aws:s3:::{BUCKET_NAME}",
                f"arn:aws:s3:::{BUCKET_NAME}/*",
            ],
        }],
    }
    iam.put_role_policy(
        RoleName=SAGEMAKER_ROLE_NAME,
        PolicyName="ThreatHunterProjectBucketAccess",
        PolicyDocument=json.dumps(project_s3_policy),
    )

    print(f"SageMaker role created: {SAGEMAKER_ROLE_ARN}")


if __name__ == "__main__":
    create_s3_bucket()
    apply_cloudtrail_bucket_policy()
    create_cloudtrail()
    create_sagemaker_role()
    print("\nAWS infrastructure ready.")