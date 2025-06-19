import boto3
import botocore
import json

def audit_all_s3_buckets():
    s3 = boto3.client('s3')
    issues = []

    # Get list of all buckets
    try:
        buckets = s3.list_buckets().get('Buckets', [])
        print(f"✅ Found {len(buckets)} S3 buckets.")
    except Exception as e:
        print(f"❌ Failed to list S3 buckets: {e}")
        return issues

    for bucket in buckets:
        bucket_name = bucket['Name']
        print(f"\n🔍 Auditing bucket: {bucket_name}")

        # 1️⃣ Check for public ACLs
        try:
            acl = s3.get_bucket_acl(Bucket=bucket_name)
            for grant in acl['Grants']:
                if 'URI' in grant.get('Grantee', {}) and 'AllUsers' in grant['Grantee']['URI']:
                    warning = f"🚨 {bucket_name} is PUBLIC via ACL"
                    print(warning)
                    issues.append(warning)
        except botocore.exceptions.ClientError as e:
            print(f"⚠️ Could not retrieve ACL for {bucket_name}: {e}")

        # 2️⃣ Check for public bucket policy
        try:
            policy_response = s3.get_bucket_policy(Bucket=bucket_name)
            policy = json.loads(policy_response['Policy'])

            for statement in policy.get('Statement', []):
                if (
                    statement.get('Effect') == 'Allow' and
                    statement.get('Principal') == '*' and
                    (
                        's3:GetObject' in statement.get('Action', []) or
                        's3:*' in statement.get('Action', [])
                    )
                ):
                    warning = f"🚨 {bucket_name} is PUBLIC via bucket policy"
                    print(warning)
                    issues.append(warning)
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                print(f"ℹ️ No bucket policy on {bucket_name}")
            else:
                print(f"⚠️ Could not check policy on {bucket_name}: {e}")

        # 3️⃣ Check for encryption
        try:
            encryption = s3.get_bucket_encryption(Bucket=bucket_name)
            if not encryption.get('ServerSideEncryptionConfiguration'):
                warning = f"⚠️ {bucket_name} is NOT encrypted"
                print(warning)
                issues.append(warning)
            else:
                print(f"✅ {bucket_name} is encrypted")
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                warning = f"⚠️ {bucket_name} is NOT encrypted"
                print(warning)
                issues.append(warning)
            else:
                print(f"⚠️ Could not check encryption for {bucket_name}: {e}")

    return issues


def send_alert(message):
    sns = boto3.client('sns')
    try:
        sns.publish(
            TopicArn='arn:aws:sns:us-east-2:625083152506:s3-security-alerts:ced17068-644a-4063-bc26-0cba19a4da4e',
            Message=message
        )
        print("📢 Alert published to SNS successfully.")
    except Exception as e:
        print(f"❌ Failed to send SNS alert: {e}")


if __name__ == "__main__":
    print("🔐 Starting S3 bucket audit...\n")
    issues = audit_all_s3_buckets()

    if issues:
        print("\n⚠️ Security issues detected:")
        for issue in issues:
            print(f" - {issue}")
        send_alert("AWS S3 Audit Findings:\n" + "\n".join(issues))
    else:
        print("\n✅ All buckets passed the audit.")
