import boto3
import botocore
import json

def audit_all_s3_buckets():
    s3 = boto3.client('s3')
    issues = []

    # Get list of all buckets
    buckets = s3.list_buckets().get('Buckets', [])

    for bucket in buckets:
        bucket_name = bucket['Name']
        print(f"Auditing bucket: {bucket_name}")

        #  Check for public ACLs
        try:
            acl = s3.get_bucket_acl(Bucket=bucket_name)
            for grant in acl['Grants']:
                if 'URI' in grant.get('Grantee', {}) and 'AllUsers' in grant['Grantee']['URI']:
                    warning = f"🚨 Bucket {bucket_name} is public via ACL!"
                    print(warning)
                    issues.append(warning)
        except botocore.exceptions.ClientError as e:
            print(f"Could not get ACL for bucket {bucket_name}: {e}")

        # Check for public bucket policy
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
                    warning = f"🚨 Bucket {bucket_name} is public via bucket policy!"
                    print(warning)
                    issues.append(warning)
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                print(f"No bucket policy on {bucket_name}")
            else:
                print(f"Could not retrieve policy for {bucket_name}: {e}")

        # Check for encryption
        try:
            encryption = s3.get_bucket_encryption(Bucket=bucket_name)
            if not encryption.get('ServerSideEncryptionConfiguration'):
                warning = f"⚠️ Bucket {bucket_name} is unencrypted!"
                print(warning)
                issues.append(warning)
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                warning = f"⚠️ Bucket {bucket_name} is unencrypted!"
                print(warning)
                issues.append(warning)
            else:
                print(f"Could not check encryption for bucket {bucket_name}: {e}")

    return issues
