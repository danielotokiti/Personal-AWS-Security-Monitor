import boto3
import botocore

def audit_all_s3_buckets():
    s3 = boto3.client('s3')
    issues = []

    # Get list of all buckets
    buckets = s3.list_buckets().get('Buckets', [])

    for bucket in buckets:
        bucket_name = bucket['Name']
        print(f"Auditing bucket: {bucket_name}")

        # Check if public
        try:
            acl = s3.get_bucket_acl(Bucket=bucket_name)
            for grant in acl['Grants']:
                if 'URI' in grant.get('Grantee', {}) and 'AllUsers' in grant['Grantee']['URI']:
                    warning = f"Bucket {bucket_name} is public!"
                    print(warning)
                    issues.append(warning)
        except botocore.exceptions.ClientError as e:
            print(f"Could not get ACL for bucket {bucket_name}: {e}")

        # Check encryption
        try:
            encryption = s3.get_bucket_encryption(Bucket=bucket_name)
            if not encryption.get('ServerSideEncryptionConfiguration'):
                warning = f"Bucket {bucket_name} is unencrypted!"
                print(warning)
                issues.append(warning)
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                warning = f"Bucket {bucket_name} is unencrypted!"
                print(warning)
                issues.append(warning)
            else:
                print(f"Could not check encryption for bucket {bucket_name}: {e}")

    return issues


def send_alert(message):
    sns = boto3.client('sns')
    sns.publish(
        TopicArn='arn:aws:sns:us-east-2:625083152506:s3-security-alerts:ced17068-644a-4063-bc26-0cba19a4da4e',  
        Message=message
    )


if __name__ == "__main__":
    issues = audit_all_s3_buckets()
    if issues:
        send_alert("AWS S3 Audit Findings:\n" + "\n".join(issues))
    else:
        print("All buckets passed the audit.")
