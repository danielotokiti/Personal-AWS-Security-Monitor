import boto3
import json
import os

def detect_changes():
    try:
        # Initialize AWS clients
        ec2 = boto3.client('ec2')
        s3 = boto3.client('s3')
        
        # Get current state
        instances = ec2.describe_instances()['Reservations']
        buckets = s3.list_buckets()['Buckets']
        
        # Initialize default state if file doesn't exist
        if not os.path.exists('last_state.json'):
            print("No last_state.json found. Creating initial state...")
            initial_state = {
                'instances': [],
                'buckets': []
            }
            with open('last_state.json', 'w') as f:
                json.dump(initial_state, f)
            return  # Exit on first run (no comparison possible yet)

        # Load last state
        with open('last_state.json', 'r') as f:
            last_state = json.load(f)
        
        # Compare and alert
        if len(instances) > len(last_state.get('instances', [])):
            print("New EC2 instance detected!")
        else:
            print("No New EC2 instance detected!")
        
        if len(buckets) > len(last_state.get('buckets', [])):
            print("New S3 bucket detected!")
        else:
            print("No New S3 bucket detected!")

        # Update state
        with open('last_state.json', 'w') as f:
            json.dump({
                'instances': instances,
                'buckets': buckets
            }, f)
            
    except json.JSONDecodeError:
        print("Error: last_state.json is corrupt. Resetting...")
        os.remove('last_state.json')
        detect_changes()  # Retry
    except Exception as e:
        print(f"Unexpected error: {str(e)}")

if __name__ == "__main__":
    detect_changes()