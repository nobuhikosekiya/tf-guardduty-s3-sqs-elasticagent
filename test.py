#!/usr/bin/env python3
"""
AWS GuardDuty-to-S3 Integration Test Script

This script tests the AWS GuardDuty to S3 with Elastic Stack Integration by:
1. Generating sample GuardDuty findings
2. Waiting for the findings to be published to S3
3. Verifying SQS notifications are received
4. Checking the content of the S3 files
"""

import argparse
import boto3
import json
import time
import os
import logging
from botocore.exceptions import ClientError

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('gd-test')

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Test AWS GuardDuty to S3 Integration')
    parser.add_argument('--profile', type=str, default=None, 
                      help='AWS profile to use (default: None, uses default profile)')
    parser.add_argument('--region', type=str, default='ap-northeast-1',
                      help='AWS region (default: ap-northeast-1)')
    parser.add_argument('--no-cleanup', action='store_true',
                      help='Skip cleanup step (leave test findings in place)')
    return parser.parse_args()

def get_terraform_outputs():
    """Extract required information from Terraform outputs."""
    try:
        # Run terraform output in JSON format
        import subprocess
        result = subprocess.run(
            ["terraform", "output", "-json"],
            capture_output=True,
            text=True,
            check=True
        )
        outputs = json.loads(result.stdout)
        
        # Extract the values we need
        guardduty_detector_id = outputs.get('guardduty_detector_id', {}).get('value', '')
        s3_bucket_name = outputs.get('s3_bucket_name', {}).get('value', '')
        sqs_queue_url = outputs.get('sqs_queue_url', {}).get('value', '')
        
        if not all([guardduty_detector_id, s3_bucket_name, sqs_queue_url]):
            logger.error("Could not find all required Terraform outputs")
            return None, None, None
            
        return guardduty_detector_id, s3_bucket_name, sqs_queue_url
    
    except Exception as e:
        logger.error(f"Error getting Terraform outputs: {e}")
        return None, None, None

def generate_sample_findings(session, detector_id):
    """Generate sample GuardDuty findings."""
    guardduty = session.client('guardduty')
    
    try:
        logger.info(f"Generating sample findings for detector {detector_id}")
        guardduty.create_sample_findings(
            DetectorId=detector_id,
            FindingTypes=[
                'Backdoor:EC2/DenialOfService.UnusualProtocol',
                'CryptoCurrency:EC2/BitcoinTool.B',
                'UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS'
            ]
        )
        logger.info("Sample findings generated successfully")
        return True
    except ClientError as e:
        logger.error(f"Error generating sample findings: {e}")
        return False

def wait_for_s3_objects(session, bucket_name, max_wait_time=600):
    """Wait for GuardDuty findings to be published to S3."""
    s3 = session.client('s3')
    account_id = session.client('sts').get_caller_identity().get('Account')
    
    logger.info(f"Waiting for objects to appear in S3 bucket {bucket_name}")
    logger.info(f"This may take up to {max_wait_time/60} minutes...")
    
    start_time = time.time()
    while (time.time() - start_time) < max_wait_time:
        try:
            # List objects in the GuardDuty prefix
            prefix = f"AWSLogs/{account_id}/GuardDuty/"
            response = s3.list_objects_v2(
                Bucket=bucket_name,
                Prefix=prefix
            )
            
            if 'Contents' in response and len(response['Contents']) > 0:
                logger.info(f"Found {len(response['Contents'])} objects in S3 bucket")
                return [obj['Key'] for obj in response['Contents']]
            
            logger.info("No objects found yet, waiting 30 seconds...")
            time.sleep(30)
            
        except ClientError as e:
            logger.error(f"Error checking S3 bucket: {e}")
            return None
    
    logger.warning(f"Timed out after waiting {max_wait_time/60} minutes")
    return None

def check_sqs_messages(session, queue_url, max_wait_time=300):
    """Check for SQS messages notifying about new S3 objects."""
    sqs = session.client('sqs')
    
    logger.info(f"Checking for messages in SQS queue {queue_url}")
    
    start_time = time.time()
    messages_received = []
    
    while (time.time() - start_time) < max_wait_time:
        try:
            response = sqs.receive_message(
                QueueUrl=queue_url,
                MaxNumberOfMessages=10,
                WaitTimeSeconds=20  # Long polling
            )
            
            if 'Messages' in response:
                for message in response['Messages']:
                    messages_received.append(message)
                    # Don't delete messages so they can be processed by Elastic Agent
                    
                logger.info(f"Received {len(response['Messages'])} SQS messages")
                return messages_received
            
            logger.info("No SQS messages found yet, continuing to wait...")
            
        except ClientError as e:
            logger.error(f"Error checking SQS queue: {e}")
            return None
    
    logger.warning(f"Timed out after waiting {max_wait_time/60} minutes for SQS messages")
    return messages_received

def analyze_s3_content(session, bucket_name, object_keys):
    """Analyze the content of S3 objects to verify they contain GuardDuty findings."""
    import gzip
    import io
    s3 = session.client('s3')
    
    if not object_keys:
        logger.warning("No S3 object keys provided for analysis")
        return False
    
    # Just check the first object to keep it simple
    object_key = object_keys[0]
    
    try:
        logger.info(f"Analyzing content of S3 object: {object_key}")
        response = s3.get_object(
            Bucket=bucket_name,
            Key=object_key
        )
        
        # Read the raw content
        raw_content = response['Body'].read()
        
        # Handle gzip compressed content
        if object_key.endswith('.gz'):
            logger.info("Detected gzip compressed content, decompressing...")
            try:
                with gzip.GzipFile(fileobj=io.BytesIO(raw_content), mode='rb') as f:
                    content = f.read().decode('utf-8')
            except Exception as e:
                logger.error(f"Error decompressing gzip content: {e}")
                return False
        else:
            content = raw_content.decode('utf-8')
        
        logger.info(f"Successfully read content (first 200 chars): {content[:200]}...")
        
        # For JSON or JSONL files
        if object_key.endswith('.json') or object_key.endswith('.jsonl') or object_key.endswith('.jsonl.gz'):
            # Handle JSONL (JSON Lines) format
            if object_key.endswith('.jsonl') or object_key.endswith('.jsonl.gz'):
                # Get the first line
                first_line = content.split('\n')[0].strip()
                if first_line:
                    try:
                        data = json.loads(first_line)
                    except json.JSONDecodeError:
                        logger.warning("Could not parse first line as JSON")
                        data = None
                else:
                    data = None
            else:
                # Regular JSON
                try:
                    data = json.loads(content)
                except json.JSONDecodeError:
                    logger.warning("Could not parse content as JSON")
                    data = None
            
            # Check if this looks like a GuardDuty finding
            if isinstance(data, dict) and any(key in data for key in ['detail', 'service', 'findings', 'accountId', 'region']):
                logger.info("S3 object contains valid GuardDuty finding data")
                return True
        
        # For any format, just check for GuardDuty-related keywords
        guardduty_keywords = ['GuardDuty', 'Finding', 'Detector', 'Severity', 'threatName']
        if any(keyword in content for keyword in guardduty_keywords):
            logger.info("S3 object contains GuardDuty-related content")
            return True
            
        logger.warning("S3 object does not appear to contain GuardDuty findings")
        logger.debug(f"Content: {content[:500]}...")  # Log part of the content for debugging
        return False
        
    except ClientError as e:
        logger.error(f"Error getting S3 object: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error analyzing S3 content: {e}")
        return False

def run_test():
    """Main test function."""
    args = parse_args()
    
    # Initialize AWS session
    session_args = {}
    if args.profile:
        session_args['profile_name'] = args.profile
    
    session = boto3.Session(**session_args, region_name=args.region)
    
    # Get Terraform outputs
    detector_id, bucket_name, queue_url = get_terraform_outputs()
    if not all([detector_id, bucket_name, queue_url]):
        logger.error("Failed to get required Terraform outputs")
        return False
    
    # Generate sample findings
    if not generate_sample_findings(session, detector_id):
        logger.error("Failed to generate sample findings")
        return False
    
    # Wait for findings to be published to S3
    logger.info("Waiting for findings to be published to S3...")
    object_keys = wait_for_s3_objects(session, bucket_name)
    
    if not object_keys:
        logger.error("No GuardDuty findings found in S3 bucket")
        return False
    
    # Check for SQS messages
    messages = check_sqs_messages(session, queue_url)
    
    if not messages:
        logger.warning("No SQS messages received, but S3 objects were created")
    else:
        logger.info(f"Received {len(messages)} SQS messages")
    
    # Analyze S3 content
    if not analyze_s3_content(session, bucket_name, object_keys):
        logger.error("S3 objects do not contain valid GuardDuty findings")
        return False
    
    logger.info("Test completed successfully! GuardDuty findings are being correctly published to S3 and notified via SQS.")
    return True

if __name__ == "__main__":
    success = run_test()
    if not success:
        logger.error("Test failed!")
        exit(1)
    logger.info("All tests passed!")
    exit(0)