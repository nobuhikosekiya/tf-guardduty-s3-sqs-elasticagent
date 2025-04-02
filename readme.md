![Terraform CI/CD Tests](https://github.com/nobuhikosekiya/tf-guardduty-s3-sqs-elasticagent/actions/workflows/terraform-test.yml/badge.svg)

# AWS GuardDuty to S3 with Elastic Stack Integration

This Terraform configuration sets up AWS GuardDuty with S3 bucket logging, SQS notifications for new objects, and an EC2 instance where you can manually install the Elastic Agent to collect logs.

## Architecture

The following resources are created:

- GuardDuty detector with basic configuration
- S3 bucket to store GuardDuty findings
- SQS queue to receive notifications about new objects in the S3 bucket
- EC2 instance with the necessary permissions to access the S3 bucket and SQS queue
- All required IAM roles and policies

## Prerequisites

- AWS CLI installed and configured with a profile
- Terraform installed (version >= 1.0.0)
- SSH key pair for connecting to the EC2 instance

## Setup

1. Copy `terraform.tfvars.example` to `terraform.tfvars` and modify as needed:

```bash
cp terraform.tfvars.example terraform.tfvars
```

2. Edit `terraform.tfvars` to customize your deployment

3. Initialize Terraform:

```bash
terraform init
```

4. Apply the Terraform configuration:

```bash
terraform apply
```

5. After successful deployment, you'll get outputs including the EC2 instance IP address and SQS queue URL.

## Manual Installation of Elastic Agent

Connect to the EC2 instance using the SSH command from the output:

```bash
ssh ec2-user@<ec2_instance_public_dns>
```

Then follow the steps to install and configure Elastic Agent with the AWS S3 input.

### Configuring AWS S3 Input

When installing Elastic Agent, use the following configuration for the AWS S3 input:

```yaml
- type: aws-s3
  queue_url: <sqs_queue_url_from_terraform_output>
  credential_profile_name: default
  expand_event_list_from_field: detail
```

The EC2 instance has the necessary IAM permissions to access the S3 bucket and SQS queue.

## Testing GuardDuty

### Method 1: Generate Sample Findings (Recommended)

The easiest way to test the setup is by generating sample findings directly from the GuardDuty console:

1. Log in to the AWS Management Console
2. Navigate to the GuardDuty service
3. Select "Settings" from the left navigation panel
4. Scroll down to the "Sample findings" section
5. Click "Generate sample findings"
6. Wait approximately 5-10 minutes for the findings to be processed

This will generate sample findings for all supported finding types without creating actual security issues in your environment. 

After generating the sample findings:
1. Wait for 10-15 minutes (since the publishing frequency is set to "FIFTEEN_MINUTES")
2. Check your S3 bucket for new objects in the path pattern: `AWSLogs/[account-id]/GuardDuty/[region]/[year]/[month]/[day]/...`
3. Verify SQS notifications are being sent by checking the queue in the SQS console
4. Confirm the Elastic Agent is collecting these logs once installed

### Alternative Testing Methods

You can also test the setup by:
1. Performing activities that trigger genuine GuardDuty findings (like unusual API calls)
2. Creating a CloudWatch Events rule that simulates GuardDuty findings

For production environments, we recommend reviewing AWS GuardDuty documentation for a full understanding of finding types and their significance.

## Cleaning Up

To remove all created resources:

```bash
terraform destroy
```

## Resources

- [AWS GuardDuty Documentation](https://docs.aws.amazon.com/guardduty/latest/ug/what-is-guardduty.html)
- [Elastic Agent Documentation](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html)
- [AWS S3 Input Documentation](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-aws-s3.html)