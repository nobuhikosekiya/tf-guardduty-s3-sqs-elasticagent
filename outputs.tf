output "ec2_instance_id" {
  description = "ID of the EC2 instance"
  value       = aws_instance.elastic_agent.id
}

output "ec2_instance_public_ip" {
  description = "Public IP address of the EC2 instance"
  value       = aws_instance.elastic_agent.public_ip
}

output "ec2_instance_public_dns" {
  description = "Public DNS name of the EC2 instance"
  value       = aws_instance.elastic_agent.public_dns
}

output "s3_bucket_name" {
  description = "Name of the S3 bucket for GuardDuty findings"
  value       = aws_s3_bucket.guardduty_findings.id
}

output "sqs_queue_url" {
  description = "URL of the SQS queue for S3 notifications"
  value       = aws_sqs_queue.guardduty_findings_queue.url
}

output "guardduty_detector_id" {
  description = "ID of the GuardDuty detector"
  value       = data.aws_guardduty_detector.existing[0].id
}

output "ssh_command" {
  description = "SSH command to connect to EC2 instance"
  value       = "ssh ec2-user@${aws_instance.elastic_agent.public_dns}"
}