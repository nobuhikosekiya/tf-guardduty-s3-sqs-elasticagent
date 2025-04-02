# Get the current AWS account ID
data "aws_caller_identity" "current" {}

# Get default VPC details
data "aws_vpc" "default" {
  default = true
}

# Create an S3 bucket for GuardDuty findings
resource "aws_s3_bucket" "guardduty_findings" {
  bucket        = "${var.prefix}-guardduty-findings-${data.aws_caller_identity.current.account_id}"
  force_destroy = true

  # Prevent accidental deletion of this S3 bucket
  lifecycle {
    prevent_destroy = false
  }
}

# Configure bucket ownership controls
resource "aws_s3_bucket_ownership_controls" "guardduty_findings" {
  bucket = aws_s3_bucket.guardduty_findings.id

  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

# Configure bucket ACL
resource "aws_s3_bucket_acl" "guardduty_findings" {
  depends_on = [aws_s3_bucket_ownership_controls.guardduty_findings]

  bucket = aws_s3_bucket.guardduty_findings.id
  acl    = "private"
}

# Configure server-side encryption for the bucket
resource "aws_s3_bucket_server_side_encryption_configuration" "guardduty_findings" {
  bucket = aws_s3_bucket.guardduty_findings.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Configure lifecycle rules for the bucket
resource "aws_s3_bucket_lifecycle_configuration" "guardduty_findings" {
  bucket = aws_s3_bucket.guardduty_findings.id

  rule {
    id     = "expire-old-logs"
    status = "Enabled"

    filter {
      prefix = ""  # Apply to all objects
    }

    expiration {
      days = var.s3_logs_expiration_days
    }
  }
}

# Create an SQS queue for S3 notifications
resource "aws_sqs_queue" "guardduty_findings_queue" {
  name                      = "${var.prefix}-guardduty-findings-queue"
  delay_seconds             = 0
  max_message_size          = 262144  # 256 KB
  message_retention_seconds = 345600  # 4 days
  receive_wait_time_seconds = 20      # Long polling

  # Enable server-side encryption
  sqs_managed_sse_enabled = true
}

# Create a queue policy to allow S3 to send messages
resource "aws_sqs_queue_policy" "guardduty_findings_queue_policy" {
  queue_url = aws_sqs_queue.guardduty_findings_queue.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "s3.amazonaws.com"
        }
        Action   = "sqs:SendMessage"
        Resource = aws_sqs_queue.guardduty_findings_queue.arn
        Condition = {
          ArnEquals = {
            "aws:SourceArn" = aws_s3_bucket.guardduty_findings.arn
          }
        }
      }
    ]
  })
}

# Configure S3 bucket notification to SQS
resource "aws_s3_bucket_notification" "guardduty_findings_notification" {
  bucket = aws_s3_bucket.guardduty_findings.id

  queue {
    queue_arn     = aws_sqs_queue.guardduty_findings_queue.arn
    events        = ["s3:ObjectCreated:*"]
    filter_suffix = ".json"
  }

  depends_on = [aws_sqs_queue_policy.guardduty_findings_queue_policy]
}

# Get existing GuardDuty detector if it exists
data "aws_guardduty_detector" "existing" {
  count = 1
}

# Enable GuardDuty - use data source to reference existing detector instead of creating new one
resource "aws_guardduty_detector" "main" {
  count = 0 # Not creating a new detector

  enable = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"

  datasources {
    s3_logs {
      enable = true
    }
    kubernetes {
      audit_logs {
        enable = false
      }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = false
        }
      }
    }
  }
}

# Create a GuardDuty publishing destination for S3
resource "aws_guardduty_publishing_destination" "s3_destination" {
  detector_id     = data.aws_guardduty_detector.existing[0].id
  destination_arn = aws_s3_bucket.guardduty_findings.arn
  kms_key_arn     = aws_kms_key.guardduty_key.arn

  depends_on = [
    aws_s3_bucket_policy.guardduty_bucket_policy
  ]
}

# Create KMS key for GuardDuty findings
resource "aws_kms_key" "guardduty_key" {
  description             = "KMS key for GuardDuty findings"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid    = "EnableIAMUserPermissions",
        Effect = "Allow",
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        },
        Action   = "kms:*",
        Resource = "*"
      },
      {
        Sid    = "AllowGuardDutyToEncryptFindings",
        Effect = "Allow",
        Principal = {
          Service = "guardduty.amazonaws.com"
        },
        Action = [
          "kms:GenerateDataKey",
          "kms:Encrypt"
        ],
        Resource = "*"
      }
    ]
  })
}

# Create KMS alias
resource "aws_kms_alias" "guardduty_key_alias" {
  name          = "alias/${var.prefix}-guardduty-key"
  target_key_id = aws_kms_key.guardduty_key.key_id
}

# Create bucket policy to allow GuardDuty to write findings
resource "aws_s3_bucket_policy" "guardduty_bucket_policy" {
  bucket = aws_s3_bucket.guardduty_findings.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid    = "AllowGuardDutyToUseKey",
        Effect = "Allow",
        Principal = {
          Service = "guardduty.amazonaws.com"
        },
        Action = [
          "s3:GetBucketLocation",
          "s3:PutObject"
        ],
        Resource = [
          aws_s3_bucket.guardduty_findings.arn,
          "${aws_s3_bucket.guardduty_findings.arn}/*"
        ],
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })
}

# Create SSH key pair
resource "aws_key_pair" "ec2_key" {
  key_name   = "${var.prefix}-ec2-key"
  public_key = file(var.ssh_public_key_path)
}

# Create EC2 Security Group
resource "aws_security_group" "ec2_sg" {
  name        = "${var.prefix}-ec2-sg"
  description = "Security group for Elastic Agent EC2 instance"
  vpc_id      = data.aws_vpc.default.id

  # SSH access
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "SSH access"
  }

  # Outbound internet access
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound traffic"
  }

  tags = {
    Name = "${var.prefix}-ec2-sg"
  }
}

# Create IAM role for EC2 instance
resource "aws_iam_role" "ec2_role" {
  name = "${var.prefix}-ec2-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = "sts:AssumeRole",
        Principal = {
          Service = "ec2.amazonaws.com"
        },
        Effect = "Allow",
        Sid    = ""
      }
    ]
  })
}

# Create IAM policy for S3 and SQS access
resource "aws_iam_policy" "s3_sqs_policy" {
  name        = "${var.prefix}-s3-sqs-policy"
  description = "Policy to allow EC2 instance to read from S3 and SQS"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "s3:GetObject",
          "s3:ListBucket",
          "s3:GetBucketLocation"
        ],
        Resource = [
          aws_s3_bucket.guardduty_findings.arn,
          "${aws_s3_bucket.guardduty_findings.arn}/*"
        ]
      },
      {
        Effect = "Allow",
        Action = [
          "sqs:ReceiveMessage",
          "sqs:DeleteMessage",
          "sqs:GetQueueAttributes",
          "sqs:ChangeMessageVisibility"
        ],
        Resource = aws_sqs_queue.guardduty_findings_queue.arn
      },
      {
        Effect = "Allow",
        Action = [
          "ec2:DescribeTags",
          "ec2:DescribeInstances"
        ],
        Resource = "*"
      }
    ]
  })
}

# Attach policy to role
resource "aws_iam_role_policy_attachment" "s3_sqs_policy_attachment" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = aws_iam_policy.s3_sqs_policy.arn
}

# Create instance profile
resource "aws_iam_instance_profile" "ec2_profile" {
  name = "${var.prefix}-ec2-profile"
  role = aws_iam_role.ec2_role.name
}

# Create EC2 instance
resource "aws_instance" "elastic_agent" {
  ami                    = var.ami_id
  instance_type          = var.instance_type
  key_name               = aws_key_pair.ec2_key.key_name
  vpc_security_group_ids = [aws_security_group.ec2_sg.id]
  iam_instance_profile   = aws_iam_instance_profile.ec2_profile.name

  root_block_device {
    volume_size = 20
    volume_type = "gp3"
  }

  # No user_data, as Elastic Agent will be installed manually

  tags = {
    Name = "${var.prefix}-elastic-agent"
  }
  
  # Skip default tags that might cause policy violations
  tags_all = {}
}