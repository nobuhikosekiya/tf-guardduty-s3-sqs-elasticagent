variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "ap-northeast-1"
}

variable "aws_profile" {
  description = "AWS CLI profile to use"
  type        = string
  default     = "elastic-sa"
}

variable "prefix" {
  description = "Prefix for all resources"
  type        = string
  default     = "elastic-logs"
}

variable "default_tags" {
  description = "AWS default tags for resources"
  type        = map(string)
  default     = {}
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t3.micro"
}

variable "ami_id" {
  description = "AMI ID to use for EC2 instances"
  type        = string
  default     = "ami-0599b6e53ca798bb2"
}

variable "s3_logs_expiration_days" {
  description = "Number of days to keep logs in S3"
  type        = number
  default     = 90
}

variable "ssh_public_key_path" {
  description = "Path to the SSH public key"
  type        = string
  default     = "~/.ssh/id_rsa.pub"
}