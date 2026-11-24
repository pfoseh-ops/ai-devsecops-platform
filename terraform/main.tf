terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

variable "aws_region" {
  type    = string
  default = "us-east-1"
}

resource "aws_s3_bucket" "artifact_bucket" {
  bucket = var.artifact_bucket_name

  lifecycle {
    prevent_destroy = true
  }

  tags = {
    Environment = "production"
    ManagedBy   = "terraform"
    CostCenter  = "platform"
  }
}

variable "artifact_bucket_name" {
  type        = string
  description = "Globally unique production artifact bucket name; preserve an existing bucket's name during migration."
}

variable "access_log_bucket_name" {
  type        = string
  description = "Dedicated same-account, same-region S3 server-access-log destination. Must differ from artifact_bucket_name."
}

variable "log_retention_days" {
  type        = number
  default     = 365
  description = "Proposed log retention; obtain policy approval before applying."
  validation {
    condition     = var.log_retention_days >= 90 && floor(var.log_retention_days) == var.log_retention_days
    error_message = "Log retention must be a whole number of at least 90 days."
  }
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

resource "aws_kms_key" "artifacts" {
  description             = "DevSecOps artifact encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "EnableAccountIAMDelegation"
      Effect    = "Allow"
      Principal = { AWS = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root" }
      Action    = "kms:*"
      Resource  = "*"
    }]
  })
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_versioning" "artifacts" {
  bucket = aws_s3_bucket.artifact_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifact_bucket.id
  rule {
    bucket_key_enabled = true
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.artifacts.arn
    }
  }
}

resource "aws_s3_bucket_ownership_controls" "artifacts" {
  bucket = aws_s3_bucket.artifact_bucket.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

# Architectural exceptions, intentionally NOT hidden with scanner ignores:
# AWS-0089: logging the log sink to itself would recurse.
# AWS-0132: S3 server access-log delivery requires SSE-S3 at the destination.
resource "aws_s3_bucket" "access_logs" {
  bucket = var.access_log_bucket_name
  lifecycle {
    prevent_destroy = true
    precondition {
      condition     = var.access_log_bucket_name != var.artifact_bucket_name
      error_message = "Access logs must use a distinct bucket to avoid recursive logging."
    }
  }
  tags = {
    Environment = "production"
    ManagedBy   = "terraform"
    Purpose     = "s3-access-logs"
  }
}

resource "aws_s3_bucket_public_access_block" "access_logs" {
  bucket                  = aws_s3_bucket.access_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_ownership_controls" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_policy" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowS3LogDelivery"
        Effect    = "Allow"
        Principal = { Service = "logging.s3.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.access_logs.arn}/s3-access/*"
        Condition = {
          StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id }
          ArnLike      = { "aws:SourceArn" = aws_s3_bucket.artifact_bucket.arn }
        }
      },
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.access_logs.arn, "${aws_s3_bucket.access_logs.arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      }
    ]
  })
}

resource "aws_s3_bucket_policy" "artifacts" {
  bucket = aws_s3_bucket.artifact_bucket.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [aws_s3_bucket.artifact_bucket.arn, "${aws_s3_bucket.artifact_bucket.arn}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
}

resource "aws_s3_bucket_logging" "artifacts" {
  bucket        = aws_s3_bucket.artifact_bucket.id
  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "s3-access/"
  depends_on    = [aws_s3_bucket_policy.access_logs]
}

resource "aws_s3_bucket_lifecycle_configuration" "access_logs" {
  bucket     = aws_s3_bucket.access_logs.id
  depends_on = [aws_s3_bucket_versioning.access_logs]
  rule {
    id     = "approved-log-retention"
    status = "Enabled"
    filter {}
    expiration {
      days = var.log_retention_days
    }
    noncurrent_version_expiration {
      noncurrent_days = var.log_retention_days
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

resource "aws_s3_bucket_public_access_block" "artifact_bucket" {
  bucket                  = aws_s3_bucket.artifact_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
