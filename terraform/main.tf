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
  bucket = "replace-with-unique-ai-devsecops-artifacts"

  tags = {
    Environment = "dev"
    ManagedBy   = "terraform"
    CostCenter  = "platform"
  }
}

resource "aws_s3_bucket_public_access_block" "artifact_bucket" {
  bucket                  = aws_s3_bucket.artifact_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
