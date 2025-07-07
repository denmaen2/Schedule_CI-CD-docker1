terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "6.0.0"
    }
  }
  # Backend configuration will be generated automatically
}

provider "aws" {
  region = var.aws_region
}

# Get current AWS account ID for unique naming
data "aws_caller_identity" "current" {}

# Data source to find existing buckets
data "aws_s3_buckets" "all" {}

# Automatically detect bucket name
locals {
  secret_content = jsondecode(file("${path.module}/secrets.json"))
  
  # Find existing bucket with "aws-bucket-" pattern
  existing_buckets = [
    for bucket in data.aws_s3_buckets.all.names : bucket
    if can(regex("^aws-bucket-", bucket))
  ]
  
  # Use existing bucket or create new one
  bucket_name = length(local.existing_buckets) > 0 ? local.existing_buckets[0] : "aws-bucket-${formatdate("YYYY-MM-DD-HH-mm-ss", timestamp())}"
  secret_name = "aws-secret-${data.aws_caller_identity.current.account_id}"
}

# Create bucket only if none exists
resource "aws_s3_bucket" "versioned_locked_bucket" {
  count = length(local.existing_buckets) == 0 ? 1 : 0
  
  bucket              = local.bucket_name
  force_destroy       = false
  object_lock_enabled = true
}

# Upload database.dump file to S3
resource "aws_s3_object" "database_dump" {
  bucket = local.bucket_name
  key    = "database.dump"
  source = "${path.module}/database.dump"
  etag   = filemd5("${path.module}/database.dump")
  
  depends_on = [aws_s3_bucket.versioned_locked_bucket]
}

# Automatically generate backend configuration
resource "local_file" "backend_config" {
  content = <<-EOF
    terraform {
      backend "s3" {
        bucket = "${local.bucket_name}"
        key    = "terraform.tfstate"
        region = "us-east-1"
      }
    }
  EOF
  filename = "${path.module}/backend_generated.tf"
}

# Create setup script for easy backend migration
resource "local_file" "setup_script" {
  content = <<-EOF
    #!/bin/bash
    cp main.tf main.tf.backup
    sed -i '/# Backend configuration will be generated automatically/a\\
    backend "s3" {\
      bucket = "${local.bucket_name}"\
      key    = "terraform.tfstate"\
      region = "us-east-1"\
    }' main.tf
  EOF
  filename = "${path.module}/setup-backend.sh"
  file_permission = "0755"
}

resource "aws_secretsmanager_secret" "timestamp_secret" {
  name = local.secret_name
}

resource "aws_secretsmanager_secret_version" "timestamp_secret_version" {
  secret_id     = aws_secretsmanager_secret.timestamp_secret.id
  secret_string = jsonencode(local.secret_content)
}

# backend
resource "aws_iam_role" "ec2_backend" {
  name = "ec2-backend"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_instance_profile" "ec2_backend_profile" {
  name = "ec2-backend"
  role = aws_iam_role.ec2_backend.name
}

resource "aws_iam_role_policy" "ec2_backend_inline" {
  name = "ec2-backend-inline-policy"
  role = aws_iam_role.ec2_backend.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "ecr:GetAuthorizationToken",
          "ecr:BatchGetImage",
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchCheckLayerAvailability",
          "rds:DescribeDBInstances",
          "elasticache:DescribeCacheClusters"
        ]
        Resource = "*"
      }
    ]
  })
}

# S3 access for future backend application (optional - remove if not needed)
resource "aws_iam_role_policy_attachment" "ec2_backend_s3_readonly" {
  role       = aws_iam_role.ec2_backend.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
}

# frontend
resource "aws_iam_role" "ec2_frontend" {
  name = "ec2-frontend"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Principal = {
          Service = "ec2.amazonaws.com"
        },
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_instance_profile" "ec2_frontend_profile" {
  name = "ec2-frontend"
  role = aws_iam_role.ec2_frontend.name
}

resource "aws_iam_role_policy" "ec2_frontend_inline" {
  name = "ec2-frontend-inline-policy"
  role = aws_iam_role.ec2_frontend.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "secretsmanager:GetSecretValue",
          "ecr:GetAuthorizationToken",
          "ecr:BatchGetImage",
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchCheckLayerAvailability"
        ],
        Resource = "*"
      }
    ]
  })
}

# proxy
resource "aws_iam_role" "ec2-proxy" {
  name = "ec2-proxy"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Principal = {
          Service = "ec2.amazonaws.com"
        },
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_instance_profile" "ec2-proxy_profile" {
  name = "ec2-proxy"
  role = aws_iam_role.ec2-proxy.name
}

resource "aws_iam_role_policy" "ec2-proxy_inline" {
  name = "ec2-proxy-inline-policy"
  role = aws_iam_role.ec2-proxy.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "ec2:DescribeInstances"
        ],
        Resource = "*"
      }
    ]
  })
}
