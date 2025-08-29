terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "AML-CC-INFRA"
      Environment = "production"
      ManagedBy   = "terraform"
      Repository  = "dataruk/AML-CC-INFRA"
    }
  }
}

# Data source for current AWS account
data "aws_caller_identity" "current" {}

# Data source for current AWS region
data "aws_region" "current" {}

# Security Group for EC2 instances
resource "aws_security_group" "aml_cc_sg" {
  name_prefix = "aml-cc-sg-"
  description = "Security group for AML-CC infrastructure"

  # SSH access (restrict to specific IPs in production)
  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
  }

  # HTTPS access
  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # HTTP access (consider removing in production)
  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # All outbound traffic
  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "aml-cc-security-group"
  }
}

# IAM Role for EC2 instances
resource "aws_iam_role" "aml_cc_ec2_role" {
  name = "AML-CC-EC2-Role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name = "AML-CC-EC2-Role"
  }
}

# IAM Role for Lambda functions
resource "aws_iam_role" "aml_cc_lambda_role" {
  name = "AML-CC-Lambda-Role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name = "AML-CC-Lambda-Role"
  }
}

# IAM Policy for AML/CC specific permissions
resource "aws_iam_policy" "aml_cc_policy" {
  name        = "AML-CC-Policy"
  description = "Policy for AML-CC infrastructure access"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:ListBucket"
        ]
        Resource = [
          "arn:aws:s3:::aml-cc-*",
          "arn:aws:s3:::aml-cc-*/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams"
        ]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Effect = "Allow"
        Action = [
          "cloudwatch:PutMetricData",
          "cloudwatch:GetMetricStatistics",
          "cloudwatch:ListMetrics"
        ]
        Resource = "*"
      }
    ]
  })

  tags = {
    Name = "AML-CC-Policy"
  }
}

# Attach policy to EC2 role
resource "aws_iam_role_policy_attachment" "aml_cc_ec2_policy_attachment" {
  role       = aws_iam_role.aml_cc_ec2_role.name
  policy_arn = aws_iam_policy.aml_cc_policy.arn
}

# Attach policy to Lambda role
resource "aws_iam_role_policy_attachment" "aml_cc_lambda_policy_attachment" {
  role       = aws_iam_role.aml_cc_lambda_role.name
  policy_arn = aws_iam_policy.aml_cc_policy.arn
}

# Attach AWS managed policy for Lambda basic execution
resource "aws_iam_role_policy_attachment" "lambda_basic_execution" {
  role       = aws_iam_role.aml_cc_lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Instance profile for EC2
resource "aws_iam_instance_profile" "aml_cc_ec2_profile" {
  name = "AML-CC-EC2-Profile"
  role = aws_iam_role.aml_cc_ec2_role.name

  tags = {
    Name = "AML-CC-EC2-Profile"
  }
}

# IAM Users with admin access (dynamic creation)
resource "aws_iam_user" "aml_cc_users" {
  count = var.user_count
  name  = var.user_count > 1 ? "${var.base_username}-${count.index + 1}" : var.base_username
  path  = "/aml-cc/"

  tags = {
    Name        = var.user_count > 1 ? "${var.base_username}-${count.index + 1}" : var.base_username
    Project     = "AML-CC-INFRA"
    Environment = "production"
  }
}

# Attach AdministratorAccess policy to users
resource "aws_iam_user_policy_attachment" "admin_access" {
  count      = var.user_count
  user       = aws_iam_user.aml_cc_users[count.index].name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# Create access keys for users
resource "aws_iam_access_key" "user_keys" {
  count = var.user_count
  user  = aws_iam_user.aml_cc_users[count.index].name
}

# Force MFA policy for users
resource "aws_iam_user_policy" "force_mfa" {
  count = var.user_count
  name  = "ForceMFA"
  user  = aws_iam_user.aml_cc_users[count.index].name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowViewAccountInfo"
        Effect = "Allow"
        Action = [
          "iam:GetAccountPasswordPolicy",
          "iam:ListVirtualMFADevices",
          "iam:GetUser",
          "iam:ListMFADevices"
        ]
        Resource = "*"
      },
      {
        Sid    = "AllowManageOwnPasswords"
        Effect = "Allow"
        Action = [
          "iam:ChangePassword",
          "iam:GetUser"
        ]
        Resource = "arn:aws:iam::*:user/$${aws:username}"
      },
      {
        Sid    = "AllowManageOwnMFA"
        Effect = "Allow"
        Action = [
          "iam:CreateVirtualMFADevice",
          "iam:DeleteVirtualMFADevice",
          "iam:EnableMFADevice",
          "iam:ListMFADevices",
          "iam:ResyncMFADevice"
        ]
        Resource = [
          "arn:aws:iam::*:mfa/$${aws:username}",
          "arn:aws:iam::*:user/$${aws:username}"
        ]
      },
      {
        Sid       = "DenyAllExceptUnlessSignedInWithMFA"
        Effect    = "Deny"
        NotAction = [
          "iam:CreateVirtualMFADevice",
          "iam:EnableMFADevice",
          "iam:GetUser",
          "iam:ListMFADevices",
          "iam:ListVirtualMFADevices",
          "iam:ResyncMFADevice",
          "sts:GetSessionToken"
        ]
        Resource = "*"
        Condition = {
          BoolIfExists = {
            "aws:MultiFactorAuthPresent" = "false"
          }
        }
      }
    ]
  })
}