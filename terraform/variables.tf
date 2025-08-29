variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "us-east-1"
}

variable "base_username" {
  description = "Base username for IAM users"
  type        = string
  default     = "aml-cc-user"
  
  validation {
    condition     = can(regex("^[a-zA-Z][a-zA-Z0-9._-]*$", var.base_username))
    error_message = "Username must start with a letter and contain only alphanumeric characters, periods, underscores, and hyphens."
  }
  
  validation {
    condition     = length(var.base_username) >= 3 && length(var.base_username) <= 64
    error_message = "Username must be between 3 and 64 characters long."
  }
}

variable "user_count" {
  description = "Number of IAM users to create"
  type        = number
  default     = 1
  
  validation {
    condition     = var.user_count >= 0 && var.user_count <= 10
    error_message = "User count must be between 0 and 10."
  }
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "production"
  
  validation {
    condition     = contains(["development", "staging", "production"], var.environment)
    error_message = "Environment must be one of: development, staging, production."
  }
}

variable "project_name" {
  description = "Name of the project"
  type        = string
  default     = "AML-CC-INFRA"
}

variable "enable_mfa_enforcement" {
  description = "Enable MFA enforcement for IAM users"
  type        = bool
  default     = true
}

variable "allowed_ssh_cidrs" {
  description = "List of CIDR blocks allowed for SSH access"
  type        = list(string)
  default     = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
}

variable "tags" {
  description = "Additional tags to apply to resources"
  type        = map(string)
  default     = {}
}