output "created_users" {
  description = "List of created IAM users"
  value       = aws_iam_user.aml_cc_users[*].name
}

output "user_arns" {
  description = "ARNs of created IAM users"
  value       = aws_iam_user.aml_cc_users[*].arn
}

output "access_key_ids" {
  description = "Access key IDs for created users"
  value       = aws_iam_access_key.user_keys[*].id
  sensitive   = true
}

output "secret_access_keys" {
  description = "Secret access keys for created users"
  value       = aws_iam_access_key.user_keys[*].secret
  sensitive   = true
}

output "security_group_id" {
  description = "ID of the created security group"
  value       = aws_security_group.aml_cc_sg.id
}

output "security_group_arn" {
  description = "ARN of the created security group"
  value       = aws_security_group.aml_cc_sg.arn
}

output "ec2_role_arn" {
  description = "ARN of the EC2 IAM role"
  value       = aws_iam_role.aml_cc_ec2_role.arn
}

output "lambda_role_arn" {
  description = "ARN of the Lambda IAM role"
  value       = aws_iam_role.aml_cc_lambda_role.arn
}

output "ec2_instance_profile_arn" {
  description = "ARN of the EC2 instance profile"
  value       = aws_iam_instance_profile.aml_cc_ec2_profile.arn
}

output "aml_cc_policy_arn" {
  description = "ARN of the AML-CC custom policy"
  value       = aws_iam_policy.aml_cc_policy.arn
}

output "aws_account_id" {
  description = "AWS Account ID"
  value       = data.aws_caller_identity.current.account_id
}

output "aws_region" {
  description = "AWS Region"
  value       = data.aws_region.current.name
}

output "user_login_instructions" {
  description = "Instructions for users to log in"
  value = var.user_count > 0 ? {
    console_url = "https://${data.aws_caller_identity.current.account_id}.signin.aws.amazon.com/console"
    mfa_setup   = "Users must set up MFA before accessing AWS resources"
    username    = "Use the username provided in the created_users output"
    password    = "Initial password must be set by administrator"
  } : null
}

output "security_recommendations" {
  description = "Security recommendations for the infrastructure"
  value = {
    mfa_enforcement     = "MFA is enforced for all IAM users"
    admin_access        = "Users have AdministratorAccess - consider principle of least privilege"
    ssh_access          = "SSH access is restricted to private networks only"
    access_key_rotation = "Regularly rotate access keys for security"
    monitoring          = "Enable CloudTrail and CloudWatch for monitoring"
  }
}