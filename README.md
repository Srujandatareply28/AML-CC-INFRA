# AML-CC-INFRA - AWS IAM User Management

A streamlined GitHub Actions workflow for managing AWS IAM users for Anti-Money Laundering Compliance and Control (AML-CC) projects. This solution uses direct AWS CLI commands for simple and efficient IAM user management, while infrastructure is managed separately using AWS CDK.

## Features

- **Simple IAM User Management**: Create, delete, and list IAM users using AWS CLI
- **GitHub Actions Integration**: Secure OIDC-based authentication with AWS
- **Bulk Operations**: Create multiple users with consistent configuration
- **Security Best Practices**: Secure credential handling and audit logging
- **CDK Compatible**: Designed to work alongside CDK-managed infrastructure

## 📋 Prerequisites

### AWS Setup
1. AWS Account with appropriate permissions
2. IAM role for GitHub Actions with the following permissions:
   - `iam:*` (for user and role management)
   - `ec2:*` (for security group management)
   - `sts:AssumeRole` (for role assumption)

### GitHub Setup
1. Fork or clone this repository
2. Configure the following GitHub Secrets:
   - `AWS_ROLE_ARN`: ARN of the IAM role for GitHub Actions

## 🔧 Setup Instructions

### 1. Create GitHub OIDC Provider in AWS

```bash
# Create OIDC provider for GitHub Actions
aws iam create-open-id-connect-provider \
  --url https://token.actions.githubusercontent.com \
  --client-id-list sts.amazonaws.com \
  --thumbprint-list 6938fd4d98bab03faadb97b34396831e3780aea1
```

### 2. Create IAM Role for GitHub Actions

Create a role with the following trust policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::YOUR_ACCOUNT_ID:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
          "token.actions.githubusercontent.com:sub": "repo:Srujandatareply28/AML-CC-INFRA:ref:refs/heads/main"
        }
      }
    }
  ]
}
```

Attach the following policies to the role:
- `IAMFullAccess`
- `EC2FullAccess`
- `AWSCloudFormationFullAccess`

### 3. Configure GitHub Secrets

In your GitHub repository, go to Settings → Secrets and variables → Actions, and add:

- `AWS_ROLE_ARN`: The ARN of the IAM role created above

## 🎯 Usage

### Running the Workflow

1. Go to the **Actions** tab in your GitHub repository
2. Select **AWS IAM Roles and User Management** workflow
3. Click **Run workflow**
4. Fill in the required parameters:
   - **Action**: Choose from `create`, `delete`, or `list`
   - **Username**: Base username for IAM users (required for create/delete)
   - **User Count**: Number of users to create (1-10, for bulk creation)

### Workflow Parameters

| Parameter | Description | Required | Default | Options |
|-----------|-------------|----------|---------|----------|
| `action` | Action to perform | Yes | `create` | `create`, `delete`, `list` |
| `username` | IAM Username | For create/delete | - | Any valid IAM username |
| `user_count` | Number of users to create | No | `1` | 1-10 |

### Examples

#### Create a Single User
- Action: `create`
- Username: `john.doe`
- User Count: `1`

Result: Creates user `john.doe` with admin access

#### Create Multiple Users
- Action: `create`
- Username: `developer`
- User Count: `3`

Result: Creates users `developer-1`, `developer-2`, `developer-3`

#### List All Users
- Action: `list`

Result: Displays all IAM users and roles

#### Delete Users
- Action: `delete`
- Username: `john.doe`

Result: Deletes the specified user(s)

## 🏗️ Infrastructure Components

### Created IAM Users
- **Path**: `/aml-cc/`
- **Policies**: `AdministratorAccess` + MFA enforcement policy
- **Access Keys**: Automatically generated (stored as workflow artifacts)
- **MFA**: Required for all operations except MFA setup

### IAM Roles
1. **AML-CC-EC2-Role**: For EC2 instances
2. **AML-CC-Lambda-Role**: For Lambda functions

### Security Groups
- **aml-cc-sg**: Configured for:
  - SSH (port 22) from private networks only
  - HTTPS (port 443) from anywhere
  - HTTP (port 80) from anywhere
  - All outbound traffic

### Custom IAM Policy
- **AML-CC-Policy**: Provides access to:
  - S3 buckets with `aml-cc-*` prefix
  - CloudWatch Logs
  - CloudWatch Metrics

## 🔒 Security Features

### MFA Enforcement
All IAM users are required to set up MFA before accessing AWS resources. The policy denies all actions except MFA setup until MFA is configured.

### Network Security
- SSH access restricted to private networks (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
- HTTPS/HTTP access for web services
- All outbound traffic allowed

### Access Keys
- Automatically generated for programmatic access
- Stored as GitHub Actions artifacts with 30-day retention
- Should be rotated regularly

## 📊 Workflow Outputs

The workflow provides detailed outputs including:
- List of created users
- Security group IDs
- IAM role ARNs
- Access key information (sensitive)
- Security recommendations

## 🔍 Monitoring and Validation

The workflow includes automatic security validation:
- Checks for overly permissive policies
- Validates MFA enforcement
- Verifies security group configurations
- Provides security recommendations

## 🚨 Troubleshooting

### Common Issues

1. **"Repository not found" error**
   - Verify the GitHub OIDC provider trust policy includes the correct repository
   - Check that the repository name matches exactly

2. **"Access denied" errors**
   - Ensure the IAM role has sufficient permissions
   - Verify the role trust policy allows GitHub Actions

3. **"User already exists" error**
   - Use the `list` action to check existing users
   - Use the `delete` action to remove existing users before recreating

4. **Terraform state issues**
   - The workflow uses local state (not recommended for production)
   - Consider implementing remote state with S3 backend

### Debug Steps

1. Check the workflow logs in GitHub Actions
2. Verify AWS credentials and permissions
3. Validate Terraform configuration syntax
4. Review AWS CloudTrail logs for API calls

## 🔧 Customization

### Modifying User Permissions
Edit `terraform/main.tf` to change the attached policies:

```hcl
# Replace AdministratorAccess with more restrictive policies
resource "aws_iam_user_policy_attachment" "custom_access" {
  count      = var.user_count
  user       = aws_iam_user.aml_cc_users[count.index].name
  policy_arn = "arn:aws:iam::aws:policy/PowerUserAccess"
}
```

### Adding Custom Policies
Create additional IAM policies in `terraform/main.tf`:

```hcl
resource "aws_iam_policy" "custom_policy" {
  name        = "CustomAMLPolicy"
  description = "Custom policy for AML operations"
  
  policy = jsonencode({
    # Your custom policy document
  })
}
```

### Environment-Specific Configurations
Use Terraform variables to customize for different environments:

```hcl
variable "environment" {
  description = "Environment name"
  type        = string
  default     = "production"
}
```

## 📝 Best Practices

1. **Principle of Least Privilege**: Consider replacing `AdministratorAccess` with more specific policies
2. **Regular Key Rotation**: Rotate access keys every 90 days
3. **MFA Compliance**: Ensure all users set up MFA immediately
4. **Monitoring**: Enable CloudTrail and CloudWatch for audit logging
5. **State Management**: Implement remote Terraform state for production use
6. **Backup**: Regular backup of Terraform state and configurations

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 📞 Support

For issues and questions:
1. Check the troubleshooting section
2. Review GitHub Actions logs
3. Create an issue in this repository
4. Contact the infrastructure team

---

**⚠️ Security Notice**: This configuration provides administrative access to AWS. Use with caution and follow your organization's security policies.