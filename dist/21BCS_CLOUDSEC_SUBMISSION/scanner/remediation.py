from __future__ import annotations
from .models import Remediation


class RemediationGenerator:
    """
    Generates actionable AWS CLI commands and Terraform HCL resource definitions
    for detected cloud misconfigurations.
    """

    @staticmethod
    def for_public_access(bucket_name: str) -> Remediation:
        cli = f"aws s3api put-public-access-block --bucket {bucket_name} --public-access-block-configuration \"BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true\""
        tf = f"""resource "aws_s3_bucket_public_access_block" "block_{bucket_name.replace('-', '_')}" {{
  bucket = aws_s3_bucket.{bucket_name.replace('-', '_')}.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}}"""
        explanation = "Enforces AWS S3 Block Public Access to prevent unauthenticated public reads and writes."
        return Remediation(
            title="Enable S3 Block Public Access",
            aws_cli_command=cli,
            terraform_hcl=tf,
            explanation=explanation,
        )

    @staticmethod
    def for_missing_tls(bucket_name: str) -> Remediation:
        cli = f"""cat << 'EOF' > enforce-tls.json
{{
  "Version": "2012-10-17",
  "Statement": [
    {{
      "Sid": "EnforceTLSRequestsOnly",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::{bucket_name}",
        "arn:aws:s3:::{bucket_name}/*"
      ],
      "Condition": {{
        "Bool": {{ "aws:SecureTransport": "false" }}
      }}
    }}
  ]
}}
EOF
aws s3api put-bucket-policy --bucket {bucket_name} --policy file://enforce-tls.json"""

        tf = f"""resource "aws_s3_bucket_policy" "enforce_tls_{bucket_name.replace('-', '_')}" {{
  bucket = aws_s3_bucket.{bucket_name.replace('-', '_')}.id

  policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [
      {{
        Sid       = "EnforceTLSRequestsOnly"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.{bucket_name.replace('-', '_')}.arn,
          "${{aws_s3_bucket.{bucket_name.replace('-', '_')}.arn}}/*"
        ]
        Condition = {{
          Bool = {{ "aws:SecureTransport" = "false" }}
        }}
      }}
    ]
  }})
}}"""
        explanation = "Attaches an explicit Deny bucket policy that rejects all plaintext HTTP connections, enforcing HTTPS in transit."
        return Remediation(
            title="Enforce SSL/TLS In-Transit (CIS 2.1.3)",
            aws_cli_command=cli,
            terraform_hcl=tf,
            explanation=explanation,
        )

    @staticmethod
    def for_missing_encryption(bucket_name: str) -> Remediation:
        cli = f"""aws s3api put-bucket-encryption --bucket {bucket_name} --server-side-encryption-configuration '{{
  "Rules": [
    {{
      "ApplyServerSideEncryptionByDefault": {{
        "SSEAlgorithm": "AES256"
      }}
    }}
  ]
}}'"""
        tf = f"""resource "aws_s3_bucket_server_side_encryption_configuration" "enc_{bucket_name.replace('-', '_')}" {{
  bucket = aws_s3_bucket.{bucket_name.replace('-', '_')}.id

  rule {{
    apply_server_side_encryption_by_default {{
      sse_algorithm = "AES256"
    }}
  }}
}}"""
        explanation = "Enables default server-side encryption with AES-256 (or KMS CMK) so all objects are encrypted at rest."
        return Remediation(
            title="Enable Server-Side Encryption at Rest (CIS 2.1.2)",
            aws_cli_command=cli,
            terraform_hcl=tf,
            explanation=explanation,
        )

    @staticmethod
    def for_excessive_iam_wildcards(bucket_name: str, actions: list[str]) -> Remediation:
        cli = f"# Audit IAM role attaching excessive actions: {', '.join(actions)}\n# Replace wildcard action with specific least-privilege permissions (e.g. s3:GetObject, s3:PutObject)"
        tf = """# Principle of Least Privilege: Replace wildcard action
# Bad:  Action = ["s3:*"]
# Good: Action = ["s3:GetObject", "s3:ListBucket"]"""
        explanation = "Restricts IAM roles from granting excessive administrative wildcard permissions across storage assets."
        return Remediation(
            title="Apply Principle of Least Privilege (CIS 1.16)",
            aws_cli_command=cli,
            terraform_hcl=tf,
            explanation=explanation,
        )

    @staticmethod
    def for_missing_logging(bucket_name: str) -> Remediation:
        cli = f"aws s3api put-bucket-logging --bucket {bucket_name} --bucket-logging-status '{{\"LoggingEnabled\": {{\"TargetBucket\": \"audit-logs-central\", \"TargetPrefix\": \"s3-access/{bucket_name}/\"}}}}'"
        tf = f"""resource "aws_s3_bucket_logging" "log_{bucket_name.replace('-', '_')}" {{
  bucket = aws_s3_bucket.{bucket_name.replace('-', '_')}.id

  target_bucket = aws_s3_bucket.central_logs.id
  target_prefix = "s3-access/{bucket_name}/"
}}"""
        explanation = "Directs S3 access logs to a centralized logging bucket for incident response and audit trails."
        return Remediation(
            title="Enable S3 Access Logging (CIS 2.1.4)",
            aws_cli_command=cli,
            terraform_hcl=tf,
            explanation=explanation,
        )

    @staticmethod
    def for_missing_versioning_and_lock(bucket_name: str) -> Remediation:
        cli = f"aws s3api put-bucket-versioning --bucket {bucket_name} --versioning-configuration Status=Enabled"
        tf = f"""resource "aws_s3_bucket_versioning" "ver_{bucket_name.replace('-', '_')}" {{
  bucket = aws_s3_bucket.{bucket_name.replace('-', '_')}.id
  versioning_configuration {{
    status = "Enabled"
  }}
}}"""
        explanation = "Enables object versioning to protect against accidental deletion, malicious tampering, and ransomware."
        return Remediation(
            title="Enable S3 Object Versioning (CIS 2.1.5)",
            aws_cli_command=cli,
            terraform_hcl=tf,
            explanation=explanation,
        )
