from __future__ import annotations
from typing import List, Optional
from .evaluator import IAMEvaluator
from .models import Finding, S3BucketConfig, Severity
from .remediation import RemediationGenerator


class RuleEngine:
    """
    Modular CIS AWS Foundations Benchmark v3.0 rule engine.
    """

    @classmethod
    def check_cis_2_1_1_public_access(cls, config: S3BucketConfig) -> Optional[Finding]:
        """
        CIS 2.1.1: Ensure S3 Bucket is not publicly accessible.
        """
        is_public, reason = IAMEvaluator.evaluates_public_read_or_write(config)
        if is_public:
            return Finding(
                rule_id="CIS_2_1_1",
                rule_name="S3 Bucket Unrestricted Public Access",
                cis_control="CIS 2.1.1 (Level 1)",
                severity=Severity.CRITICAL,
                description="The S3 bucket or its policy allows unauthenticated access from the public internet.",
                details=reason,
                target_resource=config.arn,
                remediation=RemediationGenerator.for_public_access(config.bucket_name),
            )
        return None

    @classmethod
    def check_cis_1_16_wildcard_iam(cls, config: S3BucketConfig) -> Optional[Finding]:
        """
        CIS 1.16: Ensure IAM / bucket policies do not grant wildcard administrative permissions.
        """
        wildcard_findings = []
        for stmt in config.policy_statements:
            if stmt.effect.lower() == "allow":
                is_wc, matched = IAMEvaluator.is_wildcard_action(stmt.actions)
                if is_wc:
                    wildcard_findings.extend(matched)

        if wildcard_findings:
            unique_wcs = list(set(wildcard_findings))
            return Finding(
                rule_id="CIS_1_16",
                rule_name="Excessive Wildcard Permissions in Policy",
                cis_control="CIS 1.16 (Level 1)",
                severity=Severity.HIGH,
                description="The policy attaches over-permissive wildcard actions that violate least-privilege principles.",
                details=f"Over-permissive actions found: {', '.join(unique_wcs)}",
                target_resource=config.arn,
                remediation=RemediationGenerator.for_excessive_iam_wildcards(config.bucket_name, unique_wcs),
            )
        return None

    @classmethod
    def check_cis_2_1_3_tls_enforcement(cls, config: S3BucketConfig) -> Optional[Finding]:
        """
        CIS 2.1.3: Ensure S3 Bucket Policy enforces SSL/TLS in-transit.
        """
        enforces_tls, reason = IAMEvaluator.evaluates_tls_enforcement(config)
        if not enforces_tls:
            return Finding(
                rule_id="CIS_2_1_3",
                rule_name="Missing SSL/TLS In-Transit Enforcement",
                cis_control="CIS 2.1.3 (Level 2)",
                severity=Severity.HIGH,
                description="The bucket policy lacks an explicit Deny statement for non-HTTPS (unencrypted) requests.",
                details=reason,
                target_resource=config.arn,
                remediation=RemediationGenerator.for_missing_tls(config.bucket_name),
            )
        return None

    @classmethod
    def check_cis_2_1_2_encryption(cls, config: S3BucketConfig) -> Optional[Finding]:
        """
        CIS 2.1.2: Ensure S3 Bucket has default Server-Side Encryption enabled.
        """
        has_enc, reason = IAMEvaluator.evaluates_server_side_encryption(config)
        if not has_enc:
            return Finding(
                rule_id="CIS_2_1_2",
                rule_name="Missing Default Server-Side Encryption",
                cis_control="CIS 2.1.2 (Level 1)",
                severity=Severity.MEDIUM,
                description="Bucket is missing default Server-Side Encryption (SSE-S3 or SSE-KMS).",
                details=reason,
                target_resource=config.arn,
                remediation=RemediationGenerator.for_missing_encryption(config.bucket_name),
            )
        return None

    @classmethod
    def check_cis_2_1_4_logging(cls, config: S3BucketConfig) -> Optional[Finding]:
        """
        CIS 2.1.4: Ensure S3 Bucket access logging is enabled.
        """
        if not config.logging_enabled:
            return Finding(
                rule_id="CIS_2_1_4",
                rule_name="S3 Access Logging Disabled",
                cis_control="CIS 2.1.4 (Level 2)",
                severity=Severity.MEDIUM,
                description="Server access logging is not enabled. Read/write activities are not audited.",
                details="No target logging bucket configured in S3 bucket logging settings.",
                target_resource=config.arn,
                remediation=RemediationGenerator.for_missing_logging(config.bucket_name),
            )
        return None

    @classmethod
    def check_cis_2_1_5_versioning(cls, config: S3BucketConfig) -> Optional[Finding]:
        """
        CIS 2.1.5: Ensure S3 Bucket versioning & object lock is enabled for ransomware recovery.
        """
        if config.versioning_status != "Enabled" and not config.object_lock_enabled:
            return Finding(
                rule_id="CIS_2_1_5",
                rule_name="Object Versioning & Immutability Disabled",
                cis_control="CIS 2.1.5 (Level 2)",
                severity=Severity.LOW,
                description="Object versioning and object lock are disabled, leaving bucket vulnerable to accidental or ransomware deletion.",
                details=f"Current versioning status: {config.versioning_status}",
                target_resource=config.arn,
                remediation=RemediationGenerator.for_missing_versioning_and_lock(config.bucket_name),
            )
        return None

    @classmethod
    def run_all_checks(cls, config: S3BucketConfig) -> List[Finding]:
        """Runs all CIS benchmark checks against the configuration."""
        findings = []
        checks = [
            cls.check_cis_2_1_1_public_access,
            cls.check_cis_1_16_wildcard_iam,
            cls.check_cis_2_1_3_tls_enforcement,
            cls.check_cis_2_1_2_encryption,
            cls.check_cis_2_1_4_logging,
            cls.check_cis_2_1_5_versioning,
        ]
        for check in checks:
            res = check(config)
            if res is not None:
                findings.append(res)
        return findings
