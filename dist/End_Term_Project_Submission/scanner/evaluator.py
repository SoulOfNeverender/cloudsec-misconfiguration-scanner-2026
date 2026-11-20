from __future__ import annotations
import re
from typing import List, Tuple
from .models import ConditionClause, PolicyStatement, S3BucketConfig


class IAMEvaluator:
    """
    Evaluates AWS IAM and S3 bucket policy statements with condition-awareness
    and Explicit Deny precedence.
    """

    SAFE_CONDITION_KEYS = {
        "aws:sourceip",
        "aws:principalorgid",
        "aws:sourcevpce",
        "aws:sourcevpc",
        "aws:sourcearn",
        "aws:principalaccount",
    }

    @staticmethod
    def is_wildcard_principal(principals: List[str]) -> bool:
        """Returns True if the principal set grants access to all callers ('*')."""
        for p in principals:
            if p == "*" or p.endswith(":*") or p.lower() == "arn:aws:iam:::root":
                return True
        return False

    @staticmethod
    def is_wildcard_action(actions: List[str]) -> Tuple[bool, List[str]]:
        """
        Detects if actions include broad wildcards ('*', 's3:*', 'iam:*', 's3:Get*').
        Returns (is_wildcard, list_of_wildcard_matches).
        """
        wildcards = []
        for action in actions:
            if action in ("*", "s3:*", "iam:*", "admin:*"):
                wildcards.append(action)
            elif re.match(r"^s3:\w*\*", action, re.IGNORECASE):
                wildcards.append(action)
        return (len(wildcards) > 0, wildcards)

    @classmethod
    def has_restricting_condition(cls, conditions: List[ConditionClause]) -> bool:
        """
        Checks if a statement contains conditions that restrict access
        to corporate IPs, VPCs, or AWS Organizations.
        """
        for cond in conditions:
            key_lower = cond.key.lower()
            if key_lower in cls.SAFE_CONDITION_KEYS:
                return True
            # Also check if operator is IpAddress or StringEquals on org/vpc
            if cond.operator.lower() in ("ipaddress", "stringequals", "stringlike", "arnlike"):
                if any(k in key_lower for k in ("ip", "vpc", "org", "account", "source")):
                    return True
        return False

    @classmethod
    def evaluates_public_read_or_write(cls, config: S3BucketConfig) -> Tuple[bool, str]:
        """
        Determines if the bucket allows unauthenticated public read or write access.
        Simulates Allow vs Deny and condition filtering.
        """
        # If public access block is fully enabled, bucket is protected at the API level
        if config.block_public_policy and config.restrict_public_buckets:
            return (False, "Protected by AWS S3 Block Public Access settings.")

        # Check for explicit global Deny that gates all external access
        global_deny_with_condition = False
        for stmt in config.policy_statements:
            if stmt.effect.lower() == "deny":
                if cls.is_wildcard_principal(stmt.principals) or not stmt.principals:
                    # e.g., Deny if NotIpAddress or NotPrincipalOrgID
                    for cond in stmt.conditions:
                        if cond.operator.lower() in ("notipaddress", "stringnotequals", "arnnotequals"):
                            global_deny_with_condition = True
                            break

        if global_deny_with_condition:
            return (False, "Protected by explicit Deny statement restricting external callers.")

        # Check Allow statements
        for stmt in config.policy_statements:
            if stmt.effect.lower() == "allow":
                if cls.is_wildcard_principal(stmt.principals):
                    # Check if this Allow statement is guarded by an IP or VPC condition
                    if not cls.has_restricting_condition(stmt.conditions):
                        # Unrestricted public allow!
                        actions_str = ", ".join(stmt.actions) if stmt.actions else "All Actions"
                        return (True, f"Unrestricted Allow granted to Principal '*' for actions: {actions_str}")

        return (False, "No unauthenticated public exposure detected.")

    @classmethod
    def evaluates_tls_enforcement(cls, config: S3BucketConfig) -> Tuple[bool, str]:
        """
        CIS 2.1.3: S3 Bucket Policy must enforce SSL/TLS in-transit.
        The standard AWS pattern is:
        Effect: Deny, Principal: "*", Action: "s3:*", Condition: Bool {"aws:SecureTransport": "false"}
        """
        if config.tls_enforced:
            return (True, "TLS explicitly marked as enforced.")

        for stmt in config.policy_statements:
            if stmt.effect.lower() == "deny":
                for cond in stmt.conditions:
                    if cond.key.lower() == "aws:securetransport":
                        # Check if condition values match "false"
                        if any(v.lower() == "false" for v in cond.values):
                            return (True, f"TLS enforced via Deny statement (Sid: {stmt.sid})")
                    elif "tlsversion" in cond.key.lower():
                        return (True, f"TLS version enforced via condition (Sid: {stmt.sid})")

        return (False, "Missing explicit Deny policy for requests where aws:SecureTransport is false.")

    @classmethod
    def evaluates_server_side_encryption(cls, config: S3BucketConfig) -> Tuple[bool, str]:
        """
        CIS 2.1.2: Server-Side Encryption at rest must be enabled by default.
        """
        if config.encryption_enabled:
            algo = config.encryption_algorithm or "AES256"
            return (True, f"Default server-side encryption enabled ({algo}).")

        # Check if bucket policy rejects unencrypted object uploads
        for stmt in config.policy_statements:
            if stmt.effect.lower() == "deny":
                for cond in stmt.conditions:
                    if "s3:x-amz-server-side-encryption" in cond.key.lower():
                        return (True, f"Unencrypted uploads denied by policy (Sid: {stmt.sid})")

        return (False, "Bucket lacks default server-side encryption configuration (SSE-S3 or SSE-KMS).")
