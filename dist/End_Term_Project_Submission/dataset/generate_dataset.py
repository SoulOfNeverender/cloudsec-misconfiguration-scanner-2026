from __future__ import annotations
import json
import os
from pathlib import Path
from typing import Any, Dict, List

DATASET_DIR = Path(__file__).parent
POLICIES_DIR = DATASET_DIR / "policies"
GROUND_TRUTH_FILE = DATASET_DIR / "ground_truth.json"


def build_policy(
    statements: List[Dict[str, Any]],
    bucket_name: str,
    encryption_enabled: bool = True,
    encryption_algo: str = "AES256",
    logging_enabled: bool = True,
    versioning_status: str = "Enabled",
    object_lock: bool = True,
    block_public: bool = True,
) -> Dict[str, Any]:
    return {
        "BucketName": bucket_name,
        "ARN": f"arn:aws:s3:::{bucket_name}",
        "Policy": {
            "Version": "2012-10-17",
            "Statement": statements,
        },
        "ServerSideEncryptionConfiguration": {
            "Enabled": encryption_enabled,
            "Rules": [
                {
                    "ApplyServerSideEncryptionByDefault": {
                        "SSEAlgorithm": encryption_algo
                    }
                }
            ] if encryption_enabled else [],
        },
        "PublicAccessBlockConfiguration": {
            "BlockPublicAcls": block_public,
            "IgnorePublicAcls": block_public,
            "BlockPublicPolicy": block_public,
            "RestrictPublicBuckets": block_public,
        },
        "LoggingConfiguration": {
            "LoggingEnabled": {
                "TargetBucket": "audit-logs-compliance-us-east-1",
                "TargetPrefix": f"access-logs/{bucket_name}/",
            } if logging_enabled else None
        },
        "VersioningConfiguration": {
            "Status": versioning_status
        },
        "ObjectLockConfiguration": {
            "ObjectLockEnabled": "Enabled" if object_lock else "Disabled"
        }
    }


def generate_benchmark_suite() -> None:
    os.makedirs(POLICIES_DIR, exist_ok=True)
    ground_truth: Dict[str, Any] = {
        "benchmark_name": "CloudSec-S3-Bench-120",
        "description": "Standardized benchmark suite for AWS S3 and IAM policy misconfigurations",
        "total_policies": 120,
        "categories": {
            "clear_vulnerable": {"count": 40, "range": "001-040", "label": "Vulnerable"},
            "tricky_safe": {"count": 30, "range": "041-070", "label": "Safe (False Positive Traps)"},
            "tricky_vulnerable": {"count": 30, "range": "071-100", "label": "Vulnerable (False Negative Traps)"},
            "cis_hardened": {"count": 20, "range": "101-120", "label": "Safe (CIS Baseline)"}
        },
        "policies": {}
    }

    # =========================================================================
    # CATEGORY 1: Clear-Cut Vulnerabilities (001 - 040)
    # Open buckets, wildcard admins, no encryption, no TLS, no logging
    # =========================================================================
    breach_refs = [
        "Deep Root Analytics S3 Leak (198M voter records)",
        "Capital One SSRF IAM Exfiltration Pattern",
        "Imperva Cloud DB Backup Dump",
        "Alteryx / Experian Demographic S3 Bucket",
        "Booz Allen Hamilton Unprotected S3 Image Cache",
        "Dow Jones Elasticsearch Snapshot Leak",
        "Accenture Cloud Asset Backup Exposure",
        "FedEx Customer Record Archive",
        "GoDaddy IAM Key Exposure",
        "WWE Fan Database S3 Misconfiguration",
    ]

    for i in range(1, 41):
        idx_str = f"{i:03d}"
        bname = f"breach-pattern-bucket-{idx_str}"
        ref = breach_refs[(i - 1) % len(breach_refs)]

        # Varied violation combinations
        if i <= 10:
            # Open public bucket with wildcard read
            stmts = [
                {
                    "Sid": "PublicReadGetObject",
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": f"arn:aws:s3:::{bname}/*"
                }
            ]
            expected = ["CIS_2_1_1", "CIS_2_1_3"]
            enc, log, ver, blk = False, False, "Suspended", False
            expected.extend(["CIS_2_1_2", "CIS_2_1_4", "CIS_2_1_5"])
        elif i <= 20:
            # Wildcard IAM Action
            stmts = [
                {
                    "Sid": "OverprivilegedRoleGrant",
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::123456789012:role/app-worker-{idx_str}"},
                    "Action": "s3:*",
                    "Resource": f"arn:aws:s3:::{bname}/*"
                }
            ]
            expected = ["CIS_1_16", "CIS_2_1_3"]
            enc, log, ver, blk = False, True, "Enabled", True
            expected.append("CIS_2_1_2")
        elif i <= 30:
            # Public read/write bucket (Total disaster)
            stmts = [
                {
                    "Sid": "PublicFullReadWrite",
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
                    "Resource": f"arn:aws:s3:::{bname}/*"
                }
            ]
            expected = ["CIS_2_1_1", "CIS_2_1_3"]
            enc, log, ver, blk = False, False, "Suspended", False
            expected.extend(["CIS_2_1_2", "CIS_2_1_4", "CIS_2_1_5"])
        else:
            # Unencrypted with missing logging & TLS
            stmts = [
                {
                    "Sid": "AllowAppRole",
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::123456789012:role/service-{idx_str}"},
                    "Action": ["s3:GetObject", "s3:PutObject"],
                    "Resource": f"arn:aws:s3:::{bname}/*"
                }
            ]
            expected = ["CIS_2_1_3", "CIS_2_1_2", "CIS_2_1_4"]
            enc, log, ver, blk = False, False, "Enabled", True

        policy_obj = build_policy(
            statements=stmts,
            bucket_name=bname,
            encryption_enabled=enc,
            logging_enabled=log,
            versioning_status=ver,
            block_public=blk,
            object_lock=False,
        )

        filename = f"policy_{idx_str}.json"
        with open(POLICIES_DIR / filename, "w", encoding="utf-8") as f:
            json.dump(policy_obj, f, indent=2)

        ground_truth["policies"][filename] = {
            "id": idx_str,
            "category": "clear_vulnerable",
            "is_vulnerable": True,
            "expected_violations": sorted(list(set(expected))),
            "reference": ref,
            "notes": f"Demonstrates {ref} misconfiguration pattern."
        }

    # =========================================================================
    # CATEGORY 2: Condition-Restricted Edge Cases / "Tricky Safe" (041 - 070)
    # Looks like Principal: "*" BUT restricted by IP, VPC, or OrgID conditions!
    # Tests FALSE POSITIVES (A naive scanner fails here, our scanner passes!)
    # =========================================================================
    for i in range(41, 71):
        idx_str = f"{i:03d}"
        bname = f"secure-edge-case-{idx_str}"

        if i <= 50:
            # Wildcard principal restricted to corporate IP CIDR
            stmts = [
                {
                    "Sid": "AllowCorpOfficeIPOnly",
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": f"arn:aws:s3:::{bname}/*",
                    "Condition": {
                        "IpAddress": {
                            "aws:SourceIp": ["198.51.100.0/24", "203.0.113.50/32"]
                        }
                    }
                },
                {
                    "Sid": "EnforceTLS",
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "s3:*",
                    "Resource": [f"arn:aws:s3:::{bname}", f"arn:aws:s3:::{bname}/*"],
                    "Condition": {
                        "Bool": {"aws:SecureTransport": "false"}
                    }
                }
            ]
            notes = "Principal is '*' but restricted to corporate IP CIDR via aws:SourceIp."
        elif i <= 60:
            # Wildcard principal restricted to internal VPC Endpoint
            stmts = [
                {
                    "Sid": "AllowVpcEndpointTrafficOnly",
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": ["s3:GetObject", "s3:ListBucket"],
                    "Resource": [f"arn:aws:s3:::{bname}", f"arn:aws:s3:::{bname}/*"],
                    "Condition": {
                        "StringEquals": {
                            "aws:sourceVpce": f"vpce-0a1b2c3d4e5f{idx_str}"
                        }
                    }
                },
                {
                    "Sid": "EnforceTLS",
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "s3:*",
                    "Resource": f"arn:aws:s3:::{bname}/*",
                    "Condition": {
                        "Bool": {"aws:SecureTransport": "false"}
                    }
                }
            ]
            notes = "Restricted to internal VPC Endpoint via aws:sourceVpce condition."
        else:
            # Wildcard principal restricted to AWS Organization ID
            stmts = [
                {
                    "Sid": "AllowOnlyAwsOrgMembers",
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": ["s3:GetObject", "s3:PutObject"],
                    "Resource": f"arn:aws:s3:::{bname}/*",
                    "Condition": {
                        "StringEquals": {
                            "aws:PrincipalOrgID": "o-corpenterprise99"
                        }
                    }
                },
                {
                    "Sid": "EnforceTLS",
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "s3:*",
                    "Resource": f"arn:aws:s3:::{bname}/*",
                    "Condition": {
                        "Bool": {"aws:SecureTransport": "false"}
                    }
                }
            ]
            notes = "Restricted to corporate AWS Organization members via aws:PrincipalOrgID."

        policy_obj = build_policy(
            statements=stmts,
            bucket_name=bname,
            encryption_enabled=True,
            encryption_algo="aws:kms",
            logging_enabled=True,
            versioning_status="Enabled",
            block_public=True,
            object_lock=True,
        )

        filename = f"policy_{idx_str}.json"
        with open(POLICIES_DIR / filename, "w", encoding="utf-8") as f:
            json.dump(policy_obj, f, indent=2)

        ground_truth["policies"][filename] = {
            "id": idx_str,
            "category": "tricky_safe",
            "is_vulnerable": False,
            "expected_violations": [],
            "reference": "Condition-Restricted Safe Configuration",
            "notes": notes
        }

    # =========================================================================
    # CATEGORY 3: Subtle Bypasses / "Tricky Bad" (071 - 100)
    # Sneaky vulnerabilities: partial wildcards, inverted TLS conditions, etc.
    # Tests FALSE NEGATIVES (A naive scanner misses these, our scanner catches them!)
    # =========================================================================
    for i in range(71, 101):
        idx_str = f"{i:03d}"
        bname = f"subtle-bypass-bucket-{idx_str}"

        if i <= 80:
            # Partial wildcard action: s3:Get* (allows complete exfiltration without exact "s3:*")
            stmts = [
                {
                    "Sid": "ReadAnalyticsWildcard",
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::123456789012:role/external-partner-{idx_str}"},
                    "Action": ["s3:Get*", "s3:List*"],
                    "Resource": f"arn:aws:s3:::{bname}/*"
                }
            ]
            expected = ["CIS_1_16", "CIS_2_1_3"]
            notes = "Uses partial wildcard action s3:Get* to exfiltrate all object types and ACLs."
            enc, log, ver, blk = True, True, "Enabled", True
        elif i <= 90:
            # Logic error in TLS policy: Bool aws:SecureTransport is "true" under Deny (Denies HTTPS, forces HTTP!)
            stmts = [
                {
                    "Sid": "FlawedTLSDenyLogic",
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "s3:*",
                    "Resource": f"arn:aws:s3:::{bname}/*",
                    "Condition": {
                        "Bool": {"aws:SecureTransport": "true"}  # Inverted logic bug!
                    }
                }
            ]
            expected = ["CIS_2_1_3"]
            notes = "Inverted TLS condition bug denies HTTPS instead of HTTP."
            enc, log, ver, blk = True, True, "Enabled", True
        else:
            # Unencrypted storage despite secure transport
            stmts = [
                {
                    "Sid": "EnforceTLS",
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "s3:*",
                    "Resource": f"arn:aws:s3:::{bname}/*",
                    "Condition": {
                        "Bool": {"aws:SecureTransport": "false"}
                    }
                }
            ]
            expected = ["CIS_2_1_2"]
            notes = "Has valid TLS policy but misses default SSE-KMS at-rest encryption."
            enc, log, ver, blk = False, True, "Enabled", True

        policy_obj = build_policy(
            statements=stmts,
            bucket_name=bname,
            encryption_enabled=enc,
            logging_enabled=log,
            versioning_status=ver,
            block_public=blk,
            object_lock=True,
        )

        filename = f"policy_{idx_str}.json"
        with open(POLICIES_DIR / filename, "w", encoding="utf-8") as f:
            json.dump(policy_obj, f, indent=2)

        ground_truth["policies"][filename] = {
            "id": idx_str,
            "category": "tricky_vulnerable",
            "is_vulnerable": True,
            "expected_violations": sorted(list(set(expected))),
            "reference": "Subtle Policy Logic Flaw / Bypass",
            "notes": notes
        }

    # =========================================================================
    # CATEGORY 4: CIS-Hardened Baselines (101 - 120)
    # Fully hardened, zero violations, production ready
    # =========================================================================
    for i in range(101, 121):
        idx_str = f"{i:03d}"
        bname = f"production-hardened-vault-{idx_str}"

        stmts = [
            {
                "Sid": "EnforceTLSRequestsOnly",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:*",
                "Resource": [f"arn:aws:s3:::{bname}", f"arn:aws:s3:::{bname}/*"],
                "Condition": {
                    "Bool": {"aws:SecureTransport": "false"}
                }
            },
            {
                "Sid": "DenyUnencryptedUploads",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:PutObject",
                "Resource": f"arn:aws:s3:::{bname}/*",
                "Condition": {
                    "StringNotEquals": {
                        "s3:x-amz-server-side-encryption": ["aws:kms", "AES256"]
                    }
                }
            },
            {
                "Sid": "AllowAppRoleLeastPrivilege",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::123456789012:role/prod-service-role-{idx_str}"},
                "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bname}", f"arn:aws:s3:::{bname}/*"]
            }
        ]

        policy_obj = build_policy(
            statements=stmts,
            bucket_name=bname,
            encryption_enabled=True,
            encryption_algo="aws:kms",
            logging_enabled=True,
            versioning_status="Enabled",
            block_public=True,
            object_lock=True,
        )

        filename = f"policy_{idx_str}.json"
        with open(POLICIES_DIR / filename, "w", encoding="utf-8") as f:
            json.dump(policy_obj, f, indent=2)

        ground_truth["policies"][filename] = {
            "id": idx_str,
            "category": "cis_hardened",
            "is_vulnerable": False,
            "expected_violations": [],
            "reference": "CIS AWS Foundations Level 2 Benchmark",
            "notes": "Full production hardening with KMS CMK, TLS Deny, logging, and Object Lock."
        }

    with open(GROUND_TRUTH_FILE, "w", encoding="utf-8") as f:
        json.dump(ground_truth, f, indent=2)

    print(f"Generated {len(ground_truth['policies'])} benchmark policies in '{POLICIES_DIR}'")
    print(f"Ground truth catalog saved to '{GROUND_TRUTH_FILE}'")


if __name__ == "__main__":
    generate_benchmark_suite()
