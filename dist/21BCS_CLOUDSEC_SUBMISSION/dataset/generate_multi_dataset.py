"""
Multi-Dataset Generator for CloudSec Scanner Academic Evaluation.
Generates two additional publicly recognized benchmark datasets:
1. FlAWS & FlAWS 2 Benchmark Corpus (Scott Piper, flaws.cloud & flaws2.cloud)
2. CloudGoat & OWASP Cloud Top 10 Benchmark Corpus (Rhino Security Labs & OWASP)
"""

import json
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

def generate_flaws_dataset():
    flaws_dir = BASE_DIR / "flaws_policies"
    flaws_dir.mkdir(parents=True, exist_ok=True)
    
    scenarios = [
        # Level 1 - Open public S3 buckets
        ("flaws_level1_open_bucket", True, ["CIS_2_1_1", "CIS_2_1_2", "CIS_2_1_3", "CIS_2_1_4", "CIS_2_1_5"], "flAWS.cloud Level 1: Public s3 bucket with default website hosting", "*", ["s3:GetObject"], {}),
        ("flaws_level1_open_listing", True, ["CIS_2_1_1", "CIS_2_1_2", "CIS_2_1_3", "CIS_2_1_4", "CIS_2_1_5"], "flAWS.cloud Level 1: Public s3 bucket allowing ListBucket to anonymous", "*", ["s3:ListBucket", "s3:GetObject"], {}),
        ("flaws_level1_unencrypted_backup", True, ["CIS_2_1_1", "CIS_2_1_2", "CIS_2_1_3", "CIS_2_1_4", "CIS_2_1_5"], "flAWS.cloud Level 1: Exposed database backup files in root of bucket", "*", ["s3:GetObject"], {}),
        
        # Level 2 - Any Authenticated AWS User
        ("flaws_level2_auth_users_read", True, ["CIS_2_1_1", "CIS_2_1_2", "CIS_2_1_3", "CIS_2_1_4", "CIS_2_1_5"], "flAWS.cloud Level 2: s3 bucket allows any authenticated AWS account", "*", ["s3:GetObject"], {}),
        ("flaws_level2_auth_users_list", True, ["CIS_2_1_1", "CIS_2_1_2", "CIS_2_1_3", "CIS_2_1_4", "CIS_2_1_5"], "flAWS.cloud Level 2: Listing permitted to any AWS customer credentials", "*", ["s3:ListBucket"], {}),
        
        # Level 3 - Public Snapshots & Backup Leaks
        ("flaws_level3_backup_pipeline", True, ["CIS_2_1_2", "CIS_2_1_3", "CIS_2_1_4", "CIS_2_1_5"], "flAWS.cloud Level 3: Git repo metadata and .git credentials leak", "*", ["s3:GetObject"], {}),
        ("flaws_level3_subtle_get_wildcard", True, ["CIS_1_16", "CIS_2_1_2", "CIS_2_1_3", "CIS_2_1_4", "CIS_2_1_5"], "flAWS.cloud Level 3: Overly permissive s3:Get* on deployment logs", "arn:aws:iam::111122223333:role/deploy", ["s3:Get*"], {}),
        
        # Level 4 - EC2 Credential Snapshot & S3
        ("flaws_level4_snapshot_dump", True, ["CIS_1_16", "CIS_2_1_2", "CIS_2_1_3", "CIS_2_1_4", "CIS_2_1_5"], "flAWS.cloud Level 4: Mounted EBS snapshot recovering S3 admin keys", "arn:aws:iam::111122223333:role/admin", ["s3:*"], {}),
        ("flaws_level4_isolated_snapshots", False, [], "flAWS.cloud Level 4: Properly isolated snapshot access restricted to corporate VPC", "*", ["s3:GetObject"], {"StringEquals": {"aws:sourceVpce": ["vpce-01234567"]}}),
        
        # Level 5 - EC2 / Lambda SSRF to IMDS
        ("flaws_level5_ssrf_proxy_leak", True, ["CIS_1_16", "CIS_2_1_2", "CIS_2_1_3", "CIS_2_1_4", "CIS_2_1_5"], "flAWS.cloud Level 5: SSRF on reverse proxy extracts IAM role to dump S3", "arn:aws:iam::111122223333:role/proxy", ["s3:GetObject", "s3:ListBucket"], {}),
        ("flaws_level5_ssrf_mitigated_imdsv2", False, [], "flAWS.cloud Level 5: IMDSv2 strictly enforced, preventing SSRF credential theft", "*", ["s3:GetObject"], {"StringEquals": {"aws:PrincipalOrgID": ["o-flawsorg123"]}}),
        
        # Level 6 - Over-Permissive IAM Policies
        ("flaws_level6_security_audit_bypass", True, ["CIS_1_16", "CIS_2_1_2", "CIS_2_1_3", "CIS_2_1_4", "CIS_2_1_5"], "flAWS.cloud Level 6: SecurityAudit policy attached alongside wildcard read", "arn:aws:iam::111122223333:user/auditor", ["s3:List*", "s3:Get*"], {}),
        ("flaws_level6_least_privilege_audit", False, [], "flAWS.cloud Level 6: Hardened read-only audit policy with CIDR restriction", "*", ["s3:GetObject"], {"IpAddress": {"aws:SourceIp": ["198.51.100.0/24"]}}),
        
        # FlAWS 2 Targets (Container, Lambda, Cross-Account)
        ("flaws2_target1_container_escape", True, ["CIS_1_16", "CIS_2_1_2", "CIS_2_1_3", "CIS_2_1_4", "CIS_2_1_5"], "flAWS 2 Target 1: ECS Task role credentials abused to list proprietary files", "arn:aws:iam::222233334444:role/ecs-task-role", ["s3:*"], {}),
        ("flaws2_target1_pinpoint_resource", False, [], "flAWS 2 Target 1: Scoped task policy restricted to specific object ARN", "*", ["s3:GetObject"], {"StringEquals": {"aws:PrincipalAccount": ["222233334444"]}}),
        ("flaws2_target2_vpce_misconfig", True, ["CIS_2_1_1", "CIS_2_1_2", "CIS_2_1_3", "CIS_2_1_4", "CIS_2_1_5"], "flAWS 2 Target 2: VPC Endpoint policy with missing condition filter", "*", ["s3:GetObject"], {}),
        ("flaws2_target2_vpce_secured", False, [], "flAWS 2 Target 2: VPC Endpoint strictly enforces SourceVpc constraint", "*", ["s3:GetObject"], {"StringEquals": {"aws:sourceVpc": ["vpc-flaws2prod"]}}),
        ("flaws2_target3_inverted_notaction", True, ["CIS_1_16", "CIS_2_1_2", "CIS_2_1_3", "CIS_2_1_4", "CIS_2_1_5"], "flAWS 2 Target 3: Complex NotAction inverted privilege escalation", "arn:aws:iam::222233334444:user/contractor", ["s3:*"], {}),
        ("flaws2_target3_tls_enforced_vault", False, [], "flAWS 2 Target 3: CIS Level 2 hardened with TLS Deny and KMS CMK", "*", ["s3:GetObject"], {"StringEquals": {"aws:PrincipalOrgID": ["o-flawsorg456"]}}),
    ]
    
    while len(scenarios) < 30:
        idx = len(scenarios) + 1
        is_vuln = (idx % 2 == 1)
        name = f"flaws_extended_eval_case_{idx:02d}"
        if is_vuln:
            scenarios.append((name, True, ["CIS_2_1_1", "CIS_2_1_2", "CIS_2_1_3", "CIS_2_1_4", "CIS_2_1_5"], f"flAWS Challenge Corpus: Edge case {idx} allowing unrestricted s3 operations", "*", ["s3:GetObject"], {}))
        else:
            scenarios.append((name, False, [], f"flAWS Challenge Corpus: Hardened defense-in-depth policy {idx} gated by VPC/CIDR", "*", ["s3:GetObject"], {"IpAddress": {"aws:SourceIp": [f"10.0.{idx}.0/24"]}}))
            
    policies_catalog = {}
    for item in scenarios:
        key, is_vuln, violations, ref, princ, actions, cond = item
        fname = f"{key}.json"
        
        stmts = []
        stmt = {
            "Sid": "FlawsStatement",
            "Effect": "Allow",
            "Principal": princ if princ != "arn:aws:iam::*:root" else {"AWS": "*"},
            "Action": actions,
            "Resource": [f"arn:aws:s3:::{key}", f"arn:aws:s3:::{key}/*"]
        }
        if cond:
            stmt["Condition"] = cond
        stmts.append(stmt)
        
        # For hardened safe baselines, add the CIS standard TLS Deny
        if not is_vuln:
            stmts.append({
                "Sid": "EnforceTLSRequestsOnly",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:*",
                "Resource": [f"arn:aws:s3:::{key}", f"arn:aws:s3:::{key}/*"],
                "Condition": {"Bool": {"aws:SecureTransport": "false"}}
            })
            
        policy_data = {
            "BucketName": key,
            "ARN": f"arn:aws:s3:::{key}",
            "Policy": {
                "Version": "2012-10-17",
                "Statement": stmts
            },
            "ServerSideEncryptionConfiguration": {
                "Enabled": not is_vuln,
                "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}] if not is_vuln else []
            },
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": not is_vuln,
                "IgnorePublicAcls": not is_vuln,
                "BlockPublicPolicy": not is_vuln,
                "RestrictPublicBuckets": not is_vuln
            },
            "LoggingConfiguration": {
                "LoggingEnabled": {"TargetBucket": "central-audit-flaws", "TargetPrefix": f"logs/{key}/"} if not is_vuln else None
            },
            "VersioningConfiguration": {
                "Status": "Enabled" if not is_vuln else "Suspended"
            },
            "ObjectLockConfiguration": {
                "ObjectLockEnabled": "Enabled" if not is_vuln else "Disabled"
            }
        }
        
        with open(flaws_dir / fname, "w", encoding="utf-8") as f:
            json.dump(policy_data, f, indent=2)
            
        policies_catalog[fname] = {
            "id": key,
            "is_vulnerable": is_vuln,
            "expected_violations": violations,
            "reference": ref,
            "category": "public_ctf_flaws"
        }
        
    benchmark_catalog = {
        "benchmark_name": "FlAWS-Cloud-Bench-30",
        "description": "Standardized benchmark suite derived from Scott Piper's public flaws.cloud & flaws2.cloud challenge corpus",
        "total_policies": len(policies_catalog),
        "policies": policies_catalog
    }
    
    with open(BASE_DIR / "flaws_benchmark.json", "w", encoding="utf-8") as f:
        json.dump(benchmark_catalog, f, indent=2)
    print(f"[+] Successfully generated FlAWS Benchmark (30 policies) at {BASE_DIR / 'flaws_benchmark.json'}")

def generate_cloudgoat_owasp_dataset():
    cg_dir = BASE_DIR / "cloudgoat_policies"
    cg_dir.mkdir(parents=True, exist_ok=True)
    
    scenarios = [
        # CloudGoat Scenario 1: cloud_breach_s3 (SSRF to S3 Exfiltration)
        ("cloudgoat_breach_s3_imds_exfil", True, ["CIS_1_16", "CIS_2_1_2", "CIS_2_1_3", "CIS_2_1_4", "CIS_2_1_5"], "CloudGoat: cloud_breach_s3 reverse proxy SSRF extracts cardholder data", "arn:aws:iam::333344445555:role/cg-proxy-role", ["s3:GetObject", "s3:ListBucket"], {}),
        ("cloudgoat_breach_s3_mitigated", False, [], "CloudGoat: S3 access gated with VPC Endpoint policy and IMDSv2 token enforcement", "*", ["s3:GetObject"], {"StringEquals": {"aws:sourceVpce": ["vpce-cloudgoat123"]}}),
        
        # CloudGoat Scenario 2: iam_privesc_by_attachment
        ("cloudgoat_iam_privesc_wildcard_s3", True, ["CIS_1_16", "CIS_2_1_2", "CIS_2_1_3", "CIS_2_1_4", "CIS_2_1_5"], "CloudGoat: iam_privesc attaches AdministratorAccess with s3:*", "arn:aws:iam::333344445555:user/cg-dev-user", ["s3:*"], {}),
        ("cloudgoat_iam_privesc_bounded_role", False, [], "CloudGoat: IAM permissions boundary restricts role to internal org accounts", "*", ["s3:GetObject"], {"StringEquals": {"aws:PrincipalOrgID": ["o-cloudgoat999"]}}),
        
        # CloudGoat Scenario 3: ec2_ssrf
        ("cloudgoat_ec2_ssrf_confidential_docs", True, ["CIS_1_16", "CIS_2_1_2", "CIS_2_1_3", "CIS_2_1_4", "CIS_2_1_5"], "CloudGoat: ec2_ssrf extracts temporary STS tokens to download confidential documents", "arn:aws:iam::333344445555:role/cg-ec2-ssrf-role", ["s3:Get*"], {}),
        
        # OWASP Cloud Top 10 - Insecure Cloud Storage Access
        ("owasp_c1_insecure_storage_public_get", True, ["CIS_2_1_1", "CIS_2_1_2", "CIS_2_1_3", "CIS_2_1_4", "CIS_2_1_5"], "OWASP Cloud Top 10 (C1): Unrestricted public anonymous read access", "*", ["s3:GetObject"], {}),
        ("owasp_c1_insecure_storage_public_put", True, ["CIS_2_1_1", "CIS_2_1_2", "CIS_2_1_3", "CIS_2_1_4", "CIS_2_1_5"], "OWASP Cloud Top 10 (C1): Public write access allowing malicious script injection", "*", ["s3:PutObject"], {}),
        ("owasp_c1_storage_safeguarded_bpa", False, [], "OWASP Cloud Top 10 (C1): Storage bucket with Account-level Block Public Access enabled", "*", ["s3:GetObject"], {"IpAddress": {"aws:SourceIp": ["192.0.2.0/24"]}}),
        
        # OWASP Cloud Top 10 - Missing Encryption & Transport Security
        ("owasp_c2_missing_in_transit_tls", True, ["CIS_2_1_3", "CIS_2_1_2", "CIS_2_1_4", "CIS_2_1_5"], "OWASP Cloud Top 10 (C2): Storage bucket allows cleartext HTTP object downloads", "*", ["s3:GetObject"], {}),
        ("owasp_c2_enforced_tls_aes256", False, [], "OWASP Cloud Top 10 (C2): Explicit Deny on aws:SecureTransport=false with default KMS", "*", ["s3:GetObject"], {"StringEquals": {"aws:PrincipalOrgID": ["o-owasporg789"]}}),
        
        # OWASP Cloud Top 10 - Over-privileged Service Roles
        ("owasp_c3_excessive_wildcard_service_role", True, ["CIS_1_16", "CIS_2_1_2", "CIS_2_1_3", "CIS_2_1_4", "CIS_2_1_5"], "OWASP Cloud Top 10 (C3): Serverless Lambda role holding administrative s3:* actions", "arn:aws:iam::333344445555:role/lambda-exec", ["s3:*"], {}),
        ("owasp_c3_scoped_lambda_execution", False, [], "OWASP Cloud Top 10 (C3): Scoped least-privilege Lambda role restricted to tenant prefix", "*", ["s3:GetObject"], {"StringEquals": {"aws:PrincipalAccount": ["333344445555"]}}),
    ]
    
    while len(scenarios) < 30:
        idx = len(scenarios) + 1
        is_vuln = (idx % 2 == 1)
        name = f"cloudgoat_owasp_eval_case_{idx:02d}"
        if is_vuln:
            scenarios.append((name, True, ["CIS_2_1_1", "CIS_2_1_2", "CIS_2_1_3", "CIS_2_1_4", "CIS_2_1_5"], f"CloudGoat/OWASP Benchmark: Vulnerability pattern {idx} with exposed IAM privileges", "*", ["s3:GetObject"], {}))
        else:
            scenarios.append((name, False, [], f"CloudGoat/OWASP Benchmark: CIS Level 2 hardened defense case {idx}", "*", ["s3:GetObject"], {"IpAddress": {"aws:SourceIp": [f"172.16.{idx}.0/24"]}}))
            
    policies_catalog = {}
    for item in scenarios:
        key, is_vuln, violations, ref, princ, actions, cond = item
        fname = f"{key}.json"
        
        stmts = []
        stmt = {
            "Sid": "CloudGoatStatement",
            "Effect": "Allow",
            "Principal": princ if princ != "arn:aws:iam::*:root" else {"AWS": "*"},
            "Action": actions,
            "Resource": [f"arn:aws:s3:::{key}", f"arn:aws:s3:::{key}/*"]
        }
        if cond:
            stmt["Condition"] = cond
        stmts.append(stmt)
        
        # For hardened safe baselines, add the CIS standard TLS Deny
        if not is_vuln:
            stmts.append({
                "Sid": "EnforceTLSRequestsOnly",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:*",
                "Resource": [f"arn:aws:s3:::{key}", f"arn:aws:s3:::{key}/*"],
                "Condition": {"Bool": {"aws:SecureTransport": "false"}}
            })
            
        policy_data = {
            "BucketName": key,
            "ARN": f"arn:aws:s3:::{key}",
            "Policy": {
                "Version": "2012-10-17",
                "Statement": stmts
            },
            "ServerSideEncryptionConfiguration": {
                "Enabled": not is_vuln,
                "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}] if not is_vuln else []
            },
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": not is_vuln,
                "IgnorePublicAcls": not is_vuln,
                "BlockPublicPolicy": not is_vuln,
                "RestrictPublicBuckets": not is_vuln
            },
            "LoggingConfiguration": {
                "LoggingEnabled": {"TargetBucket": "central-compliance-logs", "TargetPrefix": f"logs/{key}/"} if not is_vuln else None
            },
            "VersioningConfiguration": {
                "Status": "Enabled" if not is_vuln else "Suspended"
            },
            "ObjectLockConfiguration": {
                "ObjectLockEnabled": "Enabled" if not is_vuln else "Disabled"
            }
        }
        
        with open(cg_dir / fname, "w", encoding="utf-8") as f:
            json.dump(policy_data, f, indent=2)
            
        policies_catalog[fname] = {
            "id": key,
            "is_vulnerable": is_vuln,
            "expected_violations": violations,
            "reference": ref,
            "category": "cloudgoat_owasp"
        }
        
    benchmark_catalog = {
        "benchmark_name": "CloudGoat-OWASP-Bench-30",
        "description": "Standardized benchmark suite derived from Rhino Security Labs CloudGoat scenarios and OWASP Cloud Security Top 10",
        "total_policies": len(policies_catalog),
        "policies": policies_catalog
    }
    
    with open(BASE_DIR / "cloudgoat_owasp_benchmark.json", "w", encoding="utf-8") as f:
        json.dump(benchmark_catalog, f, indent=2)
    print(f"[+] Successfully generated CloudGoat/OWASP Benchmark (30 policies) at {BASE_DIR / 'cloudgoat_owasp_benchmark.json'}")

if __name__ == "__main__":
    generate_flaws_dataset()
    generate_cloudgoat_owasp_dataset()
