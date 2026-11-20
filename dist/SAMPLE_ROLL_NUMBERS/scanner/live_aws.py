from __future__ import annotations
import json
import os
from typing import Any, Dict, List, Optional
from .live_connector import CloudConnector
from .models import (
    AccountBPA,
    CloudEnvironment,
    CloudProvider,
    PolicyStatement,
    S3BucketConfig,
    SCPPolicy,
    VPCEndpointPolicy,
)
from .parser import PolicyParser


class AWSConnector(CloudConnector):
    """
    Live AWS SDK (boto3) and LocalStack discovery connector.
    Supports continuous cloud posture assessment, account-level BPA inspection,
    and automated drift remediation.
    """

    def __init__(
        self,
        region: str = "us-east-1",
        endpoint_url: Optional[str] = None,
        profile: Optional[str] = None,
        use_localstack: bool = False,
    ):
        self.region = region
        self.endpoint_url = endpoint_url
        self.profile = profile
        self.use_localstack = use_localstack
        self._account_id = "123456789012"

        # Initialize boto3 session safely
        try:
            import boto3
            from botocore.config import Config
        except ImportError:
            raise ImportError(
                "AWS SDK ('boto3') is required for live cloud discovery. "
                "Install it using: pip install boto3"
            )

        if use_localstack:
            os.environ.setdefault("AWS_ACCESS_KEY_ID", "mock_key")
            os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "mock_secret")
            if not self.endpoint_url:
                self.endpoint_url = "http://localhost:4566"

        session_kwargs = {"region_name": self.region}
        if self.profile:
            session_kwargs["profile_name"] = self.profile

        self.session = boto3.Session(**session_kwargs)
        self.s3_client = self.session.client("s3", endpoint_url=self.endpoint_url)

        try:
            sts = self.session.client("sts", endpoint_url=self.endpoint_url)
            self._account_id = sts.get_caller_identity().get("Account", "123456789012")
        except Exception:
            self._account_id = "123456789012"

    def list_buckets(self) -> List[str]:
        try:
            resp = self.s3_client.list_buckets()
            return [b["Name"] for b in resp.get("Buckets", [])]
        except Exception as e:
            print(f"[!] Warning: Failed to list S3 buckets: {e}")
            return []

    def get_bucket_config(self, bucket_name: str) -> S3BucketConfig:
        arn = f"arn:aws:s3:::{bucket_name}"
        statements: List[PolicyStatement] = []
        raw_policy: Optional[Dict[str, Any]] = None

        # 1. Bucket Policy
        try:
            pol_resp = self.s3_client.get_bucket_policy(Bucket=bucket_name)
            raw_policy_str = pol_resp.get("Policy", "{}")
            raw_policy = json.loads(raw_policy_str)
            if "Statement" in raw_policy:
                stmts_node = raw_policy["Statement"]
                if isinstance(stmts_node, dict):
                    stmts_node = [stmts_node]
                for s in stmts_node:
                    if isinstance(s, dict):
                        statements.append(PolicyParser.parse_statement(s))
        except Exception:
            raw_policy = None

        # 2. Public Access Block (Bucket-Level)
        b_pab = {"BlockPublicAcls": False, "IgnorePublicAcls": False, "BlockPublicPolicy": False, "RestrictPublicBuckets": False}
        try:
            pab_resp = self.s3_client.get_public_access_block(Bucket=bucket_name)
            b_pab = pab_resp.get("PublicAccessBlockConfiguration", b_pab)
        except Exception:
            pass

        # 3. Encryption
        enc_enabled = False
        enc_algo = None
        try:
            enc_resp = self.s3_client.get_bucket_encryption(Bucket=bucket_name)
            rules = enc_resp.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
            if rules:
                enc_enabled = True
                def_enc = rules[0].get("ApplyServerSideEncryptionByDefault", {})
                enc_algo = def_enc.get("SSEAlgorithm", "AES256")
        except Exception:
            enc_enabled = False

        # 4. Versioning
        versioning_status = "Suspended"
        try:
            ver_resp = self.s3_client.get_bucket_versioning(Bucket=bucket_name)
            versioning_status = ver_resp.get("Status", "Suspended")
        except Exception:
            pass

        # 5. Logging
        logging_enabled = False
        try:
            log_resp = self.s3_client.get_bucket_logging(Bucket=bucket_name)
            logging_enabled = "LoggingEnabled" in log_resp
        except Exception:
            pass

        # 6. Object Lock
        object_lock = False
        try:
            ol_resp = self.s3_client.get_object_lock_configuration(Bucket=bucket_name)
            object_lock = ol_resp.get("ObjectLockConfiguration", {}).get("ObjectLockEnabled") == "Enabled"
        except Exception:
            pass

        # 7. Check TLS enforcement from policy statements
        tls_enforced = False
        for stmt in statements:
            if stmt.effect.lower() == "deny":
                for cond in stmt.conditions:
                    if cond.key.lower() == "aws:securetransport" and any(v.lower() == "false" for v in cond.values):
                        tls_enforced = True

        return S3BucketConfig(
            bucket_name=bucket_name,
            arn=arn,
            policy_statements=statements,
            raw_policy=raw_policy,
            encryption_enabled=enc_enabled,
            encryption_algorithm=enc_algo,
            tls_enforced=tls_enforced,
            logging_enabled=logging_enabled,
            versioning_status=versioning_status,
            object_lock_enabled=object_lock,
            block_public_acls=b_pab.get("BlockPublicAcls", False),
            ignore_public_acls=b_pab.get("IgnorePublicAcls", False),
            block_public_policy=b_pab.get("BlockPublicPolicy", False),
            restrict_public_buckets=b_pab.get("RestrictPublicBuckets", False),
        )

    def get_account_bpa(self) -> AccountBPA:
        try:
            s3control = self.session.client("s3control", endpoint_url=self.endpoint_url)
            resp = s3control.get_public_access_block(AccountId=self._account_id)
            pab = resp.get("PublicAccessBlockConfiguration", {})
            return AccountBPA(
                block_public_acls=pab.get("BlockPublicAcls", False),
                ignore_public_acls=pab.get("IgnorePublicAcls", False),
                block_public_policy=pab.get("BlockPublicPolicy", False),
                restrict_public_buckets=pab.get("RestrictPublicBuckets", False),
            )
        except Exception:
            # Safe default fallback
            return AccountBPA(
                block_public_acls=False,
                ignore_public_acls=False,
                block_public_policy=False,
                restrict_public_buckets=False,
            )

    def get_scps(self) -> List[SCPPolicy]:
        scps = []
        try:
            org = self.session.client("organizations")
            pols = org.list_policies(Filter="SERVICE_CONTROL_POLICY").get("Policies", [])
            for p in pols:
                desc = org.describe_policy(PolicyId=p["Id"])
                content = json.loads(desc.get("Policy", {}).get("Content", "{}"))
                for s in content.get("Statement", []):
                    scps.append(
                        SCPPolicy(
                            sid=s.get("Sid", p["Name"]),
                            effect=s.get("Effect", "Allow"),
                            actions=s.get("Action", []) if isinstance(s.get("Action"), list) else [s.get("Action", "")],
                            resources=s.get("Resource", []) if isinstance(s.get("Resource"), list) else [s.get("Resource", "")],
                            description=p.get("Description", ""),
                        )
                    )
        except Exception:
            pass
        return scps

    def get_vpc_endpoints(self) -> List[VPCEndpointPolicy]:
        vpces = []
        try:
            ec2 = self.session.client("ec2", endpoint_url=self.endpoint_url)
            resp = ec2.describe_vpc_endpoints()
            for ep in resp.get("VpcEndpoints", []):
                if "s3" in ep.get("ServiceName", "").lower():
                    vpces.append(
                        VPCEndpointPolicy(
                            vpc_endpoint_id=ep["VpcEndpointId"],
                            vpc_id=ep.get("VpcId", ""),
                        )
                    )
        except Exception:
            pass
        return vpces

    def get_full_environment(self) -> CloudEnvironment:
        provider = CloudProvider.LOCALSTACK if self.use_localstack else CloudProvider.AWS
        return CloudEnvironment(
            provider=provider,
            account_id=self._account_id,
            region=self.region,
            account_bpa=self.get_account_bpa(),
            scps=self.get_scps(),
            vpc_endpoints=self.get_vpc_endpoints(),
        )

    def apply_bucket_bpa(self, bucket_name: str) -> bool:
        """Remediation: apply full S3 Block Public Access to target bucket."""
        try:
            self.s3_client.put_public_access_block(
                Bucket=bucket_name,
                PublicAccessBlockConfiguration={
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                },
            )
            return True
        except Exception as e:
            print(f"[!] Remediation API error for {bucket_name}: {e}")
            return False

    def apply_bucket_encryption(self, bucket_name: str, algorithm: str = "AES256") -> bool:
        """Remediation: enable server-side encryption by default."""
        try:
            self.s3_client.put_bucket_encryption(
                Bucket=bucket_name,
                ServerSideEncryptionConfiguration={
                    "Rules": [
                        {
                            "ApplyServerSideEncryptionByDefault": {
                                "SSEAlgorithm": algorithm,
                            }
                        }
                    ]
                },
            )
            return True
        except Exception as e:
            print(f"[!] Remediation API error for {bucket_name}: {e}")
            return False
