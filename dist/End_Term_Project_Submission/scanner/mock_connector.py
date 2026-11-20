from __future__ import annotations
from typing import Dict, List, Optional
from .live_connector import CloudConnector
from .models import (
    AccountBPA,
    CloudEnvironment,
    CloudProvider,
    ConditionClause,
    IAMIdentityContext,
    PolicyStatement,
    S3BucketConfig,
    SCPPolicy,
    VPCEndpointPolicy,
)


class MockConnector(CloudConnector):
    """
    Zero-Dependency Mock Cloud Connector for testing, benchmarking, and real breach demos.
    Allows running complete enterprise attack-surface and exploitability assessments
    without requiring active cloud credentials or internet connectivity.
    """

    def __init__(self, buckets: Dict[str, S3BucketConfig], environment: CloudEnvironment):
        self._buckets = buckets
        self._env = environment

    def list_buckets(self) -> List[str]:
        return list(self._buckets.keys())

    def get_bucket_config(self, bucket_name: str) -> S3BucketConfig:
        if bucket_name not in self._buckets:
            raise KeyError(f"Mock bucket '{bucket_name}' not found. Available: {list(self._buckets.keys())}")
        return self._buckets[bucket_name]

    def get_account_bpa(self) -> AccountBPA:
        return self._env.account_bpa

    def get_scps(self) -> List[SCPPolicy]:
        return self._env.scps

    def get_vpc_endpoints(self) -> List[VPCEndpointPolicy]:
        return self._env.vpc_endpoints

    def get_full_environment(self) -> CloudEnvironment:
        return self._env

    def apply_bucket_bpa(self, bucket_name: str) -> bool:
        if bucket_name in self._buckets:
            b = self._buckets[bucket_name]
            b.block_public_acls = True
            b.ignore_public_acls = True
            b.block_public_policy = True
            b.restrict_public_buckets = True
            return True
        return False

    def apply_bucket_encryption(self, bucket_name: str, algorithm: str = "AES256") -> bool:
        if bucket_name in self._buckets:
            b = self._buckets[bucket_name]
            b.encryption_enabled = True
            b.encryption_algorithm = algorithm
            return True
        return False

    # -------------------------------------------------------------------------
    # Built-in Real-World Breach & Cloud Misconfiguration Scenarios
    # -------------------------------------------------------------------------
    @classmethod
    def from_scenario(cls, scenario_name: str) -> "MockConnector":
        name = scenario_name.lower().strip()

        # ---------------------------------------------------------------------
        # SCENARIO 1: Capital One SSRF Breach (140,000 SSNs Leaked)
        # ---------------------------------------------------------------------
        if name in ("capital_one", "capital_one_breach", "ssrf_breach"):
            bucket_name = "capital-one-credit-applications-vault"
            stmt = PolicyStatement(
                sid="AllowWafProxyRole",
                effect="Allow",
                principals=["arn:aws:iam::123456789012:role/waf-reverse-proxy-role"],
                actions=["s3:GetObject", "s3:ListBucket"],
                resources=[f"arn:aws:s3:::{bucket_name}", f"arn:aws:s3:::{bucket_name}/*"],
            )
            bucket = S3BucketConfig(
                bucket_name=bucket_name,
                arn=f"arn:aws:s3:::{bucket_name}",
                policy_statements=[stmt],
                encryption_enabled=True,
                encryption_algorithm="AES256",
                tls_enforced=True,
                logging_enabled=True,
                versioning_status="Enabled",
                block_public_policy=True,
                restrict_public_buckets=True,
            )
            # The flaw: WAF EC2 instance has IMDSv1 enabled and holds this IAM role!
            env = CloudEnvironment(
                provider=CloudProvider.AWS,
                account_id="123456789012",
                region="us-east-1",
                account_bpa=AccountBPA(True, True, True, True),
                iam_identities=[
                    IAMIdentityContext(
                        principal_arn="arn:aws:iam::123456789012:role/waf-reverse-proxy-role",
                        imdsv1_enabled=True,  # Attacker hits http://169.254.169.254 via SSRF
                        attached_policies=[
                            {
                                "PolicyName": "FullS3SyncAccess",
                                "Action": ["s3:GetObject", "s3:ListBucket"],
                                "Resource": f"arn:aws:s3:::{bucket_name}/*",
                            }
                        ],
                    )
                ],
            )
            return cls({bucket_name: bucket}, env)

        # ---------------------------------------------------------------------
        # SCENARIO 2: Deep Root Analytics (198M Voter Records Leaked)
        # ---------------------------------------------------------------------
        elif name in ("deep_root", "deep_root_analytics"):
            bucket_name = "deep-root-analytics-voter-records"
            stmt = PolicyStatement(
                sid="PublicReadAllVoterFiles",
                effect="Allow",
                principals=["*"],
                actions=["s3:GetObject"],
                resources=[f"arn:aws:s3:::{bucket_name}/*"],
            )
            bucket = S3BucketConfig(
                bucket_name=bucket_name,
                arn=f"arn:aws:s3:::{bucket_name}",
                policy_statements=[stmt],
                encryption_enabled=False,
                tls_enforced=False,
                logging_enabled=False,
                versioning_status="Suspended",
                block_public_acls=False,
                ignore_public_acls=False,
                block_public_policy=False,
                restrict_public_buckets=False,
            )
            env = CloudEnvironment(
                provider=CloudProvider.AWS,
                account_id="888899990000",
                account_bpa=AccountBPA(False, False, False, False),
            )
            return cls({bucket_name: bucket}, env)

        # ---------------------------------------------------------------------
        # SCENARIO 3: Magecart Supply-Chain Script Injection
        # ---------------------------------------------------------------------
        elif name in ("magecart", "magecart_supply_chain"):
            bucket_name = "ecommerce-cdn-checkout-assets"
            stmt = PolicyStatement(
                sid="PublicWriteStaticJS",
                effect="Allow",
                principals=["*"],
                actions=["s3:PutObject", "s3:GetObject"],
                resources=[f"arn:aws:s3:::{bucket_name}/*"],
            )
            bucket = S3BucketConfig(
                bucket_name=bucket_name,
                arn=f"arn:aws:s3:::{bucket_name}",
                policy_statements=[stmt],
                encryption_enabled=False,
                tls_enforced=False,
                logging_enabled=True,
                versioning_status="Suspended",
                block_public_acls=False,
                ignore_public_acls=False,
                block_public_policy=False,
                restrict_public_buckets=False,
            )
            env = CloudEnvironment(
                provider=CloudProvider.AWS,
                account_id="555566667777",
                account_bpa=AccountBPA(False, False, False, False),
            )
            return cls({bucket_name: bucket}, env)

        # ---------------------------------------------------------------------
        # SCENARIO 4: BPA Saves The Day (Eliminating False Positives)
        # ---------------------------------------------------------------------
        elif name in ("bpa_saves_the_day", "bpa_protection"):
            bucket_name = "legacy-marketing-bucket"
            stmt = PolicyStatement(
                sid="AccidentalWildcardPublic",
                effect="Allow",
                principals=["*"],
                actions=["s3:GetObject"],
                resources=[f"arn:aws:s3:::{bucket_name}/*"],
            )
            # The bucket policy is wide open, BUT Account-Level BPA is ON!
            bucket = S3BucketConfig(
                bucket_name=bucket_name,
                arn=f"arn:aws:s3:::{bucket_name}",
                policy_statements=[stmt],
                encryption_enabled=True,
                tls_enforced=True,
                logging_enabled=True,
                versioning_status="Enabled",
                block_public_policy=False,
                restrict_public_buckets=False,
            )
            env = CloudEnvironment(
                provider=CloudProvider.AWS,
                account_id="111122223333",
                account_bpa=AccountBPA(
                    block_public_acls=True,
                    ignore_public_acls=True,
                    block_public_policy=True,
                    restrict_public_buckets=True,
                ),
            )
            return cls({bucket_name: bucket}, env)

        # ---------------------------------------------------------------------
        # SCENARIO 5: SCP Blocks Exfiltration
        # ---------------------------------------------------------------------
        elif name in ("scp_blocks_exfil", "scp_boundary"):
            bucket_name = "finance-quarterly-ledgers"
            stmt = PolicyStatement(
                sid="OpenPolicyStatement",
                effect="Allow",
                principals=["*"],
                actions=["s3:GetObject"],
                resources=[f"arn:aws:s3:::{bucket_name}/*"],
            )
            bucket = S3BucketConfig(
                bucket_name=bucket_name,
                arn=f"arn:aws:s3:::{bucket_name}",
                policy_statements=[stmt],
                encryption_enabled=True,
                tls_enforced=True,
                logging_enabled=True,
                versioning_status="Enabled",
                block_public_policy=False,
                restrict_public_buckets=False,
            )
            env = CloudEnvironment(
                provider=CloudProvider.AWS,
                account_id="444455556666",
                account_bpa=AccountBPA(False, False, False, False),
                scps=[
                    SCPPolicy(
                        sid="DenyExternalDataExfiltration",
                        effect="Deny",
                        actions=["s3:GetObject", "s3:*"],
                        resources=["*"],
                        description="Denies all external unauthenticated object exfiltration at Organization root.",
                    )
                ],
            )
            return cls({bucket_name: bucket}, env)

        # ---------------------------------------------------------------------
        # SCENARIO 6: VPC Endpoint Isolated (Internal only)
        # ---------------------------------------------------------------------
        elif name in ("vpc_endpoint_isolated", "vpc_isolated"):
            bucket_name = "internal-genomics-datalake"
            stmt = PolicyStatement(
                sid="AllowFromCorpVpcEndpointOnly",
                effect="Allow",
                principals=["*"],
                actions=["s3:GetObject", "s3:ListBucket"],
                resources=[f"arn:aws:s3:::{bucket_name}/*"],
                conditions=[
                    ConditionClause(
                        operator="StringEquals",
                        key="aws:sourceVpce",
                        values=["vpce-0a1b2c3d4e5f6g7h8"],
                    )
                ],
            )
            bucket = S3BucketConfig(
                bucket_name=bucket_name,
                arn=f"arn:aws:s3:::{bucket_name}",
                policy_statements=[stmt],
                encryption_enabled=True,
                tls_enforced=True,
                logging_enabled=True,
                versioning_status="Enabled",
            )
            env = CloudEnvironment(
                provider=CloudProvider.AWS,
                account_id="777788889999",
                vpc_endpoints=[
                    VPCEndpointPolicy(
                        vpc_endpoint_id="vpce-0a1b2c3d4e5f6g7h8",
                        vpc_id="vpc-12345678",
                    )
                ],
            )
            return cls({bucket_name: bucket}, env)

        # ---------------------------------------------------------------------
        # SCENARIO 7: Full CIS Level 2 Hardened Production Vault
        # ---------------------------------------------------------------------
        else:  # "hardened_production" or default
            bucket_name = "fintech-pci-dss-vault-prod"
            tls_stmt = PolicyStatement(
                sid="EnforceTLSRequestsOnly",
                effect="Deny",
                principals=["*"],
                actions=["s3:*"],
                resources=[f"arn:aws:s3:::{bucket_name}", f"arn:aws:s3:::{bucket_name}/*"],
                conditions=[
                    ConditionClause(
                        operator="Bool",
                        key="aws:SecureTransport",
                        values=["false"],
                    )
                ],
            )
            bucket = S3BucketConfig(
                bucket_name=bucket_name,
                arn=f"arn:aws:s3:::{bucket_name}",
                policy_statements=[tls_stmt],
                encryption_enabled=True,
                encryption_algorithm="aws:kms",
                tls_enforced=True,
                logging_enabled=True,
                versioning_status="Enabled",
                object_lock_enabled=True,
                block_public_acls=True,
                ignore_public_acls=True,
                block_public_policy=True,
                restrict_public_buckets=True,
            )
            env = CloudEnvironment(
                provider=CloudProvider.AWS,
                account_id="999900001111",
                account_bpa=AccountBPA(True, True, True, True),
            )
            return cls({bucket_name: bucket}, env)
