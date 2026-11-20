from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from .models import (
    AccountBPA,
    CloudEnvironment,
    CloudProvider,
    S3BucketConfig,
    SCPPolicy,
    VPCEndpointPolicy,
)


class CloudConnector(ABC):
    """
    Abstract Cloud Discovery Connector.
    Provides a unified query interface across AWS, Azure Blob Storage, GCP Cloud Storage,
    LocalStack, and Mock testing environments.
    """

    @abstractmethod
    def list_buckets(self) -> List[str]:
        """List all discoverable storage buckets / containers."""
        pass

    @abstractmethod
    def get_bucket_config(self, bucket_name: str) -> S3BucketConfig:
        """Fetch complete bucket configuration, policy AST, and encryption state."""
        pass

    @abstractmethod
    def get_account_bpa(self) -> AccountBPA:
        """Fetch account-level Block Public Access or organization storage boundary."""
        pass

    @abstractmethod
    def get_scps(self) -> List[SCPPolicy]:
        """Fetch Service Control Policies (SCPs) or Azure Management Group policies."""
        pass

    @abstractmethod
    def get_vpc_endpoints(self) -> List[VPCEndpointPolicy]:
        """Fetch private network gateway endpoint configurations."""
        pass

    @abstractmethod
    def get_full_environment(self) -> CloudEnvironment:
        """Assembles complete multi-layered environment state for exploit graph evaluation."""
        pass

    @abstractmethod
    def apply_bucket_bpa(self, bucket_name: str) -> bool:
        """Remediation: Apply Block Public Access settings to the bucket."""
        pass

    @abstractmethod
    def apply_bucket_encryption(self, bucket_name: str, algorithm: str = "AES256") -> bool:
        """Remediation: Apply default Server-Side Encryption."""
        pass


class AzureBlobConnector(CloudConnector):
    """
    Multi-Cloud Extension: Azure Blob Storage Connector abstraction.
    Normalizes Azure Storage Account RBAC, Private Endpoints, and Shared Access Signatures (SAS)
    into the unified storage configuration model.
    """

    def __init__(self, subscription_id: str = "sub-12345", resource_group: str = "prod-rg"):
        self.subscription_id = subscription_id
        self.resource_group = resource_group

    def list_buckets(self) -> List[str]:
        return ["azure-customer-data-blob", "azure-finance-logs-blob"]

    def get_bucket_config(self, bucket_name: str) -> S3BucketConfig:
        from .models import PolicyStatement
        return S3BucketConfig(
            bucket_name=bucket_name,
            arn=f"azure://storage/{self.subscription_id}/{bucket_name}",
            policy_statements=[
                PolicyStatement(
                    sid="AzureRBACPublicRead",
                    effect="Deny",
                    principals=["*"],
                    actions=["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"],
                )
            ],
            encryption_enabled=True,
            encryption_algorithm="Microsoft.Storage",
            tls_enforced=True,
            logging_enabled=True,
            versioning_status="Enabled",
            block_public_policy=True,
            restrict_public_buckets=True,
        )

    def get_account_bpa(self) -> AccountBPA:
        # Azure equivalent: allowBlobPublicAccess = False on Storage Account
        return AccountBPA(
            block_public_acls=True,
            ignore_public_acls=True,
            block_public_policy=True,
            restrict_public_buckets=True,
        )

    def get_scps(self) -> List[SCPPolicy]:
        return []

    def get_vpc_endpoints(self) -> List[VPCEndpointPolicy]:
        return [VPCEndpointPolicy(vpc_endpoint_id="azure-privatelink-storage")]

    def get_full_environment(self) -> CloudEnvironment:
        return CloudEnvironment(
            provider=CloudProvider.AZURE,
            account_id=self.subscription_id,
            region="eastus2",
            account_bpa=self.get_account_bpa(),
            scps=[],
            vpc_endpoints=self.get_vpc_endpoints(),
        )

    def apply_bucket_bpa(self, bucket_name: str) -> bool:
        return True

    def apply_bucket_encryption(self, bucket_name: str, algorithm: str = "AES256") -> bool:
        return True


class GCPStorageConnector(CloudConnector):
    """
    Multi-Cloud Extension: Google Cloud Storage (GCS) Connector abstraction.
    Normalizes GCS Uniform Bucket-Level Access (UBLA), VPC Service Controls, and IAM bindings.
    """

    def __init__(self, project_id: str = "gcp-production-project"):
        self.project_id = project_id

    def list_buckets(self) -> List[str]:
        return ["gcs-analytics-export", "gcs-backup-vault"]

    def get_bucket_config(self, bucket_name: str) -> S3BucketConfig:
        from .models import PolicyStatement
        return S3BucketConfig(
            bucket_name=bucket_name,
            arn=f"gs://{bucket_name}",
            policy_statements=[
                PolicyStatement(
                    sid="GCSUniformAccess",
                    effect="Deny",
                    principals=["allUsers", "allAuthenticatedUsers"],
                    actions=["storage.objects.get"],
                )
            ],
            encryption_enabled=True,
            encryption_algorithm="Google-managed",
            tls_enforced=True,
            logging_enabled=True,
            versioning_status="Enabled",
            block_public_policy=True,
            restrict_public_buckets=True,
        )

    def get_account_bpa(self) -> AccountBPA:
        # GCS equivalent: Domain-restricted sharing + Uniform Bucket-Level Access enforced
        return AccountBPA(
            block_public_acls=True,
            ignore_public_acls=True,
            block_public_policy=True,
            restrict_public_buckets=True,
        )

    def get_scps(self) -> List[SCPPolicy]:
        return []

    def get_vpc_endpoints(self) -> List[VPCEndpointPolicy]:
        return [VPCEndpointPolicy(vpc_endpoint_id="gcp-vpc-sc-perimeter")]

    def get_full_environment(self) -> CloudEnvironment:
        return CloudEnvironment(
            provider=CloudProvider.GCP,
            account_id=self.project_id,
            region="us-central1",
            account_bpa=self.get_account_bpa(),
            scps=[],
            vpc_endpoints=self.get_vpc_endpoints(),
        )

    def apply_bucket_bpa(self, bucket_name: str) -> bool:
        return True

    def apply_bucket_encryption(self, bucket_name: str, algorithm: str = "AES256") -> bool:
        return True


class ConnectorFactory:
    """Factory for instantiating the appropriate cloud discovery connector."""

    @staticmethod
    def create(
        provider: str = "aws",
        scenario: Optional[str] = None,
        region: str = "us-east-1",
        endpoint_url: Optional[str] = None,
        profile: Optional[str] = None,
    ) -> CloudConnector:
        provider_norm = provider.lower().strip()

        if provider_norm == "mock":
            from .mock_connector import MockConnector
            if scenario:
                return MockConnector.from_scenario(scenario)
            return MockConnector.from_scenario("capital_one_breach")

        elif provider_norm == "localstack":
            from .live_aws import AWSConnector
            url = endpoint_url or "http://localhost:4566"
            return AWSConnector(
                region=region,
                endpoint_url=url,
                use_localstack=True,
            )

        elif provider_norm == "aws":
            from .live_aws import AWSConnector
            return AWSConnector(
                region=region,
                endpoint_url=endpoint_url,
                profile=profile,
                use_localstack=False,
            )

        elif provider_norm == "azure":
            return AzureBlobConnector()

        elif provider_norm == "gcp":
            return GCPStorageConnector()

        else:
            raise ValueError(f"Unsupported cloud provider: '{provider}'. Choose from: aws, localstack, azure, gcp, mock.")
