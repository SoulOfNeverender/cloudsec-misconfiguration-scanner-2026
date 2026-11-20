from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class CloudProvider(str, Enum):
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    LOCALSTACK = "localstack"
    MOCK = "mock"


class AttackVector(str, Enum):
    ANONYMOUS_PUBLIC = "ANONYMOUS_PUBLIC_INTERNET"
    AUTHENTICATED_CROSS_ACCOUNT = "AUTHENTICATED_CROSS_ACCOUNT"
    SSRF_IMDSV1 = "SSRF_IMDSv1_CREDENTIAL_THEFT"
    MISCONFIGURED_ROLE = "OVER_PERMISSIVE_IAM_ROLE"
    VPC_LATERAL = "VPC_LATERAL_MOVEMENT"


@dataclass
class Remediation:
    title: str
    aws_cli_command: str
    terraform_hcl: str
    explanation: str


@dataclass
class ConditionClause:
    operator: str
    key: str
    values: List[str]


@dataclass
class PolicyStatement:
    sid: str
    effect: str  # "Allow" or "Deny"
    principals: List[str] = field(default_factory=list)
    not_principals: List[str] = field(default_factory=list)
    actions: List[str] = field(default_factory=list)
    not_actions: List[str] = field(default_factory=list)
    resources: List[str] = field(default_factory=list)
    not_resources: List[str] = field(default_factory=list)
    conditions: List[ConditionClause] = field(default_factory=list)


@dataclass
class AccountBPA:
    """Account-Level S3 Block Public Access Settings."""
    block_public_acls: bool = True
    ignore_public_acls: bool = True
    block_public_policy: bool = True
    restrict_public_buckets: bool = True

    @property
    def is_fully_enforced(self) -> bool:
        return (
            self.block_public_acls
            and self.ignore_public_acls
            and self.block_public_policy
            and self.restrict_public_buckets
        )

    def to_dict(self) -> Dict[str, bool]:
        return {
            "BlockPublicAcls": self.block_public_acls,
            "IgnorePublicAcls": self.ignore_public_acls,
            "BlockPublicPolicy": self.block_public_policy,
            "RestrictPublicBuckets": self.restrict_public_buckets,
        }


@dataclass
class SCPPolicy:
    """AWS Organization Service Control Policy (SCP)."""
    sid: str
    effect: str  # "Allow" or "Deny"
    actions: List[str] = field(default_factory=list)
    resources: List[str] = field(default_factory=list)
    conditions: List[ConditionClause] = field(default_factory=list)
    description: str = ""


@dataclass
class VPCEndpointPolicy:
    """VPC Gateway / Interface Endpoint Policy for S3."""
    vpc_endpoint_id: str
    vpc_id: str = "vpc-00000000"
    policy_statements: List[PolicyStatement] = field(default_factory=list)
    restrict_to_bucket_arns: List[str] = field(default_factory=list)


@dataclass
class IAMIdentityContext:
    """IAM Role / User Identity context for exploit path analysis."""
    principal_arn: str
    permission_boundary_arn: Optional[str] = None
    attached_policies: List[Dict[str, Any]] = field(default_factory=list)
    inline_policies: List[Dict[str, Any]] = field(default_factory=list)
    imdsv1_enabled: bool = False  # Critical for SSRF attack vectors (e.g. Capital One)


@dataclass
class CloudEnvironment:
    """
    Multi-layered cloud environment context for compound exploitability evaluation.
    Enables: Effective Access = Bucket Policy ∩ Account BPA ∩ Identity Boundary ∩ SCP ∩ VPC
    """
    provider: CloudProvider = CloudProvider.AWS
    account_id: str = "123456789012"
    region: str = "us-east-1"
    account_bpa: AccountBPA = field(default_factory=AccountBPA)
    scps: List[SCPPolicy] = field(default_factory=list)
    vpc_endpoints: List[VPCEndpointPolicy] = field(default_factory=list)
    iam_identities: List[IAMIdentityContext] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ExploitabilityResult:
    """
    Deterministic exploitability proof and attack path scoring.
    """
    score: float  # 0.0 to 10.0
    cvss_vector: str  # e.g., "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    attack_vector: AttackVector
    is_exploitable: bool
    evidence_chain: List[str] = field(default_factory=list)
    blocked_by: List[str] = field(default_factory=list)
    effective_access_summary: str = ""
    curl_proof_command: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score": round(self.score, 1),
            "cvss_vector": self.cvss_vector,
            "attack_vector": self.attack_vector.value,
            "is_exploitable": self.is_exploitable,
            "evidence_chain": self.evidence_chain,
            "blocked_by": self.blocked_by,
            "effective_access_summary": self.effective_access_summary,
            "curl_proof_command": self.curl_proof_command,
        }


@dataclass
class Finding:
    rule_id: str
    rule_name: str
    cis_control: str
    severity: Severity
    description: str
    details: str
    target_resource: str
    remediation: Optional[Remediation] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "cis_control": self.cis_control,
            "severity": self.severity.value,
            "description": self.description,
            "details": self.details,
            "target_resource": self.target_resource,
            "remediation": {
                "title": self.remediation.title,
                "aws_cli": self.remediation.aws_cli_command,
                "terraform": self.remediation.terraform_hcl,
                "explanation": self.remediation.explanation,
            } if self.remediation else None
        }


@dataclass
class EnrichedFinding(Finding):
    """Finding augmented with exploitability score and contextual attack path."""
    exploitability: Optional[ExploitabilityResult] = None
    environment_context: Optional[str] = None
    cloud_provider: str = "aws"

    def to_dict(self) -> Dict[str, Any]:
        base = super().to_dict()
        base["cloud_provider"] = self.cloud_provider
        base["environment_context"] = self.environment_context
        base["exploitability"] = self.exploitability.to_dict() if self.exploitability else None
        return base


@dataclass
class S3BucketConfig:
    bucket_name: str
    arn: str
    policy_statements: List[PolicyStatement] = field(default_factory=list)
    raw_policy: Optional[Dict[str, Any]] = None
    encryption_enabled: bool = False
    encryption_algorithm: Optional[str] = None  # "aws:kms" or "AES256"
    tls_enforced: bool = False
    logging_enabled: bool = False
    versioning_status: str = "Suspended"  # "Enabled" or "Suspended"
    object_lock_enabled: bool = False
    block_public_acls: bool = False
    ignore_public_acls: bool = False
    block_public_policy: bool = False
    restrict_public_buckets: bool = False
    acl_grants: List[Dict[str, Any]] = field(default_factory=list)
    tags: Dict[str, str] = field(default_factory=dict)


@dataclass
class RemediationAction:
    """Actionable drift correction or PR change set."""
    action_type: str  # "api_call", "terraform_patch", "github_pr"
    target_resource: str
    title: str
    api_call: Optional[Dict[str, Any]] = None
    terraform_patch: Optional[str] = None
    is_dry_run: bool = True
    execution_result: Optional[str] = None
    applied_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action_type": self.action_type,
            "target_resource": self.target_resource,
            "title": self.title,
            "api_call": self.api_call,
            "terraform_patch": self.terraform_patch,
            "is_dry_run": self.is_dry_run,
            "execution_result": self.execution_result,
            "applied_at": self.applied_at,
        }


@dataclass
class ScanResult:
    target_name: str
    findings: List[Finding] = field(default_factory=list)
    scan_time_ms: float = 0.0
    exploitability: Optional[ExploitabilityResult] = None
    cloud_environment: Optional[CloudEnvironment] = None

    @property
    def is_vulnerable(self) -> bool:
        return len(self.findings) > 0

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.LOW)
