from __future__ import annotations
import json
from typing import Any, Dict, List, Union
from .models import ConditionClause, PolicyStatement, S3BucketConfig


class PolicyParser:
    """
    Normalizes heterogeneous AWS JSON policies and bucket configurations
    into strongly-typed AST structures.
    """

    @staticmethod
    def _to_list(val: Union[str, List[str], None]) -> List[str]:
        if val is None:
            return []
        if isinstance(val, str):
            return [val]
        if isinstance(val, list):
            return [str(v) for v in val]
        return []

    @classmethod
    def _parse_principals(cls, principal_node: Any) -> List[str]:
        if not principal_node:
            return []
        if principal_node == "*":
            return ["*"]
        if isinstance(principal_node, str):
            return [principal_node]
        if isinstance(principal_node, dict):
            principals = []
            for k, v in principal_node.items():
                if isinstance(v, list):
                    for item in v:
                        principals.append(f"{k}:{item}" if k.lower() != "aws" or item != "*" else item)
                elif isinstance(v, str):
                    principals.append(v if v == "*" else f"{k}:{v}")
            return principals
        return []

    @classmethod
    def _parse_conditions(cls, condition_node: Any) -> List[ConditionClause]:
        if not condition_node or not isinstance(condition_node, dict):
            return []
        clauses = []
        for operator, key_dict in condition_node.items():
            if isinstance(key_dict, dict):
                for key, val in key_dict.items():
                    clauses.append(
                        ConditionClause(
                            operator=str(operator),
                            key=str(key),
                            values=cls._to_list(val),
                        )
                    )
        return clauses

    @classmethod
    def parse_statement(cls, stmt_dict: Dict[str, Any]) -> PolicyStatement:
        return PolicyStatement(
            sid=str(stmt_dict.get("Sid", "")),
            effect=str(stmt_dict.get("Effect", "Allow")),
            principals=cls._parse_principals(stmt_dict.get("Principal")),
            not_principals=cls._parse_principals(stmt_dict.get("NotPrincipal")),
            actions=cls._to_list(stmt_dict.get("Action")),
            not_actions=cls._to_list(stmt_dict.get("NotAction")),
            resources=cls._to_list(stmt_dict.get("Resource")),
            not_resources=cls._to_list(stmt_dict.get("NotResource")),
            conditions=cls._parse_conditions(stmt_dict.get("Condition")),
        )

    @classmethod
    def parse_config_dict(cls, data: Dict[str, Any], default_bucket_name: str = "target-bucket") -> S3BucketConfig:
        """
        Ingests either a full S3 configuration envelope or a standalone bucket policy JSON.
        """
        # Determine if the root is an S3 bucket envelope or raw policy
        policy_root = None
        bucket_name = default_bucket_name
        arn = f"arn:aws:s3:::{bucket_name}"

        if "Policy" in data and isinstance(data["Policy"], (str, dict)):
            # LocalStack / AWS API wrapper format
            if isinstance(data["Policy"], str):
                try:
                    policy_root = json.loads(data["Policy"])
                except Exception:
                    policy_root = {}
            else:
                policy_root = data["Policy"]
        elif "Statement" in data:
            # Standalone IAM / S3 Policy Document
            policy_root = data
        elif "BucketPolicy" in data and isinstance(data["BucketPolicy"], dict):
            policy_root = data["BucketPolicy"]

        if "BucketName" in data:
            bucket_name = data["BucketName"]
            arn = f"arn:aws:s3:::{bucket_name}"

        # Parse statements
        statements: List[PolicyStatement] = []
        if policy_root and "Statement" in policy_root:
            raw_stmts = policy_root["Statement"]
            if isinstance(raw_stmts, dict):
                raw_stmts = [raw_stmts]
            if isinstance(raw_stmts, list):
                for s in raw_stmts:
                    if isinstance(s, dict):
                        statements.append(cls.parse_statement(s))

        # Check envelope configuration metadata
        sse = data.get("ServerSideEncryptionConfiguration", {})
        enc_enabled = False
        enc_algo = None
        if sse:
            enc_enabled = sse.get("Enabled", True)
            rules = sse.get("Rules", [])
            if rules and isinstance(rules, list):
                def_enc = rules[0].get("ApplyServerSideEncryptionByDefault", {})
                enc_algo = def_enc.get("SSEAlgorithm", "AES256")
                enc_enabled = True

        pab = data.get("PublicAccessBlockConfiguration", {})
        logging_conf = data.get("LoggingConfiguration", {})
        versioning = data.get("VersioningConfiguration", {})
        object_lock = data.get("ObjectLockConfiguration", {})

        return S3BucketConfig(
            bucket_name=bucket_name,
            arn=arn,
            policy_statements=statements,
            raw_policy=policy_root,
            encryption_enabled=enc_enabled or data.get("encryption_enabled", False),
            encryption_algorithm=enc_algo or data.get("encryption_algorithm"),
            logging_enabled=bool(logging_conf.get("LoggingEnabled") or data.get("logging_enabled", False)),
            versioning_status=versioning.get("Status", "Suspended") if isinstance(versioning, dict) else ("Enabled" if data.get("versioning_enabled") else "Suspended"),
            object_lock_enabled=bool(object_lock.get("ObjectLockEnabled") == "Enabled" or data.get("object_lock_enabled", False)),
            block_public_acls=pab.get("BlockPublicAcls", data.get("block_public_acls", False)),
            ignore_public_acls=pab.get("IgnorePublicAcls", data.get("ignore_public_acls", False)),
            block_public_policy=pab.get("BlockPublicPolicy", data.get("block_public_policy", False)),
            restrict_public_buckets=pab.get("RestrictPublicBuckets", data.get("restrict_public_buckets", False)),
        )

    @classmethod
    def parse_file(cls, filepath: str) -> S3BucketConfig:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        bucket_name = filepath.replace("\\", "/").split("/")[-1].replace(".json", "")
        return cls.parse_config_dict(data, default_bucket_name=bucket_name)
