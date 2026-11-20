from __future__ import annotations
import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from .auto_remediate import AutoRemediator
from .exploit_graph import ExploitabilityEngine
from .live_connector import ConnectorFactory
from .models import (
    AttackVector,
    CloudEnvironment,
    ExploitabilityResult,
    Finding,
    ScanResult,
    Severity,
)
from .parser import PolicyParser
from .rules import RuleEngine

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Terminal ANSI formatting
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[91m"
ORANGE = "\033[38;5;208m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
PURPLE = "\033[38;5;141m"


def format_severity(sev: Severity) -> str:
    if sev == Severity.CRITICAL:
        return f"{RED}{BOLD}[CRITICAL]{RESET}"
    elif sev == Severity.HIGH:
        return f"{ORANGE}{BOLD}[HIGH]    {RESET}"
    elif sev == Severity.MEDIUM:
        return f"{YELLOW}[MEDIUM]  {RESET}"
    elif sev == Severity.LOW:
        return f"{GREEN}[LOW]     {RESET}"
    return f"{DIM}[INFO]    {RESET}"


def format_exploit_score(score: float) -> str:
    if score >= 9.0:
        return f"{RED}{BOLD}{score:.1f} / 10.0 (IMMINENT BREACH){RESET}"
    elif score >= 7.0:
        return f"{ORANGE}{BOLD}{score:.1f} / 10.0 (HIGH EXPLOITABILITY){RESET}"
    elif score >= 4.0:
        return f"{YELLOW}{score:.1f} / 10.0 (MEDIUM RISK){RESET}"
    elif score > 0.0:
        return f"{CYAN}{score:.1f} / 10.0 (LOW / ISOLATED){RESET}"
    return f"{GREEN}{BOLD}0.0 / 10.0 (EFFECTIVELY SAFE / BLOCKED){RESET}"


def scan_single_file(
    filepath: str,
    run_exploit_analysis: bool = False,
    env: Optional[CloudEnvironment] = None,
) -> ScanResult:
    start = time.perf_counter()
    config = PolicyParser.parse_file(filepath)
    findings = RuleEngine.run_all_checks(config)
    elapsed_ms = (time.perf_counter() - start) * 1000

    exploit_res = None
    if run_exploit_analysis:
        actual_env = env or ExploitabilityEngine.create_default_open_environment()
        exploit_res = ExploitabilityEngine.evaluate(config, actual_env)

    return ScanResult(
        target_name=config.bucket_name,
        findings=findings,
        scan_time_ms=elapsed_ms,
        exploitability=exploit_res,
        cloud_environment=env,
    )


def print_scan_result_text(result: ScanResult, verbose_remediation: bool = True) -> None:
    print(f"\n{BOLD}{CYAN}=== CloudSec Enterprise Attack-Surface Scan Result ==={RESET}")
    print(f"Target Resource : {BOLD}{result.target_name}{RESET}")
    print(f"Latency         : {result.scan_time_ms:.2f} ms")
    print(f"Status          : {RED + 'MISCONFIGURED' if result.is_vulnerable else GREEN + 'SECURE'}{RESET}")
    print(f"Findings Summary: {RED}{result.critical_count} Critical{RESET} | {ORANGE}{result.high_count} High{RESET} | {YELLOW}{result.medium_count} Medium{RESET} | {GREEN}{result.low_count} Low{RESET}")

    # Exploitability Graph Details
    if result.exploitability:
        ex = result.exploitability
        print(f"\n{BOLD}{PURPLE}--- Effective Exploitability Analysis ---{RESET}")
        print(f"Exploit Score   : {format_exploit_score(ex.score)}")
        print(f"CVSS v3.1 Vector: {BOLD}{ex.cvss_vector}{RESET}")
        print(f"Attack Vector   : {ex.attack_vector.value}")
        print(f"Exploitable?    : {RED + 'YES (Vulnerable to Exfiltration)' if ex.is_exploitable else GREEN + 'NO (Blocked by Cloud Controls)'}{RESET}")
        print(f"Summary         : {ex.effective_access_summary}")

        if ex.blocked_by:
            print(f"Mitigated By    :")
            for b in ex.blocked_by:
                print(f"  {GREEN}[+] {b}{RESET}")

        if ex.curl_proof_command:
            print(f"PoC Proof       : {DIM}{ex.curl_proof_command}{RESET}")

    print("-" * 65)

    if not result.findings:
        print(f"{GREEN}[+] No CIS benchmark violations detected. Policy adheres to security baselines.{RESET}")
        return

    for idx, f in enumerate(result.findings, 1):
        sev_tag = format_severity(f.severity)
        print(f"{idx}. {sev_tag} {BOLD}{f.rule_name}{RESET} ({f.cis_control})")
        print(f"   {DIM}Details    :{RESET} {f.details}")
        print(f"   {DIM}Description:{RESET} {f.description}")
        if verbose_remediation and f.remediation:
            print(f"   {MAGENTA}{BOLD}Remediation (AWS CLI):{RESET}")
            for line in f.remediation.aws_cli_command.split("\n"):
                print(f"     {CYAN}{line}{RESET}")
            print(f"   {MAGENTA}{BOLD}Remediation (Terraform):{RESET}")
            for line in f.remediation.terraform_hcl.split("\n")[:4]:
                print(f"     {DIM}{line}{RESET}")
            if len(f.remediation.terraform_hcl.split("\n")) > 4:
                print(f"     {DIM}... (truncated, view full HCL in report){RESET}")
        print()


def run_live_scan(args: argparse.Namespace) -> int:
    provider = getattr(args, "provider", "mock")
    scenario = getattr(args, "scenario", "capital_one_breach")
    region = getattr(args, "region", "us-east-1")
    endpoint_url = getattr(args, "endpoint_url", None)

    print(f"\n{BOLD}{CYAN}=== CloudSec Live Cloud Environment Discovery ==={RESET}")
    print(f"Provider: {BOLD}{provider.upper()}{RESET} | Scenario/Target: {scenario or 'All Resources'}")

    try:
        connector = ConnectorFactory.create(
            provider=provider,
            scenario=scenario,
            region=region,
            endpoint_url=endpoint_url,
        )
    except Exception as e:
        print(f"{RED}Error initializing {provider} connector: {e}{RESET}")
        return 1

    env = connector.get_full_environment()
    buckets = connector.list_buckets()
    print(f"Discovered Storage Resources: {len(buckets)} found\n")

    all_results = []
    for b_name in buckets:
        config = connector.get_bucket_config(b_name)
        findings = RuleEngine.run_all_checks(config)
        ex = ExploitabilityEngine.evaluate(config, env)
        res = ScanResult(
            target_name=b_name,
            findings=findings,
            scan_time_ms=1.5,
            exploitability=ex,
            cloud_environment=env,
        )
        all_results.append(res)
        if args.format == "text":
            print_scan_result_text(res, verbose_remediation=True)

    if args.format == "json":
        json_output = {
            "provider": provider,
            "total_scanned": len(all_results),
            "results": [
                {
                    "target": r.target_name,
                    "is_vulnerable": r.is_vulnerable,
                    "exploitability": r.exploitability.to_dict() if r.exploitability else None,
                    "findings": [f.to_dict() for f in r.findings],
                }
                for r in all_results
            ],
        }
        print(json.dumps(json_output, indent=2))

    has_critical_or_high = any(r.critical_count > 0 or r.high_count > 0 for r in all_results)
    return 1 if has_critical_or_high else 0


def run_remediate(args: argparse.Namespace) -> int:
    dry_run = not getattr(args, "live", False)
    out_tf = getattr(args, "out_tf", None)
    filepath = getattr(args, "path", None)

    if not filepath:
        print(f"{RED}Error: --path <policy.json> is required for remediation.{RESET}")
        return 1

    config = PolicyParser.parse_file(filepath)
    findings = RuleEngine.run_all_checks(config)

    print(f"\n{BOLD}{MAGENTA}=== CloudSec Autonomous Remediation Engine ==={RESET}")
    print(f"Target Resource : {BOLD}{config.bucket_name}{RESET}")
    print(f"Mode            : {YELLOW + '[DRY-RUN]' if dry_run else RED + '[LIVE EXECUTION]'}{RESET}")
    print(f"Findings Found  : {len(findings)}")

    remediator = AutoRemediator(dry_run=dry_run)
    for f in findings:
        remediator.remediate_finding(f, config.bucket_name, config)

    print(remediator.summary_report())

    tf_patch = remediator.generate_terraform_patch(findings, config.bucket_name)
    if out_tf:
        with open(out_tf, "w", encoding="utf-8") as f:
            f.write(tf_patch)
        print(f"{GREEN}[+] Saved Terraform patch to: {out_tf}{RESET}")
    else:
        print(f"\n{BOLD}{CYAN}Generated Terraform Patch:{RESET}")
        print(tf_patch)

    return 0


def run_ci(args: argparse.Namespace) -> int:
    target_dir = args.dir or "dataset/policies"
    exit_on_high = args.exit_code_on_high
    max_exploit = args.max_exploit_score

    print(f"\n{BOLD}{CYAN}=== CloudSec CI/CD Security Gate ==={RESET}")
    print(f"Scanning Directory: {target_dir}")

    targets = []
    for root, _, files in os.walk(target_dir):
        for file in files:
            if file.endswith(".json") and file != "ground_truth.json":
                targets.append(os.path.join(root, file))

    env = ExploitabilityEngine.create_default_open_environment()
    results = []
    failed_policies = []

    for t in sorted(targets):
        res = scan_single_file(t, run_exploit_analysis=True, env=env)
        results.append(res)
        ex_score = res.exploitability.score if res.exploitability else 0.0

        is_failed = False
        if exit_on_high and (res.critical_count > 0 or res.high_count > 0):
            is_failed = True
        if max_exploit is not None and ex_score > max_exploit:
            is_failed = True

        if is_failed:
            failed_policies.append(res.target_name)

    print(f"Total Policies Scanned : {len(results)}")
    print(f"Pipeline Status        : {RED + 'FAILED' if failed_policies else GREEN + 'PASSED'}{RESET}")
    if failed_policies:
        print(f"Failing Targets ({len(failed_policies)}): {', '.join(failed_policies[:5])}...")

    if args.format == "json":
        out = {
            "passed": len(failed_policies) == 0,
            "total_scanned": len(results),
            "failed_count": len(failed_policies),
            "failed_policies": failed_policies,
        }
        print(json.dumps(out, indent=2))

    return 1 if failed_policies else 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="cloudsec-scan",
        description="CloudSec: Enterprise Attack-Surface, IaC & Exploitability Engine (CIS AWS Foundations v3.0)",
    )
    subparsers = parser.add_subparsers(dest="command", help="Subcommand to execute")

    # 1. scan command
    scan_parser = subparsers.add_parser("scan", help="Scan a local JSON policy or bucket directory")
    scan_parser.add_argument("--path", "-p", help="Path to single AWS JSON policy/bucket config")
    scan_parser.add_argument("--dir", "-d", help="Directory of JSON policies to batch scan")
    scan_parser.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    scan_parser.add_argument("--no-fix", action="store_true", help="Hide remediation code snippets")
    scan_parser.add_argument("--exploit-analysis", "-e", action="store_true", help="Run Effective Exploitability Graph analysis")
    scan_parser.add_argument("--env", choices=["open", "hardened", "bpa"], default="open", help="Cloud environment profile")

    # 2. live command
    live_parser = subparsers.add_parser("live", help="Live cloud discovery (AWS SDK, LocalStack, Azure, GCP, Mock)")
    live_parser.add_argument("--provider", default="mock", choices=["aws", "localstack", "azure", "gcp", "mock"], help="Cloud provider")
    live_parser.add_argument("--scenario", default="capital_one_breach", help="Mock breach scenario name")
    live_parser.add_argument("--region", default="us-east-1", help="AWS Region")
    live_parser.add_argument("--endpoint-url", help="LocalStack or custom S3 endpoint URL")
    live_parser.add_argument("--format", choices=["text", "json"], default="text", help="Output format")

    # 3. remediate command
    rem_parser = subparsers.add_parser("remediate", help="Autonomous drift remediation & Terraform patch generator")
    rem_parser.add_argument("--path", "-p", required=True, help="Target policy file")
    rem_parser.add_argument("--auto-remediate", action="store_true", help="Automatically generate remediation actions")
    rem_parser.add_argument("--dry-run", action="store_true", default=True, help="Simulate remediation without making changes")
    rem_parser.add_argument("--live", action="store_true", help="Apply fixes directly via cloud API")
    rem_parser.add_argument("--out-tf", help="Filepath to write consolidated Terraform patch (e.g. remediation.tf)")

    # 4. ci command
    ci_parser = subparsers.add_parser("ci", help="CI/CD quality gate for pre-commit & GitHub Actions")
    ci_parser.add_argument("--dir", "-d", default="dataset/policies", help="Directory of policies to scan")
    ci_parser.add_argument("--exit-code-on-high", action="store_true", help="Exit 1 if Critical or High findings are detected")
    ci_parser.add_argument("--max-exploit-score", type=float, default=7.0, help="Maximum allowed exploitability score before pipeline failure")
    ci_parser.add_argument("--format", choices=["text", "json"], default="text", help="Output format")

    # 5. benchmark command
    subparsers.add_parser("benchmark", help="Run empirical benchmark evaluation & tool comparative matrix")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    if args.command == "scan":
        targets: List[str] = []
        if args.path:
            targets.append(args.path)
        elif args.dir:
            for root, _, files in os.walk(args.dir):
                for file in files:
                    if file.endswith(".json") and file != "ground_truth.json":
                        targets.append(os.path.join(root, file))

        if not targets:
            print(f"{RED}Error: No valid JSON policy targets found.{RESET}")
            return 1

        env = None
        if args.exploit_analysis:
            if args.env == "hardened":
                env = ExploitabilityEngine.create_hardened_environment()
            elif args.env == "bpa":
                env = ExploitabilityEngine.create_bpa_protected_environment()
            else:
                env = ExploitabilityEngine.create_default_open_environment()

        all_results = []
        for t in sorted(targets):
            res = scan_single_file(t, run_exploit_analysis=args.exploit_analysis, env=env)
            all_results.append(res)
            if args.format == "text":
                print_scan_result_text(res, verbose_remediation=not args.no_fix)

        if args.format == "json":
            json_output = {
                "total_scanned": len(all_results),
                "results": [
                    {
                        "target": r.target_name,
                        "is_vulnerable": r.is_vulnerable,
                        "latency_ms": round(r.scan_time_ms, 3),
                        "exploitability": r.exploitability.to_dict() if r.exploitability else None,
                        "findings": [f.to_dict() for f in r.findings],
                    }
                    for r in all_results
                ],
            }
            print(json.dumps(json_output, indent=2))

        has_critical_or_high = any(r.critical_count > 0 or r.high_count > 0 for r in all_results)
        return 1 if has_critical_or_high else 0

    elif args.command == "live":
        return run_live_scan(args)

    elif args.command == "remediate":
        return run_remediate(args)

    elif args.command == "ci":
        return run_ci(args)

    elif args.command == "benchmark":
        from evaluate import main as eval_main
        return eval_main()

    return 0


if __name__ == "__main__":
    sys.exit(main())
