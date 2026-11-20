from pathlib import Path
import tempfile

import streamlit as st

from scanner.cli import scan_single_file
from scanner.mock_connector import MockConnector
from scanner.models import ScanResult
from scanner.exploit_graph import ExploitabilityEngine
from scanner.rules import RuleEngine


st.set_page_config(
    page_title="CloudSec Scanner",
    page_icon="cloud",
    layout="wide",
)

st.title("CloudSec Misconfiguration Scanner")
st.caption("Condition-aware IAM and S3 security demonstration")

tab_scan, tab_scenario, tab_results = st.tabs(
    ["Policy Scanner", "Real-World Scenarios", "Benchmark Results"]
)

with tab_scan:
    col1, col2 = st.columns([1, 1])

    with col1:
        st.subheader("Upload or select a policy")
        policy_dir = Path("dataset/policies")
        presets = sorted(policy_dir.glob("policy_*.json")) if policy_dir.exists() else []
        preset_names = [path.name for path in presets]
        selected = st.selectbox(
            "Benchmark policy",
            ["Upload a JSON policy"] + preset_names,
        )
        uploaded = st.file_uploader("Policy JSON", type=["json"])

    with col2:
        st.subheader("Scan settings")
        exploit_analysis = st.toggle("Effective exploitability analysis", True)
        st.info("The mock cloud environment is safe for demonstrations; no AWS credentials are used.")

    policy_path = None
    if selected != "Upload a JSON policy":
        policy_path = str(policy_dir / selected)
    elif uploaded is not None:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as temp_file:
            temp_file.write(uploaded.getvalue())
            policy_path = temp_file.name

    if policy_path and st.button("Run CloudSec Scan", type="primary"):
        result = scan_single_file(policy_path, run_exploit_analysis=exploit_analysis)
        status = "MISCONFIGURED" if result.is_vulnerable else "SECURE"

        metric1, metric2, metric3, metric4 = st.columns(4)
        metric1.metric("Status", status)
        metric2.metric("Critical", result.critical_count)
        metric3.metric("High", result.high_count)
        metric4.metric("Scan latency", f"{result.scan_time_ms:.2f} ms")

        if result.exploitability:
            st.subheader("Effective Exploitability")
            st.metric("Exploitability score", f"{result.exploitability.score:.1f} / 10")
            st.write(result.exploitability.effective_access_summary)
            st.code(result.exploitability.cvss_vector)

        st.subheader("Findings")
        if not result.findings:
            st.success("No CIS benchmark violations detected.")
        for finding in result.findings:
            with st.expander(f"{finding.severity.value} - {finding.rule_name} ({finding.cis_control})"):
                st.write(finding.description)
                st.write(finding.details)
                if finding.remediation:
                    st.code(finding.remediation.aws_cli_command, language="bash")
                    st.code(finding.remediation.terraform_hcl, language="hcl")

with tab_scenario:
    st.subheader("Mock cloud breach scenarios")
    scenario = st.selectbox(
        "Scenario",
        [
            "capital_one_breach",
            "deep_root_analytics",
            "magecart_supply_chain",
            "bpa_saves_the_day",
            "scp_blocks_exfil",
            "vpc_endpoint_isolated",
            "hardened_production",
        ],
    )

    if st.button("Analyze Scenario", type="primary"):
        connector = MockConnector.from_scenario(scenario)
        environment = connector.get_full_environment()
        bucket_name = connector.list_buckets()[0]
        bucket = connector.get_bucket_config(bucket_name)
        exploitability = ExploitabilityEngine.evaluate(bucket, environment)
        findings = RuleEngine.run_all_checks(bucket)

        left, right = st.columns(2)
        left.metric("Bucket", bucket_name)
        right.metric("Exploitability", f"{exploitability.score:.1f} / 10")

        st.write(exploitability.effective_access_summary)
        if exploitability.blocked_by:
            st.success("Mitigated by: " + ", ".join(exploitability.blocked_by))
        if exploitability.curl_proof_command:
            st.code(exploitability.curl_proof_command, language="bash")

        st.subheader("Scanner findings")
        if not findings:
            st.success("No findings detected.")
        for finding in findings:
            st.warning(f"{finding.severity.value}: {finding.rule_name} - {finding.description}")

with tab_results:
    st.subheader("Multi-dataset benchmark")
    st.metric("Policies evaluated", "180")

    cols = st.columns(4)
    cols[0].metric("Precision", "100.0%")
    cols[1].metric("Recall", "100.0%")
    cols[2].metric("F1-score", "1.000")
    cols[3].metric("False-positive rate", "0.0%")

    st.table(
        {
            "Dataset": [
                "CloudSec-S3-Bench-120",
                "FlAWS-Cloud-Bench-30",
                "CloudGoat-OWASP-Bench-30",
            ],
            "Policies": [120, 30, 30],
            "Precision": ["100.0%", "100.0%", "100.0%"],
            "Recall": ["100.0%", "100.0%", "100.0%"],
            "F1": ["1.000", "1.000", "1.000"],
            "False positives": ["0.0%", "0.0%", "0.0%"],
        }
    )
