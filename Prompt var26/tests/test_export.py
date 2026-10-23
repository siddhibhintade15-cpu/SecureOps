"""Unit tests for report and CSV export helpers."""

import json
import pytest
import pandas as pd
from src.utils import (
    load_synthetic_sample_dataframe,
    export_remediation_plan_csv,
    export_audit_manifest_json,
)
from src.scoring import compute_risk_scores
from src.planner import generate_remediation_plan, PlanningConstraints


def test_load_synthetic_sample_dataframe():
    """Ensure synthetic dataset is non-empty and has required columns."""
    df = load_synthetic_sample_dataframe()
    assert len(df) >= 20
    assert "cve_id" in df.columns
    assert "cvss_score" in df.columns
    assert "asset_criticality" in df.columns
    assert "internet_exposed" in df.columns


def test_export_remediation_plan_csv():
    """Ensure plan export generates valid UTF-8 CSV bytes."""
    df = load_synthetic_sample_dataframe().head(5)
    scored = compute_risk_scores(df)
    plan_df, _ = generate_remediation_plan(scored)

    csv_bytes = export_remediation_plan_csv(plan_df)
    assert isinstance(csv_bytes, bytes)
    assert len(csv_bytes) > 0
    decoded = csv_bytes.decode("utf-8")
    assert "cve_id" in decoded
    assert "risk_score" in decoded
    assert "approval_status" in decoded


def test_export_audit_manifest_json():
    """Ensure JSON audit manifest is properly structured and serializable."""
    df = load_synthetic_sample_dataframe().head(5)
    scored = compute_risk_scores(df)
    plan_df, summary = generate_remediation_plan(scored)

    json_str = export_audit_manifest_json(summary, plan_df)
    parsed = json.loads(json_str)

    assert "generator" in parsed
    assert "plan_summary" in parsed
    assert "planned_vulnerabilities" in parsed
    assert "human_governance_notice" in parsed
    assert parsed["plan_summary"]["total_cves"] == 5
