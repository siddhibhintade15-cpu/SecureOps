"""Unit tests for deterministic risk scoring engine."""

import pytest
import pandas as pd
from src.scoring import (
    calculate_single_cve_risk,
    compute_risk_scores,
    PriorityThresholds,
)


def test_calculate_single_cve_risk_critical_exposed():
    """Test risk calculation for a critical, internet-exposed CVE with active exploit."""
    score, steps, metrics = calculate_single_cve_risk(
        cvss=10.0,
        criticality="Critical",
        exposed=True,
        epss=0.95,
        cisa_kev=True,
        exploit_evidence="Active",
    )
    # Score should clamp to 100.0
    assert score == 100.0
    assert metrics["raw_score"] > 100.0
    assert "Base CVSS Impact" in steps
    assert "Threat Boosters" in steps


def test_calculate_single_cve_risk_low_isolated():
    """Test risk calculation for a low criticality, internal asset with no exploit."""
    score, steps, metrics = calculate_single_cve_risk(
        cvss=3.0,
        criticality="Low",
        exposed=False,
        epss=0.01,
        cisa_kev=False,
        exploit_evidence="None",
    )
    # Base: 3.0 * 6.5 = 19.5; Low mult: 0.75 -> 14.63; Exposure: 1.0 -> 14.63; EPSS boost: 0.2 -> 14.83
    assert 14.0 <= score <= 16.0
    assert 0.0 <= score <= 100.0


def test_score_bounds():
    """Ensure risk scores are strictly clamped within [0, 100]."""
    # Max possible inputs
    max_score, _, _ = calculate_single_cve_risk(10.0, "Critical", True, 1.0, True, "Active")
    assert max_score == 100.0

    # Min possible inputs
    min_score, _, _ = calculate_single_cve_risk(0.0, "Low", False, 0.0, False, "None")
    assert min_score == 0.0


def test_priority_thresholds():
    """Test classification into P1-P4 tiers with custom thresholds."""
    thresholds = PriorityThresholds(p1_cutoff=85.0, p2_cutoff=65.0, p3_cutoff=45.0)

    # Standard thresholds
    assert thresholds.classify(90.0) == "P1"
    assert thresholds.classify(70.0) == "P2"
    assert thresholds.classify(50.0) == "P3"
    assert thresholds.classify(30.0) == "P4"

    # Active wild exploit elevation rule: KEV + Internet Exposed + CVSS >= 7.0 should elevate to P1 even if score < 85
    elevated_tier = thresholds.classify(score=75.0, cisa_kev=True, internet_exposed=True, cvss=8.0)
    assert elevated_tier == "P1"


def test_compute_risk_scores_dataframe():
    """Test batch risk computation across a DataFrame."""
    df = pd.DataFrame([
        {
            "cve_id": "CVE-2023-0001",
            "cvss_score": 9.0,
            "asset_criticality": "High",
            "internet_exposed": True,
            "epss_score": 0.5,
            "cisa_kev": True,
            "exploit_evidence": "PoC",
            "remediation_effort_hours": 2.0,
        },
        {
            "cve_id": "CVE-2023-0002",
            "cvss_score": 4.0,
            "asset_criticality": "Low",
            "internet_exposed": False,
            "epss_score": 0.02,
            "cisa_kev": False,
            "exploit_evidence": "None",
            "remediation_effort_hours": 1.0,
        },
    ])

    scored = compute_risk_scores(df)
    assert "risk_score" in scored.columns
    assert "priority" in scored.columns
    assert "risk_roi" in scored.columns
    assert "scoring_explanation" in scored.columns

    assert scored.loc[0, "risk_score"] > scored.loc[1, "risk_score"]
    assert scored.loc[0, "priority"] in {"P1", "P2"}
    assert scored.loc[1, "priority"] == "P4"
