"""Unit tests for resource-constrained remediation planner."""

import pytest
import pandas as pd
from src.scoring import compute_risk_scores
from src.planner import (
    generate_remediation_plan,
    categorize_vulnerability,
    PlanningConstraints,
)


@pytest.fixture
def sample_scored_df():
    """Create sample scored dataframe for planning tests."""
    raw_data = [
        # Immediate Fix (P1, Critical)
        {
            "cve_id": "CVE-2023-0001",
            "cvss_score": 10.0,
            "asset_criticality": "Critical",
            "internet_exposed": True,
            "epss_score": 0.95,
            "cisa_kev": True,
            "exploit_evidence": "Active",
            "remediation_effort_hours": 4.0,
            "maintenance_window": "Emergency",
            "patch_available": True,
        },
        # Quick Win (High Risk, Low Effort)
        {
            "cve_id": "CVE-2023-0002",
            "cvss_score": 8.0,
            "asset_criticality": "High",
            "internet_exposed": False,
            "epss_score": 0.4,
            "cisa_kev": False,
            "exploit_evidence": "PoC",
            "remediation_effort_hours": 1.5,
            "maintenance_window": "Off-Hours",
            "patch_available": True,
        },
        # Scheduled Fix (Heavy Effort)
        {
            "cve_id": "CVE-2023-0003",
            "cvss_score": 7.5,
            "asset_criticality": "Medium",
            "internet_exposed": False,
            "epss_score": 0.1,
            "cisa_kev": False,
            "exploit_evidence": "None",
            "remediation_effort_hours": 20.0,
            "maintenance_window": "Weekend",
            "patch_available": True,
        },
        # Unpatched (Monitor/Verify)
        {
            "cve_id": "CVE-2023-0004",
            "cvss_score": 6.0,
            "asset_criticality": "Low",
            "internet_exposed": False,
            "epss_score": 0.05,
            "cisa_kev": False,
            "exploit_evidence": "None",
            "remediation_effort_hours": 2.0,
            "maintenance_window": "Anytime",
            "patch_available": False,
        },
    ]
    return compute_risk_scores(pd.DataFrame(raw_data))


def test_categorize_vulnerability(sample_scored_df):
    """Test proper categorization into the 4 quadrants."""
    cat0 = categorize_vulnerability(sample_scored_df.iloc[0])
    assert cat0 == "Immediate Fixes"

    cat1 = categorize_vulnerability(sample_scored_df.iloc[1])
    assert cat1 == "Quick Wins"

    cat3 = categorize_vulnerability(sample_scored_df.iloc[3])
    assert cat3 == "Monitor/Verify"


def test_capacity_constraints(sample_scored_df):
    """Test that items exceeding capacity limit are deferred with clear reasons."""
    # Constrain capacity to 10 hours
    # CVE-1 takes 4h (Immediate -> Planned)
    # CVE-2 takes 1.5h (Quick Win -> Planned, total 5.5h)
    # CVE-3 takes 20h -> 5.5 + 20 > 10h -> Deferred due to capacity!
    constraints = PlanningConstraints(team_capacity_hours=10.0)
    plan_df, summary = generate_remediation_plan(sample_scored_df, constraints)

    assert summary.allocated_hours == 5.5
    assert summary.capacity_hours_limit == 10.0
    assert summary.allocated_hours <= summary.capacity_hours_limit
    assert summary.planned_cves_count == 2
    assert summary.deferred_cves_count == 2

    # Check deferral reason on CVE-3
    cve3_row = plan_df[plan_df["cve_id"] == "CVE-2023-0003"].iloc[0]
    assert cve3_row["plan_status"] == "Deferred"
    assert "capacity" in cve3_row["deferral_reason"].lower()


def test_allocated_hours_never_exceed_capacity(sample_scored_df):
    """Ensure allocated hours never exceed available capacity, even for immediate fixes."""
    # Constrain capacity to 2 hours, but Immediate fix needs 4 hours
    tight_constraints = PlanningConstraints(team_capacity_hours=2.0)
    plan_df, summary = generate_remediation_plan(sample_scored_df, tight_constraints)

    assert summary.allocated_hours <= summary.capacity_hours_limit
    assert summary.allocated_hours == 1.5  # Quick Win (1.5h) fits, 4.0h Immediate does not!
    immediate_row = plan_df[plan_df["cve_id"] == "CVE-2023-0001"].iloc[0]
    assert immediate_row["plan_status"] == "Deferred"
    assert "capacity" in immediate_row["deferral_reason"].lower()


def test_risk_reduction_calculations(sample_scored_df):
    """Test baseline vs residual risk and risk reduction percentage mathematical consistency."""
    constraints = PlanningConstraints(team_capacity_hours=100.0)
    plan_df, summary = generate_remediation_plan(sample_scored_df, constraints)

    # Mathematical consistency checks
    assert summary.baseline_total_risk > summary.residual_total_risk
    assert summary.baseline_mean_risk > summary.projected_mean_risk
    assert round(summary.baseline_total_risk - summary.residual_total_risk, 1) == summary.remediated_risk
    expected_pct = round((summary.remediated_risk / summary.baseline_total_risk) * 100.0, 1)
    assert summary.risk_reduction_pct == expected_pct
    assert summary.allocated_hours <= summary.capacity_hours_limit
    assert "remediation" in summary.trade_off_analysis.lower()


def test_distinguish_projected_vs_verified_risk(sample_scored_df):
    """Verify that projected risk reduction and human-approved verified risk reduction are distinct."""
    constraints = PlanningConstraints(team_capacity_hours=100.0)

    # 1. Without any lead approval: verified reduction is 0%
    _, summary_unapproved = generate_remediation_plan(sample_scored_df, constraints, approved_cve_ids=set())
    assert summary_unapproved.projected_mean_risk < summary_unapproved.baseline_mean_risk
    assert summary_unapproved.risk_reduction_pct > 0.0
    assert summary_unapproved.verified_cves_count == 0
    assert summary_unapproved.verified_risk_reduction_pct == 0.0
    assert summary_unapproved.verified_residual_total_risk == summary_unapproved.baseline_total_risk

    # 2. With partial lead approval: verified reduction matches approved subset
    approved = {"CVE-2023-0001"}
    plan_df_app, summary_approved = generate_remediation_plan(sample_scored_df, constraints, approved_cve_ids=approved)
    assert summary_approved.verified_cves_count == 1
    assert 0.0 < summary_approved.verified_risk_reduction_pct <= summary_approved.risk_reduction_pct
    assert summary_approved.verified_remediated_risk > 0.0
    assert summary_approved.verified_residual_total_risk < summary_approved.baseline_total_risk

    # Check status column in dataframe
    cve1 = plan_df_app[plan_df_app["cve_id"] == "CVE-2023-0001"].iloc[0]
    assert cve1["approval_status"] == "Approved by Lead"


def test_priority_counts_tracking(sample_scored_df):
    """Test priority total vs planned count tracking."""
    constraints = PlanningConstraints(team_capacity_hours=10.0)
    _, summary = generate_remediation_plan(sample_scored_df, constraints)

    assert "P1" in summary.priority_total_counts
    assert summary.priority_planned_counts.get("P1", 0) <= summary.priority_total_counts.get("P1", 0)
