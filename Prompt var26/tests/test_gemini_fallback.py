"""Unit tests verifying Gemini optional mode and offline fallback behavior."""

import pytest
from src.gemini_service import (
    is_gemini_available,
    mask_api_key,
    build_offline_fallback_review,
    generate_executive_review,
)


def test_api_disabled_detection():
    """Ensure system recognizes when Gemini is not configured or placeholder is present."""
    assert not is_gemini_available(override_key="")
    assert not is_gemini_available(override_key=None)
    assert not is_gemini_available(override_key="your_gemini_api_key_here")


def test_mask_api_key():
    """Verify secrets are masked and never exposed in plain text."""
    assert mask_api_key(None) == "Not Configured"
    assert mask_api_key("") == "Not Configured"
    masked = mask_api_key("AIzaSyD-example-key-123456789")
    assert masked.startswith("AIza")
    assert masked.endswith("6789")
    assert "example-key" not in masked


def test_offline_fallback_review_generation():
    """Test deterministic report review generation when running offline."""
    summary = {
        "total_cves": 10,
        "planned_cves_count": 6,
        "deferred_cves_count": 4,
        "allocated_hours": 32.5,
        "capacity_hours_limit": 40.0,
        "hours_utilization_pct": 81.2,
        "allocated_cost": 4062.50,
        "baseline_mean_risk": 78.4,
        "projected_mean_risk": 24.1,
        "risk_reduction_pct": 69.3,
    }
    top_planned = [
        {"cve_id": "CVE-2021-44228", "asset_name": "Gateway", "risk_score": 100.0, "remediation_category": "Immediate Fixes", "remediation_effort_hours": 4.0}
    ]
    top_deferred = [
        {"cve_id": "CVE-2023-0004", "asset_name": "Workstation", "risk_score": 35.0, "deferral_reason": "Low risk threshold"}
    ]

    review_text, is_ai = generate_executive_review(
        summary_data=summary,
        top_planned=top_planned,
        top_deferred=top_deferred,
        override_key=None,  # Force offline
    )

    assert not is_ai
    assert "Deterministic Rule-Based Fallback Engine" in review_text
    assert "CVE-2021-44228" in review_text
    assert "Zero Automated Shell Execution Policy" in review_text
