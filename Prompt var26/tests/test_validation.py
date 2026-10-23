"""Unit tests for schema validation and upload integrity."""

import pytest
import pandas as pd
from src.schemas import (
    validate_dataframe,
    validate_file_size,
    MAX_UPLOAD_SIZE_BYTES,
    MAX_ROW_LIMIT,
)


def test_validate_file_size():
    """Test file size enforcement."""
    # Empty file
    valid, err = validate_file_size(b"")
    assert not valid
    assert "empty" in err.lower()

    # Normal file
    valid, err = validate_file_size(b"cve_id,cvss_score\nCVE-2023-1234,9.0")
    assert valid
    assert err is None

    # Oversized file
    huge_bytes = b"X" * (MAX_UPLOAD_SIZE_BYTES + 1024)
    valid, err = validate_file_size(huge_bytes)
    assert not valid
    assert "exceeds maximum" in err.lower()


def test_validate_dataframe_valid_input():
    """Test validation with valid schema input."""
    df = pd.DataFrame([
        {
            "cve_id": "CVE-2021-44228",
            "cvss_score": 10.0,
            "asset_criticality": "Critical",
            "internet_exposed": "True",
            "remediation_effort_hours": 4.0,
        }
    ])
    result = validate_dataframe(df)
    assert result.is_valid
    assert len(result.errors) == 0
    assert result.cleaned_df is not None
    assert bool(result.cleaned_df.loc[0, "internet_exposed"]) is True
    # Default threat intel should be safely populated with provenance notes
    assert result.cleaned_df.loc[0, "epss_score"] == 0.01
    assert "UNAVAILABLE" in result.cleaned_df.loc[0, "epss_provenance"]


def test_validate_dataframe_missing_required_column():
    """Test error when required columns are absent."""
    df = pd.DataFrame([
        {
            "cve_id": "CVE-2021-44228",
            # cvss_score is missing
            "asset_criticality": "Critical",
            "internet_exposed": True,
            "remediation_effort_hours": 4.0,
        }
    ])
    result = validate_dataframe(df)
    assert not result.is_valid
    assert any("missing required column" in err.lower() for err in result.errors)


def test_validate_dataframe_invalid_cve_pattern():
    """Test malformed CVE identifier rejection."""
    df = pd.DataFrame([
        {
            "cve_id": "MALICIOUS-INPUT-123",
            "cvss_score": 7.0,
            "asset_criticality": "High",
            "internet_exposed": False,
            "remediation_effort_hours": 2.0,
        }
    ])
    result = validate_dataframe(df)
    assert not result.is_valid
    assert any("invalid cve identifier" in err.lower() for err in result.errors)


def test_validate_dataframe_out_of_bounds_cvss():
    """Test rejection of CVSS > 10.0 or < 0.0."""
    df = pd.DataFrame([
        {
            "cve_id": "CVE-2023-1111",
            "cvss_score": 15.5,  # Impossible CVSS
            "asset_criticality": "High",
            "internet_exposed": False,
            "remediation_effort_hours": 2.0,
        }
    ])
    result = validate_dataframe(df)
    assert not result.is_valid
    assert any("invalid cvss score" in err.lower() for err in result.errors)


def test_validate_dataframe_row_limit():
    """Test enforcement of max row limits."""
    rows = [
        {
            "cve_id": f"CVE-2023-{i:04d}",
            "cvss_score": 5.0,
            "asset_criticality": "Medium",
            "internet_exposed": False,
            "remediation_effort_hours": 1.0,
        }
        for i in range(MAX_ROW_LIMIT + 5)
    ]
    huge_df = pd.DataFrame(rows)
    result = validate_dataframe(huge_df)
    assert not result.is_valid
    assert any("exceeds the maximum safe limit" in err.lower() for err in result.errors)
