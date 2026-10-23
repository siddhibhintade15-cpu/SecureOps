"""Schema definitions, limits, and input validation for SecureOps AI.

Ensures strict bounds checking, secure upload validation, and transparent
data provenance (Supplied vs Derived vs Unavailable).
"""

from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any
import pandas as pd

# Security bounds & upload limits
MAX_UPLOAD_SIZE_BYTES: int = 5 * 1024 * 1024  # 5 MB maximum
MAX_ROW_LIMIT: int = 2000  # DoS mitigation for local calculation
MAX_CVE_ID_LEN: int = 30
MAX_TEXT_LEN: int = 200

# Canonical domain values
VALID_CRITICALITY = {"Critical", "High", "Medium", "Low"}
VALID_MAINTENANCE_WINDOWS = {"Emergency", "Off-Hours", "Weekend", "Anytime"}
VALID_EXPLOIT_EVIDENCE = {"Active", "Weaponized", "PoC", "None", "Unknown"}

# Expected Column Specifications
REQUIRED_COLUMNS = [
    "cve_id",
    "cvss_score",
    "asset_criticality",
    "internet_exposed",
    "remediation_effort_hours",
]

OPTIONAL_COLUMNS = [
    "asset_name",
    "vulnerability_title",
    "epss_score",
    "cisa_kev",
    "exploit_evidence",
    "maintenance_window",
    "patch_available",
    "remediation_cost_est",
]

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


@dataclass
class ValidationResult:
    """Holds results of dataset schema and integrity validation."""
    is_valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    cleaned_df: Optional[pd.DataFrame] = None
    provenance_metadata: Dict[str, Any] = field(default_factory=dict)


def validate_file_size(file_bytes: bytes) -> Tuple[bool, Optional[str]]:
    """Validate that uploaded raw file bytes do not exceed the safe limit."""
    size = len(file_bytes)
    if size == 0:
        return False, "Uploaded file is empty (0 bytes)."
    if size > MAX_UPLOAD_SIZE_BYTES:
        return (
            False,
            f"File size ({size / (1024*1024):.2f} MB) exceeds maximum allowed limit of {MAX_UPLOAD_SIZE_BYTES / (1024*1024):.1f} MB.",
        )
    return True, None


def normalize_boolean(val: Any) -> Optional[bool]:
    """Safely parse boolean-like values from CSV strings or numbers."""
    if pd.isna(val):
        return None
    if isinstance(val, (bool, int, float)):
        return bool(val)
    str_val = str(val).strip().lower()
    if str_val in {"true", "yes", "1", "t", "y"}:
        return True
    if str_val in {"false", "no", "0", "f", "n"}:
        return False
    return None


def validate_dataframe(df: pd.DataFrame) -> ValidationResult:
    """Perform schema validation, type checking, bounds enforcement, and provenance tracking.

    Ensures no malformed data breaches the scoring pipeline and tracks whether
    data elements were SUPPLIED, UNAVAILABLE, or DERIVED.
    """
    errors: List[str] = []
    warnings: List[str] = []

    if df is None or df.empty:
        return ValidationResult(
            is_valid=False,
            errors=["Supplied dataset contains no rows."],
        )

    # Check row limits
    if len(df) > MAX_ROW_LIMIT:
        return ValidationResult(
            is_valid=False,
            errors=[
                f"Row count ({len(df)}) exceeds the maximum safe limit of {MAX_ROW_LIMIT} rows."
            ],
        )

    # Standardize column headers (strip whitespace and lower case mapping)
    col_map = {col: col.strip().lower() for col in df.columns}
    normalized_df = df.rename(columns=col_map).copy()

    # Verify required columns
    missing_required = [col for col in REQUIRED_COLUMNS if col not in normalized_df.columns]
    if missing_required:
        return ValidationResult(
            is_valid=False,
            errors=[
                f"Missing required column(s): {', '.join(missing_required)}. "
                f"Required schema includes: {', '.join(REQUIRED_COLUMNS)}."
            ],
        )

    cleaned_df = pd.DataFrame()
    data_provenance = {
        "supplied_optional_fields": [],
        "unavailable_optional_fields": [],
        "defaulted_rows_count": 0,
    }

    # 1. Validate cve_id
    cve_series = normalized_df["cve_id"].astype(str).str.strip()
    invalid_cves = cve_series[~cve_series.str.match(CVE_PATTERN)]
    if not invalid_cves.empty:
        sample_bad = invalid_cves.head(3).tolist()
        errors.append(
            f"Found {len(invalid_cves)} invalid CVE identifier(s). Format must match 'CVE-YYYY-NNNN+': {sample_bad}"
        )
    cleaned_df["cve_id"] = cve_series.str.slice(0, MAX_CVE_ID_LEN)

    # 2. Validate cvss_score
    try:
        cvss = pd.to_numeric(normalized_df["cvss_score"], errors="coerce")
        out_of_bounds = cvss[(cvss < 0.0) | (cvss > 10.0) | cvss.isna()]
        if not out_of_bounds.empty:
            errors.append(
                f"Found {len(out_of_bounds)} row(s) with invalid CVSS score. CVSS must be a numeric value between 0.0 and 10.0."
            )
        cleaned_df["cvss_score"] = cvss.fillna(0.0)
    except Exception as e:
        errors.append(f"Failed parsing cvss_score column: {e}")

    # 3. Validate asset_criticality
    criticality = normalized_df["asset_criticality"].astype(str).str.strip().str.title()
    invalid_crit = criticality[~criticality.isin(VALID_CRITICALITY)]
    if not invalid_crit.empty:
        errors.append(
            f"Found {len(invalid_crit)} row(s) with invalid asset_criticality. Valid options are: {', '.join(sorted(VALID_CRITICALITY))}."
        )
    cleaned_df["asset_criticality"] = criticality

    # 4. Validate internet_exposed
    exposed_parsed = normalized_df["internet_exposed"].apply(normalize_boolean)
    if exposed_parsed.isna().any():
        bad_count = exposed_parsed.isna().sum()
        errors.append(
            f"Found {bad_count} row(s) with invalid internet_exposed value. Must be True/False, Yes/No, or 1/0."
        )
    cleaned_df["internet_exposed"] = exposed_parsed.fillna(False).astype(bool)

    # 5. Validate remediation_effort_hours
    try:
        effort = pd.to_numeric(normalized_df["remediation_effort_hours"], errors="coerce")
        invalid_effort = effort[(effort <= 0) | effort.isna()]
        if not invalid_effort.empty:
            errors.append(
                f"Found {len(invalid_effort)} row(s) with invalid remediation_effort_hours. Effort must be a positive number (> 0)."
            )
        cleaned_df["remediation_effort_hours"] = effort.fillna(1.0).clip(lower=0.25, upper=200.0)
    except Exception as e:
        errors.append(f"Failed parsing remediation_effort_hours column: {e}")

    # Optional Fields Handling with Provenance Flags
    # 6. asset_name
    if "asset_name" in normalized_df.columns:
        cleaned_df["asset_name"] = (
            normalized_df["asset_name"].fillna("Unknown-Asset").astype(str).str.slice(0, MAX_TEXT_LEN)
        )
        cleaned_df["asset_name_provenance"] = "SUPPLIED"
        data_provenance["supplied_optional_fields"].append("asset_name")
    else:
        cleaned_df["asset_name"] = [f"Asset-{i+1}" for i in range(len(normalized_df))]
        cleaned_df["asset_name_provenance"] = "DERIVED (Auto-indexed)"
        data_provenance["unavailable_optional_fields"].append("asset_name")

    # 7. vulnerability_title
    if "vulnerability_title" in normalized_df.columns:
        cleaned_df["vulnerability_title"] = (
            normalized_df["vulnerability_title"].fillna("Security Vulnerability").astype(str).str.slice(0, MAX_TEXT_LEN)
        )
        cleaned_df["vulnerability_title_provenance"] = "SUPPLIED"
        data_provenance["supplied_optional_fields"].append("vulnerability_title")
    else:
        cleaned_df["vulnerability_title"] = "General Security Vulnerability"
        cleaned_df["vulnerability_title_provenance"] = "UNAVAILABLE (Generic label)"
        data_provenance["unavailable_optional_fields"].append("vulnerability_title")

    # 8. epss_score (Threat Intel: Exploit Prediction Scoring System 0.0 - 1.0)
    if "epss_score" in normalized_df.columns:
        epss = pd.to_numeric(normalized_df["epss_score"], errors="coerce")
        # Record provenance per row
        epss_prov = []
        epss_clean = []
        for val in epss:
            if pd.isna(val) or val < 0.0 or val > 1.0:
                epss_prov.append("UNAVAILABLE (Assumed baseline 0.01)")
                epss_clean.append(0.01)
            else:
                epss_prov.append("SUPPLIED")
                epss_clean.append(float(val))
        cleaned_df["epss_score"] = epss_clean
        cleaned_df["epss_provenance"] = epss_prov
        data_provenance["supplied_optional_fields"].append("epss_score")
    else:
        cleaned_df["epss_score"] = 0.01  # Safe baseline
        cleaned_df["epss_provenance"] = "UNAVAILABLE (Default 0.01 applied - Not Fabricated)"
        data_provenance["unavailable_optional_fields"].append("epss_score")
        warnings.append(
            "EPSS score column was not supplied. Baseline exploit probability (0.01) applied; no live threat data was fabricated."
        )

    # 9. cisa_kev (CISA Known Exploited Vulnerability Catalog)
    if "cisa_kev" in normalized_df.columns:
        cisa = normalized_df["cisa_kev"].apply(normalize_boolean)
        cisa_prov = []
        cisa_clean = []
        for val in cisa:
            if val is None:
                cisa_prov.append("UNAVAILABLE (Assumed False)")
                cisa_clean.append(False)
            else:
                cisa_prov.append("SUPPLIED")
                cisa_clean.append(val)
        cleaned_df["cisa_kev"] = cisa_clean
        cleaned_df["cisa_kev_provenance"] = cisa_prov
        data_provenance["supplied_optional_fields"].append("cisa_kev")
    else:
        cleaned_df["cisa_kev"] = False
        cleaned_df["cisa_kev_provenance"] = "UNAVAILABLE (Assumed False - Not Fabricated)"
        data_provenance["unavailable_optional_fields"].append("cisa_kev")
        warnings.append(
            "CISA KEV column was not supplied. Defaulting to False; no live threat intelligence was fabricated."
        )

    # 10. exploit_evidence
    if "exploit_evidence" in normalized_df.columns:
        exploit = normalized_df["exploit_evidence"].astype(str).str.strip().str.title()
        exploit_clean = exploit.apply(lambda x: x if x in VALID_EXPLOIT_EVIDENCE else "None")
        cleaned_df["exploit_evidence"] = exploit_clean
        cleaned_df["exploit_evidence_provenance"] = "SUPPLIED"
        data_provenance["supplied_optional_fields"].append("exploit_evidence")
    else:
        cleaned_df["exploit_evidence"] = "None"
        cleaned_df["exploit_evidence_provenance"] = "UNAVAILABLE (Defaulted to None)"
        data_provenance["unavailable_optional_fields"].append("exploit_evidence")

    # 11. maintenance_window
    if "maintenance_window" in normalized_df.columns:
        maint = normalized_df["maintenance_window"].astype(str).str.strip().str.title()
        # Map common aliases
        maint = maint.replace({"Offhours": "Off-Hours", "Off Hours": "Off-Hours", "Weekends": "Weekend"})
        cleaned_df["maintenance_window"] = maint.apply(lambda x: x if x in VALID_MAINTENANCE_WINDOWS else "Off-Hours")
    else:
        cleaned_df["maintenance_window"] = "Off-Hours"

    # 12. patch_available
    if "patch_available" in normalized_df.columns:
        patch = normalized_df["patch_available"].apply(normalize_boolean)
        cleaned_df["patch_available"] = patch.fillna(True).astype(bool)
    else:
        cleaned_df["patch_available"] = True

    # 13. remediation_cost_est
    if "remediation_cost_est" in normalized_df.columns:
        cost = pd.to_numeric(normalized_df["remediation_cost_est"], errors="coerce")
        cleaned_df["remediation_cost_est"] = cost.fillna(cleaned_df["remediation_effort_hours"] * 125.0)  # $125/hr standard
    else:
        cleaned_df["remediation_cost_est"] = cleaned_df["remediation_effort_hours"] * 125.0

    is_valid = len(errors) == 0
    return ValidationResult(
        is_valid=is_valid,
        errors=errors,
        warnings=warnings,
        cleaned_df=cleaned_df if is_valid else None,
        provenance_metadata=data_provenance,
    )
