"""Deterministic Risk Scoring Engine for SecureOps AI.

Provides transparent, verifiable risk calculations with mathematical explanations,
auditable step-by-step traces, and configurable P1-P4 priority thresholds.
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, Tuple
import pandas as pd


@dataclass
class PriorityThresholds:
    """Configurable priority cutoffs for vulnerability triage."""
    p1_cutoff: float = 80.0  # P1 - Critical / Urgent
    p2_cutoff: float = 60.0  # P2 - High Priority
    p3_cutoff: float = 40.0  # P3 - Medium Priority
    # Under P3 cutoff is P4 - Low Priority

    def classify(self, score: float, cisa_kev: bool = False, internet_exposed: bool = False, cvss: float = 0.0) -> str:
        """Classify into P1-P4 tier, with deterministic emergency elevation for active wild threats."""
        # Active wild threat override: KEV + Internet Exposed + High CVSS guarantees P1
        if cisa_kev and internet_exposed and cvss >= 7.0:
            return "P1"
        if score >= self.p1_cutoff:
            return "P1"
        if score >= self.p2_cutoff:
            return "P2"
        if score >= self.p3_cutoff:
            return "P3"
        return "P4"


# Standardized multipliers
CRITICALITY_MULTIPLIERS = {
    "Critical": 1.35,
    "High": 1.15,
    "Medium": 1.00,
    "Low": 0.75,
}

EXPOSURE_MULTIPLIERS = {
    True: 1.30,   # Internet-facing surface
    False: 1.00,  # Internal / segmented
}

EXPLOIT_EVIDENCE_BOOSTERS = {
    "Active": 12.0,      # Actively observed in the wild
    "Weaponized": 8.0,   # Metasploit/automated kit ready
    "Poc": 4.0,          # Proof of Concept published
    "None": 0.0,
    "Unknown": 0.0,
}

CISA_KEV_BOOSTER = 18.0  # Federal CISA catalog confirmation booster


def calculate_single_cve_risk(
    cvss: float,
    criticality: str,
    exposed: bool,
    epss: float,
    cisa_kev: bool,
    exploit_evidence: str,
) -> Tuple[float, str, Dict[str, float]]:
    """Deterministically compute composite risk score and generate human-readable mathematical proof.

    Formula:
      Base Impact = CVSS * 6.5 (range: 0 - 65)
      Asset Factor = Base Impact * Criticality Multiplier
      Contextual Subtotal = Asset Factor * Exposure Multiplier
      Threat Add-ons = CISA KEV Booster + (EPSS * 20.0) + Exploit Evidence Booster
      Raw Score = Contextual Subtotal + Threat Add-ons
      Final Score = Clamp(Raw Score, 0.0, 100.0)
    """
    # 1. Base Impact
    base_impact = round(cvss * 6.5, 2)

    # 2. Criticality Multiplier
    crit_mult = CRITICALITY_MULTIPLIERS.get(criticality, 1.00)
    asset_adjusted = round(base_impact * crit_mult, 2)

    # 3. Exposure Multiplier
    expo_mult = EXPOSURE_MULTIPLIERS.get(exposed, 1.00)
    context_subtotal = round(asset_adjusted * expo_mult, 2)

    # 4. Threat Intelligence Add-ons
    cisa_boost = CISA_KEV_BOOSTER if cisa_kev else 0.0
    epss_boost = round(min(max(epss, 0.0), 1.0) * 20.0, 2)
    exploit_clean = exploit_evidence.title() if exploit_evidence else "None"
    exploit_boost = EXPLOIT_EVIDENCE_BOOSTERS.get(exploit_clean, 0.0)

    total_threat_boost = round(cisa_boost + epss_boost + exploit_boost, 2)

    # 5. Raw and Clamped Score
    raw_score = round(context_subtotal + total_threat_boost, 2)
    final_score = round(max(0.0, min(100.0, raw_score)), 1)

    # 6. Detailed step-by-step mathematical explanation
    steps = (
        f"1. Base CVSS Impact: {cvss:.1f} × 6.5 = {base_impact:.1f}\n"
        f"2. Asset Criticality Multiplier ({criticality}): {base_impact:.1f} × {crit_mult:.2f} = {asset_adjusted:.1f}\n"
        f"3. Exposure Multiplier ({'Internet' if exposed else 'Internal'}): {asset_adjusted:.1f} × {expo_mult:.2f} = {context_subtotal:.1f}\n"
        f"4. Threat Boosters: CISA KEV (+{cisa_boost:.1f}) + EPSS {epss:.3f} (+{epss_boost:.1f}) + Exploit '{exploit_clean}' (+{exploit_boost:.1f}) = +{total_threat_boost:.1f}\n"
        f"5. Total Raw Score: {context_subtotal:.1f} + {total_threat_boost:.1f} = {raw_score:.1f} → Final Clamped Score: {final_score:.1f}/100"
    )

    metrics = {
        "base_impact": base_impact,
        "asset_multiplier": crit_mult,
        "exposure_multiplier": expo_mult,
        "cisa_boost": cisa_boost,
        "epss_boost": epss_boost,
        "exploit_boost": exploit_boost,
        "raw_score": raw_score,
        "final_score": final_score,
    }

    return final_score, steps, metrics


def compute_risk_scores(df: pd.DataFrame, thresholds: PriorityThresholds = None) -> pd.DataFrame:
    """Apply deterministic scoring across the entire validated vulnerability dataframe."""
    if thresholds is None:
        thresholds = PriorityThresholds()

    scored_df = df.copy()

    scores = []
    explanations = []
    priorities = []
    roi_factors = []

    for _, row in scored_df.iterrows():
        score, explanation, _ = calculate_single_cve_risk(
            cvss=float(row["cvss_score"]),
            criticality=str(row["asset_criticality"]),
            exposed=bool(row["internet_exposed"]),
            epss=float(row.get("epss_score", 0.01)),
            cisa_kev=bool(row.get("cisa_kev", False)),
            exploit_evidence=str(row.get("exploit_evidence", "None")),
        )
        priority = thresholds.classify(
            score=score,
            cisa_kev=bool(row.get("cisa_kev", False)),
            internet_exposed=bool(row.get("internet_exposed", False)),
            cvss=float(row["cvss_score"]),
        )
        effort = max(float(row.get("remediation_effort_hours", 1.0)), 0.25)
        # Risk Reduction Efficiency (Risk Points reduced per engineering hour)
        roi = round(score / effort, 2)

        scores.append(score)
        explanations.append(explanation)
        priorities.append(priority)
        roi_factors.append(roi)

    scored_df["risk_score"] = scores
    scored_df["priority"] = priorities
    scored_df["risk_roi"] = roi_factors
    scored_df["scoring_explanation"] = explanations

    return scored_df
