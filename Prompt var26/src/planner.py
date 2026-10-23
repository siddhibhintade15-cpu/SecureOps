"""Resource-Aware Remediation Planning Engine for SecureOps AI.

Implements constrained capacity optimization across 4 remediation categories
(Immediate Fixes, Quick Wins, Scheduled Fixes, Monitor/Verify), generates
trade-off explanations, calculates before/after risk reductions, distinguishes
projected from verified risk reduction, and enforces strict capacity limits.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any, Set
import pandas as pd


@dataclass
class PlanningConstraints:
    """Resource constraints for remediation sprint planning."""
    team_capacity_hours: float = 80.0     # Total engineering hours in cycle
    budget_limit: float = 15000.0         # Total budget limit ($)
    allowed_windows: List[str] = field(
        default_factory=lambda: ["Emergency", "Off-Hours", "Weekend", "Anytime"]
    )
    enforce_budget: bool = False           # Whether budget constraint is strictly enforced


@dataclass
class PlanSummary:
    """Summary of the remediation plan, capacity utilization, and risk reduction."""
    total_cves: int
    planned_cves_count: int
    deferred_cves_count: int
    baseline_total_risk: float
    remediated_risk: float
    residual_total_risk: float
    baseline_mean_risk: float
    projected_mean_risk: float
    risk_reduction_pct: float
    allocated_hours: float
    capacity_hours_limit: float
    hours_utilization_pct: float
    allocated_cost: float
    budget_limit: float
    category_counts: Dict[str, int]
    category_hours: Dict[str, float]
    priority_total_counts: Dict[str, int] = field(default_factory=dict)
    priority_planned_counts: Dict[str, int] = field(default_factory=dict)
    verified_cves_count: int = 0
    verified_remediated_risk: float = 0.0
    verified_residual_total_risk: float = 0.0
    verified_residual_mean_risk: float = 0.0
    verified_risk_reduction_pct: float = 0.0
    trade_off_analysis: str = ""


def categorize_vulnerability(
    row: pd.Series,
    quick_win_max_hours: float = 3.0,
    quick_win_min_risk: float = 45.0,
) -> str:
    """Categorize a vulnerability based on urgency, risk, and effort.

    Categories:
      - Immediate Fixes: P1, active exploits, or critical internet threats
      - Quick Wins: High risk reduction relative to minimal effort (<= 3h)
      - Scheduled Fixes: Substantial P2/P3 vulnerabilities needing normal sprint time
      - Monitor/Verify: P4, unpatched, or low-urgency items
    """
    priority = row.get("priority", "P4")
    risk_score = float(row.get("risk_score", 0.0))
    effort = float(row.get("remediation_effort_hours", 1.0))
    patch_avail = bool(row.get("patch_available", True))
    cisa_kev = bool(row.get("cisa_kev", False))
    exploit_evidence = str(row.get("exploit_evidence", "None")).title()

    if not patch_avail:
        return "Monitor/Verify"

    # Immediate Fixes: Emergency, P1, or actively exploited
    if priority == "P1" or cisa_kev or exploit_evidence == "Active":
        return "Immediate Fixes"

    # Quick Wins: High impact, low effort
    if risk_score >= quick_win_min_risk and effort <= quick_win_max_hours:
        return "Quick Wins"

    # Scheduled Fixes: Significant risk requiring normal sprint schedule
    if priority in {"P2", "P3"} or risk_score >= 35.0:
        return "Scheduled Fixes"

    return "Monitor/Verify"


def generate_remediation_plan(
    df: pd.DataFrame,
    constraints: PlanningConstraints = None,
    approved_cve_ids: Optional[Set[str]] = None,
) -> Tuple[pd.DataFrame, PlanSummary]:
    """Allocate vulnerabilities to sprint plan subject to capacity and budget constraints.

    Allocation heuristic:
      1. Immediate Fixes are prioritized first (critical duty).
      2. Quick Wins are scheduled next (highest ROI per engineering hour).
      3. Scheduled Fixes are scheduled by descending Risk ROI (Risk / Effort).
      4. Strict capacity limit is enforced: items that cannot fit in the sprint or
         budget are deferred with explicit deferral reasons. Allocated hours will
         never exceed the configured capacity limit.
    """
    if constraints is None:
        constraints = PlanningConstraints()

    plan_df = df.copy()

    # Initial heuristic categorization
    plan_df["remediation_category"] = plan_df.apply(categorize_vulnerability, axis=1)

    # Sort priorities for resource allocation
    # 1: Immediate Fixes (ordered by risk_score desc)
    # 2: Quick Wins (ordered by risk_roi desc)
    # 3: Scheduled Fixes (ordered by risk_roi desc)
    # 4: Monitor/Verify (ordered by risk_score desc)
    category_rank = {
        "Immediate Fixes": 1,
        "Quick Wins": 2,
        "Scheduled Fixes": 3,
        "Monitor/Verify": 4,
    }
    plan_df["cat_rank"] = plan_df["remediation_category"].map(category_rank).fillna(5)
    plan_df = plan_df.sort_values(
        by=["cat_rank", "risk_score", "risk_roi"],
        ascending=[True, False, False],
    ).reset_index(drop=True)

    allocated_hours = 0.0
    allocated_cost = 0.0
    plan_status = []
    deferral_reason = []
    approval_status = []

    capacity_limit = constraints.team_capacity_hours
    budget_limit = constraints.budget_limit
    allowed_windows = set(constraints.allowed_windows)
    approved_set = set(approved_cve_ids) if approved_cve_ids is not None else set()

    for _, row in plan_df.iterrows():
        effort = float(row["remediation_effort_hours"])
        cost = float(row.get("remediation_cost_est", effort * 125.0))
        cat = row["remediation_category"]
        maint_win = str(row.get("maintenance_window", "Off-Hours"))
        patch_avail = bool(row.get("patch_available", True))
        cve_id = str(row["cve_id"])

        # Check patch availability
        if not patch_avail:
            plan_status.append("Deferred")
            deferral_reason.append("Vendor patch unavailable; compensating controls active")
            approval_status.append("N/A - Monitor Only")
            continue

        # Check maintenance window alignment
        if maint_win not in allowed_windows and maint_win != "Anytime":
            plan_status.append("Deferred")
            deferral_reason.append(f"Requires '{maint_win}' window outside current sprint configuration")
            approval_status.append("N/A - Deferred Window")
            continue

        # If it was initially Monitor/Verify
        if cat == "Monitor/Verify":
            plan_status.append("Deferred")
            deferral_reason.append("Low risk threshold / Routine monitoring")
            approval_status.append("N/A - Monitor Only")
            continue

        # Strict capacity enforcement across ALL categories:
        # allocated_hours will NEVER exceed capacity_limit
        would_exceed_hours = (allocated_hours + effort) > capacity_limit
        would_exceed_budget = constraints.enforce_budget and ((allocated_cost + cost) > budget_limit)

        if would_exceed_hours:
            plan_status.append("Deferred")
            remaining_h = max(0.0, capacity_limit - allocated_hours)
            if cat == "Immediate Fixes":
                deferral_reason.append(
                    f"Immediate fix deferred: exceeds team capacity ({remaining_h:.1f}h left, needs {effort:.1f}h)"
                )
            else:
                deferral_reason.append(
                    f"Exceeds available team capacity ({remaining_h:.1f}h left, needs {effort:.1f}h)"
                )
            approval_status.append("Deferred - Capacity Cap")
        elif would_exceed_budget:
            plan_status.append("Deferred")
            remaining_b = max(0.0, budget_limit - allocated_cost)
            deferral_reason.append(
                f"Exceeds budget limit (${remaining_b:.0f} left, needs ${cost:.0f})"
            )
            approval_status.append("Deferred - Budget Cap")
        else:
            allocated_hours += effort
            allocated_cost += cost
            plan_status.append("Planned")
            deferral_reason.append("None (Fits in sprint capacity)")
            if cve_id in approved_set:
                approval_status.append("Approved by Lead")
            else:
                approval_status.append("Pending Review")

    plan_df["plan_status"] = plan_status
    plan_df["deferral_reason"] = deferral_reason
    plan_df["approval_status"] = approval_status

    # Drop temporary sort column
    plan_df = plan_df.drop(columns=["cat_rank"])

    # Baseline Risk Calculations
    total_cves = len(plan_df)
    baseline_total_risk = round(float(plan_df["risk_score"].sum()), 1)
    baseline_mean_risk = round(baseline_total_risk / total_cves, 1) if total_cves > 0 else 0.0

    # Planned vs Deferred
    planned_mask = plan_df["plan_status"] == "Planned"
    planned_cves = plan_df[planned_mask]
    deferred_cves = plan_df[~planned_mask]

    # Estimated / Projected Risk Metrics (assuming all planned remediations are executed)
    remediated_risk = round(float(planned_cves["risk_score"].sum()), 1)
    residual_total_risk = round(max(0.0, baseline_total_risk - remediated_risk), 1)
    projected_mean_risk = round(residual_total_risk / total_cves, 1) if total_cves > 0 else 0.0
    risk_reduction_pct = (
        round((remediated_risk / baseline_total_risk) * 100.0, 1) if baseline_total_risk > 0 else 0.0
    )

    # Verified Risk Metrics (subset of planned items explicitly approved by Security Lead)
    verified_mask = planned_mask & (plan_df["approval_status"] == "Approved by Lead")
    verified_cves = plan_df[verified_mask]
    verified_remediated_risk = round(float(verified_cves["risk_score"].sum()), 1)
    verified_residual_total_risk = round(max(0.0, baseline_total_risk - verified_remediated_risk), 1)
    verified_residual_mean_risk = round(verified_residual_total_risk / total_cves, 1) if total_cves > 0 else 0.0
    verified_risk_reduction_pct = (
        round((verified_remediated_risk / baseline_total_risk) * 100.0, 1) if baseline_total_risk > 0 else 0.0
    )

    hours_util_pct = (
        round((allocated_hours / capacity_limit) * 100.0, 1) if capacity_limit > 0 else 0.0
    )

    category_counts = plan_df["remediation_category"].value_counts().to_dict()
    category_hours = (
        planned_cves.groupby("remediation_category")["remediation_effort_hours"]
        .sum()
        .round(1)
        .to_dict()
        if not planned_cves.empty else {}
    )

    # Priority Counts: Total Detected vs Planned
    priority_total_counts = plan_df["priority"].value_counts().to_dict()
    priority_planned_counts = (
        planned_cves["priority"].value_counts().to_dict()
        if not planned_cves.empty else {}
    )

    # Generate analytical trade-off summary
    trade_off = (
        f"The planner selected {len(planned_cves)} vulnerabilities for remediation utilizing "
        f"{allocated_hours:.1f}h of {capacity_limit:.1f}h ({hours_util_pct}% capacity) and "
        f"${allocated_cost:,.0f} estimated effort. "
        f"Projected Risk Reduction: {risk_reduction_pct}% ({remediated_risk:.1f} risk points eliminated, residual mean risk {projected_mean_risk:.1f}). "
        f"Verified Risk Reduction: {verified_risk_reduction_pct}% ({len(verified_cves)} items authorized by Lead, {verified_remediated_risk:.1f} risk points eliminated). "
        f"{len(deferred_cves)} vulnerabilities were deferred due to capacity limitations, low risk impact, or unavailable vendor patches."
    )

    summary = PlanSummary(
        total_cves=total_cves,
        planned_cves_count=len(planned_cves),
        deferred_cves_count=len(deferred_cves),
        baseline_total_risk=baseline_total_risk,
        remediated_risk=remediated_risk,
        residual_total_risk=residual_total_risk,
        baseline_mean_risk=baseline_mean_risk,
        projected_mean_risk=projected_mean_risk,
        risk_reduction_pct=risk_reduction_pct,
        allocated_hours=round(allocated_hours, 1),
        capacity_hours_limit=capacity_limit,
        hours_utilization_pct=hours_util_pct,
        allocated_cost=round(allocated_cost, 2),
        budget_limit=budget_limit,
        category_counts=category_counts,
        category_hours=category_hours,
        priority_total_counts=priority_total_counts,
        priority_planned_counts=priority_planned_counts,
        verified_cves_count=len(verified_cves),
        verified_remediated_risk=verified_remediated_risk,
        verified_residual_total_risk=verified_residual_total_risk,
        verified_residual_mean_risk=verified_residual_mean_risk,
        verified_risk_reduction_pct=verified_risk_reduction_pct,
        trade_off_analysis=trade_off,
    )

    return plan_df, summary
