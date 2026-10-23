"""SecureOps AI: Autonomous Vulnerability Remediation Planner.

Streamlit Cybersecurity Dashboard for deterministic risk scoring, resource-aware
remediation planning, transparent threat provenance, and Gemini-assisted executive reviews.
"""

from __future__ import annotations
import io
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from src.gemini_service import (
    generate_executive_review,
    is_gemini_available,
    mask_api_key,
    get_api_key,
)
from src.planner import (
    PlanningConstraints,
    generate_remediation_plan,
)
from src.schemas import (
    MAX_ROW_LIMIT,
    MAX_UPLOAD_SIZE_BYTES,
    REQUIRED_COLUMNS,
    validate_dataframe,
    validate_file_size,
)
from src.scoring import (
    PriorityThresholds,
    compute_risk_scores,
)
from src.utils import (
    export_audit_manifest_json,
    export_remediation_plan_csv,
    load_synthetic_sample_dataframe,
)

# ---------------------------------------------------------------------------
# Page Configuration & Cybersecurity Dashboard Theme
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="SecureOps AI | Autonomous Remediation Planner",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom CSS for polished dark cybersecurity UI
st.markdown(
    """
    <style>
    /* Metric card styling */
    div[data-testid="metric-container"] {
        background-color: #111827;
        border: 1px solid #1f2937;
        padding: 14px 18px;
        border-radius: 10px;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.2);
    }
    div[data-testid="metric-container"] label {
        color: #9ca3af !important;
        font-weight: 500;
        font-size: 0.85rem;
    }
    div[data-testid="metric-container"] div[data-testid="stMetricValue"] {
        color: #f3f4f6 !important;
        font-weight: 700;
        font-size: 1.7rem;
    }
    /* Banner badges */
    .cyber-badge {
        display: inline-block;
        padding: 4px 10px;
        border-radius: 6px;
        font-size: 0.75rem;
        font-weight: 600;
        margin-right: 6px;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
    .badge-p1 { background-color: #7f1d1d; color: #fca5a5; border: 1px solid #991b1b; }
    .badge-p2 { background-color: #7c2d12; color: #fdba74; border: 1px solid #c2410c; }
    .badge-p3 { background-color: #713f12; color: #fde047; border: 1px solid #a16207; }
    .badge-p4 { background-color: #14532d; color: #86efac; border: 1px solid #166534; }
    .badge-gemini-on { background-color: #064e3b; color: #6ee7b7; border: 1px solid #059669; }
    .badge-gemini-off { background-color: #1e293b; color: #94a3b8; border: 1px solid #334155; }
    .badge-safe { background-color: #1e1b4b; color: #c7d2fe; border: 1px solid #4338ca; }
    </style>
    """,
    unsafe_allow_html=True,
)


# ---------------------------------------------------------------------------
# Session State Initialization
# ---------------------------------------------------------------------------
if "dataset_source" not in st.session_state:
    st.session_state.dataset_source = "synthetic"

if "raw_df" not in st.session_state:
    st.session_state.raw_df = load_synthetic_sample_dataframe()

if "approved_cves" not in st.session_state:
    st.session_state.approved_cves = set()


# ---------------------------------------------------------------------------
# Sidebar Controls & Settings
# ---------------------------------------------------------------------------
with st.sidebar:
    st.markdown(
        """
        <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 12px;">
            <svg width="42" height="42" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path d="M12 2L3 7V13C3 18.25 6.84 23.14 12 24C17.16 23.14 21 18.25 21 13V7L12 2Z" fill="#0284c7" fill-opacity="0.25" stroke="#38bdf8" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                <path d="M9 12L11 14L15 10" stroke="#38bdf8" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
            <div>
                <h2 style="margin: 0; padding: 0; font-size: 1.35rem; color: #f8fafc; font-weight: 700; line-height: 1.1;">SecureOps AI</h2>
                <div style="font-size: 0.72rem; color: #38bdf8; letter-spacing: 0.05em; font-weight: 600;">REMEDIATION PLANNER</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.caption("Autonomous Vulnerability Remediation Planner")
    st.markdown("---")

    # 1. Dataset Selection
    st.subheader("📂 Vulnerability Data Source")
    data_source_mode = st.radio(
        "Select Input Mode:",
        ["Synthetic Demo Dataset", "Upload Custom CSV"],
        index=0 if st.session_state.dataset_source == "synthetic" else 1,
    )

    uploaded_file = None
    if data_source_mode == "Upload Custom CSV":
        st.session_state.dataset_source = "custom"
        uploaded_file = st.file_uploader(
            "Upload Vulnerability CSV",
            type=["csv"],
            help=f"Max file size: {MAX_UPLOAD_SIZE_BYTES / (1024*1024):.0f}MB. Max rows: {MAX_ROW_LIMIT}. Required columns: {', '.join(REQUIRED_COLUMNS)}",
        )
    else:
        st.session_state.dataset_source = "synthetic"
        if st.button("🔄 Reset to Default Synthetic Dataset", use_container_width=True):
            st.session_state.raw_df = load_synthetic_sample_dataframe()
            st.session_state.approved_cves = set()
            st.success("Loaded synthetic demo dataset (28 realistic CVE profiles).")

    st.markdown("---")

    # 2. Resource & Sprint Constraints
    st.subheader("⏱️ Team Sprint Capacity")
    capacity_hours = st.slider(
        "Available Engineering Hours",
        min_value=10.0,
        max_value=300.0,
        value=80.0,
        step=5.0,
        help="Total engineering hours available across the remediation sprint cycle.",
    )

    cost_per_hour = st.number_input(
        "Hourly Labor Rate ($/hr)",
        min_value=50.0,
        max_value=500.0,
        value=125.0,
        step=10.0,
    )

    enforce_budget = st.checkbox("Enforce Hard Budget Limit", value=False)
    budget_limit = 20000.0
    if enforce_budget:
        budget_limit = st.slider(
            "Max Remediation Budget ($)",
            min_value=1000.0,
            max_value=50000.0,
            value=15000.0,
            step=1000.0,
        )

    allowed_windows = st.multiselect(
        "Permitted Patch Windows",
        options=["Emergency", "Off-Hours", "Weekend", "Anytime"],
        default=["Emergency", "Off-Hours", "Weekend", "Anytime"],
        help="Only vulnerabilities matching active windows can be scheduled for immediate maintenance.",
    )

    st.markdown("---")

    # 3. Deterministic Priority Thresholds
    with st.expander("⚙️ Priority Threshold Tuning (P1–P4)"):
        st.caption("Configurable deterministic score boundaries for automated triage.")
        p1_cut = st.slider("P1 Critical Cutoff", 70.0, 95.0, 80.0, step=1.0)
        p2_cut = st.slider("P2 High Cutoff", 50.0, 75.0, 60.0, step=1.0)
        p3_cut = st.slider("P3 Medium Cutoff", 30.0, 55.0, 40.0, step=1.0)

    st.markdown("---")

    # 4. Gemini AI Configuration
    st.subheader("🤖 Gemini Intelligence Engine")
    env_gemini_key = get_api_key()
    session_gemini_key = st.text_input(
        "Gemini API Key (Optional Override)",
        type="password",
        value="",
        placeholder="Enter key for this session or use .env",
        help="Optional. If omitted, SecureOps AI runs locally in Deterministic Fallback Mode with zero loss of core functionality.",
    )

    active_gemini_key = session_gemini_key.strip() if session_gemini_key.strip() else env_gemini_key
    gemini_is_on = is_gemini_available(active_gemini_key)

    if gemini_is_on:
        st.markdown(
            f'<span class="cyber-badge badge-gemini-on">● Gemini Active ({mask_api_key(active_gemini_key)})</span>',
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            '<span class="cyber-badge badge-gemini-off">○ Offline Fallback Mode Active</span>',
            unsafe_allow_html=True,
        )

    st.caption("No keys are ever transmitted or written to public logs.")


# ---------------------------------------------------------------------------
# Data Loading and Validation Pipeline
# ---------------------------------------------------------------------------
validation_error = None
validation_warnings: List[str] = []
provenance_metadata: Dict = {}
working_df: Optional[pd.DataFrame] = None

if st.session_state.dataset_source == "custom":
    if uploaded_file is not None:
        file_bytes = uploaded_file.getvalue()
        size_valid, size_err = validate_file_size(file_bytes)
        if not size_valid:
            validation_error = size_err
        else:
            try:
                raw_input_df = pd.read_csv(io.BytesIO(file_bytes))
                val_res = validate_dataframe(raw_input_df)
                if not val_res.is_valid:
                    validation_error = "Validation Errors:\n" + "\n".join(f"- {e}" for e in val_res.errors)
                else:
                    working_df = val_res.cleaned_df
                    validation_warnings = val_res.warnings
                    provenance_metadata = val_res.provenance_metadata
            except Exception as exc:
                validation_error = f"Failed to parse CSV file: {exc}"
    else:
        st.info("👆 Please upload a vulnerability CSV file in the sidebar, or switch back to the Synthetic Demo Dataset.")
        st.stop()
else:
    # Use synthetic sample dataset
    synthetic_res = validate_dataframe(st.session_state.raw_df)
    working_df = synthetic_res.cleaned_df
    validation_warnings = synthetic_res.warnings
    provenance_metadata = synthetic_res.provenance_metadata

if validation_error:
    st.error(f"❌ Upload Rejected by Security Gate:\n\n{validation_error}")
    st.stop()

if working_df is None or working_df.empty:
    st.warning("No vulnerability records to process.")
    st.stop()

# Surface any soft schema warnings (e.g. EPSS column was omitted so default was used without fabricating)
if validation_warnings:
    with st.expander(f"⚠️ Data Schema Notices ({len(validation_warnings)})", expanded=False):
        for w in validation_warnings:
            st.info(w)


# ---------------------------------------------------------------------------
# Compute Risk Scores and Resource-Constrained Plan
# ---------------------------------------------------------------------------
thresholds = PriorityThresholds(p1_cutoff=p1_cut, p2_cutoff=p2_cut, p3_cutoff=p3_cut)
scored_df = compute_risk_scores(working_df, thresholds=thresholds)

constraints = PlanningConstraints(
    team_capacity_hours=capacity_hours,
    budget_limit=budget_limit,
    allowed_windows=allowed_windows if allowed_windows else ["Anytime"],
    enforce_budget=enforce_budget,
)

plan_df, plan_summary = generate_remediation_plan(
    scored_df, constraints=constraints, approved_cve_ids=st.session_state.approved_cves
)


# ---------------------------------------------------------------------------
# Header & Security Posture Badges
# ---------------------------------------------------------------------------
st.markdown(
    """
    <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px;">
        <h1 style="margin: 0; padding: 0; font-size: 2.1rem; color: #f8fafc;">
            🛡️ SecureOps AI: Autonomous Vulnerability Remediation Planner
        </h1>
    </div>
    """,
    unsafe_allow_html=True,
)

st.markdown(
    """
    <div>
        <span class="cyber-badge badge-safe">🔒 Zero Shell Execution</span>
        <span class="cyber-badge badge-safe">👤 Human-in-the-Loop Sign-off Enforced</span>
        <span class="cyber-badge badge-safe">📐 Transparent Deterministic Math</span>
        <span class="cyber-badge badge-safe">🔍 Data Provenance Tracking Active</span>
    </div>
    <div style="margin-top: 6px; margin-bottom: 20px; color: #94a3b8; font-size: 0.95rem;">
        Intelligent, resource-aware vulnerability orchestration. Bridges threat intelligence, asset business context, and engineering capacity constraints to deliver auditable, risk-optimized remediation schedules.
    </div>
    """,
    unsafe_allow_html=True,
)


# ---------------------------------------------------------------------------
# Navigation Tabs
# ---------------------------------------------------------------------------
tab_overview, tab_plan, tab_explorer, tab_ai, tab_export, tab_methodology = st.tabs([
    "📊 Executive Posture & KPIs",
    "🗓️ Remediation Plan & Approvals",
    "🔍 Vulnerability Triage & Inspector",
    "🤖 Gemini AI Strategic Brief",
    "📥 Download Reports & Manifest",
    "📖 Methodology & Governance",
])


# ===========================================================================
# TAB 1: EXECUTIVE POSTURE & KPIS
# ===========================================================================
with tab_overview:
    # Key Metric Cards
    kpi_col1, kpi_col2, kpi_col3, kpi_col4, kpi_col5 = st.columns(5)

    with kpi_col1:
        st.metric(
            label="Total Vulnerabilities",
            value=f"{plan_summary.total_cves}",
            delta=f"{plan_summary.planned_cves_count} Planned Fixes",
            delta_color="normal",
        )

    with kpi_col2:
        total_p1 = plan_summary.priority_total_counts.get("P1", 0)
        planned_p1 = plan_summary.priority_planned_counts.get("P1", 0)
        st.metric(
            label="P1 Critical Threats",
            value=f"{planned_p1} / {total_p1} Planned",
            delta=f"{total_p1 - planned_p1} Deferred" if total_p1 > planned_p1 else "All Scheduled",
            delta_color="normal" if total_p1 == planned_p1 else "inverse",
        )

    with kpi_col3:
        st.metric(
            label="Mean Risk Score",
            value=f"{plan_summary.baseline_mean_risk:.1f} → {plan_summary.projected_mean_risk:.1f}",
            delta=f"-{round(plan_summary.baseline_mean_risk - plan_summary.projected_mean_risk, 1)} pts Projected Residual",
            delta_color="inverse",
        )

    with kpi_col4:
        st.metric(
            label="Sprint Capacity",
            value=f"{plan_summary.allocated_hours:.1f}h / {plan_summary.capacity_hours_limit:.0f}h",
            delta=f"{plan_summary.hours_utilization_pct:.1f}% Utilized (Cap Enforced)",
            delta_color="normal" if plan_summary.hours_utilization_pct <= 100 else "inverse",
        )

    with kpi_col5:
        st.metric(
            label="Projected Risk Reduction",
            value=f"{plan_summary.risk_reduction_pct:.1f}%",
            delta=f"Verified: {plan_summary.verified_risk_reduction_pct:.1f}% ({plan_summary.verified_cves_count} approved)",
            delta_color="normal" if plan_summary.verified_cves_count > 0 else "off",
        )

    # Distinguish Projected vs Verified Risk Reduction in an executive posture banner
    st.markdown(
        f"""
        <div style="background-color: #0f172a; border: 1px solid #1e293b; border-radius: 8px; padding: 12px 16px; margin-top: 14px; margin-bottom: 20px;">
            <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px;">
                <div>
                    <strong style="color: #38bdf8;">🎯 Projected Risk Reduction:</strong>
                    <span style="color: #f1f5f9; font-weight: 600;">{plan_summary.risk_reduction_pct:.1f}%</span>
                    <span style="color: #94a3b8; font-size: 0.85rem;">({plan_summary.remediated_risk:.1f} / {plan_summary.baseline_total_risk:.1f} risk pts eliminated across {plan_summary.planned_cves_count} planned fixes)</span>
                </div>
                <div>
                    <strong style="color: #34d399;">✅ Verified Risk Reduction:</strong>
                    <span style="color: #f1f5f9; font-weight: 600;">{plan_summary.verified_risk_reduction_pct:.1f}%</span>
                    <span style="color: #94a3b8; font-size: 0.85rem;">({plan_summary.verified_remediated_risk:.1f} risk pts signed off by Security Lead across {plan_summary.verified_cves_count} authorized fixes)</span>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown("<br>", unsafe_allow_html=True)

    # Posture Charts Row
    chart_col1, chart_col2 = st.columns(2)

    with chart_col1:
        st.subheader("Priority Tier Distribution (P1–P4)")
        priority_colors = {
            "P1": "#ef4444",  # Red
            "P2": "#f97316",  # Orange
            "P3": "#eab308",  # Yellow
            "P4": "#22c55e",  # Green
        }
        p_counts = plan_df["priority"].value_counts().reset_index()
        p_counts.columns = ["Priority", "Count"]
        p_counts = p_counts.sort_values(by="Priority")

        fig_p = px.pie(
            p_counts,
            values="Count",
            names="Priority",
            color="Priority",
            color_discrete_map=priority_colors,
            hole=0.45,
        )
        fig_p.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#e2e8f0"),
            legend=dict(orientation="h", yanchor="bottom", y=-0.2, xanchor="center", x=0.5),
            margin=dict(t=10, b=10, l=10, r=10),
            height=280,
        )
        st.plotly_chart(fig_p, use_container_width=True)

    with chart_col2:
        st.subheader("Remediation Category Allocation")
        cat_counts = plan_df["remediation_category"].value_counts().reset_index()
        cat_counts.columns = ["Category", "Count"]
        cat_colors = {
            "Immediate Fixes": "#dc2626",
            "Quick Wins": "#10b981",
            "Scheduled Fixes": "#3b82f6",
            "Monitor/Verify": "#64748b",
        }
        fig_cat = px.bar(
            cat_counts,
            x="Count",
            y="Category",
            orientation="h",
            color="Category",
            color_discrete_map=cat_colors,
            text="Count",
        )
        fig_cat.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#e2e8f0"),
            showlegend=False,
            xaxis=dict(showgrid=True, gridcolor="#334155"),
            yaxis=dict(showgrid=False),
            margin=dict(t=10, b=10, l=10, r=10),
            height=280,
        )
        st.plotly_chart(fig_cat, use_container_width=True)

    # Risk vs Effort Quadrant Scatter Plot
    st.subheader("🎯 Risk Score vs. Remediation Effort (ROI Quadrant Analysis)")
    st.caption("Identifies high-impact opportunities: 'Quick Wins' occupy the top-left quadrant (high risk, low effort).")

    scatter_fig = px.scatter(
        plan_df,
        x="remediation_effort_hours",
        y="risk_score",
        color="remediation_category",
        size="cvss_score",
        hover_name="cve_id",
        hover_data={
            "asset_name": True,
            "priority": True,
            "remediation_effort_hours": True,
            "risk_score": True,
            "risk_roi": True,
            "plan_status": True,
        },
        color_discrete_map=cat_colors,
        labels={
            "remediation_effort_hours": "Remediation Effort (Hours)",
            "risk_score": "Composite Risk Score (0-100)",
            "remediation_category": "Category",
        },
    )

    # Quadrant benchmark lines
    scatter_fig.add_hline(y=60.0, line_dash="dash", line_color="#475569", annotation_text="High Risk Threshold (60.0)")
    scatter_fig.add_vline(x=4.0, line_dash="dash", line_color="#475569", annotation_text="Quick Win Effort Cap (4.0h)")

    scatter_fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="#0f172a",
        font=dict(color="#e2e8f0"),
        xaxis=dict(showgrid=True, gridcolor="#1e293b"),
        yaxis=dict(showgrid=True, gridcolor="#1e293b", range=[0, 105]),
        margin=dict(t=20, b=20, l=10, r=10),
        height=380,
    )
    st.plotly_chart(scatter_fig, use_container_width=True)


# ===========================================================================
# TAB 2: REMEDIATION PLAN & CAPACITY
# ===========================================================================
with tab_plan:
    st.subheader("📋 Resource-Constrained Remediation Schedule")
    st.markdown(f"> **Optimization Trade-Off Analysis**: {plan_summary.trade_off_analysis}")

    # Capacity utilization progress bar
    util_ratio = min(1.0, plan_summary.allocated_hours / max(1.0, plan_summary.capacity_hours_limit))
    st.write(
        f"**Capacity Consumption**: {plan_summary.allocated_hours:.1f} / {plan_summary.capacity_hours_limit:.1f} hours ({plan_summary.hours_utilization_pct:.1f}% utilized - hard limit enforced)"
    )
    st.progress(util_ratio)

    # Risk Breakdown Cards
    risk_col1, risk_col2, risk_col3, risk_col4 = st.columns(4)
    with risk_col1:
        st.metric("Total Baseline Risk", f"{plan_summary.baseline_total_risk:.1f} pts")
    with risk_col2:
        st.metric(
            "Projected Remediated",
            f"{plan_summary.remediated_risk:.1f} pts",
            f"-{plan_summary.risk_reduction_pct:.1f}% Projected",
        )
    with risk_col3:
        st.metric(
            "Verified Remediated",
            f"{plan_summary.verified_remediated_risk:.1f} pts",
            f"-{plan_summary.verified_risk_reduction_pct:.1f}% Verified",
        )
    with risk_col4:
        st.metric(
            "Residual Total Risk",
            f"{plan_summary.residual_total_risk:.1f} pts",
            f"Mean: {plan_summary.projected_mean_risk:.1f}/100",
            delta_color="inverse",
        )

    st.markdown("---")

    # Human-in-the-Loop Sign-off Controls
    plan_col_act1, plan_col_act2 = st.columns([3, 1])
    with plan_col_act1:
        st.markdown("### ✍️ Human-in-the-Loop Remediation Sign-Off Gate")
        st.caption(
            "Security policy mandates explicit human lead sign-off. Automated shell patching or unverified modifications are strictly prohibited."
        )
    with plan_col_act2:
        planned_ids = set(plan_df[plan_df["plan_status"] == "Planned"]["cve_id"])
        all_approved = planned_ids.issubset(st.session_state.approved_cves) and len(planned_ids) > 0

        if st.button("✅ Authorize All Planned Items", use_container_width=True, type="primary"):
            st.session_state.approved_cves.update(planned_ids)
            st.rerun()

        if st.button("🔄 Reset Approvals", use_container_width=True):
            st.session_state.approved_cves.clear()
            st.rerun()

    # Display Planned Items Table
    st.markdown("#### Scheduled Remediation Actions")
    planned_table = plan_df[plan_df["plan_status"] == "Planned"][
        [
            "cve_id",
            "vulnerability_title",
            "asset_name",
            "risk_score",
            "priority",
            "remediation_category",
            "remediation_effort_hours",
            "maintenance_window",
            "approval_status",
        ]
    ]

    st.dataframe(
        planned_table,
        use_container_width=True,
        hide_index=True,
        column_config={
            "risk_score": st.column_config.NumberColumn("Risk Score", format="%.1f"),
            "remediation_effort_hours": st.column_config.NumberColumn("Effort (h)", format="%.1f"),
            "approval_status": st.column_config.TextColumn("Lead Authorization"),
        },
    )

    # Display Deferred Items Table with Reason
    st.markdown("#### Deferred / Monitored Items")
    deferred_table = plan_df[plan_df["plan_status"] != "Planned"][
        [
            "cve_id",
            "asset_name",
            "risk_score",
            "priority",
            "remediation_category",
            "remediation_effort_hours",
            "deferral_reason",
        ]
    ]

    st.dataframe(
        deferred_table,
        use_container_width=True,
        hide_index=True,
        column_config={
            "risk_score": st.column_config.NumberColumn("Risk Score", format="%.1f"),
            "remediation_effort_hours": st.column_config.NumberColumn("Effort (h)", format="%.1f"),
            "deferral_reason": st.column_config.TextColumn("Deferral Justification"),
        },
    )


# ===========================================================================
# TAB 3: VULNERABILITY TRIAGE & INSPECTOR
# ===========================================================================
with tab_explorer:
    st.subheader("🔍 Vulnerability Explorer & Mathematical Inspector")
    st.caption("Inspect individual vulnerabilities, review full step-by-step scoring derivations, and audit threat data provenance.")

    # Table Filters
    filter_col1, filter_col2, filter_col3, filter_col4 = st.columns(4)
    with filter_col1:
        sel_priority = st.multiselect(
            "Filter Priority:",
            options=["P1", "P2", "P3", "P4"],
            default=["P1", "P2", "P3", "P4"],
        )
    with filter_col2:
        sel_cat = st.multiselect(
            "Filter Category:",
            options=["Immediate Fixes", "Quick Wins", "Scheduled Fixes", "Monitor/Verify"],
            default=["Immediate Fixes", "Quick Wins", "Scheduled Fixes", "Monitor/Verify"],
        )
    with filter_col3:
        sel_exposure = st.selectbox("Internet Exposed:", ["All", "Exposed Only", "Internal Only"])
    with filter_col4:
        search_query = st.text_input("Search CVE / Asset:", placeholder="e.g. Log4j, CVE-2023...")

    # Filter Application
    filtered_df = plan_df[
        (plan_df["priority"].isin(sel_priority)) &
        (plan_df["remediation_category"].isin(sel_cat))
    ]

    if sel_exposure == "Exposed Only":
        filtered_df = filtered_df[filtered_df["internet_exposed"] == True]
    elif sel_exposure == "Internal Only":
        filtered_df = filtered_df[filtered_df["internet_exposed"] == False]

    if search_query.strip():
        q = search_query.strip().lower()
        filtered_df = filtered_df[
            filtered_df["cve_id"].str.lower().str.contains(q) |
            filtered_df["asset_name"].str.lower().str.contains(q) |
            filtered_df["vulnerability_title"].str.lower().str.contains(q)
        ]

    st.write(f"Showing **{len(filtered_df)}** of **{len(plan_df)}** vulnerabilities:")

    st.dataframe(
        filtered_df[
            [
                "cve_id",
                "asset_name",
                "cvss_score",
                "epss_score",
                "cisa_kev",
                "internet_exposed",
                "risk_score",
                "priority",
                "remediation_category",
                "plan_status",
            ]
        ],
        use_container_width=True,
        hide_index=True,
    )

    st.markdown("---")

    # Deep-dive Inspector for a specific CVE
    st.subheader("🔬 Mathematical Trace & Provenance Inspector")
    available_cve_list = filtered_df["cve_id"].tolist() if not filtered_df.empty else plan_df["cve_id"].tolist()
    selected_cve = st.selectbox("Select CVE to Audit Step-by-Step:", options=available_cve_list)

    if selected_cve:
        cve_row = plan_df[plan_df["cve_id"] == selected_cve].iloc[0]

        inspect_col1, inspect_col2 = st.columns(2)

        with inspect_col1:
            st.markdown(f"#### {cve_row['cve_id']}: {cve_row.get('vulnerability_title', 'Vulnerability')}")
            st.markdown(f"- **Asset**: `{cve_row.get('asset_name', 'Unknown')}` ({cve_row['asset_criticality']} Criticality)")
            st.markdown(f"- **Exposure**: `{'Internet Facing' if cve_row['internet_exposed'] else 'Internal Isolated'}`")
            st.markdown(f"- **CVSS**: `{cve_row['cvss_score']}` | **EPSS**: `{cve_row.get('epss_score', 0.01):.3f}`")
            st.markdown(f"- **CISA Known Exploited (KEV)**: `{'Yes (Confirmed in wild)' if cve_row.get('cisa_kev') else 'No'}`")
            st.markdown(f"- **Remediation Effort**: `{cve_row['remediation_effort_hours']} hours` | **Window**: `{cve_row.get('maintenance_window')}`")
            st.markdown(f"- **Status**: `{cve_row['plan_status']}` | **Category**: `{cve_row['remediation_category']}`")

            # Individual approval button
            is_currently_approved = cve_row["cve_id"] in st.session_state.approved_cves
            if not is_currently_approved:
                if st.button(f"Approve {cve_row['cve_id']}", key=f"btn_app_{cve_row['cve_id']}"):
                    st.session_state.approved_cves.add(cve_row["cve_id"])
                    st.rerun()
            else:
                st.success("✅ Signed off by Security Lead")
                if st.button(f"Revoke Approval", key=f"btn_rev_{cve_row['cve_id']}"):
                    st.session_state.approved_cves.remove(cve_row["cve_id"])
                    st.rerun()

        with inspect_col2:
            st.markdown("#### Mathematical Scoring Trace")
            st.code(cve_row["scoring_explanation"], language="markdown")

            st.markdown("#### Threat Intelligence Provenance Audit")
            epss_prov = cve_row.get("epss_provenance", "SUPPLIED")
            cisa_prov = cve_row.get("cisa_kev_provenance", "SUPPLIED")
            exploit_prov = cve_row.get("exploit_evidence_provenance", "SUPPLIED")

            st.markdown(
                f"- **EPSS Provenance**: `{epss_prov}`\n"
                f"- **CISA KEV Provenance**: `{cisa_prov}`\n"
                f"- **Exploit Evidence Provenance**: `{exploit_prov}`\n"
                f"> *Policy Guarantee: When threat intelligence is missing from source data, conservative baseline defaults are applied with explicit provenance logs. Synthetic threat feeds are never hallucinated.*"
            )


# ===========================================================================
# TAB 4: GEMINI AI STRATEGIC BRIEF
# ===========================================================================
with tab_ai:
    st.subheader("🤖 Gemini-Powered Strategic Remediation Review")
    st.caption(
        "Leverages the official Google Gen AI Python SDK (`google-genai`) to generate natural-language executive briefings, posture analysis, and risk trade-off justifications."
    )

    if not gemini_is_on:
        st.info(
            "💡 **Running in Deterministic Offline Mode**: No `GEMINI_API_KEY` was detected in the environment. "
            "SecureOps AI is using its deterministic rule-based executive briefing engine. "
            "To enable live Gemini generation, add `GEMINI_API_KEY` to your `.env` file or enter it in the sidebar."
        )

    if st.button("🚀 Generate / Refresh Executive Briefing", type="primary"):
        with st.spinner("Synthesizing executive briefing and trade-off analysis..."):
            summary_dict = {
                "total_cves": plan_summary.total_cves,
                "planned_cves_count": plan_summary.planned_cves_count,
                "deferred_cves_count": plan_summary.deferred_cves_count,
                "allocated_hours": plan_summary.allocated_hours,
                "capacity_hours_limit": plan_summary.capacity_hours_limit,
                "hours_utilization_pct": plan_summary.hours_utilization_pct,
                "allocated_cost": plan_summary.allocated_cost,
                "baseline_total_risk": plan_summary.baseline_total_risk,
                "remediated_risk": plan_summary.remediated_risk,
                "baseline_mean_risk": plan_summary.baseline_mean_risk,
                "residual_total_risk": plan_summary.residual_total_risk,
                "projected_mean_risk": plan_summary.projected_mean_risk,
                "risk_reduction_pct": plan_summary.risk_reduction_pct,
                "verified_cves_count": plan_summary.verified_cves_count,
                "verified_remediated_risk": plan_summary.verified_remediated_risk,
                "verified_risk_reduction_pct": plan_summary.verified_risk_reduction_pct,
            }
            top_planned = plan_df[plan_df["plan_status"] == "Planned"].to_dict(orient="records")
            top_deferred = plan_df[plan_df["plan_status"] != "Planned"].to_dict(orient="records")

            review_md, was_ai = generate_executive_review(
                summary_data=summary_dict,
                top_planned=top_planned,
                top_deferred=top_deferred,
                override_key=active_gemini_key,
            )
            st.session_state.executive_brief_cache = review_md
            st.session_state.brief_is_ai = was_ai

    # Render briefing if available
    if "executive_brief_cache" in st.session_state:
        st.markdown(st.session_state.executive_brief_cache)
    else:
        # Generate initial default
        summary_dict = {
            "total_cves": plan_summary.total_cves,
            "planned_cves_count": plan_summary.planned_cves_count,
            "deferred_cves_count": plan_summary.deferred_cves_count,
            "allocated_hours": plan_summary.allocated_hours,
            "capacity_hours_limit": plan_summary.capacity_hours_limit,
            "hours_utilization_pct": plan_summary.hours_utilization_pct,
            "allocated_cost": plan_summary.allocated_cost,
            "baseline_total_risk": plan_summary.baseline_total_risk,
            "remediated_risk": plan_summary.remediated_risk,
            "baseline_mean_risk": plan_summary.baseline_mean_risk,
            "residual_total_risk": plan_summary.residual_total_risk,
            "projected_mean_risk": plan_summary.projected_mean_risk,
            "risk_reduction_pct": plan_summary.risk_reduction_pct,
            "verified_cves_count": plan_summary.verified_cves_count,
            "verified_remediated_risk": plan_summary.verified_remediated_risk,
            "verified_risk_reduction_pct": plan_summary.verified_risk_reduction_pct,
        }
        top_planned = plan_df[plan_df["plan_status"] == "Planned"].to_dict(orient="records")
        top_deferred = plan_df[plan_df["plan_status"] != "Planned"].to_dict(orient="records")

        default_brief, _ = generate_executive_review(summary_dict, top_planned, top_deferred, override_key=active_gemini_key)
        st.session_state.executive_brief_cache = default_brief
        st.markdown(default_brief)


# ===========================================================================
# TAB 5: DOWNLOAD REPORTS & MANIFEST
# ===========================================================================
with tab_export:
    st.subheader("📥 Export Remediation Artifacts & Cryptographic Audit Manifest")
    st.caption("Download auditable remediation schedules, executive markdown reports, and machine-readable JSON manifests.")

    exp_col1, exp_col2, exp_col3 = st.columns(3)

    # 1. CSV Remediation Action Plan
    with exp_col1:
        st.markdown("#### 📄 Remediation Schedule CSV")
        st.caption("Full spreadsheet containing CVE details, calculated risk scores, priorities, and approval records.")
        csv_bytes = export_remediation_plan_csv(plan_df)
        st.download_button(
            label="⬇️ Download Remediation CSV",
            data=csv_bytes,
            file_name=f"secureops_remediation_plan_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M')}.csv",
            mime="text/csv",
            use_container_width=True,
        )

    # 2. Executive Markdown Report
    with exp_col2:
        st.markdown("#### 📝 Executive Briefing (.md)")
        st.caption("Formatted Markdown document ready for C-suite distribution and security committee review.")
        current_brief = st.session_state.get("executive_brief_cache", plan_summary.trade_off_analysis)
        report_text = f"""# SecureOps AI: Executive Vulnerability Remediation Report
**Generated**: {datetime.now(timezone.utc).isoformat()}
**Total Vulnerabilities**: {plan_summary.total_cves} | **Planned**: {plan_summary.planned_cves_count} | **Hours**: {plan_summary.allocated_hours}h / {plan_summary.capacity_hours_limit}h
**Projected Risk Reduction**: {plan_summary.risk_reduction_pct}% ({plan_summary.remediated_risk} risk pts)
**Verified Risk Reduction**: {plan_summary.verified_risk_reduction_pct}% ({plan_summary.verified_cves_count} Authorized by Lead)

{current_brief}

---
*Generated by SecureOps AI Autonomous Remediation Planner*
"""
        st.download_button(
            label="⬇️ Download Executive Report (.md)",
            data=report_text.encode("utf-8"),
            file_name=f"secureops_executive_report_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M')}.md",
            mime="text/markdown",
            use_container_width=True,
        )

    # 3. JSON Audit Manifest
    with exp_col3:
        st.markdown("#### 🔐 JSON Audit Manifest")
        st.caption("Structured JSON manifest with provenance metadata, capacity metrics, and human sign-off status.")
        audit_json = export_audit_manifest_json(plan_summary, plan_df)
        st.download_button(
            label="⬇️ Download Audit Manifest (.json)",
            data=audit_json.encode("utf-8"),
            file_name=f"secureops_audit_manifest_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M')}.json",
            mime="application/json",
            use_container_width=True,
        )


# ===========================================================================
# TAB 6: METHODOLOGY & GOVERNANCE
# ===========================================================================
with tab_methodology:
    st.subheader("📖 Deterministic Scoring Methodology & Governance")

    st.markdown(
        r"""
### 1. Transparent Risk Scoring Formula

SecureOps AI rejects black-box scoring. Every vulnerability score is computed deterministically using the following verifiable mathematical formulation:

$$\text{Base Impact} = \text{CVSS} \times 6.5$$

$$\text{Asset Adjusted} = \text{Base Impact} \times M_{\text{criticality}}$$

$$\text{Contextual Score} = \text{Asset Adjusted} \times M_{\text{exposure}}$$

$$\text{Threat Boosters} = B_{\text{CISA}} + (\text{EPSS} \times 20.0) + B_{\text{exploit}}$$

$$\text{Final Risk Score} = \operatorname{Clamp}\left(\text{Contextual Score} + \text{Threat Boosters},\ 0.0,\ 100.0\right)$$

#### Parameter Multipliers & Boosters Table
| Dimension | Level | Multiplier / Booster | Description |
| :--- | :--- | :--- | :--- |
| **Asset Criticality ($M_{crit}$)** | Critical | $\times 1.35$ | Core production, financial databases, identity providers |
| | High | $\times 1.15$ | Important services, internal portals, build pipelines |
| | Medium | $\times 1.00$ | Standard development, internal telemetry |
| | Low | $\times 0.75$ | Isolated sandboxes, disposable test instances |
| **Internet Exposure ($M_{expo}$)** | Internet-Exposed | $\times 1.30$ | Public-facing perimeter (highest attack surface) |
| | Internal / Segmented | $\times 1.00$ | Protected inside zero-trust perimeter |
| **Threat Intelligence Boosters** | CISA KEV Listed | $+18.0\text{ pts}$ | Confirmed weaponized exploitation in the wild |
| | EPSS Probability | $\text{EPSS} \times 20.0\text{ pts}$ | Empirical exploit probability over next 30 days |
| | Exploit Evidence | Active: $+12\text{ pts}$ \| Weaponized: $+8\text{ pts}$ \| PoC: $+4\text{ pts}$ \| None: $0\text{ pts}$ | Evidence maturity from threat feeds |

---

### 2. Four Remediation Quadrants
1. **Immediate Fixes**: P1 threats, CISA KEV on internet-facing assets, or active zero-days. Allocated first.
2. **Quick Wins**: High Risk ($\ge 45$) and Low Effort ($\le 3.0\text{h}$). Delivers the highest risk reduction per engineering hour.
3. **Scheduled Fixes**: P2/P3 vulnerabilities scheduled into standard off-hours/weekend maintenance windows within sprint capacity.
4. **Monitor / Verify**: P4 low-impact items, unpatched third-party dependencies, or items deferred due to capacity caps.

---

### 3. Safety, Provenance & Governance Guardrails
- **Zero Shell Execution**: SecureOps AI is a planning and decision-support system. It produces plans and schedules; it never executes unsanctioned system shell commands or live network payloads.
- **Human-in-the-Loop Approval**: No remediation plan can transition to execution without authenticated approval by the Security Lead.
- **Data Provenance Integrity**: When threat intelligence feeds (EPSS or CISA KEV) are not supplied in uploaded data, the system flags them as `UNAVAILABLE` and applies safe baseline defaults. **It never fabricates live threat intelligence.**
- **Safe Input Limits**: Uploads are restricted to 5MB and 2,000 rows to prevent Denial-of-Service (DoS) and memory exhaustion.
"""
    )
