"""Google Gen AI Python SDK integration for SecureOps AI.

Provides natural language executive briefing and plan review using Gemini when
GEMINI_API_KEY is configured, with seamless offline deterministic fallback when
API key is absent or unavailable.
"""

from __future__ import annotations
import os
from typing import Any, Dict, List, Optional, Tuple
from dotenv import load_dotenv

# Load local environment variables if available
load_dotenv()


def get_api_key(override_key: Optional[str] = None) -> Optional[str]:
    """Retrieve GEMINI_API_KEY from parameter override or system environment."""
    key = override_key or os.getenv("GEMINI_API_KEY", "")
    key = key.strip()
    # Reject placeholder dummy values
    if not key or key in {"your_gemini_api_key_here", "None", "undefined"}:
        return None
    return key


def is_gemini_available(override_key: Optional[str] = None) -> bool:
    """Check whether a valid Gemini API key is configured."""
    return get_api_key(override_key) is not None


def mask_api_key(key: Optional[str]) -> str:
    """Mask key for safe UI status display without leaking secret bytes."""
    if not key:
        return "Not Configured"
    if len(key) <= 8:
        return "****"
    return f"{key[:4]}...{key[-4:]}"


def build_offline_fallback_review(
    summary_data: Dict[str, Any],
    top_planned: List[Dict[str, Any]],
    top_deferred: List[Dict[str, Any]],
) -> str:
    """Generate a rich, deterministic executive security briefing when Gemini is offline."""
    planned_str = ""
    for idx, cve in enumerate(top_planned[:5], 1):
        planned_str += (
            f"- **{cve.get('cve_id')}** ({cve.get('asset_name', 'Asset')}): "
            f"Risk {cve.get('risk_score', 0):.1f} | Category: *{cve.get('remediation_category', 'Planned')}* | "
            f"Effort: {cve.get('remediation_effort_hours', 1):.1f}h | Window: {cve.get('maintenance_window', 'Off-Hours')}\n"
        )

    deferred_str = ""
    for idx, cve in enumerate(top_deferred[:4], 1):
        deferred_str += (
            f"- **{cve.get('cve_id')}** ({cve.get('asset_name', 'Asset')}): "
            f"Risk {cve.get('risk_score', 0):.1f} | Deferral Reason: *{cve.get('deferral_reason', 'Capacity cap')}*\n"
        )

    return f"""### 🛡️ SecureOps AI Remediation Advisory & Plan Review
*(Operating Mode: Deterministic Rule-Based Fallback Engine)*

#### 1. Executive Summary & Posture Impact
The proposed remediation sprint addresses **{summary_data.get('planned_cves_count', 0)} of {summary_data.get('total_cves', 0)}** detected vulnerabilities, committing **{summary_data.get('allocated_hours', 0.0):.1f} hours** ({summary_data.get('hours_utilization_pct', 0.0):.1f}% of sprint capacity) with an estimated operational cost of **${summary_data.get('allocated_cost', 0):,.2f}**.
- **Projected Risk Reduction**: **{summary_data.get('risk_reduction_pct', 0.0):.1f}%** (eliminating {summary_data.get('remediated_risk', 0.0):.1f} risk points; dropping mean risk from **{summary_data.get('baseline_mean_risk', 0.0):.1f} to {summary_data.get('projected_mean_risk', 0.0):.1f} / 100**).
- **Verified Risk Reduction**: **{summary_data.get('verified_risk_reduction_pct', 0.0):.1f}%** ({summary_data.get('verified_cves_count', 0)} fixes authorized by Lead; eliminating {summary_data.get('verified_remediated_risk', 0.0):.1f} risk points).

#### 2. Key Remediations Scheduled (Immediate Fixes & Quick Wins)
{planned_str if planned_str else "- No items currently allocated in this cycle."}

#### 3. Strategic Trade-Off Analysis & Deferred Items
A total of **{summary_data.get('deferred_cves_count', 0)} vulnerabilities** were deferred into monitoring status:
{deferred_str if deferred_str else "- Zero items deferred."}

**Trade-Off Rationale**:
The algorithm prioritized known actively exploited threats (CISA KEV) and Internet-exposed critical assets before allocating bandwidth to Quick Wins. Deferred items represent lower threat-probability vectors or items blocked by missing vendor patches.

#### 4. Mandatory Human Oversight & Sign-off
> ⚠️ **Zero Automated Shell Execution Policy**: This plan will **NOT** automatically deploy patches or modify infrastructure. All changes require formal approval from the IT Security Operations Lead.
"""


def generate_executive_review(
    summary_data: Dict[str, Any],
    top_planned: List[Dict[str, Any]],
    top_deferred: List[Dict[str, Any]],
    override_key: Optional[str] = None,
) -> Tuple[str, bool]:
    """Generate executive plan review using official Google Gen AI SDK or fallback.

    Returns:
      Tuple of (review_markdown_text, is_ai_generated: bool)
    """
    api_key = get_api_key(override_key)

    if not api_key:
        return build_offline_fallback_review(summary_data, top_planned, top_deferred), False

    # Attempt to query Gemini via official google-genai SDK
    try:
        from google import genai

        client = genai.Client(api_key=api_key)

        prompt = f"""
You are a Principal Cybersecurity Strategist and Lead Remediation Architect reviewing an automated vulnerability remediation plan.
Analyze the following remediation metrics and provide an authoritative, executive-level review in structured Markdown.

Plan Summary Metrics:
- Total Vulnerabilities Assessed: {summary_data.get('total_cves')}
- Planned for Remediation: {summary_data.get('planned_cves_count')}
- Deferred to Monitoring: {summary_data.get('deferred_cves_count')}
- Total Engineering Hours Allocated: {summary_data.get('allocated_hours')}h (Capacity Limit: {summary_data.get('capacity_hours_limit')}h, Utilization: {summary_data.get('hours_utilization_pct')}%)
- Estimated Remediation Cost: ${summary_data.get('allocated_cost'):,.2f}
- Baseline Total Risk: {summary_data.get('baseline_total_risk')} (Mean: {summary_data.get('baseline_mean_risk')})
- Residual Total Risk: {summary_data.get('residual_total_risk')} (Mean: {summary_data.get('projected_mean_risk')})
- Projected Risk Reduction: {summary_data.get('risk_reduction_pct')}% ({summary_data.get('remediated_risk', 0.0)} risk pts eliminated)
- Verified Risk Reduction (Human Signed-off): {summary_data.get('verified_risk_reduction_pct', 0.0)}% ({summary_data.get('verified_cves_count', 0)} authorized fixes)

Top Planned Vulnerabilities:
{top_planned[:5]}

Top Deferred Vulnerabilities:
{top_deferred[:4]}

Please provide:
1. Executive Assessment & Risk Posture (highlight risk reduction % and posture improvement).
2. Defense-in-Depth Analysis of Scheduled Items (why these specific CVEs matter).
3. Trade-off & Capacity Evaluation (justify what was postponed and evaluate residual exposure).
4. Concrete Human-in-the-Loop Recommendations for the Security Engineering Lead.
Keep the tone professional, concise, actionable, and strictly adhere to safe cybersecurity operations (no reckless auto-patching).
"""

        # Using gemini-2.5-flash as the standard fast responsive model
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt,
        )

        review_text = response.text or ""
        if review_text.strip():
            header = "### 🤖 Gemini AI Executive Vulnerability Review\n*(Generated via Google Gen AI Python SDK - `gemini-2.5-flash`)*\n\n"
            return header + review_text, True

        # Fallback if empty text
        return build_offline_fallback_review(summary_data, top_planned, top_deferred), False

    except Exception as err:
        # Gracefully handle API errors, quota limits, or invalid keys
        error_msg = str(err)
        fallback = build_offline_fallback_review(summary_data, top_planned, top_deferred)
        warning_banner = (
            f"> ℹ️ *Notice: Gemini API call was attempted but encountered: {error_msg[:120]}... "
            f"Fell back seamlessly to local deterministic briefing engine.*\n\n"
        )
        return warning_banner + fallback, False
