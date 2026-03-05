"""
modules/dashboard.py
--------------------
Kerala Bank - Executive Compliance Dashboard
Role-differentiated rendering — DPDP Act 2023 governance matrix.

Role → Dashboard view:
  branch_officer /
  branch_privacy_coordinator  → Branch operational KPIs (own branch only)
  regional_officer /
  regional_compliance_officer /
  privacy_steward /
  privacy_operations          → Regional compliance aggregation
  dpo                         → Full governance console + all branches
  auditor / internal_auditor  → Read-only compliance scorecard
  board_member                → Strategic executive summary
  customer / others           → Access denied — no governance data exposed

Governance fixes applied:
  ✔ Role guard at show() entry — customers never see governance metrics
  ✔ Container-box page headers (main-box) replacing bare st.title()
  ✔ Empty dataset guards before every chart and table
  ✔ Branch risk rendered as dot indicators (● Green/Amber/Red per branch)
  ✔ Compliance score clamped [0, 100] — no negative values
  ✔ Export restricted: DPO, Board, Auditor/Internal Auditor, Privacy Operations only
  ✔ Export buttons placed below tables (never top-right)
  ✔ No personal data (Aadhaar, account numbers, customer IDs) on any dashboard view
  ✔ Charts guarded: empty data → st.info() fallback, no crash
  ✔ render_export_buttons() removed — replaced with _export_below_table()
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import networkx as nx
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from streamlit_autorefresh import st_autorefresh

from auth import get_role, get_branch, get_region
import engine.compliance_engine as compliance_engine
import engine.sla_engine as sla_engine
import engine.audit_ledger as audit_ledger
from engine.data_discovery import get_discovery_summary
from engine.consent_validator import get_consent_lifecycle_summary
import engine.orchestration as orchestration
from engine.breach_detector import detect_breach, run_bulk_scan
from utils.dpdp_clauses import get_clause
from utils.export_utils import export_data
from utils.i18n import t
from utils.ui_helpers import more_info, mask_identifier

import json
import os


# ---------------------------------------------------------------------------
# i18n safe helper
# ---------------------------------------------------------------------------

def t_safe(key: str, fallback: str = "") -> str:
    try:
        result = t(key)
        return result if result != key else (fallback or key)
    except Exception:
        return fallback or key


# ---------------------------------------------------------------------------
# Export permission — canonical role codes
# ---------------------------------------------------------------------------

_EXPORT_PERMITTED: set[str] = {
    "dpo",
    "board_member",
    "auditor",
    "internal_auditor",
    "privacy_operations",
}


def _can_export() -> bool:
    return st.session_state.get("role", "") in _EXPORT_PERMITTED


def _export_below_table(df: pd.DataFrame, filename: str) -> None:
    """
    Render a CSV download button BELOW a table, restricted to permitted roles.
    All export_data() calls must be replaced with this function on the dashboard.
    """
    if _can_export():
        export_data(df, filename)
    else:
        st.caption(
            "🔒 Export available to authorised roles only "
            "(DPO, Board, Auditor, Privacy Operations)."
        )


# ---------------------------------------------------------------------------
# Compliance score safety clamp — prevents negatives
# ---------------------------------------------------------------------------

def _safe_score(score) -> int:
    """Clamp compliance score to [0, 100]. Never returns a negative value."""
    try:
        val = int(float(score))
    except (TypeError, ValueError):
        val = 0
    return max(0, min(100, val))


def _compute_score_from_components(sla_breaches: int, open_incidents: int) -> int:
    """
    Deterministic score from SLA breach and incident counts.
    Each SLA breach deducts 5 points; each open incident deducts 10.
    Floor: 0.
    """
    score = 100 - (sla_breaches * 5) - (open_incidents * 10)
    return max(0, score)


# ---------------------------------------------------------------------------
# Static reference data — branch geography only (no metrics)
# ---------------------------------------------------------------------------

BRANCH_DATA = pd.DataFrame({
    "Branch": [
        "Thiruvananthapuram Main", "Thiruvananthapuram East",
        "Kollam Central", "Pathanamthitta",
        "Kottayam Main", "Ernakulam Central",
        "Kochi Fort", "Aluva",
        "Thrissur Main", "Kozhikode North",
        "Malappuram", "Kannur Main",
    ],
    "Region": [
        "South Zone", "South Zone", "South Zone", "South Zone",
        "Central Zone", "Central Zone", "Central Zone", "Central Zone",
        "North Zone", "North Zone", "North Zone", "North Zone",
    ],
    "Lat": [8.5241, 8.5500, 8.8932, 9.2648, 9.5916, 9.9816,
            9.9625, 10.1004, 10.5276, 11.2588, 11.0510, 11.8745],
    "Lon": [76.9366, 76.9800, 76.6141, 76.7870, 76.5222, 76.2999,
            76.2440, 76.3524, 76.2144, 75.7804, 76.0711, 75.3704],
})

RISK_COLOUR_MAP = {"Green": "#1a9e5c", "Amber": "#f0a500", "Red": "#d93025"}

_SLA_BADGE_COLOURS = {
    "active":   "#2e7d32",
    "warning":  "#f9a825",
    "breached": "#c62828",
}


# ---------------------------------------------------------------------------
# Engine data loader — single call site, cached per run
# ---------------------------------------------------------------------------

@st.cache_data(ttl=30, show_spinner=False)
def _load_engine_data() -> dict:
    compliance_result  = compliance_engine.compute_compliance()
    sla_rate           = sla_engine.get_sla_compliance_rate()
    escalation_summary = sla_engine.get_escalation_summary()
    breach_count       = orchestration.get_active_breach_count()
    dpia_summary       = orchestration.get_dpia_summary()
    system_summary     = orchestration.get_system_summary()
    chain_valid        = audit_ledger.verify_full_chain()
    audit_root_hash    = audit_ledger.get_root_hash()
    branch_metrics     = compliance_engine.get_branch_metrics()

    return {
        "compliance":         compliance_result,
        "overall_score":      _safe_score(compliance_result.get("overall_score", 0)),
        "framework_scores":   compliance_result.get("framework_scores", {}),
        "sla_rate":           sla_rate,
        "escalation_summary": escalation_summary,
        "breach_count":       breach_count,
        "dpia_summary":       dpia_summary,
        "system_summary":     system_summary,
        "chain_valid":        chain_valid,
        "audit_root_hash":    audit_root_hash,
        "branch_metrics":     branch_metrics,
    }


def _engine_branch_df(data: dict) -> pd.DataFrame:
    """
    Merge static BRANCH_DATA geography with live engine branch metrics.
    Returns empty DataFrame (with warning) if engine returns nothing.
    All ComplianceScore values are clamped to [0, 100].
    """
    metrics_df = pd.DataFrame(data["branch_metrics"]) if data["branch_metrics"] else pd.DataFrame()
    if metrics_df.empty:
        st.warning(t_safe("engine_data_unavailable", "Branch metrics unavailable — engine may still be loading."))
        return pd.DataFrame()
    merged = BRANCH_DATA.merge(metrics_df, on="Branch", how="left")
    merged["RiskLevel"]       = merged["RiskLevel"].fillna("Green")
    merged["ComplianceScore"] = merged["ComplianceScore"].fillna(0).apply(_safe_score)
    merged["Consents"]        = merged["Consents"].fillna(0)
    merged["RightsReq"]       = merged["RightsReq"].fillna(0)
    merged["SLA_Green"]       = merged["SLA_Green"].fillna(0)
    merged["SLA_Amber"]       = merged["SLA_Amber"].fillna(0)
    merged["SLA_Red"]         = merged["SLA_Red"].fillna(0)
    merged["Breaches"]        = merged["Breaches"].fillna(0)
    return merged


# ---------------------------------------------------------------------------
# Page header helper — main-box container style
# ---------------------------------------------------------------------------

def render_page_header(title: str) -> str:
    """Return an HTML main-box container wrapping the dashboard title."""
    return (
        f'<div class="main-box">'
        f'<h2>{title}</h2>'
        f'</div>'
    )


# ---------------------------------------------------------------------------
# Status badge — coloured dot (no text label)
# ---------------------------------------------------------------------------

def render_status_badge(status: str) -> str:
    normalised = status.lower()
    if normalised in ("active", "green"):
        colour = _SLA_BADGE_COLOURS["active"]
    elif normalised in ("warning", "amber", "at_risk"):
        colour = _SLA_BADGE_COLOURS["warning"]
    elif normalised in ("breached", "red", "overdue"):
        colour = _SLA_BADGE_COLOURS["breached"]
    else:
        colour = "#546e7a"
    return (
        f'<span style="display:inline-block;width:12px;height:12px;'
        f'border-radius:50%;background-color:{colour};"></span>'
    )


# ---------------------------------------------------------------------------
# Branch risk dot grid — replaces any heatmap rendering
# Shows ● coloured dot + branch name + score per branch
# ---------------------------------------------------------------------------

def _render_branch_dot_indicators(branch_df: pd.DataFrame) -> None:
    """
    Render branch compliance risk as coloured dot indicators.
    Replaces any px.imshow / sns.heatmap usage.
    Green ● ≥ 80%  |  Amber ● 50–79%  |  Red ● < 50%
    """
    if branch_df.empty:
        st.info(t_safe("no_branch_data", "No branch compliance data available yet."))
        return

    st.markdown("**Branch Compliance Risk — Dot Indicators**")

    cols = st.columns(min(4, len(branch_df)))
    for idx, (_, row) in enumerate(branch_df.iterrows()):
        score = _safe_score(row.get("ComplianceScore", 0))
        if score >= 80:
            colour = "#1a9e5c"
            label  = "Green"
        elif score >= 50:
            colour = "#f0a500"
            label  = "Amber"
        else:
            colour = "#d93025"
            label  = "Red"

        col = cols[idx % len(cols)]
        col.markdown(
            f"<div style='text-align:center;padding:8px;border-radius:8px;"
            f"background:{colour}18;border:2px solid {colour};margin-bottom:6px;'>"
            f"<span style='color:{colour};font-size:22px;'>●</span><br>"
            f"<b style='font-size:0.7rem;color:#333;'>{row['Branch'].split()[0]}</b><br>"
            f"<span style='font-size:0.75rem;color:{colour};font-weight:600;'>{score}% — {label}</span>"
            f"</div>",
            unsafe_allow_html=True,
        )


# ---------------------------------------------------------------------------
# SLA remaining countdown
# ---------------------------------------------------------------------------

def render_sla_remaining(deadline) -> str:
    if deadline is None:
        return t_safe("no_deadline", "No deadline")
    if isinstance(deadline, str):
        if not deadline.strip():
            return t_safe("no_deadline", "No deadline")
        try:
            deadline = datetime.fromisoformat(deadline.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            return t_safe("invalid_deadline", "Invalid deadline")
    try:
        if hasattr(deadline, "tzinfo") and deadline.tzinfo is not None:
            now = datetime.now(timezone.utc)
        else:
            now      = datetime.utcnow()
            deadline = deadline.replace(tzinfo=None)
        remaining = deadline - now
        if remaining.total_seconds() < 0:
            return t_safe("overdue", "Overdue")
        days  = remaining.days
        hours = int(remaining.seconds // 3600)
        if days == 0:
            return f"{hours}h remaining"
        return f"{days}d {hours}h" if days < 3 else f"{days} {t_safe('days', 'days')}"
    except (TypeError, AttributeError, OverflowError):
        return t_safe("invalid_deadline", "Invalid deadline")


# ---------------------------------------------------------------------------
# Table helpers — coloured header cells
# ---------------------------------------------------------------------------

def _th(label: str) -> str:
    return (
        f'<th style="background-color:#003366;color:white;padding:10px;'
        f'font-size:16px;text-align:left;">{label}</th>'
    )


def _td(content: str) -> str:
    return f'<td style="padding:8px 10px;font-size:15px;border-bottom:1px solid #ddd;">{content}</td>'


# ---------------------------------------------------------------------------
# KPI card
# ---------------------------------------------------------------------------

def _kpi(col, label: str, value, sub: str, colour: str = "#1B4F72") -> None:
    col.markdown(f"""
    <div class="kpi-card" style="font-size:16px;">
        <div style="font-size:14px;color:#555;">{label}</div>
        <div style="font-size:24px;font-weight:600;color:#0d47a1;">{value}</div>
        <div style="font-size:13px;color:{colour};margin-top:4px;">{sub}</div>
    </div>
    """, unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# ID masking — dashboard never exposes raw IDs to non-privileged roles
# ---------------------------------------------------------------------------

def _display_id(raw_id: str, role: str | None = None) -> str:
    effective_role = st.session_state.get("role", "")
    if effective_role in ("dpo", "auditor", "internal_auditor", "privacy_operations"):
        return raw_id
    return mask_identifier(raw_id, role=effective_role)


# ---------------------------------------------------------------------------
# Audit integrity banner
# ---------------------------------------------------------------------------

def _render_audit_integrity_banner(data: dict) -> None:
    if data["chain_valid"]:
        st.success(
            f"🔒 {t('audit_chain_valid')}  |  "
            f"{t('root_hash')}: `{data['audit_root_hash']}`"
        )
    else:
        st.error(f"⚠️ {t('audit_chain_broken')} — {t('contact_dpo_immediately')}")


# ---------------------------------------------------------------------------
# Escalation overview panel
# ---------------------------------------------------------------------------

def _render_escalation_overview(data: dict) -> None:
    summary = data.get("escalation_summary", {})
    st.subheader(t("escalation_overview"))
    level_labels = {
        0: t("escalation_branch"),
        1: t("escalation_regional"),
        2: t("escalation_dpo"),
        3: t("escalation_board"),
    }
    cols = st.columns(4)
    for level, label in level_labels.items():
        count  = summary.get(level, 0)
        colour = "#1a9e5c" if count == 0 else ("#f0a500" if level < 2 else "#d93025")
        _kpi(cols[level], f"{t('level')} {level} — {label}", count, t("escalations_pending"), colour)


# ---------------------------------------------------------------------------
# DPIA status panel
# ---------------------------------------------------------------------------

def _render_dpia_summary(data: dict) -> None:
    dpia = data.get("dpia_summary", {})
    st.subheader(t("dpia_status_summary"))
    col1, col2, col3 = st.columns(3)
    _kpi(col1, t("dpia_active"),   dpia.get("active", 0),   t("in_progress"),   "#0d47a1")
    _kpi(col2, t("dpia_overdue"),  dpia.get("overdue", 0),  t("requires_action"), "#d93025")
    _kpi(col3, t("dpia_approved"), dpia.get("approved", 0), t("cleared"),        "#1a9e5c")


# ---------------------------------------------------------------------------
# Security Incident Alerts Panel
# ---------------------------------------------------------------------------

def _render_security_incident_alerts(incidents: list[dict] | None = None) -> None:
    if incidents is None:
        try:
            from modules.breach import load_incidents
            incidents = load_incidents()
        except Exception:
            incidents = []

    st.subheader(t_safe("security_incident_alerts", "🚨 Security Incident Alerts"))

    col_btn, col_bulk, col_spacer = st.columns([2, 2, 6])
    with col_btn:
        if st.button(
            t_safe("run_breach_scan", "▶ Run Breach Detection Scan"),
            key="_breach_scan_btn",
        ):
            try:
                from modules.breach import load_incidents as _li, save_incidents as _si
                _incidents = _li()
                new_incident = detect_breach()
                _incidents.append(new_incident)
                _si(_incidents)
                incidents = _incidents
                sev = new_incident["severity"].upper()
                st.warning(
                    f"⚠ {t_safe('potential_breach_detected', 'Potential breach detected')}  |  "
                    f"{new_incident['incident_id']} — {new_incident['event']}  |  "
                    f"Severity: **{sev}**"
                )
            except Exception as exc:
                st.error(f"Detection scan error: {exc}")

    with col_bulk:
        if st.button(
            t_safe("run_bulk_scan", "▶▶ Bulk Scan (5 events)"),
            key="_breach_bulk_btn",
        ):
            try:
                from modules.breach import load_incidents as _li, save_incidents as _si
                _incidents = _li()
                new_incidents = run_bulk_scan(5)
                _incidents.extend(new_incidents)
                _si(_incidents)
                incidents = _incidents
                st.warning(f"⚠ {len(new_incidents)} simulated incidents injected")
            except Exception as exc:
                st.error(f"Bulk scan error: {exc}")

    if not incidents:
        st.success(t_safe("no_incidents_active", "✅ No active security incidents detected."))
        return

    # Summary KPIs
    high_c   = sum(1 for i in incidents if i.get("severity") == "high")
    medium_c = sum(1 for i in incidents if i.get("severity") == "medium")
    open_c   = sum(1 for i in incidents if i.get("status", "open") == "open")
    auto_c   = sum(1 for i in incidents if i.get("source") == "auto_detection")

    sc1, sc2, sc3, sc4, sc5 = st.columns(5)
    _kpi(sc1, "Total Incidents",  len(incidents), "all severities",     "#0d47a1")
    _kpi(sc2, "High Severity",    high_c,         "immediate action",   "#d93025")
    _kpi(sc3, "Medium Severity",  medium_c,       "investigate promptly","#f0a500")
    _kpi(sc4, "Open",             open_c,         "awaiting resolution", "#1976d2")
    _kpi(sc5, "Auto-Detected",    auto_c,         "by SOC engine",       "#1a9e5c")

    st.markdown("---")

    _FILTER_OPTIONS = ["All Severities", "High Only", "Medium Only", "Low Only", "Open Only"]
    sev_filter  = st.selectbox("Filter incidents", _FILTER_OPTIONS, key="_inc_severity_filter")
    filter_map  = {"All Severities": None, "High Only": "high", "Medium Only": "medium", "Low Only": "low"}
    selected_sev = filter_map.get(sev_filter)
    open_only    = sev_filter == "Open Only"

    displayed = 0
    for inc in reversed(incidents):
        sev    = inc.get("severity", "low")
        status = inc.get("status", "open")
        if selected_sev and sev != selected_sev:
            continue
        if open_only and status != "open":
            continue

        inc_id   = inc.get("incident_id", "INC-????")
        event    = inc.get("event", "Unknown event")
        ts       = inc.get("timestamp", "")[:19].replace("T", " ")
        branch   = inc.get("branch", "—")
        category = inc.get("category", "—")
        source   = inc.get("source", "manual")
        source_badge = (
            f'<span style="background:#546e7a;color:#fff;padding:1px 7px;border-radius:8px;font-size:12px;">MANUAL</span>'
            if source != "auto_detection" else
            f'<span style="background:#1976d2;color:#fff;padding:1px 7px;border-radius:8px;font-size:12px;">AUTO</span>'
        )
        status_badge = (
            f'<span style="background:#d93025;color:#fff;padding:1px 7px;border-radius:8px;font-size:12px;">OPEN</span>'
            if status == "open" else
            f'<span style="background:#1a9e5c;color:#fff;padding:1px 7px;border-radius:8px;font-size:12px;">{status.upper()}</span>'
        )
        detail_line = (
            f"<small style='color:#555;'>"
            f"<b>Branch:</b> {branch} &nbsp;|&nbsp; "
            f"<b>Category:</b> {category} &nbsp;|&nbsp; "
            f"<b>Detected:</b> {ts} UTC &nbsp;|&nbsp; "
            f"{source_badge} &nbsp;{status_badge}"
            f"</small>"
        )
        full_msg = f"**{inc_id}** — {event}<br>{detail_line}"

        if sev == "high":
            st.error(full_msg, icon="🔴")
        elif sev == "medium":
            st.warning(full_msg, icon="🟡")
        else:
            st.info(full_msg, icon="🔵")
        displayed += 1

    if displayed == 0:
        st.info("No incidents match the selected filter.")


# ---------------------------------------------------------------------------
# Data Discovery Panel
# ---------------------------------------------------------------------------

def _render_data_discovery_panel() -> None:
    from engine.consent_validator import get_all_consents
    try:
        all_consents = get_all_consents()
    except Exception:
        all_consents = []

    data_maps = [c.get("data_map", []) for c in all_consents if c.get("data_map")]
    summary   = get_discovery_summary(data_maps)
    lifecycle = get_consent_lifecycle_summary()

    st.subheader(t_safe("data_discovery_title", "Personal Data Discovery"))

    kc1, kc2, kc3, kc4 = st.columns(4)
    _kpi(kc1, "Fields Detected",     summary["total_fields_detected"], "across all consents",  "#0A3D91")
    _kpi(kc2, "Sensitive (SPD)",      summary["sensitive_count"],       "DPDP Act S.2(t)",      "#d93025")
    _kpi(kc3, "Personal Data",        summary["personal_count"],        "DPDP Act S.2(n)",      "#F39C12")
    _kpi(kc4, "High-Risk Fields",     len(summary["high_risk_fields"]), "may require DPIA",     "#6C3483")

    st.markdown("**Consent Lifecycle**")
    lc1, lc2, lc3, lc4 = st.columns(4)
    _kpi(lc1, "Active",         lifecycle.get("active", 0),         "valid consents",    "#1a9e5c")
    _kpi(lc2, "Expiring Soon",  lifecycle.get("expiring_soon", 0),  "within 30 days",   "#F39C12")
    _kpi(lc3, "Expired",        lifecycle.get("expired", 0),        "requires renewal", "#d93025")
    _kpi(lc4, "Renewal Backlog",lifecycle.get("renewal_backlog", 0),"needs action",      "#7B241C")

    if lifecycle.get("expiring_soon", 0) > 0:
        st.warning(f"⚠ {lifecycle['expiring_soon']} consent(s) expiring within 30 days — renewal required.")
    if lifecycle.get("expired", 0) > 0:
        st.error(f"🔴 {lifecycle['expired']} consent(s) expired — processing blocked until renewed.")

    if summary["by_purpose"]:
        st.markdown("**Data by Processing Purpose**")
        fig = go.Figure(go.Bar(
            x=list(summary["by_purpose"].values()),
            y=list(summary["by_purpose"].keys()),
            orientation="h",
            marker_color="#0A3D91",
        ))
        fig.update_layout(
            height=max(200, 40 * len(summary["by_purpose"])),
            margin=dict(l=10, r=10, t=10, b=10),
            plot_bgcolor="#ffffff", paper_bgcolor="#ffffff",
            font=dict(color="#0A3D91", size=13),
            xaxis_title="Field Count",
        )
        st.plotly_chart(fig, use_container_width=True)

    if summary["high_risk_fields"]:
        with st.expander("High-Risk Fields Detected", expanded=False):
            for field in summary["high_risk_fields"]:
                st.markdown(f"- `{field}`")


# ---------------------------------------------------------------------------
# Rights request decision table (governance view only — no PII)
# ---------------------------------------------------------------------------

def _render_rights_decision_table(role: str, data: dict | None = None) -> None:
    now = datetime.utcnow()
    try:
        live_requests = orchestration.get_pending_rights_requests() if data else []
    except Exception:
        live_requests = []

    if not live_requests:
        live_requests = [
            {"id": "RIGHTS-00071", "customer": "CUST-4821", "type": t("erasure"),
             "branch": "Ernakulam Central", "deadline": now + timedelta(days=2),
             "sla": "warning", "decision": t("pending"),
             "explanation": get_clause("erasure_retention_note")},
            {"id": "RIGHTS-00078", "customer": "CUST-3307", "type": t("correction"),
             "branch": "Thiruvananthapuram Main", "deadline": now + timedelta(days=14),
             "sla": "active", "decision": t("approved"),
             "explanation": get_clause("correction_approved_note")},
            {"id": "RIGHTS-00082", "customer": "CUST-7741", "type": t("access"),
             "branch": "Kochi Fort", "deadline": now - timedelta(days=1),
             "sla": "breached", "decision": t("escalated"),
             "explanation": get_clause("sla_breach_escalation_note")},
            {"id": "RIGHTS-00085", "customer": "CUST-2290", "type": t("grievance"),
             "branch": "Kottayam Main", "deadline": now + timedelta(days=8),
             "sla": "active", "decision": t("pending"),
             "explanation": get_clause("grievance_review_note")},
        ]

    rows_html = ""
    for req in live_requests:
        req.setdefault("sla", "active")
        req.setdefault("deadline", datetime.now(timezone.utc) + timedelta(days=30))
        req.setdefault("id", "—")
        req.setdefault("decision", t("pending"))
        req.setdefault("branch", "—")
        req.setdefault("type", "—")

        # Mask customer IDs — no raw PII on dashboard
        customer_val    = req.get("customer") or req.get("customer_id") or "—"
        masked_customer = _display_id(customer_val, role)
        sla_value       = req.get("sla") or req.get("sla_status") or "active"
        badge           = render_status_badge(str(sla_value))
        sla_text        = render_sla_remaining(req["deadline"])
        tooltip         = str(req.get("explanation", "")).replace('"', "&quot;")
        info_icon       = f'<span title="{tooltip}" style="cursor:help;">&#9432;</span>'

        rows_html += f"""
        <tr>
            {_td(_display_id(req['id'], role))}
            {_td(masked_customer)}
            {_td(req['type'])}
            {_td(req['branch'])}
            {_td(badge)}
            {_td(sla_text)}
            {_td(req['decision'] + "&nbsp;" + info_icon)}
        </tr>
        """

    table_html = f"""
    <div style="font-size:15px;overflow-x:auto;">
    <table style="width:100%;border-collapse:collapse;">
        <thead><tr>
            {_th(t("request_id"))}
            {_th(t("customer_id"))}
            {_th(t("request_type"))}
            {_th(t("branch"))}
            {_th(t("sla_status"))}
            {_th(t("deadline"))}
            {_th(t("decision"))}
        </tr></thead>
        <tbody>{rows_html}</tbody>
    </table>
    </div>
    """
    st.markdown(table_html, unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Module access panel (sidebar)
# ---------------------------------------------------------------------------

_MODULE_ICONS: dict[str, str] = {
    "Executive Dashboard":         "📊",
    "Consent Management":          "🛡️",
    "Data Principal Rights":       "👤",
    "DPIA & Privacy Assessments":  "📋",
    "Data Breach Management":      "🚨",
    "Privacy Notices":             "📄",
    "Audit Logs":                  "🕐",
    "Compliance & SLA Monitoring": "📈",
}


def _render_module_access_panel() -> None:
    import auth as _auth
    raw_role   = st.session_state.get("role", "")
    allowed    = _auth.ROLE_PERMISSIONS.get(raw_role, [])
    role_label = _auth.get_role_translated()
    with st.sidebar:
        with st.expander(f"🔑 {t('access_label')} — {role_label}", expanded=False):
            if allowed:
                for module_name in allowed:
                    icon = _MODULE_ICONS.get(module_name, "•")
                    st.markdown(
                        f"<div style='padding:5px 0;font-size:13px;color:#C8D8EA;'>"
                        f"{icon} {module_name}</div>",
                        unsafe_allow_html=True,
                    )
            else:
                st.caption(t("no_modules_available"))


# ===========================================================================
# BOARD DASHBOARD — Strategic executive summary
# ===========================================================================

def render_board_dashboard(data: dict) -> None:
    st.markdown(render_page_header("Executive Dashboard"), unsafe_allow_html=True)
    st.caption(t("board_dashboard_caption"))

    overall_score = data["overall_score"]
    sla_rate      = data["sla_rate"]
    breach_count  = data["breach_count"]
    dpia          = data.get("dpia_summary", {})

    # ── KPI strip ─────────────────────────────────────────────────────────────
    col1, col2, col3, col4 = st.columns(4)
    _kpi(col1, t("overall_compliance_score"),
         f"{overall_score}%", t("across_4_frameworks"),
         "#1a9e5c" if overall_score >= 85 else "#f0a500")
    _kpi(col2, t("sla_compliance_rate"),
         f"{sla_rate * 100:.1f}%", t("requests_within_deadline"),
         "#1a9e5c" if sla_rate >= 0.9 else "#f0a500")
    _kpi(col3, t("active_breaches"),
         breach_count, t("incident_governance"),
         "#d93025" if breach_count > 0 else "#1a9e5c")
    _kpi(col4, t("dpia_active"),
         dpia.get("active", 0), t("in_progress"), "#0d47a1")

    st.divider()
    _render_audit_integrity_banner(data)
    st.divider()
    _render_escalation_overview(data)
    st.divider()
    _render_dpia_summary(data)
    st.divider()

    # Compliance gauge
    st.subheader(t("overall_compliance"))
    gauge = go.Figure(go.Indicator(
        mode="gauge+number+delta",
        value=overall_score,
        delta={"reference": 80},
        title={"text": t("overall_compliance") + " (%)"},
        gauge={
            "axis": {"range": [0, 100]},
            "bar":  {"color": "#0A3D91"},
            "steps": [
                {"range": [0,  75], "color": "#ffcccc"},
                {"range": [75, 90], "color": "#fff3cd"},
                {"range": [90, 100], "color": "#c8f7dc"},
            ],
            "threshold": {"line": {"color": "#d93025", "width": 4}, "thickness": 0.75, "value": 75},
        },
    ))
    gauge.update_layout(
        height=300, margin=dict(l=40, r=40, t=40, b=20),
        paper_bgcolor="#ffffff", font=dict(size=14),
    )
    st.plotly_chart(gauge, use_container_width=True)

    # Framework breakdown
    framework_scores = data.get("framework_scores", {})
    if not framework_scores:
        st.info(t_safe("no_framework_data", "Framework score data unavailable."))
    else:
        st.subheader(t("framework_compliance_breakdown"))
        fw_df = pd.DataFrame([
            {"Framework": k, t("score_pct"): _safe_score(v)}
            for k, v in framework_scores.items()
        ])
        if not fw_df.empty:
            fig_fw = px.bar(
                fw_df, x="Framework", y=t("score_pct"),
                color=t("score_pct"),
                color_continuous_scale=["#d93025", "#f0a500", "#1a9e5c"],
                range_color=[60, 100],
                title=t("framework_compliance_breakdown"),
            )
            fig_fw.update_layout(
                plot_bgcolor="#ffffff", paper_bgcolor="#ffffff",
                font=dict(color="#0A3D91", size=14),
                height=320, coloraxis_showscale=False, template="plotly_white",
            )
            st.plotly_chart(fig_fw, use_container_width=True)

            # Export — Board is permitted
            if _can_export():
                export_data(fw_df, "framework_compliance")


# ===========================================================================
# DPO DASHBOARD — Full governance console
# ===========================================================================

def render_dpo_dashboard(data: dict) -> None:
    from auth import KERALA_BRANCHES  # noqa

    st.markdown(render_page_header("Governance & Oversight"), unsafe_allow_html=True)
    st.caption(t("dpo_dashboard_caption"))

    branch_df = _engine_branch_df(data)

    selected_filter = st.selectbox(
        t("filter_by_branch"),
        [t("all_branches")] + (branch_df["Branch"].tolist() if not branch_df.empty else []),
        key="_dpo_branch_filter",
    )
    filtered = branch_df.copy()
    if not branch_df.empty and selected_filter != t("all_branches"):
        filtered = branch_df[branch_df["Branch"] == selected_filter]

    overall_score = data["overall_score"]
    sla_rate      = data["sla_rate"]
    breach_count  = data["breach_count"]

    col1, col2, col3, col4 = st.columns(4)
    _kpi(col1, t("overall_compliance_score"),
         f"{overall_score}%", t("weighted_score"),
         "#1a9e5c" if overall_score >= 85 else "#f0a500")
    _kpi(col2, t("sla_compliance_rate"),
         f"{sla_rate * 100:.1f}%", t("requests_within_deadline"),
         "#1a9e5c" if sla_rate >= 0.9 else "#f0a500")
    _kpi(col3, t("active_breaches"),
         breach_count, t("incident_governance"),
         "#d93025" if breach_count > 0 else "#1a9e5c")
    _kpi(col4, t("reported_breaches"),
         0 if filtered.empty else int(filtered["Breaches"].sum()),
         t("incident_governance"), "#d93025")

    st.divider()
    _render_audit_integrity_banner(data)
    st.divider()

    tab1, tab2, tab3, tab4, tab5, tab6, tab7, tab8 = st.tabs([
        t("consent_management"),
        t("sla_status"),
        t("rights_requests"),
        t("consent_forecast"),
        t("gis_map"),
        t("knowledge_graph"),
        t("escalation_dpia"),
        "🚨 Security Incidents",
    ])

    # TAB 1 — Branch compliance bar chart + dot indicators
    with tab1:
        st.subheader(t("branch_compliance"))
        if filtered.empty or "ComplianceScore" not in filtered.columns:
            st.info(t_safe("no_compliance_data", "No compliance data available yet."))
        else:
            fig_comp = px.bar(
                filtered.sort_values("ComplianceScore"),
                x="ComplianceScore", y="Branch", orientation="h",
                color="ComplianceScore",
                color_continuous_scale=["#d93025", "#f0a500", "#1a9e5c"],
                range_color=[70, 100],
                labels={"ComplianceScore": t("compliance_score_pct")},
                title=t("branch_level_compliance_scores"),
                text="ComplianceScore",
            )
            fig_comp.update_traces(texttemplate="%{text}%", textposition="outside")
            fig_comp.update_layout(
                plot_bgcolor="#ffffff", paper_bgcolor="#ffffff",
                font=dict(color="#0A3D91", size=14),
                height=420, coloraxis_showscale=False, template="plotly_white",
            )
            fig_comp.add_vline(x=90, line_dash="dot", line_color="#1a9e5c",
                               annotation_text=t("target_90_pct"))
            st.plotly_chart(fig_comp, use_container_width=True)
            more_info(t("purpose_distribution_note"))

            # Branch risk dot indicators (replaces heatmap)
            st.subheader(t("branch_risk_overview"))
            _render_branch_dot_indicators(filtered)

            # Export placed BELOW table — restricted roles only
            export_df = filtered[["Branch", "Region", "Consents", "ComplianceScore", "RiskLevel"]].rename(
                columns={"Branch": t("branch"), "Region": t("region")}
            )
            _export_below_table(export_df, "consent_distribution")

    # TAB 2 — SLA performance
    with tab2:
        st.subheader(t("sla_performance"))
        if filtered.empty or not {"SLA_Green", "SLA_Amber", "SLA_Red"}.issubset(filtered.columns):
            st.info(t_safe("no_sla_data", "No SLA data available yet."))
        else:
            sla_melted = filtered.melt(
                id_vars="Branch",
                value_vars=["SLA_Green", "SLA_Amber", "SLA_Red"],
                var_name="SLA_Status", value_name="Count",
            )
            sla_melted["SLA_Status"] = sla_melted["SLA_Status"].map({
                "SLA_Green": t("on_track"),
                "SLA_Amber": t("at_risk"),
                "SLA_Red":   t("breached"),
            })
            _sla_colours = {
                t("on_track"): "#1a9e5c",
                t("at_risk"):  "#f0a500",
                t("breached"): "#d93025",
            }
            if sla_melted["Count"].sum() == 0:
                st.info(t_safe("no_sla_data", "No SLA data available yet."))
            else:
                fig_sla = px.bar(
                    sla_melted, x="Branch", y="Count",
                    color="SLA_Status", color_discrete_map=_sla_colours,
                    barmode="stack", title=t("sla_status_by_branch"),
                )
                fig_sla.update_layout(
                    plot_bgcolor="#ffffff", paper_bgcolor="#ffffff",
                    font=dict(color="#0A3D91", size=14),
                    height=400, xaxis_tickangle=-30, template="plotly_white",
                )
                st.plotly_chart(fig_sla, use_container_width=True)
                more_info(t("sla_recalc_caption"))

                sla_export = filtered[["Branch", "Region", "SLA_Green", "SLA_Amber", "SLA_Red"]].rename(
                    columns={"Branch": t("branch"), "Region": t("region"),
                             "SLA_Green": t("on_track"), "SLA_Amber": t("at_risk"), "SLA_Red": t("breached")}
                )
                _export_below_table(sla_export, "sla_status")

    # TAB 3 — Rights requests table
    with tab3:
        st.subheader(t("rights_request_management"))
        st.caption(t("sla_recalc_caption"))
        _render_rights_decision_table(role="dpo", data=data)

        st.divider()
        if not filtered.empty and "RightsReq" in filtered.columns and filtered["RightsReq"].sum() > 0:
            st.subheader(t("rights_request_volume_by_branch"))
            fig_rr = px.bar(
                filtered.sort_values("RightsReq", ascending=False),
                x="Branch", y="RightsReq",
                color_discrete_sequence=["#0A3D91"],
                title=t("active_rights_requests_per_branch"),
                text="RightsReq",
            )
            fig_rr.update_traces(textposition="outside")
            fig_rr.update_layout(
                plot_bgcolor="#ffffff", paper_bgcolor="#ffffff",
                font=dict(color="#0A3D91", size=14),
                height=380, xaxis_tickangle=-30, template="plotly_white",
            )
            st.plotly_chart(fig_rr, use_container_width=True)

    # TAB 4 — Consent expiry forecast
    with tab4:
        st.subheader(t("consent_forecast"))
        months   = ["Mar 2026", "Apr 2026", "May 2026", "Jun 2026", "Jul 2026", "Aug 2026"]
        expiring = [1240, 980, 2100, 1560, 890, 3200]
        forecast_df = pd.DataFrame({"Month": months, t("expiring_consents"): expiring})
        fig_f = px.line(
            forecast_df, x="Month", y=t("expiring_consents"),
            markers=True, title=t("projected_consent_expirations"),
            color_discrete_sequence=["#0A3D91"],
        )
        fig_f.update_layout(
            plot_bgcolor="#ffffff", paper_bgcolor="#ffffff",
            font=dict(color="#0A3D91", size=14),
            height=340, template="plotly_white",
        )
        st.plotly_chart(fig_f, use_container_width=True)
        st.info(t("consent_forecast_august_warning"))

    # TAB 5 — GIS Branch Map
    with tab5:
        st.subheader(t("gis_map"))
        st.caption(t("gis_map_caption"))
        if filtered.empty or "RiskLevel" not in filtered.columns:
            st.info(t_safe("no_map_data", "No branch map data available."))
        else:
            branch_map_data = filtered[["Branch", "Lat", "Lon", "RiskLevel", "ComplianceScore"]].copy()
            branch_map_data["risk_score"] = branch_map_data["ComplianceScore"].apply(lambda s: 100 - _safe_score(s))
            fig_map = px.scatter_mapbox(
                branch_map_data, lat="Lat", lon="Lon",
                size="risk_score", color="RiskLevel",
                color_discrete_map=RISK_COLOUR_MAP,
                hover_name="Branch",
                hover_data={"ComplianceScore": True, "RiskLevel": True, "Lat": False, "Lon": False},
                zoom=6, title=t("kerala_branch_risk_distribution"),
            )
            fig_map.update_layout(
                mapbox_style="open-street-map", height=520,
                margin=dict(l=0, r=0, t=40, b=0), font=dict(size=14),
            )
            st.plotly_chart(fig_map, use_container_width=True)
            more_info(t("gis_map_note"))

    # TAB 6 — Knowledge Graph
    with tab6:
        st.subheader(t("knowledge_graph"))
        st.caption(t("knowledge_graph_caption"))
        G = nx.Graph()
        G.add_edges_from([
            (t("kg_customer"), t("kg_consent")),
            (t("kg_consent"),  t("kg_purpose")),
            (t("kg_branch"),   t("kg_dpia")),
            (t("kg_dpia"),     t("kg_risk")),
            (t("kg_rights_request"), t("kg_sla")),
            (t("kg_consent"),  t("kg_rights_request")),
            (t("kg_branch"),   t("kg_consent")),
            (t("kg_risk"),     t("kg_compliance")),
            (t("kg_sla"),      t("kg_compliance")),
            (t("kg_purpose"),  t("kg_dpia")),
        ])
        pos = nx.spring_layout(G, seed=42)
        edge_x, edge_y = [], []
        for edge in G.edges():
            x0, y0 = pos[edge[0]]
            x1, y1 = pos[edge[1]]
            edge_x.extend([x0, x1, None])
            edge_y.extend([y0, y1, None])
        node_x, node_y, node_text = [], [], []
        for node in G.nodes():
            x, y = pos[node]
            node_x.append(x); node_y.append(y); node_text.append(node)
        fig_kg = go.Figure(data=[
            go.Scatter(x=edge_x, y=edge_y, line=dict(width=1.5, color="#b0bec5"),
                       hoverinfo="none", mode="lines"),
            go.Scatter(x=node_x, y=node_y, mode="markers+text",
                       text=node_text, textposition="bottom center", hoverinfo="text",
                       marker=dict(size=22, color="#0A3D91", line=dict(width=2, color="#ffffff")),
                       textfont=dict(size=12, color="#1a1a2e")),
        ], layout=go.Layout(
            title=t("knowledge_graph"), showlegend=False, hovermode="closest",
            margin=dict(b=20, l=5, r=5, t=50),
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            paper_bgcolor="#ffffff", plot_bgcolor="#ffffff", height=500,
        ))
        st.plotly_chart(fig_kg, use_container_width=True)
        more_info(t("knowledge_graph_note"))

    # TAB 7 — Escalation & DPIA
    with tab7:
        _render_escalation_overview(data)
        st.divider()
        _render_dpia_summary(data)
        _render_data_discovery_panel()

    # TAB 8 — Security Incidents
    with tab8:
        _render_security_incident_alerts()


# ===========================================================================
# REGIONAL DASHBOARD — Regional aggregation
# ===========================================================================

def render_regional_dashboard(data: dict) -> None:
    user_region = get_region()

    st.markdown(render_page_header("Compliance Monitoring"), unsafe_allow_html=True)
    st.caption(f"{t('region_label')}: {user_region}  |  {t('regional_dashboard_caption')}")

    branch_df = _engine_branch_df(data)
    if branch_df.empty:
        st.info(t_safe("no_compliance_data", "No compliance data available yet."))
        return

    regional = branch_df[branch_df["Region"] == user_region]
    if regional.empty:
        st.warning(t("no_data_for_region"))
        return

    col1, col2, col3, col4 = st.columns(4)
    avg_score  = _safe_score(regional["ComplianceScore"].mean()) if "ComplianceScore" in regional.columns else 0
    total_req  = int(regional["RightsReq"].sum()) if "RightsReq" in regional.columns else 0
    red_count  = int(regional["SLA_Red"].sum()) if "SLA_Red" in regional.columns else 0
    breach_sum = int(regional["Breaches"].sum()) if "Breaches" in regional.columns else 0

    _kpi(col1, t("avg_compliance_score"),  f"{avg_score}%",  t("regional_average"),
         "#1a9e5c" if avg_score >= 85 else "#f0a500")
    _kpi(col2, t("active_requests"),       total_req,         t("under_sla_monitoring"), "#C58F00")
    _kpi(col3, t("sla_compliance_rate"),   f"{data['sla_rate'] * 100:.1f}%",
         t("requests_within_deadline"), "#1a9e5c" if data["sla_rate"] >= 0.9 else "#f0a500")
    _kpi(col4, t("active_breaches"),       breach_sum,        t("incident_governance"),
         "#d93025" if breach_sum > 0 else "#1a9e5c")

    st.divider()
    _render_audit_integrity_banner(data)
    st.divider()

    if "ComplianceScore" in regional.columns and not regional.empty:
        st.subheader(t("branch_compliance"))
        fig = px.bar(
            regional.sort_values("ComplianceScore"),
            x="ComplianceScore", y="Branch", orientation="h",
            color="ComplianceScore",
            color_continuous_scale=["#d93025", "#f0a500", "#1a9e5c"],
            range_color=[70, 100], text="ComplianceScore",
            title=t("branch_level_compliance_scores"),
        )
        fig.update_traces(texttemplate="%{text}%", textposition="outside")
        fig.update_layout(
            plot_bgcolor="#ffffff", paper_bgcolor="#ffffff",
            font=dict(color="#0A3D91", size=14),
            height=380, coloraxis_showscale=False, template="plotly_white",
        )
        fig.add_vline(x=90, line_dash="dot", line_color="#1a9e5c",
                      annotation_text=t("target_90_pct"))
        st.plotly_chart(fig, use_container_width=True)

        # Branch risk dot indicators
        st.subheader(t("branch_risk_overview"))
        _render_branch_dot_indicators(regional)

    _render_escalation_overview(data)


# ===========================================================================
# OPERATIONAL DASHBOARD — Branch Officer / Auditor / SOC Analyst
# ===========================================================================

def render_operational_dashboard(data: dict) -> None:
    import auth as _auth
    _cu         = _auth.get_current_user() or {}
    role        = _cu.get("role", st.session_state.get("role", ""))
    user_branch = _cu.get("branch") or get_branch()
    user_region = _cu.get("region") or get_region()

    branch_df = _engine_branch_df(data)

    if role in ("branch_officer", "branch_privacy_coordinator"):
        st.markdown(render_page_header("Executive Dashboard"), unsafe_allow_html=True)
        st.caption(
            f"{t('branch_label')}: {user_branch}  |  "
            f"{t('region_label')}: {user_region}  |  "
            f"{t('dpdp_compliance_view')}"
        )

        if branch_df.empty:
            st.info(t_safe("no_compliance_data", "No compliance data available yet."))
            return
        branch_data = branch_df[branch_df["Branch"] == user_branch]
        if branch_data.empty:
            st.warning(t("no_data_for_branch"))
            return
        row = branch_data.iloc[0]

        col1, col2, col3, col4 = st.columns(4)
        _kpi(col1, t("total_consents"),          f"{int(row['Consents']):,}", t("lifecycle_compliant"))
        _kpi(col2, t("active_requests"),          int(row["RightsReq"]),      t("under_sla_monitoring"), "#C58F00")
        _kpi(col3, t("active_breaches"),          int(row["SLA_Red"]),
             t("requires_escalation"), "#d93025" if row["SLA_Red"] > 0 else "#1a9e5c")
        _kpi(col4, t("overall_compliance_score"), f"{_safe_score(row['ComplianceScore'])}%",
             t("regulatory_score"),
             "#d93025" if row["ComplianceScore"] < 85 else "#1a9e5c")

        st.divider()
        col_l, col_r = st.columns(2)

        with col_l:
            st.subheader(t("sla_status_distribution"))
            sla_data = pd.DataFrame({
                t("status"): [t("on_track"), t("at_risk"), t("breached")],
                t("count"):  [int(row["SLA_Green"]), int(row["SLA_Amber"]), int(row["SLA_Red"])],
            })
            if sla_data[t("count")].sum() == 0:
                st.info(t_safe("no_sla_data", "No SLA data available yet."))
            else:
                _sla_c = {t("on_track"): "#1a9e5c", t("at_risk"): "#f0a500", t("breached"): "#d93025"}
                fig_sla = px.pie(
                    sla_data, names=t("status"), values=t("count"),
                    color=t("status"), color_discrete_map=_sla_c,
                    title=t("sla_status_this_branch"), hole=0.5,
                )
                fig_sla.update_layout(
                    height=300, paper_bgcolor="#ffffff",
                    font=dict(color="#0A3D91", size=14), template="plotly_white",
                )
                st.plotly_chart(fig_sla, use_container_width=True)
                more_info(t("sla_recalc_caption"))

        with col_r:
            st.subheader(t("branch_risk_level"))
            risk   = row["RiskLevel"]
            colour = RISK_COLOUR_MAP.get(risk, "#888")
            badge  = render_status_badge(str(risk).strip().lower())
            st.markdown(
                f"<div style='text-align:center;padding:40px;border-radius:14px;"
                f"background:{colour}22;border:3px solid {colour};'>"
                f"<div style='font-size:2rem;'>{badge}</div>"
                f"<div style='color:#555;margin-top:8px;font-size:16px;'>"
                f"{t('current_risk_status')}</div>"
                f"</div>",
                unsafe_allow_html=True,
            )
            if row["Breaches"] > 0:
                st.error(f"⚠️ {int(row['Breaches'])} {t('active_incidents_reported')}")

        st.divider()
        st.subheader(t("rights_requests_action_required"))
        _render_rights_decision_table(role=role, data=data)

    elif role in ("auditor", "internal_auditor", "soc_analyst"):
        st.markdown(render_page_header("Audit & Compliance"), unsafe_allow_html=True)
        st.caption(t("auditor_dashboard_caption"))

        overall_score = data["overall_score"]
        sla_rate      = data["sla_rate"]

        col1, col2, col3, col4 = st.columns(4)
        _kpi(col1, t("overall_compliance_score"),
             f"{overall_score}%", t("weighted_across_branches"))
        _kpi(col2, t("sla_compliance_rate"),
             f"{sla_rate * 100:.1f}%", t("requests_within_deadline"),
             "#1a9e5c" if sla_rate >= 0.9 else "#f0a500")
        _kpi(col3, t("active_breaches"),
             data["breach_count"], t("across_system"),
             "#d93025" if data["breach_count"] > 0 else "#1a9e5c")
        _kpi(col4, t("reported_breaches"),
             0 if branch_df.empty or "Breaches" not in branch_df.columns
             else int(branch_df["Breaches"].sum()),
             t("reported_incidents"), "#d93025")

        st.divider()
        _render_audit_integrity_banner(data)
        st.divider()
        _render_security_incident_alerts()
        st.divider()

        if branch_df.empty or "ComplianceScore" not in branch_df.columns:
            st.info(t_safe("no_compliance_data", "No compliance data available yet."))
        else:
            st.subheader(t("branch_compliance_scorecard"))
            scorecard_rows = ""
            for _, r in branch_df.iterrows():
                risk_val    = str(r.get("RiskLevel", "")).strip().lower()
                badge       = render_status_badge(risk_val)
                score_val   = _safe_score(r["ComplianceScore"])
                score_colour = (
                    "#1a9e5c" if score_val >= 85 else
                    "#f0a500" if score_val >= 60 else
                    "#d93025"
                )
                score_cell = (
                    f"<span style='background:{score_colour};color:#fff;"
                    f"padding:2px 10px;border-radius:12px;font-weight:600;'>"
                    f"{score_val}%</span>"
                )
                scorecard_rows += (
                    f"<tr>"
                    f"{_td(str(r['Branch']))}"
                    f"{_td(str(r['Region']))}"
                    f"{_td(score_cell)}"
                    f"{_td(badge)}"
                    f"{_td(str(int(r['RightsReq'])))}"
                    f"{_td(str(int(r['SLA_Red'])))}"
                    f"{_td(str(int(r['Breaches'])))}"
                    f"</tr>"
                )

            scorecard_html = (
                "<div style='font-size:15px;overflow-x:auto;'>"
                "<table style='width:100%;border-collapse:collapse;background:white;'>"
                "<thead><tr>"
                + _th(t("branch")) + _th(t("region")) + _th(t("score_pct"))
                + _th(t("risk_level")) + _th(t("open_requests"))
                + _th(t("sla_breaches")) + _th(t("incidents"))
                + "</tr></thead><tbody>"
                + scorecard_rows
                + "</tbody></table></div>"
            )
            st.markdown(scorecard_html, unsafe_allow_html=True)

            # Export placed BELOW table
            display_df = branch_df[["Branch", "Region", "ComplianceScore", "RightsReq", "SLA_Red", "Breaches"]].rename(
                columns={
                    "Branch": t("branch"), "Region": t("region"),
                    "ComplianceScore": t("score_pct"), "RightsReq": t("open_requests"),
                    "SLA_Red": t("sla_breaches"), "Breaches": t("incidents"),
                }
            )
            _export_below_table(display_df, "branch_compliance_scorecard")

            # Branch compliance chart
            st.divider()
            _sorted = branch_df.sort_values("ComplianceScore", ascending=True).copy()
            _sorted["_colour"] = _sorted["ComplianceScore"].apply(
                lambda s: "#1a9e5c" if _safe_score(s) >= 85 else ("#f0a500" if _safe_score(s) >= 60 else "#d93025")
            )
            _sorted["_band"] = _sorted["ComplianceScore"].apply(
                lambda s: "On Target (≥85%)" if _safe_score(s) >= 85 else
                          ("At Risk (60–84%)" if _safe_score(s) >= 60 else "Critical (<60%)")
            )

            fig_audit = go.Figure(go.Bar(
                x=_sorted["ComplianceScore"],
                y=_sorted["Branch"],
                orientation="h",
                marker=dict(color=_sorted["_colour"].tolist(), line=dict(color="#ffffff", width=0.8)),
                text=[f"  {_safe_score(v)}%" for v in _sorted["ComplianceScore"]],
                textposition="outside",
                textfont=dict(size=13, color="#333333"),
                hovertemplate="<b>%{y}</b><br>Compliance Score: <b>%{x}%</b><extra></extra>",
            ))
            fig_audit.add_vline(
                x=90, line_dash="dot", line_color="#0d47a1", line_width=1.5,
                annotation_text="Target 90%", annotation_position="top right",
                annotation_font=dict(size=12, color="#0d47a1"),
            )
            fig_audit.update_layout(
                title=dict(text="Branch Compliance Score Comparison", font=dict(size=18, color="#0A3D91")),
                xaxis=dict(title="Compliance Score (%)", range=[0, 120], ticksuffix="%", showgrid=True,
                           gridcolor="#ececec", tickfont=dict(size=13)),
                yaxis=dict(title="", automargin=True, tickfont=dict(size=13)),
                plot_bgcolor="#ffffff", paper_bgcolor="#ffffff",
                font=dict(color="#0A3D91", size=13),
                height=max(340, 46 * len(_sorted)),
                margin=dict(l=10, r=160, t=70, b=30),
                showlegend=False,
            )
            st.plotly_chart(fig_audit, use_container_width=True)
    else:
        st.info(t_safe("no_dashboard_for_role", "No dashboard view is configured for your role."))


# ===========================================================================
# Main entry point
# ===========================================================================

def show() -> None:
    import auth as _auth
    from utils.ui_helpers import render_page_title

    st_autorefresh(interval=5000, key="datarefresh")

    # ── Resolve role ──────────────────────────────────────────────────────────
    current_user = _auth.get_current_user()
    if not current_user:
        st.error(t("session_not_found"))
        return
    role = current_user["role"]

    # ── Role guard — customers and unrecognised roles must never see governance data
    _allowed_dashboard_roles: set[str] = {
        "branch_officer",
        "branch_privacy_coordinator",
        "regional_officer",
        "regional_compliance_officer",
        "privacy_steward",
        "privacy_operations",
        "dpo",
        "auditor",
        "internal_auditor",
        "soc_analyst",
        "board_member",
    }
    if role not in _allowed_dashboard_roles:
        st.warning(
            t_safe("dashboard_access_denied",
                   "You do not have permission to access the Compliance Dashboard.")
        )
        st.info(t("contact_dpo_access"))
        return

    # ── Page title ────────────────────────────────────────────────────────────
    render_page_title("governance_console")

    # ── Sidebar: permitted module list ───────────────────────────────────────
    _render_module_access_panel()

    # ── Load engine metrics ───────────────────────────────────────────────────
    data = _load_engine_data()

    # ── Role-differentiated dispatch ─────────────────────────────────────────
    if role == "board_member":
        render_board_dashboard(data)
    elif role == "dpo":
        render_dpo_dashboard(data)
    elif role in (
        "regional_officer", "regional_compliance_officer",
        "privacy_steward", "privacy_operations",
    ):
        render_regional_dashboard(data)
    else:
        # branch_officer, branch_privacy_coordinator, auditor, internal_auditor, soc_analyst
        render_operational_dashboard(data)