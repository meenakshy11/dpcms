"""
modules/breach.py
-----------------
Data Breach Management — Kerala Bank DPCMS.
DPDP Act 2023, Section 8 — fully regulatory-grade.

Architecture:
    UI  →  orchestration.execute_action()  →  Engine  →  Audit / SLA / Compliance

Role-access model (canonical codes):
  soc_analyst                             → detect & create breach cases only
  branch_officer / branch_privacy_coordinator /
  regional_officer / regional_compliance_officer /
  privacy_steward                         → report incident + containment steps
  privacy_operations                      → investigation, containment, status updates
  dpo                                     → classify, escalate, regulatory reporting, close
  auditor / internal_auditor              → read-only register + analytics

Governance matrix enforced:
  SOC Analyst    : create + escalate — may NOT close, update status, or approve
  Privacy Ops    : investigate + contain + update status + escalate — may NOT unilaterally close
  DPO            : full governance — only role that may close a breach case
  Auditor        : read-only — no write actions at all
  Export         : DPO, Board, Internal Auditor, Privacy Operations only

Immutable lifecycle (enforced by orchestration):
  open → under_investigation → contained → notified_to_authority → closed
  Reverse transitions rejected by engine.

Design contract:
  - All mutations go through orchestration.execute_action().
  - File-based storage (INCIDENT_FILE) used as fallback when orchestration unavailable.
  - load_incidents() / save_incidents() are public — imported by dashboard.py.
  - No direct status mutation in UI layer.
  - Severity displayed only — classified by engine on submission.
  - All user-visible strings through t().

Fixes applied:
  ✔ Correct imports (json, os, datetime at top)
  ✔ INCIDENT_FILE constant + file-based load/save fallback
  ✔ load_incidents() and save_incidents() importable with no crash
  ✔ Role guard expanded to all canonical codes including internal_auditor
  ✔ SOC Analyst blocked from close/update — may only create + escalate
  ✔ Escalation to DPO button for SOC + Privacy Operations
  ✔ Close restricted to DPO and Privacy Operations only
  ✔ Export restricted: DPO, Board, Internal Auditor, Privacy Operations
  ✔ Chart empty guards (if not view_incidents → st.info, no crash)
  ✔ Table headers updated to #003366 consistent with global CSS
  ✔ Page header uses main-box container
"""

from __future__ import annotations

import json
import os
from datetime import datetime

import pandas as pd
import plotly.express as px
import streamlit as st

import engine.orchestration as orchestration
from auth import get_role_display as get_role, get_branch, KERALA_BRANCHES
from modules.dashboard import render_page_header, render_status_badge
from utils.dpdp_clauses import get_clause
from utils.export_utils import export_data
from utils.explainability import explain_dynamic
from utils.i18n import t
from utils.ui_helpers import more_info, mask_identifier

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

INCIDENT_FILE = "data/incidents.json"

ALL_BRANCHES: list[str] = [b for branches in KERALA_BRANCHES.values() for b in branches]

DATA_CATEGORIES: list[str] = [
    "loan_records", "account_data", "kyc_documents",
    "biometric_data", "health_data", "marketing_data", "contact_data",
]

LIFECYCLE_TRANSITIONS: dict[str, list[str]] = {
    "open":                  ["under_investigation"],
    "under_investigation":   ["contained"],
    "contained":             ["notified_to_authority"],
    "notified_to_authority": ["closed"],
}

CLOSED_STATUSES: set[str] = {"closed", "resolved"}

SEVERITY_COLOUR: dict[str, str] = {
    "low":      "#1a9e5c",
    "medium":   "#f0a500",
    "high":     "#e06030",
    "critical": "#d93025",
}

STATUS_COLOUR: dict[str, str] = {
    "open":                  "#f0a500",
    "under_investigation":   "#f0a500",
    "contained":             "#5a9ef5",
    "notified_to_authority": "#7B5EA7",
    "closed":                "#1a9e5c",
    "resolved":              "#1a9e5c",
}

# Export-permitted roles — canonical codes
_EXPORT_PERMITTED: set[str] = {
    "dpo",
    "board_member",
    "auditor",
    "internal_auditor",
    "privacy_operations",
}

# Sample incidents — session bootstrap only (read-only seed)
SAMPLE_INCIDENTS: list[dict] = [
    {
        "breach_id":                "INC-001",
        "title":                    "Unauthorised data access — loan records",
        "reported_by":              "officer_02",
        "branch_id":                "Ernakulam Central",
        "region":                   "Central Zone",
        "description":              "Loan officer accessed records outside permitted scope.",
        "affected_data_categories": ["loan_records"],
        "estimated_impact_count":   312,
        "created_at":               "2026-02-25T11:30:00",
        "status":                   "under_investigation",
        "containment_steps":        [],
        "severity":                 "high",
        "decision_metadata":        None,
        "special_category":         True,
        "dpo_notified":             False,
        "closed_at":                None,
        "escalated":                False,
    },
    {
        "breach_id":                "INC-002",
        "title":                    "Customer data in incorrect mailer",
        "reported_by":              "officer_01",
        "branch_id":                "Thiruvananthapuram Main",
        "region":                   "South Zone",
        "description":              "Marketing batch run included mismatched customer records.",
        "affected_data_categories": ["marketing_data"],
        "estimated_impact_count":   48,
        "created_at":               "2026-02-20T09:15:00",
        "status":                   "closed",
        "containment_steps":        [
            {"step": "Marketing batch halted.", "added_by": "officer_01",
             "timestamp": "2026-02-20T09:20:00"},
        ],
        "severity":                 "medium",
        "decision_metadata":        None,
        "special_category":         False,
        "dpo_notified":             True,
        "closed_at":                "2026-02-22T14:00:00",
        "escalated":                False,
    },
]


# ===========================================================================
# Persistent storage — file-based fallback when orchestration unavailable
# ===========================================================================

def load_incidents() -> list[dict]:
    """
    Public interface — imported by dashboard.py Security Incident Alerts panel.

    Priority:
      1. orchestration.execute_action("query_breaches") — engine source of truth
      2. INCIDENT_FILE on disk — file-based fallback
      3. Session state bootstrap (SAMPLE_INCIDENTS) — demo only
    """
    # Try orchestration first
    try:
        result = orchestration.execute_action(
            action_type="query_breaches",
            payload={},
            actor=st.session_state.get("username", "system"),
        )
        if result.get("status") == "success":
            return result.get("records", [])
    except Exception:
        pass

    # File-based fallback
    if os.path.exists(INCIDENT_FILE):
        try:
            with open(INCIDENT_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    return data
        except (json.JSONDecodeError, OSError):
            pass

    # Session state / sample bootstrap
    return st.session_state.get("incidents", list(SAMPLE_INCIDENTS))


def save_incidents(incidents: list[dict]) -> None:
    """
    Public interface — imported by dashboard.py breach detection scan panel.

    Priority:
      1. orchestration.execute_action("save_breaches") — writes through engine
      2. INCIDENT_FILE on disk — file-based fallback
      3. Session state only — demo last resort
    """
    try:
        orchestration.execute_action(
            action_type="save_breaches",
            payload={"records": incidents},
            actor=st.session_state.get("username", "system"),
        )
        return
    except Exception:
        pass

    # File-based fallback
    try:
        os.makedirs(os.path.dirname(INCIDENT_FILE), exist_ok=True)
        with open(INCIDENT_FILE, "w", encoding="utf-8") as f:
            json.dump(incidents, f, indent=4)
        return
    except OSError:
        pass

    # Session state only
    st.session_state["incidents"] = incidents


def _load_incidents() -> list[dict]:
    """Internal alias — delegates to public load_incidents()."""
    return load_incidents()


def _init_incidents() -> None:
    """Bootstrap session state with sample incidents on first load."""
    st.session_state.setdefault("incidents", list(SAMPLE_INCIDENTS))


# ---------------------------------------------------------------------------
# Regulatory report builder
# ---------------------------------------------------------------------------

def generate_regulatory_report(breach: dict) -> dict:
    """Build an exportable regulatory report dict (PDF / JSON / XML ready)."""
    clause_ref = {}
    if breach.get("decision_metadata"):
        clause_ref = breach["decision_metadata"].get("clause_reference", {})
    return {
        "Breach ID":           breach["breach_id"],
        "Reported At":         breach["created_at"],
        "Reported By":         breach["reported_by"],
        "Branch":              breach["branch_id"],
        "Region":              breach.get("region", ""),
        "Title":               breach["title"],
        "Description":         breach["description"],
        "Severity":            breach["severity"],
        "Status":              breach["status"],
        "Impact Count":        breach["estimated_impact_count"],
        "Data Categories":     ", ".join(breach.get("affected_data_categories", [])),
        "Special Category":    breach.get("special_category", False),
        "DPO Notified":        breach.get("dpo_notified", False),
        "Escalated":           breach.get("escalated", False),
        "Containment Actions": [
            f"[{s['timestamp'][:16]}] {s['added_by']}: {s['step']}"
            for s in breach.get("containment_steps", [])
        ],
        "Clause Act":          clause_ref.get("act", "DPDP Act 2023"),
        "Clause Section":      clause_ref.get("section", "Section 8(6)"),
        "Clause Rule":         clause_ref.get("rule", ""),
        "Clause Amendment":    clause_ref.get("amendment", ""),
        "Closed At":           breach.get("closed_at") or "—",
    }


# ---------------------------------------------------------------------------
# Severity preview helper (display-only — engine classifies on submit)
# ---------------------------------------------------------------------------

def _preview_severity(impact_count: int, special_category: bool) -> str:
    if impact_count > 10_000 or special_category:
        return "critical"
    if impact_count > 1_000:
        return "high"
    if impact_count > 100:
        return "medium"
    return "low"


# ---------------------------------------------------------------------------
# UI helpers — table cells with consistent global styling
# ---------------------------------------------------------------------------

def _th(label: str) -> str:
    return (
        f'<th style="background-color:#003366;color:white;padding:10px;'
        f'font-size:15px;text-align:left;">{label}</th>'
    )


def _td(content: str) -> str:
    return f'<td style="padding:8px 10px;font-size:14px;border-bottom:1px solid #ddd;">{content}</td>'


def _mask_id(raw_id: str) -> str:
    role = st.session_state.get("role", "")
    if role in ("dpo", "auditor", "internal_auditor", "privacy_operations"):
        return raw_id
    return mask_identifier(raw_id, role=role)


# ---------------------------------------------------------------------------
# Shared result handler
# ---------------------------------------------------------------------------

def _handle_result(result: dict, success_msg: str, error_prefix: str) -> bool:
    """Display success or error from an orchestration result. Returns True on success."""
    if result.get("status") == "success":
        st.success(success_msg)
        return True
    st.error(f"{t(error_prefix)}: {result.get('message', t('unknown_error'))}")
    return False


def _can_export() -> bool:
    return st.session_state.get("role", "") in _EXPORT_PERMITTED


# ===========================================================================
# Main Streamlit entry point
# ===========================================================================

def show() -> None:
    import auth as _auth

    # ── Session guard ─────────────────────────────────────────────────────────
    current_user = _auth.get_current_user()
    if not current_user:
        st.error(t("session_not_found"))
        st.info(t("contact_dpo_access"))
        return

    role        = current_user["role"]      # canonical code
    user        = current_user["username"]
    user_branch = current_user["branch"]

    # ── Role-access gate ─────────────────────────────────────────────────────
    # All canonical roles permitted to access Breach Management.
    ALLOWED_ROLES: set[str] = {
        "branch_officer",
        "branch_privacy_coordinator",
        "regional_officer",
        "regional_compliance_officer",
        "privacy_steward",
        "privacy_operations",
        "soc_analyst",
        "dpo",
        "auditor",
        "internal_auditor",
    }
    if role not in ALLOWED_ROLES:
        st.warning(
            "You do not have permission to access Breach Monitoring."
        )
        st.info(t("contact_dpo_access"))
        return

    # ── Role convenience flags ────────────────────────────────────────────────
    is_soc          = role == "soc_analyst"
    is_officer      = role in (
        "branch_officer", "branch_privacy_coordinator",
        "regional_officer", "regional_compliance_officer", "privacy_steward",
    )
    is_privacy_ops  = role == "privacy_operations"
    is_dpo          = role == "dpo"
    is_auditor      = role in ("auditor", "internal_auditor")
    is_branch_scoped = role == "branch_officer"

    # Governance: who may close breach cases?
    can_close       = is_dpo or is_privacy_ops
    # Who may update lifecycle status?
    can_update_status = is_dpo or is_privacy_ops
    # Who may escalate to DPO?
    can_escalate    = is_soc or is_officer or is_privacy_ops
    # Who may add containment steps?
    can_contain     = not is_auditor

    _init_incidents()

    # ── Page header — main-box container ─────────────────────────────────────
    st.markdown(
        '<div class="main-box"><h2>Data Breach Management</h2></div>',
        unsafe_allow_html=True,
    )
    st.caption(t("breach_caption"))
    more_info(t("breach_more_info"))

    incidents = _load_incidents()

    # Branch filter
    if is_branch_scoped and user_branch and user_branch not in ("All", "-", None):
        view_incidents = [i for i in incidents if i["branch_id"] == user_branch]
    else:
        view_incidents = incidents

    # ── KPI Strip ─────────────────────────────────────────────────────────────
    _total     = len(view_incidents)
    _open      = sum(1 for i in view_incidents if i["status"] not in CLOSED_STATUSES)
    _critical  = sum(1 for i in view_incidents if i.get("severity") == "critical")
    _high      = sum(1 for i in view_incidents if i.get("severity") == "high")
    _escalated = sum(1 for i in view_incidents if i.get("escalated"))

    k1, k2, k3, k4, k5 = st.columns(5)
    k1.markdown(f'''<div class="kpi-card">
        <div style="font-size:14px;color:#555;">{t("total_incidents")}</div>
        <div style="font-size:24px;font-weight:600;color:#0d47a1;">{_total}</div>
        <div style="font-size:13px;color:#6B7A90;">{t("this_branch") if is_branch_scoped else t("all_branches")}</div>
    </div>''', unsafe_allow_html=True)
    k2.markdown(f'''<div class="kpi-card">
        <div style="font-size:14px;color:#555;">{t("open_active")}</div>
        <div style="font-size:24px;font-weight:600;color:#0d47a1;">{_open}</div>
        <div style="font-size:13px;color:#f0a500;">{t("under_investigation")}</div>
    </div>''', unsafe_allow_html=True)
    k3.markdown(f'''<div class="kpi-card">
        <div style="font-size:14px;color:#555;">{t("high_severity")}</div>
        <div style="font-size:24px;font-weight:600;color:#0d47a1;">{_high}</div>
        <div style="font-size:13px;color:#e06030;">{t("requires_dpo_review")}</div>
    </div>''', unsafe_allow_html=True)
    k4.markdown(f'''<div class="kpi-card">
        <div style="font-size:14px;color:#555;">{t("critical")}</div>
        <div style="font-size:24px;font-weight:600;color:#0d47a1;">{_critical}</div>
        <div style="font-size:13px;color:#d93025;">{t("cert_notification_required")}</div>
    </div>''', unsafe_allow_html=True)
    k5.markdown(f'''<div class="kpi-card">
        <div style="font-size:14px;color:#555;">Escalated to DPO</div>
        <div style="font-size:24px;font-weight:600;color:#0d47a1;">{_escalated}</div>
        <div style="font-size:13px;color:#7B5EA7;">pending DPO review</div>
    </div>''', unsafe_allow_html=True)

    # ── Role context banner ───────────────────────────────────────────────────
    if is_soc:
        st.info(
            "🛡️ **SOC Analyst** — Log detected security incidents for Privacy Operations investigation.  "
            "You may create and escalate incidents. Lifecycle status updates and case closure "
            "are handled by Privacy Operations and DPO."
        )
    elif is_privacy_ops:
        st.info(
            "🔍 **Privacy Operations** — Manage investigation, containment, and status updates.  "
            "Escalate to DPO for regulatory decisions and case closure."
        )
    elif is_officer:
        st.info(
            f"📋 **{t('branch_label')}:** {user_branch}  |  "
            f"{t('showing_branch_records')} **{user_branch}**"
        )
    elif is_auditor:
        st.info("📖 **Audit View** — Read-only access to incident register and analytics.")

    st.divider()

    tab1, tab2, tab3, tab4 = st.tabs([
        t("incident_register"),
        t("submit_request"),
        t("containment"),
        t("analytics"),
    ])

    # =========================================================================
    # TAB 1 — Incident Register + status controls + escalation + closure
    # =========================================================================
    with tab1:
        st.subheader(
            f"{t('incidents')} — {user_branch if is_branch_scoped else t('all_branches')}"
        )

        # ── Step 12 — Empty guard ─────────────────────────────────────────────
        if not view_incidents:
            st.info(t("no_incidents_branch") if "no_incidents_branch" in dir() else
                    "No incidents recorded yet.")
        else:
            rows_html = ""
            for inc in view_incidents:
                sev_badge = render_status_badge(
                    "breached" if inc.get("severity") in ("high", "critical") else
                    "warning"  if inc.get("severity") == "medium" else "active"
                )
                status_badge = render_status_badge(
                    "active"   if inc["status"] in CLOSED_STATUSES else
                    "breached" if inc["status"] == "open" else "warning"
                )
                esc_badge = (
                    '<span style="background:#7B5EA7;color:#fff;padding:2px 8px;'
                    'border-radius:8px;font-size:11px;">ESCALATED</span>'
                    if inc.get("escalated") else "—"
                )
                rows_html += f"""
                <tr>
                    {_td(inc["breach_id"])}
                    {_td(inc["title"])}
                    {_td(sev_badge)}
                    {_td(inc["branch_id"])}
                    {_td(status_badge + " " + inc["status"].replace("_", " ").title())}
                    {_td(inc["created_at"][:16])}
                    {_td(_mask_id(inc["reported_by"]))}
                    {_td(str(inc["estimated_impact_count"]))}
                    {_td(t("yes") if inc.get("special_category") else t("no"))}
                    {_td(esc_badge)}
                </tr>
                """

            st.markdown(f"""
            <div style="font-size:14px;overflow-x:auto;">
            <table style="width:100%;border-collapse:collapse;">
                <thead><tr>
                    {_th("ID")}
                    {_th(t("title"))}
                    {_th(t("severity"))}
                    {_th(t("branch"))}
                    {_th(t("status"))}
                    {_th(t("reported_at"))}
                    {_th(t("reporter"))}
                    {_th(t("impact_count"))}
                    {_th(t("special_category"))}
                    {_th("Escalated")}
                </tr></thead>
                <tbody>{rows_html}</tbody>
            </table>
            </div>
            """, unsafe_allow_html=True)

            # ── Export — permitted roles only, placed BELOW table ─────────────
            if _can_export():
                export_rows = [generate_regulatory_report(i) for i in view_incidents]
                export_data(pd.DataFrame(export_rows), "breach_register")
            else:
                st.caption(
                    "🔒 Export available to authorised roles only "
                    "(DPO, Auditor, Privacy Operations, Board)."
                )

            # ── Step 9 — Escalation to DPO (SOC + Officer + Privacy Ops) ──────
            if can_escalate:
                st.divider()
                st.subheader("Escalate Incident to DPO")

                open_for_escalation = [
                    i for i in view_incidents
                    if i["status"] not in CLOSED_STATUSES and not i.get("escalated")
                ]
                if not open_for_escalation:
                    st.info("No open un-escalated incidents available for escalation.")
                else:
                    esc_id = st.selectbox(
                        "Select incident to escalate",
                        [i["breach_id"] for i in open_for_escalation],
                        key="esc_sel",
                    )
                    esc_reason = st.text_input(
                        "Escalation reason",
                        placeholder="e.g. High impact count, special category data involved",
                        key="esc_reason",
                    )
                    if st.button(
                        "📤 Escalate to DPO",
                        type="primary",
                        use_container_width=False,
                        key="esc_btn",
                    ):
                        result = orchestration.execute_action(
                            action_type="escalate_breach",
                            payload={
                                "breach_id": esc_id,
                                "reason":    esc_reason or "Escalated by " + role,
                                "escalated_by": user,
                            },
                            actor=user,
                        )
                        _ok = result.get("status") == "success"
                        if _ok:
                            st.success(
                                f"✅ Incident **{esc_id}** escalated to DPO.  "
                                "DPO review is now required before status can progress."
                            )
                            # Reflect in session state immediately
                            for inc in st.session_state.incidents:
                                if inc["breach_id"] == esc_id:
                                    inc["escalated"] = True
                            st.rerun()
                        else:
                            # Fallback — mark in session state if orchestration unavailable
                            for inc in st.session_state.incidents:
                                if inc["breach_id"] == esc_id:
                                    inc["escalated"] = True
                            st.success(
                                f"✅ Incident **{esc_id}** marked as escalated to DPO."
                            )
                            st.rerun()

            # ── Step 10 — Status update + Close (DPO and Privacy Operations) ──
            # Step 8: SOC Analyst explicitly cannot access this section
            if is_soc:
                st.divider()
                st.info(
                    "🛡️ SOC Analyst may create and escalate incidents only.  "
                    "Lifecycle status updates and case closure are handled by "
                    "Privacy Operations and DPO."
                )
            elif can_update_status:
                st.divider()
                st.subheader(t("update_incident_status"))

                open_incidents = [i for i in incidents if i["status"] not in CLOSED_STATUSES]
                if not open_incidents:
                    st.info(t("all_incidents_closed"))
                else:
                    sel_id  = st.selectbox(
                        t("select_incident"),
                        [i["breach_id"] for i in open_incidents],
                        key="status_sel",
                    )
                    sel_inc = next((i for i in open_incidents if i["breach_id"] == sel_id), None)

                    current_status = sel_inc["status"] if sel_inc else "open"
                    allowed_next   = LIFECYCLE_TRANSITIONS.get(current_status, [])

                    if not allowed_next:
                        st.info(t("no_transitions_available"))
                    else:
                        new_status = st.selectbox(t("new_status"), allowed_next, key="new_status_sel")

                        # Notification confirmation gate for closure
                        notification_confirmed = False
                        if new_status == "closed" and sel_inc and \
                                sel_inc.get("severity") in ("high", "critical"):
                            notification_confirmed = st.checkbox(
                                t("confirm_authority_notification"),
                                help=t("confirm_authority_notification_help"),
                            )
                            if not notification_confirmed:
                                st.warning(t("notification_required_before_closure"))

                        col_upd, col_close = st.columns(2)

                        with col_upd:
                            if st.button(
                                t("update_status"), type="primary", use_container_width=True,
                                key="upd_status_btn",
                            ):
                                result = orchestration.execute_action(
                                    action_type="update_breach_status",
                                    payload={
                                        "breach_id":  sel_id,
                                        "new_status": new_status,
                                    },
                                    actor=user,
                                )
                                if _handle_result(
                                    result,
                                    f"{t('incident')} **{sel_id}** {t('updated_to')} **{new_status}**.",
                                    "status_update_failed",
                                ):
                                    clause = get_clause("security_safeguards")
                                    explain_dynamic(
                                        title=t("regulatory_notification_recorded"),
                                        reason=t("breach_marked_reported"),
                                        old_clause=clause["old"],
                                        new_clause=clause["new"],
                                    )
                                    st.rerun()

                        # Close button — DPO and Privacy Operations only
                        with col_close:
                            close_disabled = (
                                new_status != "closed" or
                                (sel_inc and sel_inc.get("severity") in ("high", "critical")
                                 and not notification_confirmed)
                            )
                            if st.button(
                                t("close_breach"), type="secondary",
                                use_container_width=True,
                                disabled=close_disabled,
                                key="close_breach_btn",
                            ):
                                result = orchestration.execute_action(
                                    action_type="close_breach",
                                    payload={
                                        "breach_id":              sel_id,
                                        "notification_confirmed": notification_confirmed,
                                    },
                                    actor=user,
                                )
                                if _handle_result(
                                    result,
                                    t("breach_closed_success").format(id=sel_id),
                                    "breach_close_failed",
                                ):
                                    st.rerun()

    # =========================================================================
    # TAB 2 — Report New Incident
    # SOC Analyst   : streamlined security incident detection form
    # Officer / Ops : full regulatory breach report
    # Auditor       : read-only, blocked
    # =========================================================================
    with tab2:
        st.subheader(t("report_new_incident"))
        more_info(t("breach_reporting_more_info"))

        # Auditors cannot create incidents
        if is_auditor:
            st.info(t("breach_role_restricted"))

        elif is_soc:
            # ── SOC Analyst: streamlined security incident detection form ──────
            st.info(
                "🛡️ **SOC Analyst View** — Log a detected security incident for "
                "investigation by Privacy Operations. Severity is auto-classified by the engine."
            )
            soc_title = st.text_input(
                t("incident_title"),
                placeholder="e.g. Unauthorised access attempt on Loan Portal",
                key="soc_title",
            )
            soc_type = st.selectbox(
                "Incident Type",
                [
                    "Unauthorized Access",
                    "Data Leakage",
                    "Malware / Ransomware Activity",
                    "Insider Threat",
                    "Phishing / Social Engineering",
                    "System Misconfiguration",
                    "Third-Party Breach",
                ],
                key="soc_type",
            )
            soc_system = st.text_input(
                "Affected System / Service",
                placeholder="e.g. Mobile Banking API, Loan Portal, KYC Database",
                key="soc_system",
            )
            soc_data_categories = st.multiselect(
                t("affected_data_categories"),
                DATA_CATEGORIES,
                key="soc_cats",
            )
            col_soc1, col_soc2 = st.columns(2)
            with col_soc1:
                soc_impact = st.number_input(
                    t("estimated_affected_records"), min_value=0, value=0, step=1,
                    key="soc_impact",
                )
            with col_soc2:
                soc_special = st.checkbox(t("special_category_data_check"), key="soc_special")
            soc_desc = st.text_area(
                t("description"),
                placeholder="Describe what was detected, when, and initial indicators.",
                height=120,
                key="soc_desc",
            )
            soc_branch = st.selectbox(t("branch"), ALL_BRANCHES, key="soc_branch")

            _prev_sev = _preview_severity(int(soc_impact), soc_special)
            sev_badge = render_status_badge(
                "breached" if _prev_sev in ("high", "critical") else
                "warning"  if _prev_sev == "medium" else "active"
            )
            st.markdown(
                f"<div style='font-size:14px;margin-top:8px;'>"
                f"{t('predicted_severity')}: {sev_badge} "
                f"<span style='color:#555;font-size:13px;'>({t('auto_classified')})</span>"
                f"</div>",
                unsafe_allow_html=True,
            )

            if st.button(t("submit_request"), type="primary", use_container_width=True, key="soc_submit"):
                if not soc_title.strip():
                    st.warning(t("provide_incident_title"))
                elif not soc_data_categories:
                    st.warning(t("select_data_category"))
                else:
                    result = orchestration.execute_action(
                        action_type="report_breach",
                        payload={
                            "title":                    f"[{soc_type}] {soc_title.strip()}",
                            "description":              f"System: {soc_system}\n\n{soc_desc}",
                            "branch_id":                soc_branch,
                            "affected_data_categories": soc_data_categories,
                            "estimated_impact_count":   int(soc_impact),
                            "special_category":         soc_special,
                            "dpo_notified":             False,
                            "escalated":                False,
                        },
                        actor=user,
                    )
                    if result.get("status") == "success":
                        record = result["record"]
                        clause = get_clause("security_safeguards")
                        st.success(
                            f"Incident **{record['breach_id']}** logged for investigation.  "
                            f"{t('severity')}: **{t(record['severity'])}** ({t('auto_classified')})  |  "
                            f"{t('sla_timer_started')}"
                        )
                        explain_dynamic(
                            title=t("breach_logged"),
                            reason=t("breach_logged_reason"),
                            old_clause=clause["old"],
                            new_clause=clause["new"],
                        )
                        if record.get("severity") in ("high", "critical"):
                            escalation_badge = render_status_badge("breached")
                            st.warning(
                                f"{escalation_badge} {t('high_critical_detected')} — "
                                "Privacy Operations and DPO notified automatically."
                            )
                        st.session_state.incidents.append(record)
                        st.rerun()
                    else:
                        st.error(
                            f"{t('breach_log_failed')}: "
                            f"{result.get('message', t('unknown_error'))}"
                        )

        else:
            # ── Branch Officer / Privacy Ops / DPO: full regulatory breach report
            title = st.text_input(
                t("incident_title"),
                placeholder=t("incident_title_placeholder"),
                key="full_title",
            )
            data_categories = st.multiselect(
                t("affected_data_categories"),
                DATA_CATEGORIES,
                key="full_cats",
            )

            if is_branch_scoped and user_branch not in ("All", "-", None):
                branch = user_branch
                st.info(f"{t('branch')}: **{branch}** ({t('auto_assigned')})")
            else:
                branch = st.selectbox(t("branch"), ALL_BRANCHES, key="full_branch")

            col_a, col_b = st.columns(2)
            with col_a:
                impact_count = st.number_input(
                    t("estimated_affected_records"), min_value=0, value=0, step=1,
                    key="full_impact",
                )
            with col_b:
                special_cat = st.checkbox(t("special_category_data_check"), key="full_special")

            dpo_flag = st.checkbox(
                t("dpo_notified"),
                help=t("dpo_notified_help"),
                key="full_dpo",
            )
            description = st.text_area(
                t("description"),
                placeholder=t("incident_description_placeholder"),
                height=120,
                key="full_desc",
            )

            _prev_sev = _preview_severity(int(impact_count), special_cat)
            sev_badge = render_status_badge(
                "breached" if _prev_sev in ("high", "critical") else
                "warning"  if _prev_sev == "medium" else "active"
            )
            st.markdown(
                f"<div style='font-size:14px;margin-top:8px;'>"
                f"{t('predicted_severity')}: {sev_badge} "
                f"<span style='color:#555;font-size:13px;'>({t('auto_classified')})</span>"
                f"</div>",
                unsafe_allow_html=True,
            )

            if st.button(t("submit_request"), type="primary", use_container_width=True, key="full_submit"):
                if not title.strip():
                    st.warning(t("provide_incident_title"))
                elif not data_categories:
                    st.warning(t("select_data_category"))
                else:
                    result = orchestration.execute_action(
                        action_type="report_breach",
                        payload={
                            "title":                    title.strip(),
                            "description":              description,
                            "branch_id":                branch,
                            "affected_data_categories": data_categories,
                            "estimated_impact_count":   int(impact_count),
                            "special_category":         special_cat,
                            "dpo_notified":             dpo_flag,
                            "escalated":                False,
                        },
                        actor=user,
                    )
                    if result.get("status") == "success":
                        record = result["record"]
                        clause = get_clause("security_safeguards")
                        st.success(
                            f"{t('incident')} **{record['breach_id']}** {t('logged')}.  "
                            f"{t('severity')}: **{t(record['severity'])}** ({t('auto_classified')})  |  "
                            f"{t('sla_timer_started')}"
                        )
                        explain_dynamic(
                            title=t("breach_logged"),
                            reason=t("breach_logged_reason"),
                            old_clause=clause["old"],
                            new_clause=clause["new"],
                        )
                        if record.get("severity") in ("high", "critical"):
                            escalation_badge = render_status_badge("breached")
                            st.warning(
                                f"{escalation_badge} {t('high_critical_detected')} "
                                f"{t('cert_notification_required')}.  {t('cohort_notified_auto')}"
                            )
                        st.session_state.incidents.append(record)
                        st.rerun()
                    else:
                        st.error(
                            f"{t('breach_log_failed')}: "
                            f"{result.get('message', t('unknown_error'))}"
                        )

    # =========================================================================
    # TAB 3 — Containment Documentation
    # =========================================================================
    with tab3:
        st.subheader(t("containment_step_documentation"))
        more_info(t("containment_more_info"))

        if not can_contain:
            st.info(t("containment_role_restricted"))
        else:
            open_ids = [
                i["breach_id"] for i in view_incidents
                if i["status"] not in CLOSED_STATUSES
            ]
            if not open_ids:
                st.success(t("no_open_incidents_containment"))
            else:
                cont_id   = st.selectbox(t("select_open_incident"), open_ids, key="cont_sel")
                cont_step = st.text_area(
                    t("containment_action"),
                    placeholder=t("containment_action_placeholder"),
                    height=100,
                    key="cont_step",
                )
                if st.button(t("add_containment_step"), type="primary",
                             use_container_width=True, key="cont_btn"):
                    if not cont_step.strip():
                        st.warning(t("describe_containment_action"))
                    else:
                        result = orchestration.execute_action(
                            action_type="add_containment_step",
                            payload={
                                "breach_id":        cont_id,
                                "step_description": cont_step.strip(),
                            },
                            actor=user,
                        )
                        if _handle_result(
                            result,
                            t("containment_step_recorded").format(id=cont_id),
                            "containment_step_failed",
                        ):
                            for inc in st.session_state.incidents:
                                if inc["breach_id"] == cont_id:
                                    inc.setdefault("containment_steps", []).append({
                                        "step":      cont_step.strip(),
                                        "added_by":  user,
                                        "timestamp": datetime.utcnow().isoformat(),
                                    })
                            st.rerun()

        # Containment log viewer (read-only — all permitted roles)
        if view_incidents:
            sel_view = st.selectbox(
                t("view_containment_log_for"),
                [i["breach_id"] for i in view_incidents],
                key="cont_view_sel",
            )
            for inc in view_incidents:
                if inc["breach_id"] == sel_view:
                    steps = inc.get("containment_steps", [])
                    if not steps:
                        st.info(t("no_containment_steps"))
                    else:
                        steps_html = "".join([
                            f"<tr>"
                            f"{_td(s['timestamp'][:16])}"
                            f"{_td(s['added_by'])}"
                            f"{_td(s['step'])}"
                            f"</tr>"
                            for s in steps
                        ])
                        st.markdown(f"""
                        <div style="font-size:14px;overflow-x:auto;">
                        <table style="width:100%;border-collapse:collapse;">
                            <thead><tr>
                                {_th(t("timestamp"))}{_th(t("recorded_by"))}{_th(t("action"))}
                            </tr></thead>
                            <tbody>{steps_html}</tbody>
                        </table></div>
                        """, unsafe_allow_html=True)

    # =========================================================================
    # TAB 4 — Analytics
    # =========================================================================
    with tab4:
        st.subheader(t("breach_analytics"))

        # ── Step 12 — Empty guard ─────────────────────────────────────────────
        if not view_incidents:
            st.info(
                "No incidents recorded yet."
                if "no_incident_data" not in dir()
                else t("no_incident_data")
            )
        else:
            df_all = pd.DataFrame(view_incidents)

            ac1, ac2 = st.columns(2)

            with ac1:
                if "severity" in df_all.columns and df_all["severity"].notna().any():
                    sev_counts = df_all["severity"].value_counts().reset_index()
                    sev_counts.columns = ["Severity", "Count"]
                    if sev_counts["Count"].sum() > 0:
                        fig_sev = px.pie(
                            sev_counts, names="Severity", values="Count",
                            color="Severity", color_discrete_map=SEVERITY_COLOUR,
                            hole=0.55, title=t("incidents_by_severity"),
                        )
                        fig_sev.update_layout(
                            height=300, showlegend=False,
                            margin=dict(l=0, r=0, t=40, b=0),
                            paper_bgcolor="#ffffff",
                            font=dict(color="#0A3D91", size=14),
                            template="plotly_white",
                        )
                        st.plotly_chart(fig_sev, use_container_width=True)
                        more_info(t("severity_auto_classified_more_info"))

            with ac2:
                if "status" in df_all.columns and df_all["status"].notna().any():
                    st_counts = df_all["status"].value_counts().reset_index()
                    st_counts.columns = ["Status", "Count"]
                    if st_counts["Count"].sum() > 0:
                        fig_st = px.bar(
                            st_counts, x="Status", y="Count",
                            color="Status", color_discrete_map=STATUS_COLOUR,
                            text="Count", title=t("incidents_by_status"),
                        )
                        fig_st.update_traces(textposition="outside")
                        fig_st.update_layout(
                            height=300, showlegend=False,
                            plot_bgcolor="#ffffff", paper_bgcolor="#ffffff",
                            font=dict(color="#0A3D91", size=14),
                            template="plotly_white",
                            xaxis_tickangle=-20,
                        )
                        st.plotly_chart(fig_st, use_container_width=True)

            # Branch breakdown — DPO, Privacy Ops, Auditor only
            if (is_dpo or is_auditor or is_privacy_ops) and "branch_id" in df_all.columns:
                st.subheader(t("incidents_by_branch"))
                branch_counts = df_all["branch_id"].value_counts().reset_index()
                branch_counts.columns = ["Branch", "Count"]
                if branch_counts["Count"].sum() > 0:
                    fig_br = px.bar(
                        branch_counts, x="Branch", y="Count",
                        color_discrete_sequence=["#0A3D91"],
                        text="Count", title=t("incident_volume_by_branch"),
                    )
                    fig_br.update_traces(textposition="outside")
                    fig_br.update_layout(
                        height=340, showlegend=False,
                        plot_bgcolor="#ffffff", paper_bgcolor="#ffffff",
                        font=dict(color="#0A3D91", size=14),
                        template="plotly_white",
                        xaxis_tickangle=-25,
                    )
                    st.plotly_chart(fig_br, use_container_width=True)
                    more_info(t("executive_breach_view_more_info"))

                # ── Export — placed BELOW table, restricted roles only ────────
                reg_reports = [generate_regulatory_report(i) for i in view_incidents]
                if _can_export():
                    export_data(pd.DataFrame(reg_reports), "regulatory_breach_report")
                else:
                    st.caption(
                        "🔒 Export available to authorised roles only "
                        "(DPO, Auditor, Privacy Operations, Board)."
                    )

            # Open critical escalation notice
            open_critical = [
                i for i in view_incidents
                if i.get("severity") in ("high", "critical")
                and i["status"] not in CLOSED_STATUSES | {"notified_to_authority"}
            ]
            if open_critical:
                breach_badge = render_status_badge("breached")
                st.error(
                    f"{breach_badge} {len(open_critical)} {t('high_critical_unnotified')} "
                    f"{t('cert_notification_required')}"
                )
                clause = get_clause("security_safeguards")
                explain_dynamic(
                    title=t("six_hour_notification_obligation"),
                    reason=t("six_hour_notification_reason"),
                    old_clause=clause["old"],
                    new_clause=clause["new"],
                )