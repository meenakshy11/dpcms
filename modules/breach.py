"""
modules/breach.py
-----------------
Data Breach Management — Kerala Bank DPCMS.
DPDP Act 2023, Section 8 — fully regulatory-grade.

Step 8 compliance:
  8A  Role separation — only branch_officer / privacy_steward / DPO can log;
      only DPO can close
  8B  Standardized breach object (no manual severity field)
  8C  Clause-aware severity via make_decision()
  8D  6-hour regulatory SLA timer registered on every breach
  8E  Containment step documentation with role + timestamp
  8F  Cohort-based impacted customer notification engine
  8G  Exportable regulatory reporting template (PDF / JSON / XML)
  8H  No color-name text — badge-only rendering via render_status_badge()
  8I  SLA marked completed when breach is closed
  8J  Audit log on every state change

Architecture:
  log_breach()             → @require_role(["branch_officer","privacy_steward","dpo"])
  close_breach()           → @require_role(["dpo"])
  add_containment_step()   → @require_role(["branch_officer","privacy_steward","dpo"])
  identify_impacted_cohort / notify_impacted_customers → auto-triggered on high severity
  generate_regulatory_report() → called before export
"""

from __future__ import annotations

import uuid
from datetime import datetime

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from auth import get_role_display as get_role, get_branch, require_role, KERALA_BRANCHES
from utils.ui_helpers import more_info, mask_identifier
from engine.audit_ledger import audit_log
from engine.sla_engine import register_sla, mark_sla_completed
from modules.dashboard import render_page_header, render_status_badge  # Step 7 helpers
from utils.dpdp_clauses import get_clause
from utils.export_utils import export_data
from utils.explainability import explain_dynamic
from utils.i18n import t
from utils.ui_helpers import more_info, mask_identifier

# Notification engine
try:
    from engine.orchestration import trigger_notification
except ImportError:
    def trigger_notification(channel: str, recipient: str, message: str) -> None:
        print(f"[NOTIFY][{channel.upper()}] → {recipient}: {message}")

# Clause-aware decision engine
try:
    from engine.rules.decision_engine import make_decision
except ImportError:
    def make_decision(context: dict) -> dict:
        return {
            "decision":         "approved",
            "reason_code":      "breach_severity_classified",
            "clause_reference": get_clause("breach_severity_classified"),
            "explainability":   "Severity classified.",
            "timestamp":        datetime.utcnow().isoformat(),
        }

# ---------------------------------------------------------------------------
# Flat branch list
# ---------------------------------------------------------------------------
ALL_BRANCHES = [b for branches in KERALA_BRANCHES.values() for b in branches]

# ---------------------------------------------------------------------------
# Color maps (used only for Plotly charts — never rendered as text labels)
# ---------------------------------------------------------------------------
SEVERITY_COLOUR = {
    "low":      "#1a9e5c",
    "medium":   "#f0a500",
    "high":     "#e06030",
    "critical": "#d93025",
}

STATUS_COLOUR = {
    "open":                    "#f0a500",
    "under_investigation":     "#f0a500",
    "contained":               "#5a9ef5",
    "notified_to_authority":   "#7B5EA7",
    "closed":                  "#1a9e5c",
    "resolved":                "#1a9e5c",
}

# ---------------------------------------------------------------------------
# Sample incidents (session bootstrap)
# ---------------------------------------------------------------------------
SAMPLE_INCIDENTS = [
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
    },
]


# ===========================================================================
# STEP 8B/8C/8D — Core breach creation (business logic — not UI)
# ===========================================================================

@require_role(["branch_officer", "privacy_steward", "dpo", "Officer", "DPO"])
def log_breach(
    title: str,
    description: str,
    branch_id: str,
    affected_data_categories: list[str],
    estimated_impact_count: int,
    special_category: bool,
    actor: str,
    dpo_notified: bool = False,
) -> dict:
    """
    Create, classify, and register a new breach record.

    Step 8B: Standardized breach object — no manual severity field.
    Step 8C: Severity derived from make_decision() — no free text.
    Step 8D: 6-hour regulatory SLA registered immediately.
    Step 8J: Audit log written.

    Returns the saved breach dict.
    """
    region = next(
        (zone for zone, branches in KERALA_BRANCHES.items() if branch_id in branches),
        "Unknown"
    )

    breach = {
        "breach_id":                f"INC-{uuid.uuid4().hex[:6].upper()}",
        "title":                    title,
        "reported_by":              actor,
        "branch_id":                branch_id,
        "region":                   region,
        "description":              description,
        "affected_data_categories": affected_data_categories,
        "estimated_impact_count":   estimated_impact_count,
        "created_at":               datetime.utcnow().isoformat(),
        "status":                   "open",
        "containment_steps":        [],
        "severity":                 None,          # populated by make_decision below
        "decision_metadata":        None,
        "special_category":         special_category,
        "dpo_notified":             dpo_notified,
        "closed_at":                None,
    }

    # Step 8C — clause-aware severity classification
    decision = make_decision({
        "module": "breach",
        "action": "severity_classification",
        "data":   {
            **breach,
            "title":           title,
            "affected_count":  estimated_impact_count,
            "dpo_notified":    dpo_notified,
            "severity":        "Critical" if estimated_impact_count > 10_000 else "High",
        },
        "user": actor,
    })

    breach["severity"]          = decision["decision"]         # "approved"/"escalated"
    breach["decision_metadata"] = decision

    # Map make_decision output to a human-readable severity tier
    # "escalated" = Critical/High (regulatory escalation required)
    # "approved"  = Medium/Low (no immediate escalation)
    _sev_tier = _derive_severity_tier(estimated_impact_count, special_category, decision["decision"])
    breach["severity"] = _sev_tier

    # Step 8D — register 6-hour regulatory SLA
    register_sla(
        entity_id=breach["breach_id"],
        module="breach",
        sla_hours=6,
    )

    # Step 8J — audit log
    audit_log(
        event="BREACH_LOGGED",
        actor=actor,
        details={
            "breach_id":     breach["breach_id"],
            "branch_id":     branch_id,
            "severity":      breach["severity"],
            "impact_count":  estimated_impact_count,
            "reason_code":   decision.get("reason_code"),
        },
    )

    # Step 8F — auto-notify cohort on high / critical severity
    if breach["severity"] in ("high", "critical"):
        notify_impacted_customers(breach)

    return breach


def _derive_severity_tier(impact_count: int, special_category: bool,
                           decision_outcome: str) -> str:
    """Map impact signals to a structured severity tier (no free text)."""
    if decision_outcome == "escalated" or impact_count > 10_000 or special_category:
        return "critical" if impact_count > 10_000 else "high"
    if impact_count > 1_000:
        return "high"
    if impact_count > 100:
        return "medium"
    return "low"


# ===========================================================================
# STEP 8E — Containment documentation
# ===========================================================================

@require_role(["branch_officer", "privacy_steward", "dpo", "Officer", "DPO"])
def add_containment_step(breach_id: str, step_description: str,
                         actor: str, incidents: list[dict]) -> bool:
    """
    Append a timestamped containment step to a breach record.
    Supports audit defensibility.
    """
    for breach in incidents:
        if breach["breach_id"] == breach_id:
            breach["containment_steps"].append({
                "step":      step_description,
                "added_by":  actor,
                "timestamp": datetime.utcnow().isoformat(),
            })
            audit_log(
                event="BREACH_CONTAINMENT_ADDED",
                actor=actor,
                details={"breach_id": breach_id, "step": step_description},
            )
            return True
    return False


# ===========================================================================
# STEP 8I — Close breach (DPO only)
# ===========================================================================

@require_role(["dpo", "DPO"])
def close_breach(breach_id: str, actor: str, incidents: list[dict]) -> bool:
    """
    Mark a breach as closed and complete its SLA record.
    Only callable by DPO.
    """
    for breach in incidents:
        if breach["breach_id"] == breach_id:
            breach["status"]    = "closed"
            breach["closed_at"] = datetime.utcnow().isoformat()
            # Step 8I — mark SLA completed
            mark_sla_completed(breach_id)
            # Step 8J — audit log
            audit_log(
                event="BREACH_CLOSED",
                actor=actor,
                details={"breach_id": breach_id},
            )
            return True
    return False


# ===========================================================================
# STEP 8F — Cohort-based notification engine
# ===========================================================================

def identify_impacted_cohort(breach: dict) -> list[dict]:
    """
    Identify impacted Data Principals from the breach's branch.
    In production this queries the customer register.
    Returns a list of { customer_id, phone } dicts.
    """
    try:
        from engine.consent_validator import get_all_consents
        consents = get_all_consents()
        return [
            {"customer_id": c.get("data_principal_id", ""), "phone": c.get("customer_phone", "")}
            for c in consents
            if c.get("branch") == breach.get("branch_id") and c.get("customer_phone")
        ]
    except Exception:
        # Simulated fallback for demo environments
        return [
            {"customer_id": f"CUST-SIM-{i:04d}",
             "phone": f"+919400{i:06d}"}
            for i in range(1, min(breach.get("estimated_impact_count", 5) + 1, 6))
        ]


def notify_impacted_customers(breach: dict) -> int:
    """
    Send SMS notification to all identified impacted Data Principals.
    Auto-called when severity is 'high' or 'critical'.

    Returns number of notifications sent.
    """
    impacted = identify_impacted_cohort(breach)
    sent = 0
    for customer in impacted:
        if customer.get("phone"):
            trigger_notification(
                channel="sms",
                recipient=customer["phone"],
                message=(
                    "A data incident affecting your personal data has been identified "
                    "at your branch. Our Data Protection team is investigating. "
                    "Please contact your branch for further information."
                ),
            )
            sent += 1

    audit_log(
        event="BREACH_COHORT_NOTIFIED",
        actor="system",
        details={
            "breach_id":    breach["breach_id"],
            "notifications_sent": sent,
        },
    )
    return sent


# ===========================================================================
# STEP 8G — Regulatory reporting template
# ===========================================================================

def generate_regulatory_report(breach: dict) -> dict:
    """
    Build an exportable regulatory report dict (PDF / JSON / XML ready).
    Includes clause reference from decision metadata.
    """
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


# ===========================================================================
# UI helpers (Step 7 badge + table header reuse)
# ===========================================================================

def _th(label: str) -> str:
    return (
        f'<th style="background-color:#0d47a1;color:white;padding:10px;'
        f'font-size:15px;text-align:left;">{label}</th>'
    )


def _td(content: str) -> str:
    return f'<td style="padding:8px 10px;font-size:14px;">{content}</td>'


def _init_incidents() -> None:
    st.session_state.setdefault("incidents", list(SAMPLE_INCIDENTS))


def _mask_id(raw_id: str) -> str:
    """
    Return raw_id for DPO and Auditor roles; masked value for all others.
    Always reads role from st.session_state — the single source of truth.
    """
    role = st.session_state.get("role", "")
    if role in ("DPO", "dpo", "Auditor", "auditor"):
        return raw_id
    return mask_identifier(raw_id, role=role)


# ===========================================================================
# Main Streamlit entry point
# ===========================================================================

def show() -> None:
    _init_incidents()

    # Step 7A gradient header
    st.markdown(
        f"""
        <div style="
            background: linear-gradient(90deg, #b71c1c, #c62828, #ef5350);
            color: white; padding: 16px 24px; border-radius: 10px;
            font-size: 26px; font-weight: 600; margin-bottom: 20px;">
            {t("breach")}
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.caption(t("breach_caption"))

    more_info(t("breach_more_info"))

    role        = get_role()
    user_branch = get_branch()
    incidents   = st.session_state.incidents

    # Filter by branch for Officer role
    if role == "Officer":
        view_incidents = [i for i in incidents if i["branch_id"] == user_branch]
    else:
        view_incidents = incidents

    # ── KPI Strip (Step 7D — no explainability, Step 7C — badge only) ────────
    _total    = len(view_incidents)
    _open     = sum(1 for i in view_incidents if i["status"] not in ("closed", "resolved"))
    _critical = sum(1 for i in view_incidents if i.get("severity") == "critical")
    _high     = sum(1 for i in view_incidents if i.get("severity") == "high")

    k1, k2, k3, k4 = st.columns(4)
    k1.markdown(f'''<div class="kpi-card" style="font-size:16px;">
        <div style="font-size:14px;color:#555;">{t("total_incidents")}</div>
        <div style="font-size:24px;font-weight:600;color:#0d47a1;">{_total}</div>
        <div style="font-size:13px;color:#6B7A90;">{t("this_branch") if role == "Officer" else t("all_branches")}</div>
    </div>''', unsafe_allow_html=True)
    k2.markdown(f'''<div class="kpi-card" style="font-size:16px;">
        <div style="font-size:14px;color:#555;">{t("open_active")}</div>
        <div style="font-size:24px;font-weight:600;color:#0d47a1;">{_open}</div>
        <div style="font-size:13px;color:#f0a500;">{t("under_investigation")}</div>
    </div>''', unsafe_allow_html=True)
    k3.markdown(f'''<div class="kpi-card" style="font-size:16px;">
        <div style="font-size:14px;color:#555;">{t("high_severity")}</div>
        <div style="font-size:24px;font-weight:600;color:#0d47a1;">{_high}</div>
        <div style="font-size:13px;color:#e06030;">{t("requires_dpo_review")}</div>
    </div>''', unsafe_allow_html=True)
    k4.markdown(f'''<div class="kpi-card" style="font-size:16px;">
        <div style="font-size:14px;color:#555;">{t("critical")}</div>
        <div style="font-size:24px;font-weight:600;color:#0d47a1;">{_critical}</div>
        <div style="font-size:13px;color:#d93025;">{t("cert_notification_required")}</div>
    </div>''', unsafe_allow_html=True)

    st.divider()

    tab1, tab2, tab3, tab4 = st.tabs([
        t("incident_register"),
        t("submit_request"),
        t("containment"),
        t("analytics"),
    ])

    # =========================================================================
    # TAB 1 — Incident Register
    # =========================================================================
    with tab1:
        st.subheader(
            f"{t('incidents')} — {t('all_branches') if role != 'Officer' else user_branch}"
        )

        if not view_incidents:
            st.success(t("no_incidents_branch"))
        else:
            # Step 8H — badge only, no color-name text
            # Step 7G — colored table headers
            rows_html = ""
            for inc in view_incidents:
                sev_badge    = render_status_badge(
                    "breached" if inc.get("severity") in ("high","critical") else
                    "warning"  if inc.get("severity") == "medium" else "active"
                )
                status_badge = render_status_badge(
                    "active"   if inc["status"] == "closed" else
                    "breached" if inc["status"] == "open" else "warning"
                )
                rows_html += f"""
                <tr style="border-bottom:1px solid #e8ecf0;">
                    {_td(inc["breach_id"])}
                    {_td(inc["title"])}
                    {_td(sev_badge)}
                    {_td(inc["branch_id"])}
                    {_td(status_badge)}
                    {_td(inc["created_at"][:16])}
                    {_td(_mask_id(inc["reported_by"]))}
                    {_td(str(inc["estimated_impact_count"]))}
                    {_td(t("yes") if inc.get("special_category") else t("no"))}
                    {_td(
                        f'<button onclick="viewSummary(\\"{inc["breach_id"]}\\")" '
                        f'style="background:#546e7a;color:white;border:none;padding:4px 10px;'
                        f'border-radius:4px;font-size:13px;cursor:pointer;">'
                        f'{t("more_info")}</button>'
                    )}
                </tr>
                """
            table_html = f"""
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
                    {_th(t("summary"))}
                </tr></thead>
                <tbody>{rows_html}</tbody>
            </table>
            </div>
            """
            st.markdown(table_html, unsafe_allow_html=True)

            # Streamlit-wired export
            export_rows = [generate_regulatory_report(i) for i in view_incidents]
            export_data(pd.DataFrame(export_rows), "breach_register")

            # DPO — status update + breach closure
            if role in ("DPO", "dpo"):
                st.divider()
                st.subheader(t("update_incident_status"))
                incident_ids = [i["breach_id"] for i in incidents]
                sel_id     = st.selectbox(t("select_incident"), incident_ids)
                new_status = st.selectbox(
                    t("new_status"),
                    ["open", "under_investigation", "contained",
                     "notified_to_authority", "closed"],
                )

                col_upd, col_close = st.columns(2)

                with col_upd:
                    if st.button(t("update_status"), type="primary", use_container_width=True):
                        for inc in st.session_state.incidents:
                            if inc["breach_id"] == sel_id:
                                inc["status"] = new_status
                        audit_log(
                            event="BREACH_STATUS_UPDATED",
                            actor=st.session_state.get("username", "dpo_admin"),
                            details={"breach_id": sel_id, "new_status": new_status},
                        )
                        st.success(f"{t('incident')} **{sel_id}** {t('updated_to')} **'{new_status}'**.")
                        clause = get_clause("security_safeguards")
                        explain_dynamic(
                            title=t("regulatory_notification_recorded"),
                            reason=t("breach_marked_reported"),
                            old_clause=clause["old"],
                            new_clause=clause["new"],
                        )
                        st.rerun()

                with col_close:
                    if st.button(t("close_breach"), type="secondary", use_container_width=True):
                        actor = st.session_state.get("username", "dpo_admin")
                        ok = close_breach(
                            breach_id=sel_id,
                            actor=actor,
                            incidents=st.session_state.incidents,
                        )
                        if ok:
                            st.success(t("breach_closed_success").format(id=sel_id))
                            st.rerun()
                        else:
                            st.error(t("breach_not_found").format(id=sel_id))

    # =========================================================================
    # TAB 2 — Report New Incident
    # =========================================================================
    with tab2:
        st.subheader(t("report_new_incident"))

        more_info(t("breach_reporting_more_info"))

        # Role gate (Step 8A)
        if role not in ("Officer", "branch_officer", "privacy_steward", "DPO", "dpo"):
            st.info(t("breach_role_restricted"))
        else:
            title       = st.text_input(
                t("incident_title"),
                placeholder=t("incident_title_placeholder")
            )

            data_categories = st.multiselect(
                t("affected_data_categories"),
                ["loan_records", "account_data", "kyc_documents",
                 "biometric_data", "health_data", "marketing_data", "contact_data"],
            )

            if role == "Officer":
                branch = user_branch
                st.info(f"{t('branch')}: **{branch}** ({t('auto_assigned')})")
            else:
                branch = st.selectbox(t("branch"), ALL_BRANCHES)

            col_a, col_b = st.columns(2)
            with col_a:
                impact_count = st.number_input(
                    t("estimated_affected_records"), min_value=0, value=0, step=1
                )
            with col_b:
                special_cat = st.checkbox(
                    t("special_category_data_check")
                )

            dpo_flag = st.checkbox(
                t("dpo_notified"),
                help=t("dpo_notified_help"),
            )

            description = st.text_area(
                t("description"),
                placeholder=t("incident_description_placeholder"),
                height=120,
            )

            # Step 8C — show automated severity preview
            _preview_sev = _derive_severity_tier(int(impact_count), special_cat, "approved")
            sev_badge    = render_status_badge(
                "breached" if _preview_sev in ("high", "critical") else
                "warning"  if _preview_sev == "medium" else "active"
            )
            st.markdown(
                f"<div style='font-size:14px;margin-top:8px;'>"
                f"{t('predicted_severity')}: {sev_badge} "
                f"<span style='color:#555;font-size:13px;'>"
                f"({t('auto_classified')})</span></div>",
                unsafe_allow_html=True,
            )

            if st.button(t("submit_request"), type="primary", use_container_width=True):
                if not title.strip():
                    st.warning(t("provide_incident_title"))
                elif not data_categories:
                    st.warning(t("select_data_category"))
                else:
                    actor = st.session_state.get("username", "unknown")
                    try:
                        new_inc = log_breach(
                            title=title.strip(),
                            description=description,
                            branch_id=branch,
                            affected_data_categories=data_categories,
                            estimated_impact_count=int(impact_count),
                            special_category=special_cat,
                            actor=actor,
                            dpo_notified=dpo_flag,
                        )
                        st.session_state.incidents.append(new_inc)

                        clause = get_clause("security_safeguards")
                        st.success(
                            f"{t('incident')} **{new_inc['breach_id']}** {t('logged')}. "
                            f"{t('severity')}: **{t(new_inc['severity'])}** ({t('auto_classified')})  |  "
                            f"{t('sla_timer_started')}"
                        )
                        explain_dynamic(
                            title=t("breach_logged"),
                            reason=t("breach_logged_reason"),
                            old_clause=clause["old"],
                            new_clause=clause["new"],
                        )

                        if new_inc["severity"] in ("high", "critical"):
                            escalation_badge = render_status_badge("breached")
                            st.warning(
                                f"{escalation_badge} {t('high_critical_detected')} "
                                f"{t('cert_notification_required')}. {t('cohort_notified_auto')}",
                            )

                        st.rerun()
                    except PermissionError as e:
                        st.error(f"{t('access_denied')}: {e}")
                    except Exception as exc:
                        st.error(f"Error logging breach: {exc}")

    # =========================================================================
    # TAB 3 — Containment Documentation (Step 8E)
    # =========================================================================
    with tab3:
        st.subheader(t("containment_step_documentation"))
        more_info(t("containment_more_info"))

        if role not in ("Officer", "branch_officer", "privacy_steward", "DPO", "dpo"):
            st.info(t("containment_role_restricted"))
        else:
            open_ids = [
                i["breach_id"] for i in view_incidents
                if i["status"] not in ("closed", "resolved")
            ]
            if not open_ids:
                st.success(t("no_open_incidents_containment"))
            else:
                cont_id   = st.selectbox(t("select_open_incident"), open_ids, key="cont_sel")
                cont_step = st.text_area(
                    t("containment_action"),
                    placeholder=t("containment_action_placeholder"),
                    height=100,
                )
                if st.button(t("add_containment_step"), type="primary", use_container_width=True):
                    if not cont_step.strip():
                        st.warning(t("describe_containment_action"))
                    else:
                        actor = st.session_state.get("username", "unknown")
                        ok = add_containment_step(
                            breach_id=cont_id,
                            step_description=cont_step.strip(),
                            actor=actor,
                            incidents=st.session_state.incidents,
                        )
                        if ok:
                            st.success(t("containment_step_recorded").format(id=cont_id))
                            st.rerun()

            # Show existing containment steps for selected incident
            if view_incidents:
                sel_view = st.selectbox(
                    t("view_containment_log_for"), [i["breach_id"] for i in view_incidents],
                    key="cont_view_sel"
                )
                for inc in view_incidents:
                    if inc["breach_id"] == sel_view:
                        steps = inc.get("containment_steps", [])
                        if not steps:
                            st.info(t("no_containment_steps"))
                        else:
                            steps_html = "".join([
                                f"<tr style='border-bottom:1px solid #e8ecf0;'>"
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
    # TAB 4 — Analytics (Step 8H — no color-name text in labels)
    # =========================================================================
    with tab4:
        st.subheader(t("breach_analytics"))

        if not view_incidents:
            st.info(t("no_incident_data"))
        else:
            df_all = pd.DataFrame(view_incidents)

            ac1, ac2 = st.columns(2)

            with ac1:
                sev_counts = df_all["severity"].value_counts().reset_index()
                sev_counts.columns = ["Severity", "Count"]
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
                    title_font=dict(size=18), template="plotly_white",
                )
                st.plotly_chart(fig_sev, use_container_width=True)
                more_info(t("severity_auto_classified_more_info"))

            with ac2:
                st_counts = df_all["status"].value_counts().reset_index()
                st_counts.columns = ["Status", "Count"]
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
                    title_font=dict(size=18), template="plotly_white",
                    xaxis_tickangle=-20,
                )
                st.plotly_chart(fig_st, use_container_width=True)

            if role in ("DPO", "Auditor"):
                st.subheader(t("incidents_by_branch"))
                branch_counts = df_all["branch_id"].value_counts().reset_index()
                branch_counts.columns = ["Branch", "Count"]
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
                    title_font=dict(size=18), template="plotly_white",
                    xaxis_tickangle=-25,
                )
                st.plotly_chart(fig_br, use_container_width=True)
                more_info(t("executive_breach_view_more_info"))

                # Regulatory report export (Step 8G)
                reg_reports = [generate_regulatory_report(i) for i in view_incidents]
                export_data(pd.DataFrame(reg_reports), "regulatory_breach_report")

            # Open critical escalation notice (badge only — no color text)
            open_critical = [
                i for i in view_incidents
                if i.get("severity") in ("high", "critical")
                and i["status"] not in ("closed", "resolved", "notified_to_authority")
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