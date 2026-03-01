"""
modules/dpia.py
---------------
Data Protection Impact Assessment (DPIA) — Kerala Bank DPCMS.
DPDP Act 2023, Section 9 & 10 — fully governance-grade.

Step 9 compliance:
  9A  Role-based access — create: Officer/privacy_steward;
      approve: privacy_steward/DPO; final override: DPO only; Board: read-only
  9B  Standardised DPIA object — no manual risk level entry
  9C  Automated risk scoring via calculate_risk_score()
  9D  Clause-aware risk classification via make_decision()
  9E  SLA registration on creation (14 days standard; 7 days high-risk)
  9F  Multi-level workflow stages — initiated → under_review →
      steward_approved → dpo_approved → rejected → closed
  9G  High-risk auto-escalation — SMS to DPO + force to under_review
  9H  Periodic review scheduling — next_review_date + 180-day SLA
  9I  Review reminder — sla_engine handles dpia_review module notifications
  9J  Risk badge only — no color-name text rendered anywhere
  9K  Audit logging on every state change

Architecture:
  create_dpia()          → @require_role(officer / privacy_steward)
  approve_dpia()         → @require_role(privacy_steward / DPO)
  final_approval()       → @require_role(DPO only)
  add_mitigation()       → @require_role(officer / privacy_steward / DPO)
  generate_dpia_report() → exportable regulatory template
  show()                 → Streamlit UI entry point
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from auth import get_role, get_branch, require_role, KERALA_BRANCHES
from engine.audit_ledger import audit_log
from engine.sla_engine import register_sla, mark_sla_completed
from modules.dashboard import render_page_header, render_status_badge
from utils.dpdp_clauses import get_clause
from utils.export_utils import export_data
from utils.explainability import explain, explain_dynamic
from utils.i18n import t
from utils.ui_helpers import more_info

# Notification engine
try:
    from engine.orchestration import trigger_notification, get_dpo_contact, get_privacy_steward_contact
except ImportError:
    def trigger_notification(channel: str, recipient: str, message: str) -> None:
        print(f"[NOTIFY][{channel.upper()}] → {recipient}: {message}")
    def get_dpo_contact() -> str:
        return st.session_state.get("dpo_phone", "+919400000001")
    def get_privacy_steward_contact() -> str:
        return st.session_state.get("steward_phone", "+919400000002")

# Clause-aware decision engine
try:
    from engine.rules.decision_engine import make_decision
except ImportError:
    def make_decision(context: dict) -> dict:
        data  = context.get("data", {})
        score = data.get("risk_score", 0)
        if score >= 70:
            decision    = "escalated"
            reason_code = "dpia_critical_requires_dpo"
        elif score >= 40:
            decision    = "rejected"
            reason_code = "dpia_mitigation_missing"
        else:
            decision    = "approved"
            reason_code = "dpia_risk_evaluated"
        return {
            "decision":         decision,
            "reason_code":      reason_code,
            "clause_reference": get_clause(reason_code),
            "explainability":   f"Risk score {score} → {decision}.",
            "timestamp":        datetime.utcnow().isoformat(),
        }


# ===========================================================================
# Constants — internal English keys; NEVER translate these
# ===========================================================================

WORKFLOW_STAGES = [
    "initiated",
    "under_review",
    "steward_approved",
    "dpo_approved",
    "rejected",
    "closed",
]

STAGE_PERMISSIONS: dict[str, list[str]] = {
    "under_review":      ["Officer", "branch_officer", "privacy_steward", "DPO"],
    "steward_approved":  ["privacy_steward", "DPO"],
    "dpo_approved":      ["DPO"],
    "rejected":          ["privacy_steward", "DPO"],
    "closed":            ["DPO"],
}

ALL_BRANCHES = [b for branches in KERALA_BRANCHES.values() for b in branches]

# Colour maps — Plotly internal only, never rendered as text
_RISK_COLOUR = {
    "low":       "#1a9e5c",
    "medium":    "#f0a500",
    "high":      "#e06030",
    "critical":  "#d93025",
    "escalated": "#d93025",
    "approved":  "#1a9e5c",
    "rejected":  "#e06030",
}

_STAGE_COLOUR = {
    "initiated":        "#5a9ef5",
    "under_review":     "#f0a500",
    "steward_approved": "#1a9e5c",
    "dpo_approved":     "#1a9e5c",
    "rejected":         "#d93025",
    "closed":           "#546e7a",
}

# i18n key maps for display
_RISK_LEVEL_I18N = {
    "low":       "low",
    "medium":    "medium",
    "high":      "high",
    "critical":  "critical",
    "escalated": "escalated",
}

_STAGE_I18N = {
    "initiated":        "stage_initiated",
    "under_review":     "stage_under_review",
    "steward_approved": "stage_steward_approved",
    "dpo_approved":     "stage_dpo_approved",
    "rejected":         "stage_rejected",
    "closed":           "stage_closed",
}

def _t_stage(internal: str) -> str:
    return t(_STAGE_I18N.get(internal, internal))

def _t_risk(internal: str) -> str:
    return t(_RISK_LEVEL_I18N.get(internal.lower(), internal.lower()))


# Sample data for session bootstrap
SAMPLE_DPIAS = [
    {
        "dpia_id":                "DPIA-001",
        "title":                  "Biometric Authentication Rollout",
        "initiated_by":           "officer_01",
        "branch_id":              "Ernakulam Central",
        "region":                 "Central Zone",
        "processing_description": "Fingerprint biometric authentication for all branch transactions.",
        "third_parties_involved": ["FingerTech Solutions Pvt Ltd"],
        "data_categories":        ["biometric_data", "account_data"],
        "risk_score":             80,
        "risk_level":             "high",
        "workflow_stage":         "under_review",
        "approval_history":       [],
        "mitigation_actions":     [],
        "created_at":             "2026-02-10T10:00:00",
        "next_review_date":       None,
        "decision_metadata":      None,
        "closed_at":              None,
    },
    {
        "dpia_id":                "DPIA-002",
        "title":                  "Customer Profiling for Loan Offers",
        "initiated_by":           "officer_03",
        "branch_id":              "Kottayam Main",
        "region":                 "Central Zone",
        "processing_description": "Automated credit profiling using transaction history.",
        "third_parties_involved": [],
        "data_categories":        ["loan_records", "account_data"],
        "risk_score":             35,
        "risk_level":             "medium",
        "workflow_stage":         "steward_approved",
        "approval_history":       [
            {"approved_by": "privacy_steward_01", "stage": "under_review",
             "timestamp": "2026-02-15T14:00:00"},
        ],
        "mitigation_actions":     [
            {"action": "Data minimisation policy applied.", "added_by": "privacy_steward_01",
             "timestamp": "2026-02-15T13:45:00"},
        ],
        "created_at":             "2026-02-12T09:00:00",
        "next_review_date":       None,
        "decision_metadata":      None,
        "closed_at":              None,
    },
]


# ===========================================================================
# STEP 9C — Automated risk scoring
# ===========================================================================

def calculate_risk_score(dpia: dict) -> int:
    score = 0
    desc  = (dpia.get("processing_description") or "").lower()
    cats  = [c.lower() for c in dpia.get("data_categories", [])]

    if dpia.get("third_parties_involved"):
        score += 20
    if "sensitive" in desc or "special" in desc:
        score += 30
    if "biometric" in desc or "biometric_data" in cats:
        score += 40
    if any(c in cats for c in ("health_data", "financial_data", "kyc_documents")):
        score += 15
    if dpia.get("estimated_volume", 0) > 50_000:
        score += 10

    return min(score, 100)


def _derive_risk_level(score: int) -> str:
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


# ===========================================================================
# STEP 9A/9B/9D/9E/9G/9K — Core DPIA creation
# ===========================================================================

@require_role(["Officer", "branch_officer", "privacy_steward"])
def create_dpia(
    title: str,
    processing_description: str,
    branch_id: str,
    third_parties: list[str],
    data_categories: list[str],
    estimated_volume: int,
    actor: str,
) -> dict:
    region = next(
        (zone for zone, branches in KERALA_BRANCHES.items() if branch_id in branches),
        "Unknown"
    )

    dpia: dict = {
        "dpia_id":                f"DPIA-{uuid.uuid4().hex[:6].upper()}",
        "title":                  title,
        "initiated_by":           actor,
        "branch_id":              branch_id,
        "region":                 region,
        "processing_description": processing_description,
        "third_parties_involved": third_parties,
        "data_categories":        data_categories,
        "estimated_volume":       estimated_volume,
        "risk_score":             None,
        "risk_level":             None,
        "workflow_stage":         "initiated",
        "approval_history":       [],
        "mitigation_actions":     [],
        "created_at":             datetime.utcnow().isoformat(),
        "next_review_date":       None,
        "decision_metadata":      None,
        "closed_at":              None,
    }

    dpia["risk_score"] = calculate_risk_score(dpia)

    decision = make_decision({
        "module": "dpia",
        "action": "risk_evaluation",
        "data":   {**dpia, "mitigation_actions": dpia["mitigation_actions"]},
        "user":   actor,
    })
    dpia["decision_metadata"] = decision
    dpia["risk_level"]        = _derive_risk_level(dpia["risk_score"])

    sla_days = 7 if dpia["risk_level"] in ("high", "critical") else 14
    register_sla(entity_id=dpia["dpia_id"], module="dpia", sla_days=sla_days)

    if dpia["risk_level"] in ("high", "critical"):
        dpia["workflow_stage"] = "under_review"
        try:
            trigger_notification(
                channel="sms",
                recipient=get_dpo_contact(),
                message=(
                    f"High-risk DPIA '{title}' ({dpia['dpia_id']}) requires "
                    f"immediate review. Risk score: {dpia['risk_score']}."
                ),
            )
        except Exception:
            pass

    audit_log(
        event="DPIA_CREATED",
        actor=actor,
        details={
            "dpia_id":    dpia["dpia_id"],
            "branch_id":  branch_id,
            "risk_score": dpia["risk_score"],
            "risk_level": dpia["risk_level"],
            "sla_days":   sla_days,
        },
    )

    return dpia


# ===========================================================================
# STEP 9F — Multi-level workflow transitions
# ===========================================================================

@require_role(["privacy_steward", "DPO"])
def approve_dpia(dpia_id: str, dpias: list[dict], actor: str, actor_role: str) -> bool:
    for dpia in dpias:
        if dpia["dpia_id"] != dpia_id:
            continue
        current = dpia["workflow_stage"]
        if actor_role in ("privacy_steward",) and current == "under_review":
            target = "steward_approved"
        elif actor_role == "DPO" and current in ("under_review", "steward_approved"):
            target = "dpo_approved"
        else:
            return False

        dpia["approval_history"].append({
            "approved_by": actor,
            "stage":       current,
            "timestamp":   datetime.utcnow().isoformat(),
        })
        dpia["workflow_stage"] = target

        if target == "dpo_approved":
            _schedule_periodic_review(dpia)

        audit_log(
            event="DPIA_APPROVED",
            actor=actor,
            details={"dpia_id": dpia_id, "new_stage": target},
        )
        return True
    return False


@require_role(["DPO"])
def final_approval(dpia_id: str, dpias: list[dict], actor: str) -> bool:
    for dpia in dpias:
        if dpia["dpia_id"] != dpia_id:
            continue
        if dpia["workflow_stage"] in ("dpo_approved", "closed", "rejected"):
            return False
        prev_stage = dpia["workflow_stage"]
        dpia["approval_history"].append({
            "approved_by": actor,
            "stage":       prev_stage,
            "timestamp":   datetime.utcnow().isoformat(),
            "override":    True,
        })
        dpia["workflow_stage"] = "dpo_approved"
        _schedule_periodic_review(dpia)
        audit_log(
            event="DPIA_FINAL_OVERRIDE",
            actor=actor,
            details={"dpia_id": dpia_id, "previous_stage": prev_stage},
        )
        return True
    return False


@require_role(["privacy_steward", "DPO"])
def reject_dpia(dpia_id: str, dpias: list[dict], actor: str, reason: str) -> bool:
    for dpia in dpias:
        if dpia["dpia_id"] != dpia_id:
            continue
        if dpia["workflow_stage"] in ("dpo_approved", "closed", "rejected"):
            return False
        dpia["workflow_stage"] = "rejected"
        dpia["approval_history"].append({
            "approved_by": actor,
            "stage":       "rejected",
            "reason":      reason,
            "timestamp":   datetime.utcnow().isoformat(),
        })
        audit_log(
            event="DPIA_REJECTED",
            actor=actor,
            details={"dpia_id": dpia_id, "reason": reason},
        )
        return True
    return False


@require_role(["DPO"])
def close_dpia(dpia_id: str, dpias: list[dict], actor: str) -> bool:
    for dpia in dpias:
        if dpia["dpia_id"] != dpia_id:
            continue
        dpia["workflow_stage"] = "closed"
        dpia["closed_at"]      = datetime.utcnow().isoformat()
        mark_sla_completed(dpia_id)
        audit_log(event="DPIA_CLOSED", actor=actor, details={"dpia_id": dpia_id})
        return True
    return False


# ===========================================================================
# STEP 9E — Mitigation action documentation
# ===========================================================================

@require_role(["Officer", "branch_officer", "privacy_steward", "DPO"])
def add_mitigation(dpia_id: str, action_text: str, dpias: list[dict], actor: str) -> bool:
    for dpia in dpias:
        if dpia["dpia_id"] != dpia_id:
            continue
        dpia["mitigation_actions"].append({
            "action":    action_text,
            "added_by":  actor,
            "timestamp": datetime.utcnow().isoformat(),
        })
        audit_log(
            event="DPIA_MITIGATION_ADDED",
            actor=actor,
            details={"dpia_id": dpia_id, "action": action_text},
        )
        return True
    return False


# ===========================================================================
# STEP 9H — Periodic review scheduling
# ===========================================================================

def _schedule_periodic_review(dpia: dict) -> None:
    dpia["next_review_date"] = (datetime.utcnow() + timedelta(days=180)).isoformat()
    register_sla(entity_id=dpia["dpia_id"], module="dpia_review", sla_days=180)


# ===========================================================================
# Regulatory report template
# ===========================================================================

def generate_dpia_report(dpia: dict) -> dict:
    clause_ref = {}
    if dpia.get("decision_metadata"):
        clause_ref = dpia["decision_metadata"].get("clause_reference", {})

    return {
        "DPIA ID":             dpia["dpia_id"],
        "Title":               dpia["title"],
        "Initiated By":        dpia["initiated_by"],
        "Branch":              dpia["branch_id"],
        "Region":              dpia.get("region", ""),
        "Processing Purpose":  dpia["processing_description"],
        "Data Categories":     ", ".join(dpia.get("data_categories", [])),
        "Third Parties":       ", ".join(dpia.get("third_parties_involved", [])),
        "Estimated Volume":    dpia.get("estimated_volume", 0),
        "Risk Score":          dpia.get("risk_score"),
        "Risk Level":          dpia.get("risk_level"),
        "Workflow Stage":      dpia["workflow_stage"],
        "Created At":          dpia["created_at"],
        "Next Review Date":    dpia.get("next_review_date") or "—",
        "Closed At":           dpia.get("closed_at") or "—",
        "Mitigation Actions":  [
            f"[{m['timestamp'][:16]}] {m['added_by']}: {m['action']}"
            for m in dpia.get("mitigation_actions", [])
        ],
        "Approval History":    [
            f"[{a['timestamp'][:16]}] {a['approved_by']} — {a['stage']}"
            for a in dpia.get("approval_history", [])
        ],
        "Clause Act":          clause_ref.get("act", "DPDP Act 2023"),
        "Clause Section":      clause_ref.get("section", "Section 9"),
        "Clause Rule":         clause_ref.get("rule", ""),
        "Clause Amendment":    clause_ref.get("amendment", ""),
    }


# ===========================================================================
# UI helpers
# ===========================================================================

def _th(label: str) -> str:
    return (
        f'<th style="background-color:#0d47a1;color:white;padding:10px;'
        f'font-size:15px;text-align:left;">{label}</th>'
    )


def _td(content: str) -> str:
    return f'<td style="padding:8px 10px;font-size:14px;">{content}</td>'


def _risk_badge(risk_level: str) -> str:
    """Step 9J — badge dot only, no color-name text."""
    mapping = {
        "low":       "active",
        "medium":    "warning",
        "high":      "breached",
        "critical":  "breached",
        "escalated": "breached",
        "approved":  "active",
        "rejected":  "breached",
    }
    return render_status_badge(mapping.get((risk_level or "").lower(), "warning"))


def _stage_badge(stage: str) -> str:
    mapping = {
        "initiated":        "warning",
        "under_review":     "warning",
        "steward_approved": "active",
        "dpo_approved":     "active",
        "rejected":         "breached",
        "closed":           "active",
    }
    return render_status_badge(mapping.get(stage, "warning"))


def _score_colour(score: float) -> str:
    if score >= 90:
        return "#1a9e5c"
    elif score >= 75:
        return "#f0a500"
    return "#d93025"


def _score_label(score: float) -> str:
    if score >= 90:
        return t("compliant")
    elif score >= 75:
        return t("partial")
    return t("non_compliant")


def _init_dpias() -> None:
    st.session_state.setdefault("dpias", list(SAMPLE_DPIAS))


# ===========================================================================
# Main Streamlit entry point
# ===========================================================================

def show() -> None:
    _init_dpias()

    role        = get_role()
    user_branch = get_branch()
    dpias       = st.session_state.dpias

    # Gradient header
    st.markdown(
        f"""
        <div style="
            background: linear-gradient(90deg, #1a237e, #283593, #3949ab);
            color: white; padding: 16px 24px; border-radius: 10px;
            font-size: 26px; font-weight: 600; margin-bottom: 20px;">
            {t("dpia")}
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.caption(t("dpia_caption"))
    more_info(t("dpia_more_info"))

    # Role-filtered DPIA view
    if role == "Officer":
        view_dpias = [d for d in dpias if d["branch_id"] == user_branch]
    else:
        view_dpias = dpias

    # ── KPI Strip ─────────────────────────────────────────────────────────────
    _total     = len(view_dpias)
    _open      = sum(1 for d in view_dpias if d["workflow_stage"] not in ("dpo_approved", "closed", "rejected"))
    _high_risk = sum(1 for d in view_dpias if d.get("risk_level") in ("high", "critical", "escalated"))
    _overdue   = sum(
        1 for d in view_dpias
        if d.get("next_review_date") and
        datetime.fromisoformat(d["next_review_date"]) < datetime.utcnow()
    )

    k1, k2, k3, k4 = st.columns(4)
    k1.markdown(f'''<div class="kpi-card" style="font-size:16px;">
        <div style="font-size:14px;color:#555;">{t("total_dpias")}</div>
        <div style="font-size:24px;font-weight:600;color:#0d47a1;">{_total}</div>
        <div style="font-size:13px;color:#6B7A90;">{t("this_branch") if role == "Officer" else t("all_branches")}</div>
    </div>''', unsafe_allow_html=True)
    k2.markdown(f'''<div class="kpi-card" style="font-size:16px;">
        <div style="font-size:14px;color:#555;">{t("open_in_progress")}</div>
        <div style="font-size:24px;font-weight:600;color:#0d47a1;">{_open}</div>
        <div style="font-size:13px;color:#f0a500;">{t("awaiting_action")}</div>
    </div>''', unsafe_allow_html=True)
    k3.markdown(f'''<div class="kpi-card" style="font-size:16px;">
        <div style="font-size:14px;color:#555;">{t("high_critical_risk")}</div>
        <div style="font-size:24px;font-weight:600;color:#0d47a1;">{_high_risk}</div>
        <div style="font-size:13px;color:#d93025;">{t("dpo_review_required")}</div>
    </div>''', unsafe_allow_html=True)
    k4.markdown(f'''<div class="kpi-card" style="font-size:16px;">
        <div style="font-size:14px;color:#555;">{t("reviews_overdue")}</div>
        <div style="font-size:24px;font-weight:600;color:#0d47a1;">{_overdue}</div>
        <div style="font-size:13px;color:#d93025;">{t("past_review_date")}</div>
    </div>''', unsafe_allow_html=True)

    st.divider()

    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        t("dpia_register"),
        t("new_dpia"),
        t("mitigation_workflow"),
        t("analytics"),
        t("regulatory_reports"),
    ])

    # =========================================================================
    # TAB 1 — DPIA Register
    # =========================================================================
    with tab1:
        _branch_label = t("all_branches") if role != "Officer" else user_branch
        st.subheader(f"{t('dpia_register')} — {_branch_label}")

        if not view_dpias:
            st.info(t("no_dpias_recorded"))
        else:
            rows_html = ""
            for d in view_dpias:
                risk_badge  = _risk_badge(d.get("risk_level", ""))
                stage_badge = _stage_badge(d["workflow_stage"])
                review_date = d.get("next_review_date", "—")
                if review_date and review_date != "—":
                    review_date = review_date[:10]

                rows_html += f"""
                <tr style="border-bottom:1px solid #e8ecf0;">
                    {_td(d["dpia_id"])}
                    {_td(d["title"])}
                    {_td(d["branch_id"])}
                    {_td(str(d.get("risk_score", "—")))}
                    {_td(risk_badge)}
                    {_td(stage_badge)}
                    {_td(d["created_at"][:10])}
                    {_td(review_date)}
                    {_td(
                        f'<button onclick="viewSummary(\\"{d["dpia_id"]}\\")" '
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
                    {_th(t("dpia_id"))}
                    {_th(t("title"))}
                    {_th(t("branch"))}
                    {_th(t("risk_score"))}
                    {_th(t("risk_level"))}
                    {_th(t("stage"))}
                    {_th(t("created"))}
                    {_th(t("next_review"))}
                    {_th(t("summary"))}
                </tr></thead>
                <tbody>{rows_html}</tbody>
            </table>
            </div>
            """
            st.markdown(table_html, unsafe_allow_html=True)

            export_data(
                pd.DataFrame([generate_dpia_report(d) for d in view_dpias]),
                "dpia_register"
            )

    # =========================================================================
    # TAB 2 — Create New DPIA
    # =========================================================================
    with tab2:
        st.subheader(t("initiate_new_dpia"))
        more_info(t("dpia_creation_note"))

        if role not in ("Officer", "branch_officer", "privacy_steward", "DPO"):
            st.info(t("dpia_creation_restricted"))
        else:
            title_in = st.text_input(
                t("dpia_title"),
                placeholder=t("dpia_title_placeholder"),
            )
            proc_desc = st.text_area(
                t("processing_activity_description"),
                placeholder=t("processing_activity_placeholder"),
                height=120,
            )
            data_cats = st.multiselect(
                t("data_categories_involved"),
                ["account_data", "loan_records", "biometric_data", "health_data",
                 "kyc_documents", "contact_data", "financial_data", "marketing_data"],
            )
            third_parties = st.text_area(
                t("third_parties_involved_label"),
                height=80,
            )

            col_a, col_b = st.columns(2)
            with col_a:
                if role == "Officer":
                    branch_in = user_branch
                    st.info(f"{t('branch')}: **{branch_in}** ({t('auto_assigned')})")
                else:
                    branch_in = st.selectbox(t("branch"), ALL_BRANCHES, key="dpia_branch")
            with col_b:
                est_volume = st.number_input(
                    t("estimated_records_affected"), min_value=0, value=0, step=100
                )

            # Live risk preview
            preview_dpia = {
                "processing_description": proc_desc,
                "third_parties_involved": [tp.strip() for tp in third_parties.splitlines() if tp.strip()],
                "data_categories":        data_cats,
                "estimated_volume":       int(est_volume),
            }
            preview_score = calculate_risk_score(preview_dpia)
            preview_level = _derive_risk_level(preview_score)
            preview_badge = _risk_badge(preview_level)
            st.markdown(
                f"<div style='font-size:14px;margin-top:8px;'>"
                f"{t('predicted_risk_score')}: <b>{preview_score}</b> &nbsp; "
                f"{t('level')}: {preview_badge} "
                f"<span style='color:#555;font-size:13px;'>({t('auto_computed_no_override')})</span>"
                f"</div>",
                unsafe_allow_html=True,
            )

            if st.button(t("launch_dpia"), type="primary", use_container_width=True):
                if not title_in.strip():
                    st.warning(t("provide_dpia_title"))
                elif not proc_desc.strip():
                    st.warning(t("describe_processing_activity"))
                elif not data_cats:
                    st.warning(t("select_data_category"))
                else:
                    actor   = st.session_state.get("username", "unknown")
                    tp_list = [tp.strip() for tp in third_parties.splitlines() if tp.strip()]
                    try:
                        new_dpia = create_dpia(
                            title=title_in.strip(),
                            processing_description=proc_desc.strip(),
                            branch_id=branch_in,
                            third_parties=tp_list,
                            data_categories=data_cats,
                            estimated_volume=int(est_volume),
                            actor=actor,
                        )
                        st.session_state.dpias.append(new_dpia)

                        clause = get_clause("dpia_risk_evaluated")
                        st.success(
                            f"{t('dpia_created_success')} **{new_dpia['dpia_id']}**  "
                            f"{t('risk_score')}: **{new_dpia['risk_score']}** | "
                            f"{t('level')}: **{_t_risk(new_dpia['risk_level'])}** | "
                            f"{t('stage')}: **{_t_stage(new_dpia['workflow_stage'])}**"
                        )
                        explain_dynamic(
                            title=t("dpia_initiated_title"),
                            reason=t("dpia_initiated_reason"),
                            old_clause=clause["old"],
                            new_clause=clause["new"],
                        )

                        if new_dpia["risk_level"] in ("high", "critical"):
                            st.warning(
                                f"{_risk_badge('high')} {t('high_risk_dpia_detected')} "
                                f"{t('dpo_notified_automatically')} "
                                f"{t('mitigation_required_before_approval')}"
                            )
                        st.rerun()
                    except PermissionError as e:
                        st.error(f"{t('access_denied')}: {e}")
                    except Exception as exc:
                        st.error(f"{t('error_creating_dpia')}: {exc}")

    # =========================================================================
    # TAB 3 — Mitigation & Workflow
    # =========================================================================
    with tab3:
        st.subheader(t("mitigation_workflow"))

        if not view_dpias:
            st.info(t("no_dpias_available"))
        else:
            col_mit, col_wf = st.columns(2)

            # ── Mitigation Action ─────────────────────────────────────────
            with col_mit:
                st.markdown(f"#### {t('add_mitigation_action')}")
                if role not in ("Officer", "branch_officer", "privacy_steward", "DPO"):
                    st.info(t("mitigation_restricted"))
                else:
                    open_dpia_ids = [
                        d["dpia_id"] for d in view_dpias
                        if d["workflow_stage"] not in ("dpo_approved", "closed", "rejected")
                    ]
                    if not open_dpia_ids:
                        st.success(t("no_open_dpias_mitigation"))
                    else:
                        mit_id   = st.selectbox(t("select_dpia"), open_dpia_ids, key="mit_sel")
                        mit_text = st.text_area(
                            t("mitigation_action_label"),
                            placeholder=t("mitigation_action_placeholder"),
                            height=100, key="mit_text",
                        )
                        if st.button(t("add_mitigation"), type="primary", use_container_width=True):
                            if not mit_text.strip():
                                st.warning(t("describe_mitigation_action"))
                            else:
                                actor = st.session_state.get("username", "unknown")
                                ok = add_mitigation(
                                    dpia_id=mit_id,
                                    action_text=mit_text.strip(),
                                    dpias=st.session_state.dpias,
                                    actor=actor,
                                )
                                if ok:
                                    st.success(
                                        f"{t('mitigation_recorded')} **{mit_id}**."
                                    )
                                    st.rerun()

            # ── Workflow Advancement ──────────────────────────────────────
            with col_wf:
                st.markdown(f"#### {t('advance_workflow_stage')}")
                if role not in ("privacy_steward", "DPO"):
                    st.info(t("stage_advancement_restricted"))
                else:
                    advanceable = [
                        d["dpia_id"] for d in view_dpias
                        if d["workflow_stage"] not in ("dpo_approved", "closed", "rejected")
                    ]
                    if not advanceable:
                        st.success(t("no_dpias_awaiting_approval"))
                    else:
                        adv_id = st.selectbox(t("select_dpia"), advanceable, key="adv_sel")

                        # Workflow action — translated display, internal comparison
                        _action_approve  = t("approve")
                        _action_reject   = t("reject")
                        _action_override = t("final_override_dpo_only")
                        adv_action_display = st.radio(
                            t("action"),
                            [_action_approve, _action_reject, _action_override],
                            key="adv_action",
                        )

                        reject_reason = ""
                        if adv_action_display == _action_reject:
                            reject_reason = st.text_input(
                                t("rejection_reason"), key="rej_reason"
                            )

                        if st.button(
                            t("approve") if adv_action_display == _action_approve else t("reject"),
                            type="primary", use_container_width=True
                        ):
                            actor      = st.session_state.get("username", "unknown")
                            actor_role = role

                            if adv_action_display == _action_approve:
                                ok = approve_dpia(
                                    dpia_id=adv_id,
                                    dpias=st.session_state.dpias,
                                    actor=actor,
                                    actor_role=actor_role,
                                )
                            elif adv_action_display == _action_reject:
                                ok = reject_dpia(
                                    dpia_id=adv_id,
                                    dpias=st.session_state.dpias,
                                    actor=actor,
                                    reason=reject_reason,
                                )
                            else:  # Final Override
                                if actor_role != "DPO":
                                    st.error(t("final_override_dpo_only_error"))
                                    ok = False
                                else:
                                    ok = final_approval(
                                        dpia_id=adv_id,
                                        dpias=st.session_state.dpias,
                                        actor=actor,
                                    )

                            if ok:
                                clause = get_clause("dpia_risk_evaluated")
                                st.success(
                                    f"{t('dpia_workflow_updated')} **{adv_id}**."
                                )
                                explain_dynamic(
                                    title=t("dpia_workflow_advanced_title"),
                                    reason=t("dpia_workflow_advanced_reason"),
                                    old_clause=clause["old"],
                                    new_clause=clause["new"],
                                )
                                st.rerun()
                            else:
                                st.error(t("transition_not_permitted"))

            # ── Approval history viewer ───────────────────────────────────
            st.divider()
            st.markdown(f"#### {t('approval_history')}")
            if view_dpias:
                hist_id = st.selectbox(
                    t("view_history_for"),
                    [d["dpia_id"] for d in view_dpias],
                    key="hist_sel"
                )
                for d in view_dpias:
                    if d["dpia_id"] == hist_id:
                        history = d.get("approval_history", [])
                        if not history:
                            st.info(t("no_approval_history"))
                        else:
                            hist_rows = "".join([
                                f"<tr style='border-bottom:1px solid #e8ecf0;'>"
                                f"{_td(h['timestamp'][:16])}"
                                f"{_td(h['approved_by'])}"
                                f"{_td(_t_stage(h['stage']))}"
                                f"{_td(h.get('reason', '—'))}"
                                f"</tr>"
                                for h in history
                            ])
                            st.markdown(f"""
                            <div style="font-size:14px;overflow-x:auto;">
                            <table style="width:100%;border-collapse:collapse;">
                                <thead><tr>
                                    {_th(t("timestamp"))}
                                    {_th(t("actor"))}
                                    {_th(t("stage"))}
                                    {_th(t("reason"))}
                                </tr></thead>
                                <tbody>{hist_rows}</tbody>
                            </table></div>
                            """, unsafe_allow_html=True)

    # =========================================================================
    # TAB 4 — Analytics (Step 9J — badge only, no color-name text)
    # =========================================================================
    with tab4:
        st.subheader(t("dpia_analytics"))

        if not view_dpias:
            st.info(t("no_dpia_data_to_analyse"))
        else:
            df = pd.DataFrame(view_dpias)

            col1, col2 = st.columns(2)

            with col1:
                risk_counts = df["risk_level"].value_counts().reset_index()
                risk_counts.columns = ["risk_level_internal", t("count")]
                # Translate labels for display
                risk_counts[t("risk_level")] = risk_counts["risk_level_internal"].apply(_t_risk)
                _translated_risk_colour = {_t_risk(k): v for k, v in _RISK_COLOUR.items()}
                fig_risk = px.pie(
                    risk_counts, names=t("risk_level"), values=t("count"),
                    color=t("risk_level"), color_discrete_map=_translated_risk_colour,
                    hole=0.55, title=t("dpias_by_risk_level"),
                )
                fig_risk.update_layout(
                    height=300, showlegend=False,
                    margin=dict(l=0, r=0, t=40, b=0),
                    paper_bgcolor="#ffffff",
                    font=dict(color="#0A3D91", size=14),
                    title_font=dict(size=18), template="plotly_white",
                )
                st.plotly_chart(fig_risk, use_container_width=True)
                more_info(t("risk_level_auto_computed_note"))

            with col2:
                stage_counts = df["workflow_stage"].value_counts().reset_index()
                stage_counts.columns = ["stage_internal", t("count")]
                stage_counts[t("stage")] = stage_counts["stage_internal"].apply(_t_stage)
                _translated_stage_colour = {_t_stage(k): v for k, v in _STAGE_COLOUR.items()}
                fig_stage = px.bar(
                    stage_counts, x=t("stage"), y=t("count"),
                    color=t("stage"), color_discrete_map=_translated_stage_colour,
                    text=t("count"), title=t("dpias_by_workflow_stage"),
                )
                fig_stage.update_traces(textposition="outside")
                fig_stage.update_layout(
                    height=300, showlegend=False,
                    plot_bgcolor="#ffffff", paper_bgcolor="#ffffff",
                    font=dict(color="#0A3D91", size=14),
                    title_font=dict(size=18), template="plotly_white",
                    xaxis_tickangle=-20,
                )
                st.plotly_chart(fig_stage, use_container_width=True)

            if role in ("DPO", "Auditor"):
                st.subheader(t("risk_score_distribution"))
                fig_hist = px.histogram(
                    df, x="risk_score", nbins=10,
                    color_discrete_sequence=["#0d47a1"],
                    title=t("risk_score_distribution_all_dpias"),
                    labels={"risk_score": t("risk_score")},
                )
                fig_hist.update_layout(
                    height=300, showlegend=False,
                    plot_bgcolor="#ffffff", paper_bgcolor="#ffffff",
                    font=dict(color="#0A3D91", size=14),
                    title_font=dict(size=18), template="plotly_white",
                )
                st.plotly_chart(fig_hist, use_container_width=True)

            # High-risk escalation notice (badge only — no color text)
            pending_high = [
                d for d in view_dpias
                if d.get("risk_level") in ("high", "critical")
                and d["workflow_stage"] not in ("dpo_approved", "closed", "rejected")
            ]
            if pending_high:
                high_badge = _risk_badge("high")
                st.error(
                    f"{high_badge} {len(pending_high)} {t('high_critical_dpias_pending_dpo')}"
                )
                clause = get_clause("dpia_critical_requires_dpo")
                explain_dynamic(
                    title=t("critical_dpia_escalation_title"),
                    reason=t("critical_dpia_escalation_reason"),
                    old_clause=clause["old"],
                    new_clause=clause["new"],
                )

    # =========================================================================
    # TAB 5 — Regulatory Reports
    # =========================================================================
    with tab5:
        st.subheader(t("regulatory_export_dpia_reports"))
        more_info(t("regulatory_export_note"))

        if not view_dpias:
            st.info(t("no_dpias_to_export"))
        else:
            sel_export = st.selectbox(
                t("select_dpia_to_preview"),
                [d["dpia_id"] for d in view_dpias],
                key="rpt_sel"
            )
            for d in view_dpias:
                if d["dpia_id"] == sel_export:
                    report = generate_dpia_report(d)

                    clause = get_clause(
                        d["decision_metadata"].get("reason_code", "dpia_risk_evaluated")
                        if d.get("decision_metadata") else "dpia_risk_evaluated"
                    )
                    st.markdown(f"""
                    <div style="background:#f0f4ff;border-left:5px solid #0d47a1;
                                padding:16px 20px;border-radius:8px;margin-bottom:12px;">
                        <b>{t('dpia_id')}:</b> {report['DPIA ID']}<br>
                        <b>{t('title')}:</b> {report['Title']}<br>
                        <b>{t('branch')}:</b> {report['Branch']} — {report['Region']}<br>
                        <b>{t('risk_score')}:</b> {report['Risk Score']} &nbsp;|&nbsp;
                        <b>{t('risk_level')}:</b> {_risk_badge(report.get('Risk Level', ''))}
                        <br>
                        <b>{t('stage')}:</b> {_t_stage(report['Workflow Stage'])}<br>
                        <b>{t('next_review')}:</b> {report['Next Review Date']}<br>
                    </div>
                    """, unsafe_allow_html=True)

                    if report["Mitigation Actions"]:
                        st.markdown(f"**{t('mitigation_actions')}:**")
                        for m in report["Mitigation Actions"]:
                            st.caption(f"• {m}")

                    if report["Approval History"]:
                        st.markdown(f"**{t('approval_history')}:**")
                        for a in report["Approval History"]:
                            st.caption(f"• {a}")

                    explain_dynamic(
                        title=t("regulatory_clause_reference_title"),
                        reason=f"{t('dpia_classification_based_on_score')} {report['Risk Score']}.",
                        old_clause=clause.get("old", ""),
                        new_clause=clause.get("new", ""),
                    )

                    export_data(pd.DataFrame([report]), f"dpia_report_{sel_export}")