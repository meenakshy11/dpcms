"""
modules/dpia.py
---------------
Data Protection Impact Assessment (DPIA) — Kerala Bank DPCMS.
DPDP Act 2023, Section 9 & 10 — fully governance-grade.

Architecture (updated):
    UI  →  orchestration.execute_action()  →  Engine  →  Audit / SLA / Compliance

Role-access model:
  Officer / branch_officer / privacy_steward  → may initiate DPIAs and add mitigation
  privacy_steward / DPO                       → may advance workflow (approve/reject)
  DPO only                                    → final override approval + closure
  Auditor / Board                             → read-only

Immutable lifecycle (enforced by orchestration):
  initiated → under_review → steward_approved → dpo_approved → closed
  under_review → rejected (also valid)
  Reverse transitions are rejected by the engine.

Purpose-DPIA linkage (enforced by orchestration):
  Payload includes product + purpose + risk_type.
  Engine validates PURPOSE_REGISTRY and blocks consent activation
  for high-risk purposes without a completed DPIA.

Design contract:
  - NO storage reads/writes.
  - NO risk scoring (calculate_risk_score / _derive_risk_level).
  - NO audit_log() calls.
  - NO register_sla() / mark_sla_completed() calls.
  - NO compliance_engine calls.
  - NO direct lifecycle mutation.
  - NO severity/risk override in UI — displayed only, classified by engine.
  - All mutations go through orchestration.execute_action().
  - All user-visible strings go through t().
"""

from __future__ import annotations

from datetime import datetime

import pandas as pd
import plotly.express as px
import streamlit as st

import engine.orchestration as orchestration
from auth import get_role, get_branch, KERALA_BRANCHES
from modules.dashboard import render_status_badge
from utils.dpdp_clauses import get_clause
from utils.export_utils import export_data
from utils.explainability import explain_dynamic
from utils.i18n import t
from utils.ui_helpers import more_info

# ---------------------------------------------------------------------------
# Constants — internal English keys; NEVER translate these
# ---------------------------------------------------------------------------

WORKFLOW_STAGES: list[str] = [
    "initiated",
    "under_review",
    "steward_approved",
    "dpo_approved",
    "rejected",
    "closed",
]

# Allowed forward lifecycle transitions — orchestration enforces; UI uses for display
LIFECYCLE_TRANSITIONS: dict[str, list[str]] = {
    "initiated":        ["under_review"],
    "under_review":     ["steward_approved", "rejected"],
    "steward_approved": ["dpo_approved", "rejected"],
    "dpo_approved":     ["closed"],
}

CLOSED_STAGES: set[str] = {"dpo_approved", "closed", "rejected"}

ALL_BRANCHES: list[str] = [b for branches in KERALA_BRANCHES.values() for b in branches]

DATA_CATEGORIES: list[str] = [
    "account_data", "loan_records", "biometric_data", "health_data",
    "kyc_documents", "contact_data", "financial_data", "marketing_data",
]

# Purpose registry keys exposed to UI — orchestration validates against engine registry
PURPOSE_OPTIONS: list[str] = [
    "loan_processing",
    "kyc_verification",
    "marketing",
    "account_opening",
]

# Colour maps — Plotly charts only, never rendered as text labels
_RISK_COLOUR: dict[str, str] = {
    "low":       "#1a9e5c",
    "medium":    "#f0a500",
    "high":      "#e06030",
    "critical":  "#d93025",
    "escalated": "#d93025",
    "approved":  "#1a9e5c",
    "rejected":  "#e06030",
}

_STAGE_COLOUR: dict[str, str] = {
    "initiated":        "#5a9ef5",
    "under_review":     "#f0a500",
    "steward_approved": "#1a9e5c",
    "dpo_approved":     "#1a9e5c",
    "rejected":         "#d93025",
    "closed":           "#546e7a",
}

# i18n key maps
_RISK_LEVEL_I18N: dict[str, str] = {
    "low":       "low",
    "medium":    "medium",
    "high":      "high",
    "critical":  "critical",
    "escalated": "escalated",
}

_STAGE_I18N: dict[str, str] = {
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
    return t(_RISK_LEVEL_I18N.get((internal or "").lower(), (internal or "").lower()))


# ---------------------------------------------------------------------------
# Sample data — session bootstrap only (never written back to storage)
# ---------------------------------------------------------------------------

SAMPLE_DPIAS: list[dict] = [
    {
        "dpia_id":                "DPIA-001",
        "title":                  "Biometric Authentication Rollout",
        "initiated_by":           "officer_01",
        "branch_id":              "Ernakulam Central",
        "region":                 "Central Zone",
        "processing_description": "Fingerprint biometric authentication for all branch transactions.",
        "purpose":                "kyc_verification",
        "third_parties_involved": ["FingerTech Solutions Pvt Ltd"],
        "data_categories":        ["biometric_data", "account_data"],
        "estimated_volume":       75000,
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
        "purpose":                "loan_processing",
        "third_parties_involved": [],
        "data_categories":        ["loan_records", "account_data"],
        "estimated_volume":       12000,
        "risk_score":             35,
        "risk_level":             "medium",
        "workflow_stage":         "steward_approved",
        "approval_history":       [
            {"approved_by": "privacy_steward_01", "stage": "under_review",
             "timestamp": "2026-02-15T14:00:00", "reason": ""},
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


# ---------------------------------------------------------------------------
# Regulatory report builder (read-only, no writes)
# ---------------------------------------------------------------------------

def generate_dpia_report(dpia: dict) -> dict:
    """Build an exportable regulatory report dict."""
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
        "Purpose Key":         dpia.get("purpose", ""),
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


# ---------------------------------------------------------------------------
# Risk preview helper (display-only — engine scores on submission)
# ---------------------------------------------------------------------------

def _preview_risk_level(
    data_cats: list[str],
    third_parties: list[str],
    est_volume: int,
    proc_desc: str,
) -> str:
    """
    Return a UI-only risk level preview.
    This is informational only — the DPIA engine determines actual risk score/level.
    """
    desc  = proc_desc.lower()
    cats  = [c.lower() for c in data_cats]
    score = 0
    if third_parties:                                               score += 20
    if "biometric_data" in cats or "biometric" in desc:            score += 40
    if any(c in cats for c in ("health_data", "financial_data",
                               "kyc_documents")):                   score += 15
    if "sensitive" in desc or "special" in desc:                   score += 30
    if est_volume > 50_000:                                        score += 10
    score = min(score, 100)
    if score >= 70:    return "high"
    if score >= 40:    return "medium"
    return "low"


# ---------------------------------------------------------------------------
# UI helpers
# ---------------------------------------------------------------------------

def _th(label: str) -> str:
    return (
        f'<th style="background-color:#0d47a1;color:white;padding:10px;'
        f'font-size:15px;text-align:left;">{label}</th>'
    )


def _td(content: str) -> str:
    return f'<td style="padding:8px 10px;font-size:14px;">{content}</td>'


def _risk_badge(risk_level: str) -> str:
    """Badge dot only — no colour-name text (Step 9J)."""
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


def _init_dpias() -> None:
    st.session_state.setdefault("dpias", list(SAMPLE_DPIAS))


def _load_dpias() -> list[dict]:
    """
    Return DPIA records from orchestration (engine source of truth),
    falling back to session bootstrap for demo environments.
    """
    result = orchestration.execute_action(
        action_type="query_dpias",
        payload={},
        actor=st.session_state.get("username", "system"),
    )
    if result.get("status") == "success":
        return result.get("records", [])
    return st.session_state.get("dpias", list(SAMPLE_DPIAS))


def _handle_result(result: dict, success_msg: str) -> bool:
    """Display success or error from orchestration result. Returns True on success."""
    if result.get("status") == "success":
        st.success(success_msg)
        return True
    st.error(f"{t('action_failed')}: {result.get('message', t('unknown_error'))}")
    return False


# ===========================================================================
# Main Streamlit entry point
# ===========================================================================

def show() -> None:
    _init_dpias()

    role        = get_role()
    user        = st.session_state.get("username", "unknown")
    user_branch = get_branch()

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

    dpias = _load_dpias()

    # Branch filter for officers
    if role == "Officer":
        view_dpias = [d for d in dpias if d["branch_id"] == user_branch]
    else:
        view_dpias = dpias

    # ── KPI Strip ─────────────────────────────────────────────────────────────
    _total     = len(view_dpias)
    _open      = sum(1 for d in view_dpias if d["workflow_stage"] not in CLOSED_STAGES)
    _high_risk = sum(1 for d in view_dpias if d.get("risk_level") in ("high", "critical", "escalated"))
    _overdue   = sum(
        1 for d in view_dpias
        if d.get("next_review_date") and
        datetime.fromisoformat(d["next_review_date"]) < datetime.utcnow()
    )

    k1, k2, k3, k4 = st.columns(4)
    k1.markdown(f'''<div class="kpi-card">
        <div style="font-size:14px;color:#555;">{t("total_dpias")}</div>
        <div style="font-size:24px;font-weight:600;color:#0d47a1;">{_total}</div>
        <div style="font-size:13px;color:#6B7A90;">{t("this_branch") if role == "Officer" else t("all_branches")}</div>
    </div>''', unsafe_allow_html=True)
    k2.markdown(f'''<div class="kpi-card">
        <div style="font-size:14px;color:#555;">{t("open_in_progress")}</div>
        <div style="font-size:24px;font-weight:600;color:#0d47a1;">{_open}</div>
        <div style="font-size:13px;color:#f0a500;">{t("awaiting_action")}</div>
    </div>''', unsafe_allow_html=True)
    k3.markdown(f'''<div class="kpi-card">
        <div style="font-size:14px;color:#555;">{t("high_critical_risk")}</div>
        <div style="font-size:24px;font-weight:600;color:#0d47a1;">{_high_risk}</div>
        <div style="font-size:13px;color:#d93025;">{t("dpo_review_required")}</div>
    </div>''', unsafe_allow_html=True)
    k4.markdown(f'''<div class="kpi-card">
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
                risk_badge_html  = _risk_badge(d.get("risk_level", ""))
                stage_badge_html = _stage_badge(d["workflow_stage"])
                review_date      = d.get("next_review_date") or "—"
                if review_date != "—":
                    review_date = review_date[:10]

                rows_html += f"""
                <tr style="border-bottom:1px solid #e8ecf0;">
                    {_td(d["dpia_id"])}
                    {_td(d["title"])}
                    {_td(d["branch_id"])}
                    {_td(d.get("purpose", "—"))}
                    {_td(str(d.get("risk_score", "—")))}
                    {_td(risk_badge_html)}
                    {_td(stage_badge_html)}
                    {_td(d["created_at"][:10])}
                    {_td(review_date)}
                </tr>
                """

            st.markdown(f"""
            <div style="font-size:14px;overflow-x:auto;">
            <table style="width:100%;border-collapse:collapse;">
                <thead><tr>
                    {_th(t("dpia_id"))}
                    {_th(t("title"))}
                    {_th(t("branch"))}
                    {_th(t("purpose"))}
                    {_th(t("risk_score"))}
                    {_th(t("risk_level"))}
                    {_th(t("stage"))}
                    {_th(t("created"))}
                    {_th(t("next_review"))}
                </tr></thead>
                <tbody>{rows_html}</tbody>
            </table>
            </div>
            """, unsafe_allow_html=True)

            export_data(
                pd.DataFrame([generate_dpia_report(d) for d in view_dpias]),
                "dpia_register",
            )

            # ── Approval history viewer (read-only) ───────────────────────────
            st.divider()
            st.markdown(f"#### {t('approval_history')}")
            hist_id = st.selectbox(
                t("view_history_for"),
                [d["dpia_id"] for d in view_dpias],
                key="hist_sel",
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
    # TAB 2 — Initiate New DPIA
    # =========================================================================
    with tab2:
        st.subheader(t("initiate_new_dpia"))
        more_info(t("dpia_creation_note"))

        if role not in ("Officer", "branch_officer", "privacy_steward", "DPO"):
            st.info(t("dpia_creation_restricted"))
        else:
            title_in  = st.text_input(
                t("dpia_title"), placeholder=t("dpia_title_placeholder")
            )
            proc_desc = st.text_area(
                t("processing_activity_description"),
                placeholder=t("processing_activity_placeholder"),
                height=120,
            )

            # Purpose-DPIA linkage — must be included in payload
            purpose_in = st.selectbox(
                t("processing_purpose"),
                PURPOSE_OPTIONS,
                help=t("purpose_dpia_linkage_help"),
            )

            data_cats = st.multiselect(t("data_categories_involved"), DATA_CATEGORIES)

            third_parties_raw = st.text_area(
                t("third_parties_involved_label"), height=80
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

            # Risk level preview — display only; engine scores on submission
            tp_list      = [tp.strip() for tp in third_parties_raw.splitlines() if tp.strip()]
            preview_level = _preview_risk_level(data_cats, tp_list, int(est_volume), proc_desc)
            preview_badge = _risk_badge(preview_level)
            st.markdown(
                f"<div style='font-size:14px;margin-top:8px;'>"
                f"{t('predicted_risk_level')}: {preview_badge} "
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
                    result = orchestration.execute_action(
                        action_type="create_dpia",
                        payload={
                            "title":                  title_in.strip(),
                            "processing_description": proc_desc.strip(),
                            "purpose":                purpose_in,       # purpose-DPIA linkage
                            "branch_id":              branch_in,
                            "third_parties":          tp_list,
                            "data_categories":        data_cats,
                            "estimated_volume":       int(est_volume),
                            # risk_level intentionally excluded — engine computes it
                        },
                        actor=user,
                    )
                    if result.get("status") == "success":
                        record = result["record"]
                        clause = get_clause("dpia_risk_evaluated")
                        st.success(
                            f"{t('dpia_created_success')} **{record['dpia_id']}**  "
                            f"{t('risk_score')}: **{record.get('risk_score', '—')}** | "
                            f"{t('level')}: **{_t_risk(record.get('risk_level', ''))}** | "
                            f"{t('stage')}: **{_t_stage(record['workflow_stage'])}**"
                        )
                        explain_dynamic(
                            title=t("dpia_initiated_title"),
                            reason=t("dpia_initiated_reason"),
                            old_clause=clause["old"],
                            new_clause=clause["new"],
                        )
                        if record.get("risk_level") in ("high", "critical"):
                            st.warning(
                                f"{_risk_badge('high')} {t('high_risk_dpia_detected')} "
                                f"{t('dpo_notified_automatically')} "
                                f"{t('mitigation_required_before_approval')}"
                            )
                        # Reflect in session state immediately for demo
                        st.session_state.dpias.append(record)
                        st.rerun()
                    else:
                        st.error(
                            f"{t('error_creating_dpia')}: "
                            f"{result.get('message', t('unknown_error'))}"
                        )

    # =========================================================================
    # TAB 3 — Mitigation & Workflow
    # =========================================================================
    with tab3:
        st.subheader(t("mitigation_workflow"))

        if not view_dpias:
            st.info(t("no_dpias_available"))
        else:
            col_mit, col_wf = st.columns(2)

            # ── Mitigation Action ─────────────────────────────────────────────
            with col_mit:
                st.markdown(f"#### {t('add_mitigation_action')}")
                if role not in ("Officer", "branch_officer", "privacy_steward", "DPO"):
                    st.info(t("mitigation_restricted"))
                else:
                    open_dpia_ids = [
                        d["dpia_id"] for d in view_dpias
                        if d["workflow_stage"] not in CLOSED_STAGES
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
                                result = orchestration.execute_action(
                                    action_type="add_dpia_mitigation",
                                    payload={
                                        "dpia_id":     mit_id,
                                        "action_text": mit_text.strip(),
                                    },
                                    actor=user,
                                )
                                if _handle_result(
                                    result,
                                    f"{t('mitigation_recorded')} **{mit_id}**.",
                                ):
                                    # Reflect in session state immediately
                                    from datetime import datetime as _dt
                                    for d in st.session_state.dpias:
                                        if d["dpia_id"] == mit_id:
                                            d.setdefault("mitigation_actions", []).append({
                                                "action":    mit_text.strip(),
                                                "added_by":  user,
                                                "timestamp": _dt.utcnow().isoformat(),
                                            })
                                    st.rerun()

            # ── Workflow Advancement ──────────────────────────────────────────
            with col_wf:
                st.markdown(f"#### {t('advance_workflow_stage')}")
                if role not in ("privacy_steward", "DPO"):
                    st.info(t("stage_advancement_restricted"))
                else:
                    advanceable = [
                        d for d in view_dpias
                        if d["workflow_stage"] not in CLOSED_STAGES
                    ]
                    advanceable_ids = [d["dpia_id"] for d in advanceable]

                    if not advanceable_ids:
                        st.success(t("no_dpias_awaiting_approval"))
                    else:
                        adv_id  = st.selectbox(t("select_dpia"), advanceable_ids, key="adv_sel")
                        adv_dpia = next((d for d in advanceable if d["dpia_id"] == adv_id), None)
                        current_stage = adv_dpia["workflow_stage"] if adv_dpia else "initiated"

                        # Only show valid forward transitions from current stage
                        allowed_next = LIFECYCLE_TRANSITIONS.get(current_stage, [])
                        if not allowed_next:
                            st.info(t("no_transitions_available"))
                        else:
                            # Translate allowed transitions for display
                            _next_display     = [_t_stage(s) for s in allowed_next]
                            _display_to_stage = {_t_stage(s): s for s in allowed_next}

                            chosen_display = st.selectbox(
                                t("target_stage"), _next_display, key="adv_stage"
                            )
                            chosen_stage = _display_to_stage[chosen_display]

                            # Additional inputs for rejection
                            reject_reason = ""
                            is_rejection  = chosen_stage == "rejected"
                            if is_rejection:
                                reject_reason = st.text_input(
                                    t("rejection_reason"), key="rej_reason"
                                )

                            # DPO-only override flag
                            is_override = (
                                chosen_stage == "dpo_approved"
                                and current_stage not in ("steward_approved",)
                                and role == "DPO"
                            )
                            if is_override:
                                st.warning(t("final_override_dpo_warning"))

                            btn_label = t("reject") if is_rejection else t("approve")
                            if st.button(btn_label, type="primary", use_container_width=True):
                                if is_rejection and not reject_reason.strip():
                                    st.warning(t("provide_rejection_reason"))
                                else:
                                    result = orchestration.execute_action(
                                        action_type="update_dpia_stage",
                                        payload={
                                            "dpia_id":      adv_id,
                                            "new_stage":    chosen_stage,
                                            "reason":       reject_reason,
                                            "is_override":  is_override,
                                        },
                                        actor=user,
                                    )
                                    if _handle_result(
                                        result,
                                        f"{t('dpia_workflow_updated')} **{adv_id}**.",
                                    ):
                                        clause = get_clause("dpia_risk_evaluated")
                                        explain_dynamic(
                                            title=t("dpia_workflow_advanced_title"),
                                            reason=t("dpia_workflow_advanced_reason"),
                                            old_clause=clause["old"],
                                            new_clause=clause["new"],
                                        )
                                        # Reflect in session state immediately
                                        for d in st.session_state.dpias:
                                            if d["dpia_id"] == adv_id:
                                                d["workflow_stage"] = chosen_stage
                                        st.rerun()

            # ── DPO-only closure ──────────────────────────────────────────────
            if role == "DPO":
                st.divider()
                st.markdown(f"#### {t('close_dpia')}")
                closeable = [
                    d["dpia_id"] for d in view_dpias
                    if d["workflow_stage"] == "dpo_approved"
                ]
                if not closeable:
                    st.info(t("no_dpo_approved_dpias_to_close"))
                else:
                    close_id = st.selectbox(t("select_dpia_to_close"), closeable, key="close_sel")
                    if st.button(t("close_dpia"), type="secondary", use_container_width=True):
                        result = orchestration.execute_action(
                            action_type="update_dpia_stage",
                            payload={
                                "dpia_id":   close_id,
                                "new_stage": "closed",
                            },
                            actor=user,
                        )
                        if _handle_result(result, t("dpia_closed_success").format(id=close_id)):
                            for d in st.session_state.dpias:
                                if d["dpia_id"] == close_id:
                                    d["workflow_stage"] = "closed"
                            st.rerun()

    # =========================================================================
    # TAB 4 — Analytics
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
                if "risk_score" in df.columns and df["risk_score"].notna().any():
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

            # High-risk escalation notice (badge only — no colour-name text)
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
                key="rpt_sel",
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
                        <b>{t('purpose')}:</b> {report['Purpose Key']}<br>
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