"""
modules/rights_portal.py
------------------------
Data Principal Rights Portal — role-based rendering model.

Architecture (updated):
    UI  →  orchestration.execute_action()  →  Engine  →  Audit / SLA / Compliance

Role dispatch (canonical codes):
  customer              → render_customer_view()       — submit own requests
  customer_assisted     → render_customer_view()       — assisted self-service
  customer_support      → render_officer_console()     — register requests on behalf
  branch_officer /
  branch_privacy_coordinator
                        → render_officer_console()     — monitor branch queue
  regional_officer /
  regional_compliance_officer
                        → render_officer_console()     — regional scope
  privacy_steward /
  privacy_operations    → render_dpo_console()         — execute correction/erasure
  dpo                   → render_dpo_console()         — full governance + escalations
  auditor / internal_auditor
                        → render_auditor_console()     — read-only oversight
  board_member          → read-only dashboard (via app.py fast-path)
  others                → access denied

Governance matrix enforced:
  - Customer / Assisted / Support Officer: submit requests only, NO approve/execute
  - Branch Privacy Coordinator: monitor branch queue, NO direct mutations
  - Privacy Operations: execute correction/erasure
  - DPO: full governance — all requests + escalations + analytics
  - Auditor: read-only
  - Export: Internal Auditor, Board, Privacy Operations only

Access control — Consent-driven architecture:
  - "Access My Data" has been REMOVED from the customer-facing request dropdown.
  - Data access is an official-initiated action managed in modules/access_requests.py.
  - Customers can only submit: Correction, Erasure, Revoke Consent,
    Nominate Representative, Raise Grievance.
  - CUSTOMER_REQUEST_TYPES further restricts the customer UI to the three
    most common self-service types (Correction, Erasure, Grievance).
  - Customer ID is auto-loaded from session state — never manually entered.
  - Customer identity is displayed masked (last 4 chars only).
  - Customers may only view their own requests; cross-customer data is blocked.
  - Consent artefact download is available on the customer's My Requests tab.

Design contract:
  - NO storage reads/writes (json.load / json.dump) in this module.
  - NO audit_log() calls.
  - NO register_sla() / close_sla() calls.
  - NO compliance_engine calls.
  - NO direct status mutation.
  - Session-based rate throttle only — persistent throttling belongs in orchestration.
  - All mutations go through orchestration.execute_action().
  - All user-visible strings go through t().
"""

from __future__ import annotations

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
from datetime import datetime, timedelta, timezone

import engine.orchestration as orchestration
from engine.sla_engine import get_sla_detail, SLA_CONFIG, status_badge
from auth import get_role, get_branch, set_assisted_submission
from utils.i18n import t
from utils.export_utils import export_data
from utils.explainability import explain, explain_dynamic
from utils.ui_helpers import more_info, mask_identifier


# ---------------------------------------------------------------------------
# Constants — internal English keys (NEVER translated; these are data keys)
# ---------------------------------------------------------------------------

REQUEST_TYPE_MAP: dict[str, str] = {
    # NOTE: "Access My Data" is intentionally removed.
    # Data access must be requested by officials via the official access request
    # workflow (modules/access_requests.py), NOT self-initiated by customers.
    "Correct My Data":         "data_correction_request",
    "Erase My Data":           "data_erasure_request",
    "Revoke Consent":          "consent_withdrawal_action",
    "Nominate Representative": "nomination_request",
    "Raise Grievance":         "grievance_redressal",
}

# Customer-facing subset — officials use REQUEST_TYPE_MAP directly
CUSTOMER_REQUEST_TYPES: list[str] = [
    "Correct My Data",
    "Erase My Data",
    "Raise Grievance",
]

CONSENT_GATED_TYPES: dict[str, str] = {
    "Correct My Data": "kyc",
    "Erase My Data":   "kyc",
}

CLAUSE_MAP: dict[str, str] = {
    "Correct My Data": "data_correction",
    "Erase My Data":   "data_erasure",
}

IDENTITY_VERIFICATION_REQUIRED: set[str] = {"Correct My Data", "Erase My Data"}

OPEN_STATUSES   = {"Open", "In Progress", "Escalated"}
CLOSED_STATUSES = {"Closed", "Rejected"}

# Session-based rate limit — max submissions per session
_SESSION_SUBMIT_LIMIT = 5
_SESSION_SUBMIT_KEY   = "_rights_submissions_this_session"

# ---------------------------------------------------------------------------
# Export-permitted roles — canonical codes
# Mirrors EXPORT_PERMITTED_ROLES in app.py; kept here for module-level guard.
# ---------------------------------------------------------------------------

_EXPORT_PERMITTED: set[str] = {
    "dpo",
    "board_member",
    "auditor",
    "internal_auditor",
    "privacy_operations",
}

# ---------------------------------------------------------------------------
# Kerala district list for identity form
# ---------------------------------------------------------------------------

KERALA_DISTRICTS: list[str] = [
    "Thiruvananthapuram",
    "Kollam",
    "Pathanamthitta",
    "Alappuzha",
    "Kottayam",
    "Idukki",
    "Ernakulam",
    "Thrissur",
    "Palakkad",
    "Malappuram",
    "Kozhikode",
    "Wayanad",
    "Kannur",
    "Kasaragod",
]

# ---------------------------------------------------------------------------
# i18n helpers
# ---------------------------------------------------------------------------

_REQUEST_TYPE_I18N: dict[str, str] = {
    # "Access My Data" removed — data access is an official-only workflow.
    "Correct My Data":         "correct_my_data",
    "Erase My Data":           "erase_my_data",
    "Revoke Consent":          "revoke_consent",
    "Nominate Representative": "nominate_representative",
    "Raise Grievance":         "raise_grievance",
}

_STATUS_I18N: dict[str, str] = {
    "Open":        "open",
    "In Progress": "in_progress",
    "Escalated":   "escalated",
    "Closed":      "closed",
    "Rejected":    "rejected",
}


def _t_request_type(internal: str) -> str:
    return t(_REQUEST_TYPE_I18N.get(internal, internal.lower().replace(" ", "_")))


def _t_status(internal: str) -> str:
    return t(_STATUS_I18N.get(internal, internal.lower()))


# ---------------------------------------------------------------------------
# Role-aware identifier masking
# ---------------------------------------------------------------------------

def _mask_id(raw_id: str) -> str:
    role = st.session_state.get("role", "")
    if role in ("dpo", "auditor", "internal_auditor", "privacy_operations"):
        return raw_id
    return mask_identifier(raw_id, role=role)


# ---------------------------------------------------------------------------
# Sensitive field masking — show last 4 chars only
# ---------------------------------------------------------------------------

def mask(value: str) -> str:
    """Mask sensitive identifiers, showing only the last 4 characters."""
    if not value:
        return ""
    value = str(value).strip()
    if len(value) <= 4:
        return "****"
    return "****" + value[-4:]


# ---------------------------------------------------------------------------
# Export permission helper — module-level check
# ---------------------------------------------------------------------------

def _can_export() -> bool:
    """Return True only if the current session role is permitted to export."""
    return st.session_state.get("role", "") in _EXPORT_PERMITTED


# ---------------------------------------------------------------------------
# SLA datetime normalisation
# Ensures submitted_time is always a timezone-naive datetime for SLA engine.
# Fixes: TypeError: can't subtract offset-naive and offset-aware datetimes
# ---------------------------------------------------------------------------

def _normalise_dt(submitted_time) -> datetime:
    """
    Accept a string or datetime and return a timezone-naive UTC datetime.
    Handles ISO strings with or without +00:00 / Z suffix.
    """
    if isinstance(submitted_time, str):
        # Replace Z with +00:00 for fromisoformat compatibility
        submitted_time = submitted_time.replace("Z", "+00:00")
        submitted_time = datetime.fromisoformat(submitted_time)
    # Strip timezone info so SLA engine arithmetic stays naive
    if submitted_time.tzinfo is not None:
        submitted_time = submitted_time.replace(tzinfo=None)
    return submitted_time


# ---------------------------------------------------------------------------
# DPDP clause fallback
# ---------------------------------------------------------------------------

_DPDP_CLAUSE_FALLBACK: dict[str, dict] = {
    "data_access":     {"number": "Section 11", "text": "Right to access personal data",
                        "old": "DPDPA 2023 – Section 11", "new": "DPDP Rules – Right to Access"},
    "data_correction": {"number": "Section 12", "text": "Right to correction and erasure",
                        "old": "DPDPA 2023 – Section 12", "new": "DPDP Rules – Right to Correction"},
    "data_erasure":    {"number": "Section 12", "text": "Right to correction and erasure",
                        "old": "DPDPA 2023 – Section 12", "new": "DPDP Rules – Right to Erasure"},
}

SLA_COLOUR: dict[str, str] = {
    "Green": "#1a9e5c",
    "Amber": "#f0a500",
    "Red":   "#d93025",
}


def _get_clause(clause_key: str) -> dict:
    try:
        from utils.dpdp_clauses import get_clause
        return get_clause(clause_key)
    except (ImportError, KeyError):
        return _DPDP_CLAUSE_FALLBACK.get(clause_key, {
            "number": "DPDP Act 2023", "text": clause_key,
            "old": "DPDP Act 2023", "new": "DPDP Rules",
        })


# ---------------------------------------------------------------------------
# Session-based rate throttle (UI-layer only; persistent control in orchestration)
# ---------------------------------------------------------------------------

def _check_session_rate_limit() -> bool:
    """Return True if the session has NOT exceeded the submission limit."""
    count = st.session_state.get(_SESSION_SUBMIT_KEY, 0)
    return count < _SESSION_SUBMIT_LIMIT


def _increment_session_counter() -> None:
    st.session_state[_SESSION_SUBMIT_KEY] = (
        st.session_state.get(_SESSION_SUBMIT_KEY, 0) + 1
    )


# ---------------------------------------------------------------------------
# Customer-friendly request preview (read-only, no storage)
# ---------------------------------------------------------------------------

def get_customer_friendly_view(request: dict) -> dict:
    return {
        t("request_id"):   request.get("id", "—"),
        t("request_type"): _t_request_type(request.get("type", "—")),
        t("submitted_on"): (request.get("submitted_at") or "")[:10] or "—",
        t("deadline"):     request.get("deadline", "—"),
        t("status"):       _t_status(request.get("status", "—")),
        t("branch"):       request.get("branch", "—"),
        t("assisted"):     t("assisted_branch_officer") if request.get("assisted") else t("self_service"),
    }


# ---------------------------------------------------------------------------
# Shared UI helpers
# ---------------------------------------------------------------------------

def _kpi(label: str, value, colour: str = "#0A3D91", sub: str = "") -> None:
    st.markdown(
        f'''<div class="kpi-card">
            <h4>{label}</h4>
            <h2 style="color:{colour};">{value}</h2>
            <p style="color:{colour};">{sub}</p>
        </div>''',
        unsafe_allow_html=True,
    )


def _render_sla_table(requests: list, user: str, allow_update: bool = True) -> None:
    """
    Render filterable SLA table.
    Status updates go through orchestration.
    Export is restricted to permitted roles only.
    Charts are guarded against empty datasets.
    """
    # ── Empty dataset guard ───────────────────────────────────────────────────
    if not requests:
        st.info(t("no_requests_available"))
        return

    fcol1, fcol2, fcol3 = st.columns(3)
    with fcol1:
        f_status_display = st.multiselect(
            t("status"),
            [t("open"), t("in_progress"), t("escalated"), t("closed"), t("rejected")],
            default=[],
            key=f"sla_f_status_{allow_update}",
        )
        _rev_status = {t(v): k for k, v in _STATUS_I18N.items()}
        f_status_internal = [_rev_status.get(s, s) for s in f_status_display]

    with fcol2:
        f_sla = st.multiselect(
            t("sla_status"), ["Green", "Amber", "Red"], default=[],
            key=f"sla_f_sla_{allow_update}",
        )
    with fcol3:
        f_cid = st.text_input(t("search_customer_id"), key=f"sla_f_cid_{allow_update}")

    filtered = requests
    if f_status_internal: filtered = [r for r in filtered if r["status"] in f_status_internal]
    if f_sla:             filtered = [r for r in filtered if r["sla_status"] in f_sla]
    if f_cid:             filtered = [r for r in filtered if f_cid.lower() in r["customer_id"].lower()]

    if filtered:
        rows = []
        for req in filtered:
            # SLA engine: normalise datetime to avoid offset-naive/aware TypeError
            submitted_dt = _normalise_dt(req["submitted_at"])
            detail = get_sla_detail(
                req["id"], req["sla_key"],
                submitted_dt,
            )
            rows.append({
                t("id"):           req["id"],
                t("customer_id"):  _mask_id(req["customer_id"]),
                t("request_type"): _t_request_type(req["type"]),
                t("branch"):       req.get("branch", "—"),
                t("submitted"):    req["submitted_at"][:10],
                t("deadline"):     req["deadline"],
                t("status"):       _t_status(req["status"]),
                t("sla_status"):   status_badge(req["sla_status"]),
                t("days_left"): (
                    f"{detail['remaining_days']}d"
                    if not detail["overdue"]
                    else f"+{abs(detail['remaining_days'])}d {t('overdue')}"
                ),
                t("assisted"):    t("yes") if req.get("assisted") else t("no"),
                t("id_verified"): t("yes") if req.get("identity_verified") else "—",
            })
        df = pd.DataFrame(rows)
        st.dataframe(df, use_container_width=True, hide_index=True)

        # ── Export: permitted roles only ──────────────────────────────────────
        if _can_export():
            export_data(df, "rights_requests")
        else:
            st.caption(
                f"🔒 {t('export_restricted_notice') if 'export_restricted_notice' in dir() else 'Export is available to authorised roles only (DPO, Auditor, Privacy Operations, Board).'}"
            )
    else:
        st.info(t("no_records_match_filters"))

    if not allow_update:
        return

    # ── Status update panel ───────────────────────────────────────────────────
    st.divider()
    st.subheader(t("update_status"))

    open_ids = [r["id"] for r in requests if r["status"] not in CLOSED_STATUSES]
    if not open_ids:
        st.info(t("all_requests_closed"))
        return

    sel_id  = st.selectbox(t("select_request"), open_ids)
    sel_req = next((r for r in requests if r["id"] == sel_id), None)

    _status_display_opts = [t("in_progress"), t("closed"), t("rejected")]
    _status_internal_map = {
        t("in_progress"): "In Progress",
        t("closed"):      "Closed",
        t("rejected"):    "Rejected",
    }
    new_status_display = st.selectbox(t("new_status"), _status_display_opts)
    new_status         = _status_internal_map[new_status_display]
    update_note        = st.text_input(t("resolution_note"))

    # Identity verification gate for correction/erasure
    if sel_req and sel_req["type"] in IDENTITY_VERIFICATION_REQUIRED:
        if not sel_req.get("identity_verified"):
            st.warning(
                f"⚠️ **{t('identity_verification_required')}** — "
                f"{_t_request_type(sel_req['type'])}. "
                f"{t('identity_verification_warning')}"
            )
            verify_mode = st.selectbox(
                t("verification_method"),
                ["physical_id_verified", "aadhaar_verified", "video_kyc"],
                key=f"verify_mode_{sel_id}",
            )
            if st.button(t("mark_identity_verified"), key=f"id_verify_{sel_id}"):
                result = orchestration.execute_action(
                    action_type="mark_identity_verified",
                    payload={
                        "request_id":        sel_id,
                        "verification_mode": verify_mode,
                    },
                    actor=user,
                )
                if result.get("status") == "success":
                    st.success(t("identity_marked_verified"))
                    st.rerun()
                else:
                    st.error(f"{t('identity_verification_failed')}: {result.get('message', t('unknown_error'))}")
        else:
            st.success(
                f"{t('identity_verified_by')} `{sel_req.get('identity_verified_by', '—')}` "
                f"{t('on_date')} {(sel_req.get('identity_verified_at') or '')[:10]} "
                f"[{sel_req.get('verification_mode', '—')}]"
            )

    if st.button(t("update_status"), use_container_width=True, key=f"update_{sel_id}"):
        result = orchestration.execute_action(
            action_type="update_rights_request_status",
            payload={
                "request_id": sel_id,
                "new_status": new_status,
                "note":       update_note,
            },
            actor=user,
        )
        if result.get("status") == "success":
            if result.get("escalated"):
                st.warning(t("flagged_for_dpo_review"))
            st.success(
                f"{t('request')} {sel_id} {t('updated_to')} **{_t_status(new_status)}**."
            )
            st.rerun()
        else:
            st.error(
                f"{t('update_blocked')}  \n"
                f"{t('reason')}: {result.get('message', t('policy_violation'))}"
            )


def _render_sla_analytics(all_reqs: list, open_reqs: list) -> None:
    # ── Empty dataset guard ───────────────────────────────────────────────────
    if not all_reqs:
        st.info(t("no_data_yet"))
        return

    ac1, ac2 = st.columns(2)

    with ac1:
        sla_counts = {
            t("sla_green"): sum(1 for r in open_reqs if r["sla_status"] == "Green"),
            t("sla_amber"): sum(1 for r in open_reqs if r["sla_status"] == "Amber"),
            t("sla_red"):   sum(1 for r in open_reqs if r["sla_status"] == "Red"),
        }
        # Guard: plotly pie crashes on all-zero values
        if sum(sla_counts.values()) == 0:
            st.info(t("no_open_requests_for_chart"))
        else:
            fig_pie = go.Figure(go.Pie(
                labels=list(sla_counts.keys()),
                values=list(sla_counts.values()),
                hole=0.6,
                marker_colors=["#1a9e5c", "#f0a500", "#d93025"],
                textinfo="label+value",
            ))
            fig_pie.update_layout(
                title=t("open_requests_by_sla"),
                height=300, showlegend=False,
                margin=dict(l=0, r=0, t=40, b=0),
                annotations=[dict(
                    text=f"{len(open_reqs)}<br>{t('open')}",
                    x=0.5, y=0.5, font=dict(size=15, color="#0A3D91"), showarrow=False,
                )],
            )
            st.plotly_chart(fig_pie, use_container_width=True)
            more_info(t("sla_legend_note"))

    with ac2:
        status_counts: dict[str, int] = {}
        for r in all_reqs:
            label = _t_status(r["status"])
            status_counts[label] = status_counts.get(label, 0) + 1

        if not status_counts:
            st.info(t("no_data_yet"))
        else:
            bar_colours_internal = {
                "Open":        "#5a9ef5",
                "In Progress": "#f0a500",
                "Escalated":   "#d93025",
                "Closed":      "#1a9e5c",
                "Rejected":    "#aaa",
            }
            bar_colours = {_t_status(k): v for k, v in bar_colours_internal.items()}
            fig_bar = go.Figure(go.Bar(
                x=list(status_counts.keys()),
                y=list(status_counts.values()),
                marker_color=[bar_colours.get(s, "#ccc") for s in status_counts],
                text=list(status_counts.values()),
                textposition="outside",
            ))
            fig_bar.update_layout(
                title=t("all_requests_by_status"),
                yaxis=dict(title=t("count")),
                plot_bgcolor="#ffffff", paper_bgcolor="#ffffff",
                font=dict(color="#0A3D91"),
                height=300, showlegend=False,
            )
            st.plotly_chart(fig_bar, use_container_width=True)

    closed      = [r for r in all_reqs if r["status"] == "Closed"]
    on_time     = sum(1 for r in closed if r["sla_status"] in ("Green", "Amber"))
    rate        = round(on_time / len(closed) * 100, 1) if closed else 0.0
    rate_colour = "#1a9e5c" if rate >= 90 else "#f0a500" if rate >= 75 else "#d93025"
    st.markdown(
        f"<div style='background:{rate_colour}18;border:2px solid {rate_colour};"
        f"border-radius:10px;padding:16px 24px;text-align:center'>"
        f"<div style='font-size:2rem;font-weight:800;color:{rate_colour}'>{rate}%</div>"
        f"<div style='color:#444'>{t('sla_compliance_rate')} — {t('closed_resolved_within_window')}</div>"
        f"<div style='color:#888;font-size:0.8rem'>{on_time} {t('of')} {len(closed)} {t('closed_on_time')}</div>"
        f"</div>",
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# Shared submission result handler — avoids duplicating success/blocked UI
# ---------------------------------------------------------------------------

def _handle_submission_result(result: dict, request_type: str) -> bool:
    """
    Display success or error from orchestration submission result.
    Returns True if submission succeeded (caller should st.rerun()).
    """
    if result.get("status") == "success":
        record = result["record"]
        st.success(
            f"{t('request_submitted_success')} **{record['id']}**  \n"
            f"{t('deadline')}: **{record['deadline']}**"
        )
        if result.get("escalated"):
            st.warning(t("flagged_for_dpo_review"))
        clause_key = CLAUSE_MAP.get(request_type)
        if clause_key:
            clause = _get_clause(clause_key)
            explain_dynamic(
                title=t("rights_invocation_title"),
                reason=t("rights_invocation_reason"),
                old_clause=clause.get("old", "DPDP Act 2023"),
                new_clause=clause.get("new", "DPDP Rules"),
            )
        _increment_session_counter()
        return True

    # Blocked
    if result.get("consent_gate"):
        explain("rights_blocked_no_consent")
        st.error(
            f"{t('request_blocked_consent_gate')}  \n"
            f"{t('reason')}: {result.get('message', t('policy_violation'))}  \n"
            f"{t('valid_consent_required_for')} **{_t_request_type(request_type)}**."
        )
    else:
        st.error(
            f"{t('request_blocked')}  \n"
            f"{t('reason')}: {result.get('message', t('policy_violation'))}"
        )
    return False


# ---------------------------------------------------------------------------
# CUSTOMER VIEW
# Submit own requests only. NO approve / execute / export actions.
# ---------------------------------------------------------------------------

def render_customer_view() -> None:
    # ── STEP 6: Role guard — only Customer roles may enter this view ──────────
    if st.session_state.get("role") not in ("customer", "customer_assisted"):
        st.warning(t("access_restricted"))
        return

    import auth as _auth
    _cu         = _auth.get_current_user() or {}
    user        = _cu.get("username", st.session_state.get("username", "customer"))
    # ── STEP 4: Customer ID is always auto-loaded from session — never manual ─
    customer_id = st.session_state.user.get("customer_id") if hasattr(st.session_state, "user") and isinstance(st.session_state.user, dict) else _cu.get("customer_id", user)

    st.header(t("rights_portal"))
    st.caption(t("customer_portal_caption"))

    # ── STEP 5: Show masked customer identity at page top ─────────────────────
    masked_id = "****" + str(customer_id)[-4:] if customer_id and len(str(customer_id)) > 4 else "****"
    st.info(f"🪪 {t('customer_id')}: **{masked_id}**")

    # Load via orchestration query (read-only) — STEP 10: own requests only
    query_result = orchestration.execute_action(
        action_type="query_rights_requests",
        payload={"customer_id": customer_id},
        actor=user,
    )
    my_reqs   = query_result.get("records", [])
    # ── STEP 10: Enforce customer sees ONLY their own requests ────────────────
    my_reqs   = [r for r in my_reqs if r.get("customer_id") == customer_id]
    my_open   = [r for r in my_reqs if r["status"] in OPEN_STATUSES]
    my_closed = [r for r in my_reqs if r["status"] in CLOSED_STATUSES]

    k1, k2, k3 = st.columns(3)
    with k1: _kpi(t("my_total_requests"), len(my_reqs), "#0A3D91", t("all_submitted"))
    with k2: _kpi(t("active"), len(my_open), "#0A3D91", t("being_processed"))
    with k3: _kpi(t("closed"), len(my_closed), "#1a9e5c", t("resolved"))

    tab1, tab2 = st.tabs([t("submit_request"), t("my_requests")])

    # ── Submit tab ────────────────────────────────────────────────────────────
    with tab1:
        st.subheader(t("submit_request"))
        st.caption(t("customer_rights_caption"))
        more_info(t("customer_rights_sla_note"))

        # Session rate limit guard
        if not _check_session_rate_limit():
            st.error(t("rate_limit_exceeded_session"))
            return

        col1, col2 = st.columns(2)
        with col1:
            # ── STEP 4 & 5: ID is auto-loaded; display masked, never editable ──
            st.text_input(t("customer_id"), value=masked_id, disabled=True)

            # ── STEP 2: Customer dropdown excludes "Access My Data" ────────────
            # Only Correction, Erasure, and Grievance are permitted for customers.
            # "Access My Data" is an official-initiated workflow (access_requests.py).
            _customer_rt_display_options     = [_t_request_type(k) for k in CUSTOMER_REQUEST_TYPES]
            _customer_rt_display_to_internal = {_t_request_type(k): k for k in CUSTOMER_REQUEST_TYPES}
            rt_display   = st.selectbox(t("request_type"), _customer_rt_display_options)
            request_type = _customer_rt_display_to_internal[rt_display]

            # ── Banking identity fields ────────────────────────────────────────
            aadhaar        = st.text_input("Aadhaar Number", max_chars=12, placeholder="12-digit Aadhaar")
            account_number = st.text_input("Account Number", placeholder="Kerala Bank account number")
            ifsc_code      = st.text_input("IFSC Code", placeholder="e.g. KLBK0001234")

        with col2:
            district = st.selectbox("District", KERALA_DISTRICTS)
            notes    = st.text_area(t("supporting_details"), height=100)
            sla_key  = REQUEST_TYPE_MAP[request_type]
            sla_days = SLA_CONFIG.get(sla_key, 30)
            deadline = (datetime.utcnow() + timedelta(days=sla_days)).strftime("%Y-%m-%d")
            st.info(f"{t('sla_window')}: {sla_days} {t('days')} — {t('deadline')}: {deadline}")

        with st.expander(t("preview_request")):
            preview = get_customer_friendly_view({
                "id":           f"<{t('assigned_on_submit')}>",
                "customer_id":  customer_id,
                "type":         request_type,
                "branch":       get_branch() or "All",
                "submitted_at": datetime.utcnow().isoformat(),
                "deadline":     deadline,
                "status":       "Open",
                "assisted":     False,
            })
            for k, v in preview.items():
                st.markdown(f"**{k}:** {v}")
            # Show masked sensitive fields in preview
            if aadhaar:
                st.markdown(f"**Aadhaar:** {mask(aadhaar)}")
            if account_number:
                st.markdown(f"**Account:** {mask(account_number)}")
            if district:
                st.markdown(f"**District:** {district}")

        if st.button(t("submit_request"), type="primary", use_container_width=True):
            if not customer_id or not str(customer_id).strip():
                st.error(t("customer_id_required"))
            else:
                # ── STEP 3: Correct request payload structure ─────────────────
                result = orchestration.execute_action(
                    action_type="create_rights_request",
                    payload={
                        "request_type":       request_type,
                        "customer_id":        customer_id,
                        "submitted_by":       st.session_state.get("username", user),
                        "aadhaar":            aadhaar.strip() if aadhaar else "",
                        "account_number":     account_number.strip() if account_number else "",
                        "ifsc_code":          ifsc_code.strip() if ifsc_code else "",
                        "district":           district,
                        "notes":              notes or "",
                        "supporting_details": notes or "",
                        "description":        notes or "",
                        "status":             "Pending",
                        "sla_status":         "Within SLA",
                        "assisted":           False,
                        "identity_verified":  False,
                        "submitted_time":     datetime.utcnow().isoformat(),
                    },
                    actor=user,
                )
                if _handle_submission_result(result, request_type):
                    st.rerun()

    # ── My Requests tab ───────────────────────────────────────────────────────
    with tab2:
        st.subheader(t("my_request_history"))
        st.caption(t("my_requests_only_caption"))

        if not my_reqs:
            st.info(t("no_requests_submitted_yet"))
        else:
            rows = [
                {
                    t("request_id"):   r["id"],
                    t("request_type"): _t_request_type(r["type"]),
                    t("submitted"):    r["submitted_at"][:10],
                    t("deadline"):     r["deadline"],
                    t("status"):       _t_status(r["status"]),
                    t("notes"):        r.get("notes") or "—",
                }
                for r in my_reqs
            ]
            df = pd.DataFrame(rows)
            st.dataframe(df, use_container_width=True, hide_index=True)
            # Customer CANNOT export — data export is a privileged action
            # Export available to: DPO, Board, Auditor, Privacy Operations only

            if my_open:
                st.divider()
                st.subheader(t("active_request_progress"))
                for req in my_open:
                    # SLA: normalise datetime before passing to engine
                    submitted_dt = _normalise_dt(req["submitted_at"])
                    detail = get_sla_detail(
                        req["id"], req["sla_key"],
                        submitted_dt,
                    )
                    with st.container(border=True):
                        rc1, rc2 = st.columns([3, 1])
                        rc1.markdown(f"**{req['id']}** — {_t_request_type(req['type'])}")
                        rc1.caption(
                            f"{t('submitted')}: {req['submitted_at'][:10]}   "
                            f"{t('deadline')}: {req['deadline']}"
                        )
                        if req["status"] == "Escalated":
                            rc2.error(t("escalated"))
                        elif req["status"] == "In Progress":
                            rc2.warning(t("in_progress"))
                        else:
                            rc2.info(t("open"))

                        if detail["overdue"]:
                            st.warning(
                                f"{t('request_overdue_by')} {abs(detail['remaining_days'])} "
                                f"{t('days')}. {t('escalated_priority_attention')}"
                            )
                        else:
                            st.caption(
                                f"{detail['remaining_days']} {t('days_remaining_until')} {t('deadline').lower()}."
                            )

        # ── STEP 9: Consent Artefact Download ─────────────────────────────────
        st.divider()
        st.subheader(t("consent_history") if "consent_history" in dir() else "Consent History")
        try:
            consent_result = orchestration.execute_action(
                action_type="query_consents",
                payload={"customer_id": customer_id},
                actor=user,
            )
            customer_consents = [
                c for c in consent_result.get("records", [])
                if c.get("customer_id") == customer_id
            ]
            if customer_consents:
                consent_df = pd.DataFrame(customer_consents)
                st.dataframe(consent_df, use_container_width=True, hide_index=True)
                st.download_button(
                    label="⬇️ Download Consent Artefact",
                    data=consent_df.to_csv(index=False),
                    file_name="consent_history.csv",
                    mime="text/csv",
                )
            else:
                st.info(t("no_consent_records") if "no_consent_records" in dir() else "No consent records found for your account.")
        except Exception:
            st.info("Consent history is not available at this time.")


# ---------------------------------------------------------------------------
# OFFICER VIEW
# Covers: Customer Support Officer, Branch Privacy Coordinator,
#         Regional Compliance Officer (assisted intake + branch queue monitor).
# Officers may register requests and monitor their branch queue.
# Officers may NOT directly execute erasure or approve/reject requests.
# ---------------------------------------------------------------------------

def render_officer_console() -> None:
    import auth as _auth
    _cu         = _auth.get_current_user() or {}
    user        = _cu.get("username", st.session_state.get("username", "officer"))
    user_branch = _cu.get("branch") or get_branch() or "All"
    role        = st.session_state.get("role", "")

    st.header(t("rights_portal"))
    st.caption(f"{t('branch')}: **{user_branch}** — {t('sla_recalc_caption')}")

    query_result = orchestration.execute_action(
        action_type="query_rights_requests",
        payload={"branch": user_branch},
        actor=user,
    )
    branch_reqs = query_result.get("records", [])
    open_reqs   = [r for r in branch_reqs if r["status"] not in CLOSED_STATUSES]

    _total = len(branch_reqs)
    _open  = len(open_reqs)
    _green = sum(1 for r in open_reqs if r["sla_status"] == "Green")
    _amber = sum(1 for r in open_reqs if r["sla_status"] == "Amber")
    _red   = sum(1 for r in open_reqs if r["sla_status"] == "Red" or r["status"] == "Escalated")

    m1, m2, m3, m4, m5 = st.columns(5)
    with m1: _kpi(t("branch_requests"), _total, "#6B7A90", t("this_branch"))
    with m2: _kpi(t("open"), _open, "#0A3D91", t("active_cases"))
    with m3: _kpi(t("sla_green"), _green, "#1a9e5c", t("within_window"))
    with m4: _kpi(t("sla_amber"), _amber, "#C58F00", t("approaching_deadline"))
    with m5:
        rc = "#d93025" if _red > 0 else "#6B7A90"
        _kpi(t("red_escalated"), _red, rc, t("escalated_to_dpo"))

    if _red > 0:
        st.warning(
            f"⚠️ {_red} {t('requests_escalated_at')} **{user_branch}**. "
            f"{t('requires_dpo_attention')}"
        )

    # Branch Privacy Coordinators monitor but do not submit on behalf of customers
    # Customer Support Officers may do assisted intake
    _can_submit = role in (
        "customer_support", "branch_officer", "privacy_steward",
        "regional_officer", "regional_compliance_officer",
    )

    tabs = (
        [t("assisted_submission"), f"{t('branch_requests')} — {user_branch}"]
        if _can_submit
        else [f"{t('branch_requests')} — {user_branch}"]
    )
    tab_objects = st.tabs(tabs)

    tab_idx = 0

    # ── Assisted Submission Tab (not shown for Branch Privacy Coordinator) ────
    if _can_submit:
        with tab_objects[tab_idx]:
            st.subheader(t("submit_on_behalf_of_customer"))
            st.caption(t("officer_assisted_caption"))
            st.info(t("officer_assisted_info"))
            more_info(t("officer_assisted_more_info"))

            if not _check_session_rate_limit():
                st.error(t("rate_limit_exceeded_session"))
                return

            col1, col2 = st.columns(2)
            with col1:
                cust_id = st.text_input(
                    t("customer_id"), placeholder="e.g. C110", key="officer_cust_id"
                )
                _rt_display_options     = [_t_request_type(k) for k in REQUEST_TYPE_MAP.keys()]
                _rt_display_to_internal = {_t_request_type(k): k for k in REQUEST_TYPE_MAP.keys()}
                rt_display   = st.selectbox(t("request_type"), _rt_display_options, key="officer_req_type")
                request_type = _rt_display_to_internal[rt_display]

                # ── Banking identity fields ────────────────────────────────────
                aadhaar        = st.text_input("Aadhaar Number", max_chars=12, placeholder="12-digit Aadhaar", key="officer_aadhaar")
                account_number = st.text_input("Account Number", placeholder="Kerala Bank account number", key="officer_account")
                ifsc_code      = st.text_input("IFSC Code", placeholder="e.g. KLBK0001234", key="officer_ifsc")

            with col2:
                district = st.selectbox("District", KERALA_DISTRICTS, key="officer_district")
                notes    = st.text_area(t("supporting_details"), height=100, key="officer_notes")
                sla_key  = REQUEST_TYPE_MAP[request_type]
                sla_days = SLA_CONFIG.get(sla_key, 30)
                deadline = (datetime.utcnow() + timedelta(days=sla_days)).strftime("%Y-%m-%d")
                st.info(f"{t('sla_window')}: {sla_days} {t('days')} — {t('deadline')}: {deadline}")

            needs_id_verify   = request_type in IDENTITY_VERIFICATION_REQUIRED
            identity_verified = False
            verify_mode       = "physical_id_verified"

            if needs_id_verify:
                st.warning(
                    f"⚠️ **{_t_request_type(request_type)}** {t('requires_mandatory_id_verification')}"
                )
                verify_mode = st.selectbox(
                    t("verification_method"),
                    ["physical_id_verified", "aadhaar_verified", "video_kyc"],
                    key="officer_verify_mode",
                )
                identity_verified = st.checkbox(
                    t("officer_id_verification_confirm"),
                    key="officer_id_confirmed",
                )

            with st.expander(t("preview_request_customer_view")):
                preview = get_customer_friendly_view({
                    "id":           f"<{t('assigned_on_submit')}>",
                    "customer_id":  cust_id or f"<{t('enter_above')}>",
                    "type":         request_type,
                    "branch":       user_branch,
                    "submitted_at": datetime.utcnow().isoformat(),
                    "deadline":     deadline,
                    "status":       "Open",
                    "assisted":     True,
                })
                for k, v in preview.items():
                    st.markdown(f"**{k}:** {v}")
                if aadhaar:
                    st.markdown(f"**Aadhaar:** {mask(aadhaar)}")
                if account_number:
                    st.markdown(f"**Account:** {mask(account_number)}")
                st.markdown(f"**District:** {district}")

            if st.button(
                t("submit_assisted_request"), type="primary",
                use_container_width=True, key="officer_submit",
            ):
                if not cust_id.strip():
                    st.error(t("customer_id_required"))
                elif needs_id_verify and not identity_verified:
                    st.error(
                        f"{t('must_confirm_id_verification_before')} "
                        f"**{_t_request_type(request_type)}** {t('request')}."
                    )
                else:
                    result = orchestration.execute_action(
                        action_type="create_rights_request",
                        payload={
                            "request_type":       request_type,
                            "customer_id":        cust_id.strip(),
                            "aadhaar":            aadhaar.strip() if aadhaar else "",
                            "account_number":     account_number.strip() if account_number else "",
                            "ifsc_code":          ifsc_code.strip() if ifsc_code else "",
                            "district":           district,
                            "notes":              notes or "",
                            "description":        notes or "",
                            "assisted":           True,
                            "verification_mode":  verify_mode,
                            "identity_verified":  identity_verified,
                            "submitted_by":       st.session_state.get("username", st.session_state.get("role", "customer_support")),
                            "status":             "Pending",
                            "sla_status":         "Within SLA",
                            "submitted_time":     datetime.utcnow().isoformat(),
                        },
                        actor=user,
                    )
                    if _handle_submission_result(result, request_type):
                        set_assisted_submission(False)
                        st.rerun()

        tab_idx += 1

    # ── Branch Queue Tab ──────────────────────────────────────────────────────
    with tab_objects[tab_idx]:
        st.subheader(f"{t('requests')} — {user_branch}")
        st.caption(t("officer_branch_requests_caption"))
        # Branch Privacy Coordinator: monitor only (allow_update=False)
        # Customer Support Officer and other officers: allow status updates
        _allow_update = role not in ("branch_privacy_coordinator", "regional_compliance_officer")
        _render_sla_table(branch_reqs, user, allow_update=_allow_update)


# ---------------------------------------------------------------------------
# DPO VIEW
# Full governance: all requests + status updates + escalations + analytics.
# Also used by privacy_operations for correction/erasure execution.
# ---------------------------------------------------------------------------

def render_dpo_console() -> None:
    import auth as _auth
    _cu  = _auth.get_current_user() or {}
    user = _cu.get("username", st.session_state.get("username", "dpo_admin"))

    st.header(t("rights_portal"))
    st.caption(t("sla_recalc_caption"))
    more_info(t("dpo_console_more_info"))

    query_result = orchestration.execute_action(
        action_type="query_rights_requests",
        payload={},
        actor=user,
    )
    all_reqs  = query_result.get("records", [])
    open_reqs = [r for r in all_reqs if r["status"] not in CLOSED_STATUSES]

    _total = len(all_reqs)
    _open  = len(open_reqs)
    _green = sum(1 for r in open_reqs if r["sla_status"] == "Green")
    _amber = sum(1 for r in open_reqs if r["sla_status"] == "Amber")
    _red   = sum(1 for r in open_reqs if r["sla_status"] == "Red" or r["status"] == "Escalated")

    m1, m2, m3, m4, m5 = st.columns(5)
    with m1: _kpi(t("total_requests"), _total, "#6B7A90", t("all_records"))
    with m2: _kpi(t("open"), _open, "#0A3D91", t("active_cases"))
    with m3: _kpi(t("sla_green"), _green, "#1a9e5c", t("within_window"))
    with m4: _kpi(t("sla_amber"), _amber, "#C58F00", t("approaching_deadline"))
    with m5:
        rc = "#d93025" if _red > 0 else "#6B7A90"
        _kpi(t("red_escalated"), _red, rc, t("immediate_attention"))

    tab1, tab2, tab3, tab4 = st.tabs([
        t("assisted_submission"),
        t("all_requests_sla"),
        t("escalations"),
        t("sla_analytics"),
    ])

    # ── Tab 1: DPO-assisted submission ────────────────────────────────────────
    with tab1:
        st.subheader(t("submit_on_behalf_of_customer"))
        st.info(t("dpo_submission_info"))

        if not _check_session_rate_limit():
            st.error(t("rate_limit_exceeded_session"))
            return

        col1, col2 = st.columns(2)
        with col1:
            dpo_cust_id = st.text_input(
                t("customer_id"), placeholder="e.g. C105", key="dpo_cust_id"
            )
            _rt_display_options     = [_t_request_type(k) for k in REQUEST_TYPE_MAP.keys()]
            _rt_display_to_internal = {_t_request_type(k): k for k in REQUEST_TYPE_MAP.keys()}
            rt_display   = st.selectbox(t("request_type"), _rt_display_options, key="dpo_req_type")
            request_type = _rt_display_to_internal[rt_display]

            # ── Banking identity fields ────────────────────────────────────────
            aadhaar        = st.text_input("Aadhaar Number", max_chars=12, placeholder="12-digit Aadhaar", key="dpo_aadhaar")
            account_number = st.text_input("Account Number", placeholder="Kerala Bank account number", key="dpo_account")
            ifsc_code      = st.text_input("IFSC Code", placeholder="e.g. KLBK0001234", key="dpo_ifsc")

        with col2:
            district = st.selectbox("District", KERALA_DISTRICTS, key="dpo_district")
            notes    = st.text_area(t("supporting_details"), height=120, key="dpo_notes")
            sla_key  = REQUEST_TYPE_MAP[request_type]
            sla_days = SLA_CONFIG.get(sla_key, 30)
            deadline = (datetime.utcnow() + timedelta(days=sla_days)).strftime("%Y-%m-%d")
            st.info(f"{t('sla_window')}: {sla_days} {t('days')} — {t('deadline')}: {deadline}")
            more_info(t("dpdp_timely_processing_note"))

        needs_id_verify   = request_type in IDENTITY_VERIFICATION_REQUIRED
        identity_verified = False
        verify_mode       = "physical_id_verified"
        if needs_id_verify:
            st.warning(f"⚠️ **{_t_request_type(request_type)}** {t('requires_id_verification')}.")
            verify_mode = st.selectbox(
                t("verification_method"),
                ["physical_id_verified", "aadhaar_verified", "video_kyc"],
                key="dpo_verify_mode",
            )
            identity_verified = st.checkbox(t("identity_verified_confirm"), key="dpo_id_confirmed")

        with st.expander(t("preview_request")):
            preview = get_customer_friendly_view({
                "id":           f"<{t('assigned_on_submit')}>",
                "customer_id":  dpo_cust_id or f"<{t('enter_above')}>",
                "type":         request_type,
                "branch":       get_branch() or "All",
                "submitted_at": datetime.utcnow().isoformat(),
                "deadline":     deadline,
                "status":       "Open",
                "assisted":     True,
            })
            for k, v in preview.items():
                st.markdown(f"**{k}:** {v}")
            if aadhaar:
                st.markdown(f"**Aadhaar:** {mask(aadhaar)}")
            if account_number:
                st.markdown(f"**Account:** {mask(account_number)}")
            st.markdown(f"**District:** {district}")

        if st.button(
            t("submit_request"), type="primary",
            use_container_width=True, key="dpo_submit",
        ):
            if not dpo_cust_id.strip():
                st.error(t("customer_id_required"))
            elif needs_id_verify and not identity_verified:
                st.error(t("identity_verification_required_error"))
            else:
                result = orchestration.execute_action(
                    action_type="create_rights_request",
                    payload={
                        "request_type":       request_type,
                        "customer_id":        dpo_cust_id.strip(),
                        "aadhaar":            aadhaar.strip() if aadhaar else "",
                        "account_number":     account_number.strip() if account_number else "",
                        "ifsc_code":          ifsc_code.strip() if ifsc_code else "",
                        "district":           district,
                        "notes":              notes or "",
                        "description":        notes or "",
                        "assisted":           True,
                        "verification_mode":  verify_mode,
                        "identity_verified":  identity_verified,
                        "submitted_by":       st.session_state.get("username", st.session_state.get("role", "dpo")),
                        "status":             "Pending",
                        "sla_status":         "Within SLA",
                        "submitted_time":     datetime.utcnow().isoformat(),
                    },
                    actor=user,
                )
                if _handle_submission_result(result, request_type):
                    st.rerun()

    # ── Tab 2: All requests + status update ───────────────────────────────────
    with tab2:
        st.subheader(t("all_requests_live_sla"))
        st.caption(t("sla_recalc_caption"))
        _render_sla_table(all_reqs, user, allow_update=True)

    # ── Tab 3: Escalations ────────────────────────────────────────────────────
    with tab3:
        st.subheader(t("escalated_overdue_requests"))
        st.caption(t("auto_escalated_when_red"))

        escalated = [r for r in all_reqs if r["escalated"] or r["status"] == "Escalated"]
        if not escalated:
            st.success(t("no_escalated_requests"))
        else:
            st.error(f"{len(escalated)} {t('requests_require_dpo_attention')}")
            for req in escalated:
                # SLA: normalise datetime to avoid offset-naive/aware TypeError
                submitted_dt = _normalise_dt(req["submitted_at"])
                detail = get_sla_detail(
                    req["id"], req["sla_key"],
                    submitted_dt,
                )
                colour = SLA_COLOUR.get(req["sla_status"], "#d93025")
                with st.container(border=True):
                    st.markdown(
                        f"<div style='border-left:5px solid {colour};padding-left:14px'>",
                        unsafe_allow_html=True,
                    )
                    c1, c2, c3, c4 = st.columns([2, 2, 2, 1])
                    c1.markdown(f"**{req['id']}** — `{_mask_id(req['customer_id'])}`")
                    c1.markdown(f"{t('request_type')}: {_t_request_type(req['type'])}")
                    c1.caption(
                        f"{t('branch')}: {req.get('branch', '—')} | "
                        f"{t('assisted')}: {t('yes') if req.get('assisted') else t('no')}"
                    )
                    c2.markdown(f"{t('submitted')}: `{req['submitted_at'][:10]}`")
                    c2.markdown(f"{t('deadline')}: `{req['deadline']}`")
                    c3.markdown(f"{t('status')}: **{_t_status(req['status'])}**")
                    c3.markdown(f"SLA: {status_badge(req['sla_status'])}")
                    if detail["overdue"]:
                        c4.error(f"+{abs(detail['remaining_days'])}d {t('overdue')}")
                    else:
                        c4.warning(f"{detail['remaining_days']}d {t('left')}")
                    st.markdown("</div>", unsafe_allow_html=True)

                    if req["status"] not in CLOSED_STATUSES:
                        res_note = st.text_input(
                            t("resolution_note"), key=f"res_{req['id']}"
                        )
                        if st.button(f"{t('close')} {req['id']}", key=f"close_{req['id']}"):
                            result = orchestration.execute_action(
                                action_type="update_rights_request_status",
                                payload={
                                    "request_id": req["id"],
                                    "new_status": "Closed",
                                    "note":       res_note,
                                },
                                actor=user,
                            )
                            if result.get("status") == "success":
                                st.success(f"{t('request')} {req['id']} {t('closed')}.")
                                st.rerun()
                            else:
                                st.error(
                                    f"{t('closure_blocked')}  \n"
                                    f"{t('reason')}: {result.get('message', t('policy_violation'))}"
                                )

    # ── Tab 4: Analytics ──────────────────────────────────────────────────────
    with tab4:
        st.subheader(t("sla_performance_analytics"))
        _render_sla_analytics(all_reqs, open_reqs)


# ---------------------------------------------------------------------------
# AUDITOR VIEW — read-only oversight with export access
# ---------------------------------------------------------------------------

def render_auditor_console() -> None:
    import auth as _auth
    _cu  = _auth.get_current_user() or {}
    user = _cu.get("username", st.session_state.get("username", "auditor"))

    st.header(t("rights_portal"))
    st.caption(t("auditor_rights_caption"))

    query_result = orchestration.execute_action(
        action_type="query_rights_requests",
        payload={},
        actor=user,
    )
    all_reqs  = query_result.get("records", [])
    open_reqs = [r for r in all_reqs if r["status"] not in CLOSED_STATUSES]

    # ── Empty dataset guard ───────────────────────────────────────────────────
    if not all_reqs:
        st.info(t("no_data_yet"))
        return

    _total = len(all_reqs)
    _open  = len(open_reqs)
    _green = sum(1 for r in open_reqs if r["sla_status"] == "Green")
    _amber = sum(1 for r in open_reqs if r["sla_status"] == "Amber")
    _red   = sum(1 for r in open_reqs if r["sla_status"] == "Red" or r["status"] == "Escalated")

    m1, m2, m3, m4, m5 = st.columns(5)
    with m1: _kpi(t("total_requests"), _total, "#6B7A90", t("all_records"))
    with m2: _kpi(t("open"), _open, "#0A3D91", t("active_cases"))
    with m3: _kpi(t("sla_green"), _green, "#1a9e5c", t("within_window"))
    with m4: _kpi(t("sla_amber"), _amber, "#C58F00", t("approaching_deadline"))
    with m5:
        rc = "#d93025" if _red > 0 else "#6B7A90"
        _kpi(t("red_escalated"), _red, rc, t("for_dpo_action"))

    st.info(f"🔒 {t('read_only_notice')}")

    tab1, tab2 = st.tabs([t("all_requests_sla"), t("sla_analytics")])

    with tab1:
        st.subheader(t("all_requests_live_sla_readonly"))
        st.caption(t("sla_recalc_caption"))
        _render_sla_table(all_reqs, user="auditor", allow_update=False)

    with tab2:
        st.subheader(t("sla_performance_analytics"))
        _render_sla_analytics(all_reqs, open_reqs)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def show() -> None:
    import auth as _auth

    # ── Session guard ─────────────────────────────────────────────────────────
    current_user = _auth.get_current_user()
    if not current_user:
        st.error(t("session_not_found"))
        st.info(t("contact_dpo_access"))
        return

    role = current_user["role"]   # always a canonical code

    # ── Role permission guard ─────────────────────────────────────────────────
    # Only these canonical roles may access the Rights Portal.
    # All other roles are denied regardless of how they arrive here.
    _allowed_canonical = {
        "customer",
        "customer_assisted",
        "customer_support",
        "branch_officer",
        "branch_privacy_coordinator",
        "regional_officer",
        "regional_compliance_officer",
        "privacy_steward",
        "privacy_operations",
        "dpo",
        "auditor",
        "internal_auditor",
    }

    if role not in _allowed_canonical:
        st.warning(t("access_restricted"))
        st.info(t("contact_dpo_access"))
        return

    # ── Role dispatch ─────────────────────────────────────────────────────────
    if role in ("customer", "customer_assisted"):
        render_customer_view()
    elif role in ("customer_support", "branch_officer", "branch_privacy_coordinator",
                  "regional_officer", "regional_compliance_officer", "privacy_steward"):
        render_officer_console()
    elif role in ("privacy_operations", "dpo"):
        render_dpo_console()
    elif role in ("auditor", "internal_auditor"):
        render_auditor_console()
    else:
        st.warning(t("access_restricted"))
        st.info(t("contact_dpo_access"))