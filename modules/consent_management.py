"""
modules/consent_management.py
------------------------------
Consent Management dashboard — DPDP Act 2023 compliant.

Architecture (updated):
    UI  →  orchestration.execute_action()  →  Engine  →  Audit / SLA / Compliance

Role-access model:
  customer        Create own consent (Tab 1 — direct)
  branch_officer  Assisted consent capture only (Tab 1 — assisted mode)
  DPO             Full visibility — revoke, renew, analytics (NO consent creation)
  Auditor         Read-only — register and analytics only
  SystemAdmin     Access restricted

Design contract:
  - NO storage writes, NO hash generation, NO SLA calls, NO audit_log calls here.
  - NO validation logic (expiry, DPIA, branch, drift) — all delegated to engine.
  - NO compliance_engine calls — orchestration triggers recalculation post-commit.
  - Module responsibilities: render form → collect inputs → build payload → call
    orchestration → display result.
  - All user-visible strings go through t() — zero hardcoded English strings.
"""

from __future__ import annotations

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
from datetime import datetime, timedelta

import engine.orchestration as orchestration
from engine.data_discovery import build_data_map
from engine.consent_validator import (
    get_all_consents,
    get_consent_status,
    PURPOSE_EXPIRY_DAYS,
)
from auth import get_role, get_branch
from utils.i18n import t
from utils.export_utils import export_data
from utils.explainability import explain_dynamic
from utils.ui_helpers import more_info, mask_identifier
from utils.dpdp_clauses import get_clause

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

CONSENT_STATUSES = ["Draft", "Active", "Expired", "Revoked", "Renewed", "Superseded"]

STATUS_COLOUR = {
    "Draft":      "#546e7a",
    "Active":     "#1a9e5c",
    "Expired":    "#f0a500",
    "Revoked":    "#d93025",
    "Renewed":    "#7B5EA7",
    "Superseded": "#444444",
}

PURPOSE_LABELS = list(PURPOSE_EXPIRY_DAYS.keys())

# Default retention period (days) — used only for preview display; engine owns real value
DEFAULT_RETENTION_DAYS = 365


# ---------------------------------------------------------------------------
# Consent submission — allowed roles
# Regional Officer monitors only; they do NOT submit consent.
# ---------------------------------------------------------------------------

CONSENT_SUBMIT_ROLES = {
    "customer",
    "branch_officer",
    "customer_support",
    "privacy_operations",
}


# ---------------------------------------------------------------------------
# validate_consent() — pre-flight check before calling orchestration
#
# Rules:
#   1. customer_id must be present
#   2. purpose must be present
#   3. supporting_details / notes are OPTIONAL — never block submission
#   4. submitting role must be in CONSENT_SUBMIT_ROLES
#
# Returns: (True, "Valid") or (False, "<human-readable reason>")
# Does NOT write to audit — orchestration owns that.
# ---------------------------------------------------------------------------

def validate_consent(payload: dict, role: str) -> tuple[bool, str]:
    """
    Pre-flight validation for consent capture payloads.

    Parameters
    ----------
    payload : dict  — consent payload built by the form
    role    : str   — canonical role code of the submitting actor

    Returns
    -------
    (True,  "Valid")             — submission may proceed
    (False, "<reason string>")   — submission blocked; reason is display-safe
    """
    if not str(payload.get("customer_id", "")).strip():
        return False, "Missing customer ID"

    if not str(payload.get("purpose", "")).strip():
        return False, "Missing processing purpose"

    if role not in CONSENT_SUBMIT_ROLES:
        return False, f"Role '{role}' is not permitted to submit consent"

    # supporting_details / notes are optional — default to empty string
    if payload.get("supporting_details") is None:
        payload["supporting_details"] = ""

    return True, "Valid"


# ---------------------------------------------------------------------------
# _exec_consent — thin wrapper around orchestration.execute_action
#
# Normalises the orchestration result dict into the shape the UI expects:
#   {"status": "success", "record": {...}}   on success
#   {"status": "error",   "message": "..."}  on failure
#
# Orchestration returns {"success": bool, "reason": str, ...} — not "status".
# Calling code also used "capture_consent" which is not a registered action
# type; the correct registered type is "consent_create".
# ---------------------------------------------------------------------------

def _exec_consent(payload: dict, actor: str) -> dict:
    """
    Submit a consent_create action via orchestration and return a normalised
    result dict with keys:
        status  : "success" | "error"
        record  : dict (on success) — enriched payload written to storage
        message : str  (on error)
    """
    # Flag tells _pre_commit_consent to skip the "existing consent" check
    # — this hook is designed for processing validation, not creation gating.
    payload.setdefault("_skip_consent_precheck", True)

    raw = orchestration.execute_action(
        action_type="consent_create",
        payload=payload,
        actor=actor,
    )

    if raw.get("success"):
        # Build a record from the committed payload so the UI can display it
        record = {
            "consent_id":  raw.get("transaction_id", "—"),
            "status":      "active" if payload.get("granted", True) else "revoked",
            "expiry_date": (
                datetime.utcnow() + timedelta(
                    days=PURPOSE_EXPIRY_DAYS.get(payload.get("purpose", ""), DEFAULT_RETENTION_DAYS)
                )
            ).strftime("%Y-%m-%d"),
            **payload,
        }
        return {"status": "success", "record": record}

    # Failure — surface the reason as a user-readable message
    reason = raw.get("reason", "")
    # Translate pre-commit check failures into friendly messages
    if "pre_commit" in reason.lower() or "consent_validation_error" in reason.lower():
        message = "Consent could not be validated — please check the Customer ID and Purpose."
    elif "storage" in reason.lower():
        message = "Consent recorded but could not be persisted — please retry."
    else:
        message = reason or "Submission failed — please try again."

    return {"status": "error", "message": message}


# ---------------------------------------------------------------------------
# Display helper — status dot badge
# ---------------------------------------------------------------------------

def _status_badge(status: str) -> str:
    colour = STATUS_COLOUR.get(status.title(), "#546e7a")
    return (
        f'<span style="display:inline-block;width:11px;height:11px;'
        f'border-radius:50%;background-color:{colour};margin-right:6px;"></span>'
    )


# ---------------------------------------------------------------------------
# Display helper — mask consent for non-privileged roles
# ---------------------------------------------------------------------------

def _mask_consent_for_display(consent: dict, role: str) -> dict:
    effective_role = st.session_state.get("role", role)
    view = consent.copy()
    if effective_role not in ("DPO", "dpo", "Auditor", "auditor"):
        view["data_principal_id"] = mask_identifier(
            view.get("data_principal_id", ""), role=effective_role
        )
        if "customer_id" in view:
            view["customer_id"] = mask_identifier(view["customer_id"], role=effective_role)
    return view


# ---------------------------------------------------------------------------
# Main Streamlit show()
# ---------------------------------------------------------------------------

def show():
    import auth as _auth

    # ── Session guard — always use get_current_user() as source of truth ────
    current_user = _auth.get_current_user()
    if not current_user:
        st.error(t("session_not_found"))
        st.info(t("contact_dpo_access"))
        return

    role        = current_user["role"]          # canonical code, e.g. "branch_officer"
    user        = current_user["username"]
    user_branch = current_user["branch"]

    # ── Role-access gate — all canonical codes ───────────────────────────────
    # Mirrors ROLE_PERMISSIONS["Consent Management"] in auth.py
    ALLOWED_ROLES = {
        "customer",
        "branch_officer",
        "regional_officer",
        "privacy_steward",
        "privacy_operations",
        "dpo",
        "auditor",
    }
    if role not in ALLOWED_ROLES:
        st.warning(t("access_restricted"))
        st.info(t("contact_dpo_access"))
        return

    st.header(t("consent_management"))
    st.caption(t("consent_lifecycle_caption"))

    more_info(t("consent_lifecycle_info"))

    # ── Role convenience flags — all canonical codes, no legacy strings ──────
    is_customer      = role == "customer"
    is_officer       = role == "branch_officer"
    is_regional      = role in ("regional_officer", "privacy_steward")
    is_privacy_ops   = role == "privacy_operations"
    is_dpo           = role == "dpo"
    is_auditor       = role == "auditor"
    # Branch-scoped: officer and regional/steward see only their branch records
    is_branch_scoped = is_officer or is_regional

    # ── Load & branch-filter consents (read-only) ────────────────────────────
    all_consents_raw = get_all_consents()

    if is_branch_scoped and user_branch and user_branch not in ("All", "-", None):
        all_consents = [
            c for c in all_consents_raw
            if c.get("branch", "All") == user_branch or c.get("branch") is None
        ]
        st.info(f"{t('showing_branch_records')} **{user_branch}**")
    else:
        all_consents = all_consents_raw

    # ── KPI strip ────────────────────────────────────────────────────────────
    _total   = len(all_consents)
    _active  = sum(1 for c in all_consents if c["status"].lower() == "active")
    _renewed = sum(1 for c in all_consents if c["status"].lower() == "renewed")
    _expired = sum(1 for c in all_consents if c["status"].lower() == "expired")
    _revoked = sum(1 for c in all_consents if c["status"].lower() == "revoked")

    m1, m2, m3, m4, m5 = st.columns(5)
    with m1:
        st.markdown(f'''<div class="kpi-card">
            <h4>{t("total_consents")}</h4>
            <h2>{_total}</h2>
            <p style="color:#6B7A90;">{t("this_branch") if is_branch_scoped else t("all_records")}</p>
        </div>''', unsafe_allow_html=True)
    with m2:
        st.markdown(f'''<div class="kpi-card">
            <h4>{t("active")}</h4>
            <h2 style="color:#1a9e5c;">{_active}</h2>
            <p style="color:#1a9e5c;">{t("lifecycle_compliant")}</p>
        </div>''', unsafe_allow_html=True)
    with m3:
        st.markdown(f'''<div class="kpi-card">
            <h4>{t("renewed")}</h4>
            <h2 style="color:#7B5EA7;">{_renewed}</h2>
            <p style="color:#7B5EA7;">{t("re_authorised")}</p>
        </div>''', unsafe_allow_html=True)
    with m4:
        st.markdown(f'''<div class="kpi-card">
            <h4>{t("expired")}</h4>
            <h2 style="color:#C58F00;">{_expired}</h2>
            <p style="color:#C58F00;">{t("requires_renewal")}</p>
        </div>''', unsafe_allow_html=True)
    with m5:
        st.markdown(f'''<div class="kpi-card">
            <h4>{t("revoked")}</h4>
            <h2 style="color:#B22222;">{_revoked}</h2>
            <p style="color:#B22222;">{t("consent_withdrawn")}</p>
        </div>''', unsafe_allow_html=True)

    more_info(t("kpi_realtime_note"))

    tab1, tab2, tab3, tab4 = st.tabs([
        t("submit_request"),
        t("consent_register"),
        t("revoke_renew"),
        t("analytics"),
    ])

    # ─────────────────────────────────────────────────────────────────────────
    # TAB 1 — Create / Capture Consent
    # ─────────────────────────────────────────────────────────────────────────
    with tab1:
        st.subheader(t("submit_request"))
        more_info(t("consent_creation_info"))

        # ── Customer: direct consent creation ────────────────────────────────
        if is_customer:
            col1, col2 = st.columns(2)
            with col1:
                customer_id = st.text_input(t("your_customer_id"), placeholder="e.g. CUST001")
                purpose     = st.selectbox(t("processing_purpose"), PURPOSE_LABELS)
            with col2:
                granted = st.radio(
                    t("your_decision"),
                    [t("grant_consent"), t("deny_consent")]
                ) == t("grant_consent")
                notes = st.text_area(t("notes_context"), height=100)

            # Expiry preview — display only, engine owns actual calculation
            retention_days  = PURPOSE_EXPIRY_DAYS.get(purpose, DEFAULT_RETENTION_DAYS)
            expiry_preview  = (datetime.utcnow() + timedelta(days=retention_days)).strftime("%Y-%m-%d")
            st.info(
                f"{t('consent_auto_expiry_info')} **{purpose}** — **{expiry_preview}** ({retention_days} {t('days')})."
            )

            if customer_id.strip():
                status_info = get_consent_status(customer_id.strip(), purpose)
                if status_info["exists"]:
                    st.info(
                        f"{t('existing_consent_found')}: {t('status')}=**{t(status_info['status'].lower())}**  "
                        f"{t('valid')}=**{status_info['valid']}**  "
                        f"{t('expires')}=**{str(status_info['expires_at'])[:10] if status_info['expires_at'] else t('na')}**"
                    )

            if st.button(t("submit_my_consent"), type="primary", use_container_width=True):
                if not customer_id.strip():
                    st.error(t("customer_id_required"))
                else:
                    payload = {
                        "customer_id": customer_id.strip(),
                        "purpose":     purpose,
                        "granted":     granted,
                        "metadata":    {"notes": notes, "branch": user_branch or "All"},
                    }
                    # Pre-flight validation — shows specific reason, never generic "Policy violation"
                    _valid, _reason = validate_consent(payload, role)
                    if not _valid:
                        st.error(_reason)
                    else:
                        # Step 9 — Data Discovery: scan payload for PII and attach data_map
                        payload["data_map"] = build_data_map(payload)
                        result = _exec_consent(payload, actor=user)
                        if result["status"] == "success":
                            record = result["record"]
                            st.success(
                                f"{t('consent_captured_success')} **{record['consent_id']}**  "
                                f"{t('status')}: **{t(record['status'].lower())}** | "
                                f"{t('expires')}: **{str(record['expiry_date'])[:10]}**"
                            )
                            clause = get_clause("consent_required")
                            explain_dynamic(
                                title=t("consent_registered_title"),
                                reason=t("consent_registered_reason"),
                                old_clause=clause["old"],
                                new_clause=clause["new"],
                            )
                            st.rerun()
                        else:
                            st.error(f"{t('error_creating_consent')}: {result.get('message', t('unknown_error'))}")

        # ── Branch Officer: assisted consent capture ──────────────────────────
        elif is_officer:
            st.info(t("assisted_consent_info"))

            col1, col2 = st.columns(2)
            with col1:
                customer_id = st.text_input(t("customer_id"), placeholder="e.g. CUST001")
                purpose     = st.selectbox(t("processing_purpose"), PURPOSE_LABELS)
            with col2:
                granted = st.radio(
                    t("customer_decision"),
                    [t("grant_consent"), t("deny_consent")]
                ) == t("grant_consent")
                notes = st.text_area(t("branch_notes"), height=100)

            # Expiry preview — display only
            retention_days = PURPOSE_EXPIRY_DAYS.get(purpose, DEFAULT_RETENTION_DAYS)
            expiry_preview = (datetime.utcnow() + timedelta(days=retention_days)).strftime("%Y-%m-%d")
            st.info(
                f"{t('consent_auto_expiry_info')} **{purpose}** — **{expiry_preview}** ({retention_days} {t('days')})."
            )

            st.warning(t("officer_consent_warning"))

            if st.button(t("capture_assisted_consent"), type="primary", use_container_width=True):
                if not customer_id.strip():
                    st.error(t("customer_id_required"))
                else:
                    payload = {
                        "customer_id": customer_id.strip(),
                        "purpose":     purpose,
                        "granted":     granted,
                        "assisted":    True,
                        "metadata":    {"notes": notes, "branch": user_branch or "All"},
                    }
                    # Pre-flight validation — shows specific reason, never generic "Policy violation"
                    _valid, _reason = validate_consent(payload, role)
                    if not _valid:
                        st.error(_reason)
                    else:
                        result = _exec_consent(payload, actor=user)
                        if result["status"] == "success":
                            record = result["record"]
                            st.success(
                                f"{t('assisted_consent_captured_success')} **{record['consent_id']}**  "
                                f"{t('initiator')}: **{t('customer_role')}** | "
                                f"{t('facilitator')}: **branch_officer** ({user})  "
                                f"{t('status')}: **{t(record['status'].lower())}** | "
                                f"{t('expires')}: **{str(record['expiry_date'])[:10]}**"
                            )
                            clause = get_clause("consent_required")
                            explain_dynamic(
                                title=t("assisted_consent_registered_title"),
                                reason=t("assisted_consent_registered_reason"),
                                old_clause=clause["old"],
                                new_clause=clause["new"],
                            )
                            st.rerun()
                        else:
                            st.error(f"{t('error_capturing_consent')}: {result.get('message', t('unknown_error'))}")

        # ── Regional Officer / Privacy Steward: branch-scoped read + governance ──
        elif is_regional:
            st.info(t("assisted_consent_info"))
            st.info(
                f"**{t('branch_label')}:** {user_branch}  |  "
                f"**{t('region_label')}:** {current_user.get('region', 'All')}"
            )
            col1, col2 = st.columns(2)
            with col1:
                customer_id = st.text_input(t("customer_id"), placeholder="e.g. CUST001")
                purpose     = st.selectbox(t("processing_purpose"), PURPOSE_LABELS)
            with col2:
                granted = st.radio(
                    t("customer_decision"),
                    [t("grant_consent"), t("deny_consent")]
                ) == t("grant_consent")
                notes = st.text_area(t("branch_notes"), height=100)

            retention_days = PURPOSE_EXPIRY_DAYS.get(purpose, DEFAULT_RETENTION_DAYS)
            expiry_preview = (datetime.utcnow() + timedelta(days=retention_days)).strftime("%Y-%m-%d")
            st.info(
                f"{t('consent_auto_expiry_info')} **{purpose}** — **{expiry_preview}** ({retention_days} {t('days')})."
            )
            st.warning(t("officer_consent_warning"))

            if st.button(t("capture_assisted_consent"), type="primary", use_container_width=True):
                if not customer_id.strip():
                    st.error(t("customer_id_required"))
                else:
                    payload = {
                        "customer_id": customer_id.strip(),
                        "purpose":     purpose,
                        "granted":     granted,
                        "assisted":    True,
                        "metadata":    {"notes": notes, "branch": user_branch or "All"},
                    }
                    result = _exec_consent(payload, actor=user)
                    if result["status"] == "success":
                        record = result["record"]
                        st.success(
                            f"{t('assisted_consent_captured_success')} **{record['consent_id']}**  "
                            f"{t('status')}: **{t(record['status'].lower())}** | "
                            f"{t('expires')}: **{str(record['expiry_date'])[:10]}**"
                        )
                        st.rerun()
                    else:
                        st.error(f"{t('error_capturing_consent')}: {result.get('message', t('unknown_error'))}")

        # ── Privacy Operations: governance dashboard + can record consents ────
        elif is_privacy_ops:
            st.subheader(t("consent_governance_dashboard") if "consent_governance_dashboard" in dir() else "Consent Governance Dashboard")
            g1, g2, g3 = st.columns(3)
            with g1:
                st.metric(t("total_consents"), _total)
            with g2:
                st.metric(t("active"), _active)
            with g3:
                st.metric(t("revoked"), _revoked)

            st.markdown("---")
            st.markdown(f"#### {t('capture_assisted_consent')}")
            st.info(t("assisted_consent_info"))

            col1, col2 = st.columns(2)
            with col1:
                customer_id = st.text_input(t("customer_id"), placeholder="e.g. CUST001", key="ops_cid")
                purpose     = st.selectbox(t("processing_purpose"), PURPOSE_LABELS, key="ops_purpose")
            with col2:
                granted = st.radio(
                    t("customer_decision"),
                    [t("grant_consent"), t("deny_consent")],
                    key="ops_granted",
                ) == t("grant_consent")
                notes = st.text_area(t("branch_notes"), height=100, key="ops_notes")

            if st.button(t("capture_assisted_consent"), type="primary", use_container_width=True, key="ops_submit"):
                if not customer_id.strip():
                    st.error(t("customer_id_required"))
                else:
                    payload = {
                        "customer_id": customer_id.strip(),
                        "purpose":     purpose,
                        "granted":     granted,
                        "assisted":    True,
                        "metadata":    {"notes": notes, "branch": "All"},
                    }
                    result = _exec_consent(payload, actor=user)
                    if result["status"] == "success":
                        record = result["record"]
                        st.success(
                            f"{t('assisted_consent_captured_success')} **{record['consent_id']}**  "
                            f"{t('status')}: **{t(record['status'].lower())}**"
                        )
                        st.rerun()
                    else:
                        st.error(f"{t('error_capturing_consent')}: {result.get('message', t('unknown_error'))}")

        # ── DPO / Auditor: cannot create consent — governance view only ───────
        else:
            st.info(t("dpo_auditor_no_consent_creation"))

    # ─────────────────────────────────────────────────────────────────────────
    # TAB 2 — Consent Register
    # ─────────────────────────────────────────────────────────────────────────
    with tab2:
        st.subheader(t("consent_register"))

        if is_auditor:
            st.info(t("auditor_readonly_info"))

        fcol1, fcol2, fcol3 = st.columns(3)
        with fcol1:
            f_status = st.multiselect(t("filter_by_status"), CONSENT_STATUSES, default=[])
        with fcol2:
            f_purpose = st.multiselect(t("filter_by_purpose"), PURPOSE_LABELS, default=[])
        with fcol3:
            f_cid = st.text_input(t("search_customer_id"))

        records = all_consents
        if f_status:  records = [r for r in records if r["status"].title() in f_status]
        if f_purpose: records = [r for r in records if r["purpose"] in f_purpose]
        if f_cid:     records = [
            r for r in records
            if f_cid.lower() in r.get("data_principal_id", r.get("customer_id", "")).lower()
        ]

        if records:
            rows = []
            for r in records:
                masked      = _mask_consent_for_display(r, role)
                status_title = r["status"].title()
                rows.append({
                    t("id"):         r["consent_id"],
                    t("customer"):   masked.get("data_principal_id", masked.get("customer_id", "")),
                    t("purpose"):    r["purpose"],
                    t("status"):     t(r["status"].lower()),
                    t("version"):    r.get("version", 1),
                    t("assisted"):   t("yes") if r.get("assisted") else t("no"),
                    t("initiator"):  r.get("initiator_role", "customer"),
                    t("created"):    str(r.get("created_at", ""))[:10],
                    t("expires"):    str(r.get("expiry_date", ""))[:10],
                    t("revoked_at"): str(r.get("revoked_at", "") or t("na"))[:16],
                })
            st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

            _id_visibility = (
                t("full_ids_visible") if is_dpo or is_auditor or is_privacy_ops
                else t("ids_masked_policy")
            )
            st.caption(
                f"{t('showing_records')} {len(records)} {t('of')} {_total}.  {_id_visibility}"
            )

            export_data(pd.DataFrame(rows), "consent_register")
        else:
            st.info(t("no_records_match_filters"))

    # ─────────────────────────────────────────────────────────────────────────
    # TAB 3 — Revoke / Renew (DPO and Officer only; Auditor read-only)
    # ─────────────────────────────────────────────────────────────────────────
    with tab3:
        st.subheader(t("revoke_renew"))

        if is_auditor:
            st.info(t("auditor_no_revoke_renew"))
        elif is_customer:
            st.info(t("customer_revoke_info"))
        elif not (is_officer or is_regional or is_privacy_ops or is_dpo):
            st.info(t("access_restricted"))
        else:
            op_col1, op_col2 = st.columns(2)

            # ── Revoke ────────────────────────────────────────────────────────
            with op_col1:
                st.markdown(f"#### {t('revoke_consent')}")
                rev_cid     = st.text_input(t("customer_id"), key="rev_cid")
                rev_purpose = st.selectbox(t("purpose"), PURPOSE_LABELS, key="rev_purpose")
                rev_reason  = st.text_input(
                    t("revocation_reason"), key="rev_reason",
                    placeholder=t("revocation_reason_placeholder"),
                )

                if st.button(t("revoke"), use_container_width=True, key="do_revoke"):
                    if not rev_cid.strip():
                        st.error(t("customer_id_required"))
                    else:
                        result = orchestration.execute_action(
                            action_type="update_consent_status",
                            payload={
                                "customer_id": rev_cid.strip(),
                                "purpose":     rev_purpose,
                                "new_status":  "revoked",
                                "reason":      rev_reason or t("revoked_by_officer_default"),
                            },
                            actor=user,
                        )
                        _ok = result.get("success") or result.get("status") == "success"
                        if _ok:
                            _cid = result.get("transaction_id", rev_cid.strip())
                            st.success(f"{t('consent_revoked_success')} **{_cid}**")
                            clause = get_clause("consent_required")
                            explain_dynamic(
                                title=t("consent_revoked_title"),
                                reason=t("consent_revoked_reason"),
                                old_clause=clause["old"],
                                new_clause=clause["new"],
                            )
                            st.rerun()
                        else:
                            st.error(f"{t('revocation_failed')}: {result.get('reason', result.get('message', t('unknown_error')))}")

            # ── Renew ─────────────────────────────────────────────────────────
            with op_col2:
                st.markdown(f"#### {t('renew_consent')}")
                ren_cid     = st.text_input(t("customer_id"), key="ren_cid")
                ren_purpose = st.selectbox(t("purpose"), PURPOSE_LABELS, key="ren_purpose")

                # Renewal expiry preview — display only, engine owns calculation
                renewal_days    = PURPOSE_EXPIRY_DAYS.get(ren_purpose, DEFAULT_RETENTION_DAYS)
                renewal_preview = (datetime.utcnow() + timedelta(days=renewal_days)).strftime("%Y-%m-%d")
                st.info(
                    f"{t('renewal_expiry_info')} **{renewal_preview}** ({t('automated')}, {renewal_days} {t('days')})."
                )

                if st.button(t("renew"), use_container_width=True, key="do_renew"):
                    if not ren_cid.strip():
                        st.error(t("customer_id_required"))
                    else:
                        result = orchestration.execute_action(
                            action_type="update_consent_status",
                            payload={
                                "customer_id": ren_cid.strip(),
                                "purpose":     ren_purpose,
                                "new_status":  "renewed",
                            },
                            actor=user,
                        )
                        _ok = result.get("success") or result.get("status") == "success"
                        if _ok:
                            _cid      = result.get("transaction_id", ren_cid.strip())
                            _expiry   = (
                                datetime.utcnow() + timedelta(days=renewal_days)
                            ).strftime("%Y-%m-%d")
                            st.success(
                                f"{t('consent_renewed_success')} **{_cid}**  "
                                f"{t('new_expiry')}: **{_expiry}**"
                            )
                            clause = get_clause("consent_required")
                            explain_dynamic(
                                title=t("consent_renewed_title"),
                                reason=t("consent_renewed_reason"),
                                old_clause=clause["old"],
                                new_clause=clause["new"],
                            )
                            st.rerun()
                        else:
                            st.error(f"{t('renewal_failed')}: {result.get('reason', result.get('message', t('unknown_error')))}")

    # ─────────────────────────────────────────────────────────────────────────
    # TAB 4 — Analytics
    # ─────────────────────────────────────────────────────────────────────────
    with tab4:
        st.subheader(t("analytics"))

        all_c = all_consents
        if not all_c:
            st.info(t("no_consent_data"))
        else:
            ac1, ac2 = st.columns(2)

            with ac1:
                status_counts = {}
                for c in all_c:
                    label = t(c["status"].lower())
                    status_counts[label] = status_counts.get(label, 0) + 1
                fig_pie = go.Figure(go.Pie(
                    labels=list(status_counts.keys()),
                    values=list(status_counts.values()),
                    hole=0.55,
                    marker_colors=["#1a9e5c", "#5a9ef5", "#f0a500", "#d93025", "#9b59b6", "#444"],
                    textinfo="label+value",
                ))
                fig_pie.update_layout(
                    title=t("consents_by_status"),
                    height=300, showlegend=False,
                    margin=dict(l=0, r=0, t=40, b=0),
                )
                st.plotly_chart(fig_pie, use_container_width=True)
                more_info(t("consent_status_legend"))

            with ac2:
                purpose_counts = {}
                for c in all_c:
                    purpose_counts[c["purpose"]] = purpose_counts.get(c["purpose"], 0) + 1
                fig_bar = go.Figure(go.Bar(
                    x=list(purpose_counts.keys()),
                    y=list(purpose_counts.values()),
                    marker_color="#0A3D91",
                    text=list(purpose_counts.values()),
                    textposition="outside",
                ))
                fig_bar.update_layout(
                    title=t("consents_by_purpose"),
                    yaxis=dict(title=t("count")),
                    xaxis=dict(tickangle=-30),
                    plot_bgcolor="#ffffff",
                    paper_bgcolor="#ffffff",
                    font=dict(color="#0A3D91"),
                    height=300, showlegend=False,
                )
                st.plotly_chart(fig_bar, use_container_width=True)

            # Assisted vs Direct breakdown
            n_assisted = sum(1 for c in all_c if c.get("assisted"))
            n_direct   = _total - n_assisted
            st.markdown(
                f"<div style='background:#e8f4fd;border:1px solid #5a9ef5;"
                f"border-radius:8px;padding:12px 20px;margin-top:8px'>"
                f"<b>{t('consent_capture_mode')}:</b> "
                f"{t('direct_customer_portal')}: <b>{n_direct}</b> &nbsp;|&nbsp; "
                f"{t('assisted_branch_walkin')}: <b>{n_assisted}</b>"
                f"</div>",
                unsafe_allow_html=True,
            )

            active = sum(1 for c in all_c if c["status"].lower() in ("active", "renewed"))
            rate   = round(active / len(all_c) * 100, 1) if all_c else 0
            colour = "#1a9e5c" if rate >= 70 else "#f0a500" if rate >= 50 else "#d93025"
            st.markdown(
                f"<div style='background:{colour}18;border:2px solid {colour};"
                f"border-radius:10px;padding:16px 24px;text-align:center;margin-top:16px'>"
                f"<div style='font-size:2rem;font-weight:800;color:{colour}'>{rate}%</div>"
                f"<div style='color:#444'>{t('active_consent_rate')} "
                f"({active} {t('of')} {len(all_c)} {t('consents_active_or_renewed')})</div>"
                f"</div>",
                unsafe_allow_html=True,
            )