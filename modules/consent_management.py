"""
modules/consent_management.py
------------------------------
Consent Management dashboard — DPDP Act 2023 compliant.

Architecture (updated):
    UI  →  orchestration.execute_action()  →  Engine  →  Audit / SLA / Compliance

Role-access model (canonical codes):
  customer                    Create own consent (Tab 1 — direct, self-service or branch-assisted)
  customer_assisted           Create consent via branch assistance
  customer_support            Assisted consent capture on behalf of customer (intake only)
  branch_officer /
  branch_privacy_coordinator  Assisted consent capture + branch register view (monitor only)
  regional_officer /
  regional_compliance_officer Assisted consent capture + regional scope
  privacy_steward             Assisted consent capture + governance
  privacy_operations          Full governance — capture, operational processing (NO revoke/modify)
  dpo                         Full governance — revoke, renew, analytics (NO consent creation)
  auditor / internal_auditor  Read-only register + analytics

Governance matrix enforced:
  - Customer Support Officer: may register consent, may NOT revoke or modify records
  - Branch Privacy Coordinator: monitor only (read + assisted capture), may NOT modify records
  - Privacy Operations: operational capture + processing, may NOT unilaterally revoke on behalf of customer
  - Customer / Assisted: give or revoke OWN consent only
  - Export: DPO, Board, Internal Auditor, Privacy Operations only

Design contract:
  - NO storage writes, NO hash generation, NO SLA calls, NO audit_log calls here.
  - NO validation logic (expiry, DPIA, branch, drift) — all delegated to engine.
  - NO compliance_engine calls — orchestration triggers recalculation post-commit.
  - All mutations go through orchestration.execute_action() via _exec_consent().
  - All user-visible strings go through t() — zero hardcoded English strings.
"""

from __future__ import annotations

import json
import uuid
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

# Kerala district list — shared across all forms
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
# Consent submission — allowed canonical roles
# ---------------------------------------------------------------------------

CONSENT_SUBMIT_ROLES: set[str] = {
    "customer",
    "customer_assisted",
    "customer_support",
    "branch_officer",
    "branch_privacy_coordinator",
    "regional_officer",
    "regional_compliance_officer",
    "privacy_steward",
    "privacy_operations",
}

# Roles permitted to revoke/renew consent on behalf of a data principal
CONSENT_REVOKE_ROLES: set[str] = {
    "customer",          # own consent only
    "privacy_operations",
    "dpo",
}

# Export-permitted roles — canonical codes
_EXPORT_PERMITTED: set[str] = {
    "dpo",
    "board_member",
    "auditor",
    "internal_auditor",
    "privacy_operations",
}


def _can_export() -> bool:
    return st.session_state.get("role", "") in _EXPORT_PERMITTED


# ---------------------------------------------------------------------------
# Sensitive field masking
# ---------------------------------------------------------------------------

def mask(value: str) -> str:
    """Mask a sensitive identifier, showing only the last 4 characters."""
    if not value:
        return ""
    value = str(value).strip()
    if len(value) <= 4:
        return "****"
    return "****" + value[-4:]


# ---------------------------------------------------------------------------
# validate_consent() — pre-flight check before calling orchestration
# ---------------------------------------------------------------------------

def validate_consent(payload: dict, role: str) -> tuple[bool, str]:
    """
    Pre-flight validation for consent capture payloads.
    Returns (True, "Valid") or (False, "<reason>").
    """
    if not str(payload.get("customer_id", "")).strip():
        return False, "Missing customer ID"

    if not str(payload.get("purpose", "")).strip():
        return False, "Missing processing purpose"

    if role not in CONSENT_SUBMIT_ROLES:
        return False, f"Role '{role}' is not permitted to submit consent"

    if payload.get("supporting_details") is None:
        payload["supporting_details"] = ""

    return True, "Valid"


# ---------------------------------------------------------------------------
# _exec_consent — thin wrapper around orchestration.execute_action
# ---------------------------------------------------------------------------

def _exec_consent(payload: dict, actor: str) -> dict:
    """
    Submit a consent_create action via orchestration and return a normalised
    result dict:
        status  : "success" | "error"
        record  : dict (on success)
        message : str  (on error)
    """
    payload.setdefault("_skip_consent_precheck", True)

    # Generate consent artefact ID before submission so it is embedded in the record
    consent_id = str(uuid.uuid4())
    payload["consent_id"] = consent_id

    raw = orchestration.execute_action(
        action_type="consent_create",
        payload=payload,
        actor=actor,
    )

    if raw.get("success"):
        record = {
            "consent_id":  raw.get("transaction_id", consent_id),
            "status":      "active" if payload.get("granted", True) else "revoked",
            "expiry_date": (
                datetime.utcnow() + timedelta(
                    days=PURPOSE_EXPIRY_DAYS.get(payload.get("purpose", ""), DEFAULT_RETENTION_DAYS)
                )
            ).strftime("%Y-%m-%d"),
            **payload,
        }
        return {"status": "success", "record": record}

    reason = raw.get("reason", "")
    if "pre_commit" in reason.lower() or "consent_validation_error" in reason.lower():
        message = "Consent could not be validated — please check the Customer ID and Purpose."
    elif "storage" in reason.lower():
        message = "Consent recorded but could not be persisted — please retry."
    else:
        message = reason or "Submission failed — please try again."

    return {"status": "error", "message": message}


# ---------------------------------------------------------------------------
# Consent artefact receipt — shown after successful capture
# ---------------------------------------------------------------------------

def _show_consent_artefact(record: dict) -> None:
    """
    Display a downloadable consent receipt after successful submission.
    The receipt contains all non-sensitive fields; sensitive values are masked.
    """
    # Build the artefact — mask sensitive fields before display / download
    artefact = {
        "consent_id":     record.get("consent_id", "—"),
        "customer_id":    record.get("customer_id", "—"),
        "aadhaar":        mask(record.get("aadhaar", "")),
        "account_number": mask(record.get("account_number", "")),
        "ifsc_code":      record.get("ifsc_code", "—"),
        "district":       record.get("district", "—"),
        "purpose":        record.get("purpose", "—"),
        "channel":        record.get("channel", "Self Service"),
        "assisted_by":    record.get("assisted_by") or "—",
        "submitted_by":   record.get("submitted_by", "—"),
        "status":         record.get("status", "active"),
        "expiry_date":    str(record.get("expiry_date", ""))[:10],
        "timestamp":      record.get("timestamp", datetime.utcnow().isoformat()),
    }

    st.success(f"✅ Consent recorded successfully")
    st.info(f"**Consent ID:** `{artefact['consent_id']}`")

    with st.expander("📄 View Consent Receipt"):
        col1, col2 = st.columns(2)
        with col1:
            st.markdown(f"**Customer ID:** {artefact['customer_id']}")
            st.markdown(f"**Aadhaar:** {artefact['aadhaar']}")
            st.markdown(f"**Account:** {artefact['account_number']}")
            st.markdown(f"**IFSC Code:** {artefact['ifsc_code']}")
            st.markdown(f"**District:** {artefact['district']}")
        with col2:
            st.markdown(f"**Purpose:** {artefact['purpose']}")
            st.markdown(f"**Channel:** {artefact['channel']}")
            st.markdown(f"**Status:** {artefact['status'].title()}")
            st.markdown(f"**Expires:** {artefact['expiry_date']}")
            st.markdown(f"**Recorded:** {artefact['timestamp'][:19]}")

    st.download_button(
        label="⬇️ Download Consent Receipt",
        data=json.dumps(artefact, indent=4),
        file_name=f"consent_receipt_{artefact['consent_id'][:8]}.json",
        mime="application/json",
        use_container_width=True,
    )


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
    if effective_role not in ("dpo", "auditor", "internal_auditor", "privacy_operations"):
        view["data_principal_id"] = mask_identifier(
            view.get("data_principal_id", ""), role=effective_role
        )
        if "customer_id" in view:
            view["customer_id"] = mask_identifier(view["customer_id"], role=effective_role)
    return view


# ---------------------------------------------------------------------------
# Shared consent form — identity fields + channel
# Used by customer, officer, and privacy_operations tabs.
# ---------------------------------------------------------------------------

def _render_identity_fields(
    key_prefix: str,
    customer_id_value: str = "",
    disabled_id: bool = False,
) -> tuple[str, str, str, str, str, str, str | None]:
    """
    Render the standard banking identity fields.
    Returns: (customer_id, aadhaar, account_number, ifsc_code, district, channel, assistant)
    """
    col1, col2 = st.columns(2)
    with col1:
        customer_id = st.text_input(
            t("customer_id"),
            value=customer_id_value,
            disabled=disabled_id,
            key=f"{key_prefix}_cid",
            placeholder="e.g. CUST001",
        )
        aadhaar = st.text_input(
            "Aadhaar Number",
            max_chars=12,
            placeholder="12-digit Aadhaar",
            key=f"{key_prefix}_aadhaar",
        )
        account_number = st.text_input(
            "Account Number",
            placeholder="Kerala Bank account number",
            key=f"{key_prefix}_account",
        )

    with col2:
        ifsc_code = st.text_input(
            "IFSC Code",
            placeholder="e.g. KLBK0001234",
            key=f"{key_prefix}_ifsc",
        )
        district = st.selectbox(
            "District",
            KERALA_DISTRICTS,
            key=f"{key_prefix}_district",
        )
        channel = st.selectbox(
            "Consent Channel",
            ["Self Service", "Branch Assisted"],
            key=f"{key_prefix}_channel",
        )

    assistant = None
    if channel == "Branch Assisted":
        assistant = st.session_state.get("role")

    return customer_id, aadhaar, account_number, ifsc_code, district, channel, assistant


# ---------------------------------------------------------------------------
# Main Streamlit show()
# ---------------------------------------------------------------------------

def show():
    import auth as _auth

    # ── Session guard ─────────────────────────────────────────────────────────
    current_user = _auth.get_current_user()
    if not current_user:
        st.error(t("session_not_found"))
        st.info(t("contact_dpo_access"))
        return

    role        = current_user["role"]       # canonical code
    user        = current_user["username"]
    user_branch = current_user["branch"]

    # ── Role-access gate ─────────────────────────────────────────────────────
    # All canonical codes that may access Consent Management.
    # Mirrors ROLE_PERMISSIONS["Consent Management"] in auth.py.
    ALLOWED_ROLES: set[str] = {
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
    if role not in ALLOWED_ROLES:
        st.warning(t("access_restricted"))
        st.info(t("contact_dpo_access"))
        return

    # ── Page header ───────────────────────────────────────────────────────────
    st.markdown(
        '<div class="main-box"><h2>Consent Management</h2></div>',
        unsafe_allow_html=True,
    )
    st.caption(t("consent_lifecycle_caption"))
    more_info(t("consent_lifecycle_info"))

    # ── Role convenience flags ────────────────────────────────────────────────
    is_customer      = role in ("customer", "customer_assisted")
    is_officer       = role in (
        "branch_officer", "customer_support", "branch_privacy_coordinator",
        "regional_officer", "regional_compliance_officer", "privacy_steward",
    )
    is_privacy_ops   = role == "privacy_operations"
    is_dpo           = role == "dpo"
    is_auditor       = role in ("auditor", "internal_auditor")
    # Branch-scoped: these roles see only their own branch records
    is_branch_scoped = role in (
        "branch_officer", "branch_privacy_coordinator", "customer_support",
        "regional_officer", "regional_compliance_officer", "privacy_steward",
    )
    # Officers who may assist with capture (NOT Branch Privacy Coordinator — monitor only)
    can_capture_assisted = role in (
        "branch_officer", "customer_support",
        "regional_officer", "regional_compliance_officer", "privacy_steward",
        "privacy_operations",
    )
    # Roles permitted to revoke/renew
    can_revoke_renew = role in CONSENT_REVOKE_ROLES

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

    # ── KPI strip ─────────────────────────────────────────────────────────────
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

        # ── Customer / Customer Assisted: direct consent creation ─────────────
        if is_customer:
            customer_id_val = user   # pre-fill from session
            col_form1, col_form2 = st.columns(2)
            with col_form1:
                customer_id    = st.text_input(t("your_customer_id"), value=customer_id_val, key="cust_cid")
                aadhaar        = st.text_input("Aadhaar Number", max_chars=12, placeholder="12-digit Aadhaar", key="cust_aadhaar")
                account_number = st.text_input("Account Number", placeholder="Kerala Bank account number", key="cust_account")
                ifsc_code      = st.text_input("IFSC Code", placeholder="e.g. KLBK0001234", key="cust_ifsc")

            with col_form2:
                district = st.selectbox("District", KERALA_DISTRICTS, key="cust_district")
                purpose  = st.selectbox(t("processing_purpose"), PURPOSE_LABELS, key="cust_purpose")
                channel  = st.selectbox(
                    "Consent Channel",
                    ["Self Service", "Branch Assisted"],
                    key="cust_channel",
                )
                assistant = st.session_state.get("role") if channel == "Branch Assisted" else None
                granted   = st.radio(
                    t("your_decision"),
                    [t("grant_consent"), t("deny_consent")],
                    key="cust_granted",
                ) == t("grant_consent")
                notes = st.text_area(t("notes_context"), height=80, key="cust_notes")

            # Expiry preview
            retention_days = PURPOSE_EXPIRY_DAYS.get(purpose, DEFAULT_RETENTION_DAYS)
            expiry_preview = (datetime.utcnow() + timedelta(days=retention_days)).strftime("%Y-%m-%d")
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

            if st.button(t("submit_my_consent"), type="primary", use_container_width=True, key="cust_submit"):
                if not customer_id.strip():
                    st.error(t("customer_id_required"))
                else:
                    payload = {
                        "customer_id":    customer_id.strip(),
                        "aadhaar":        aadhaar.strip() if aadhaar else "",
                        "account_number": account_number.strip() if account_number else "",
                        "ifsc_code":      ifsc_code.strip() if ifsc_code else "",
                        "district":       district,
                        "purpose":        purpose,
                        "granted":        granted,
                        "channel":        channel,
                        "assisted_by":    assistant,
                        "submitted_by":   st.session_state.get("role", "customer"),
                        "status":         "active" if granted else "revoked",
                        "timestamp":      datetime.utcnow().isoformat(),
                        "metadata":       {"notes": notes, "branch": user_branch or "All"},
                    }
                    _valid, _reason = validate_consent(payload, role)
                    if not _valid:
                        st.error(_reason)
                    else:
                        payload["data_map"] = build_data_map(payload)
                        result = _exec_consent(payload, actor=user)
                        if result["status"] == "success":
                            record = result["record"]
                            clause = get_clause("consent_required")
                            explain_dynamic(
                                title=t("consent_registered_title"),
                                reason=t("consent_registered_reason"),
                                old_clause=clause["old"],
                                new_clause=clause["new"],
                            )
                            _show_consent_artefact(record)
                            st.rerun()
                        else:
                            st.error(f"{t('error_creating_consent')}: {result.get('message', t('unknown_error'))}")

        # ── Officer / Customer Support / Regional roles: assisted consent capture
        elif is_officer:
            if not can_capture_assisted:
                # Branch Privacy Coordinator — monitor only, no capture
                st.info(t("branch_coordinator_monitor_only") if "branch_coordinator_monitor_only" in dir() else
                        "Your role allows monitoring the consent register. Consent capture is performed by branch officers or customer support staff.")
            else:
                st.info(t("assisted_consent_info"))
                if role in ("branch_officer", "customer_support"):
                    st.info(
                        f"**{t('branch_label')}:** {user_branch}"
                    )
                elif role in ("regional_officer", "regional_compliance_officer"):
                    st.info(
                        f"**{t('branch_label')}:** {user_branch}  |  "
                        f"**{t('region_label')}:** {current_user.get('region', 'All')}"
                    )

                col1, col2 = st.columns(2)
                with col1:
                    cust_id        = st.text_input(t("customer_id"), placeholder="e.g. CUST001", key="off_cid")
                    aadhaar        = st.text_input("Aadhaar Number", max_chars=12, placeholder="12-digit Aadhaar", key="off_aadhaar")
                    account_number = st.text_input("Account Number", placeholder="Kerala Bank account number", key="off_account")
                    ifsc_code      = st.text_input("IFSC Code", placeholder="e.g. KLBK0001234", key="off_ifsc")

                with col2:
                    district = st.selectbox("District", KERALA_DISTRICTS, key="off_district")
                    purpose  = st.selectbox(t("processing_purpose"), PURPOSE_LABELS, key="off_purpose")
                    channel  = st.selectbox(
                        "Consent Channel",
                        ["Self Service", "Branch Assisted"],
                        index=1,   # default to Branch Assisted for officers
                        key="off_channel",
                    )
                    assistant = st.session_state.get("role") if channel == "Branch Assisted" else None
                    granted   = st.radio(
                        t("customer_decision"),
                        [t("grant_consent"), t("deny_consent")],
                        key="off_granted",
                    ) == t("grant_consent")
                    notes = st.text_area(t("branch_notes"), height=80, key="off_notes")

                retention_days = PURPOSE_EXPIRY_DAYS.get(purpose, DEFAULT_RETENTION_DAYS)
                expiry_preview = (datetime.utcnow() + timedelta(days=retention_days)).strftime("%Y-%m-%d")
                st.info(
                    f"{t('consent_auto_expiry_info')} **{purpose}** — **{expiry_preview}** ({retention_days} {t('days')})."
                )
                st.warning(t("officer_consent_warning"))

                if st.button(t("capture_assisted_consent"), type="primary", use_container_width=True, key="off_submit"):
                    if not cust_id.strip():
                        st.error(t("customer_id_required"))
                    else:
                        payload = {
                            "customer_id":    cust_id.strip(),
                            "aadhaar":        aadhaar.strip() if aadhaar else "",
                            "account_number": account_number.strip() if account_number else "",
                            "ifsc_code":      ifsc_code.strip() if ifsc_code else "",
                            "district":       district,
                            "purpose":        purpose,
                            "granted":        granted,
                            "channel":        channel,
                            "assisted_by":    assistant,
                            "submitted_by":   st.session_state.get("role", "branch_officer"),
                            "status":         "active" if granted else "revoked",
                            "timestamp":      datetime.utcnow().isoformat(),
                            "assisted":       True,
                            "metadata":       {"notes": notes, "branch": user_branch or "All"},
                        }
                        _valid, _reason = validate_consent(payload, role)
                        if not _valid:
                            st.error(_reason)
                        else:
                            result = _exec_consent(payload, actor=user)
                            if result["status"] == "success":
                                record = result["record"]
                                clause = get_clause("consent_required")
                                explain_dynamic(
                                    title=t("assisted_consent_registered_title"),
                                    reason=t("assisted_consent_registered_reason"),
                                    old_clause=clause["old"],
                                    new_clause=clause["new"],
                                )
                                _show_consent_artefact(record)
                                st.rerun()
                            else:
                                st.error(f"{t('error_capturing_consent')}: {result.get('message', t('unknown_error'))}")

        # ── Privacy Operations: governance dashboard + assisted capture ────────
        elif is_privacy_ops:
            st.subheader("Consent Governance Dashboard")
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
                cust_id_ops    = st.text_input(t("customer_id"), placeholder="e.g. CUST001", key="ops_cid")
                aadhaar_ops    = st.text_input("Aadhaar Number", max_chars=12, placeholder="12-digit Aadhaar", key="ops_aadhaar")
                account_ops    = st.text_input("Account Number", placeholder="Kerala Bank account number", key="ops_account")
                ifsc_ops       = st.text_input("IFSC Code", placeholder="e.g. KLBK0001234", key="ops_ifsc")

            with col2:
                district_ops = st.selectbox("District", KERALA_DISTRICTS, key="ops_district")
                purpose_ops  = st.selectbox(t("processing_purpose"), PURPOSE_LABELS, key="ops_purpose")
                channel_ops  = st.selectbox(
                    "Consent Channel",
                    ["Self Service", "Branch Assisted"],
                    key="ops_channel",
                )
                assistant_ops = st.session_state.get("role") if channel_ops == "Branch Assisted" else None
                granted_ops   = st.radio(
                    t("customer_decision"),
                    [t("grant_consent"), t("deny_consent")],
                    key="ops_granted",
                ) == t("grant_consent")
                notes_ops = st.text_area(t("branch_notes"), height=80, key="ops_notes")

            if st.button(t("capture_assisted_consent"), type="primary", use_container_width=True, key="ops_submit"):
                if not cust_id_ops.strip():
                    st.error(t("customer_id_required"))
                else:
                    payload = {
                        "customer_id":    cust_id_ops.strip(),
                        "aadhaar":        aadhaar_ops.strip() if aadhaar_ops else "",
                        "account_number": account_ops.strip() if account_ops else "",
                        "ifsc_code":      ifsc_ops.strip() if ifsc_ops else "",
                        "district":       district_ops,
                        "purpose":        purpose_ops,
                        "granted":        granted_ops,
                        "channel":        channel_ops,
                        "assisted_by":    assistant_ops,
                        "submitted_by":   st.session_state.get("role", "privacy_operations"),
                        "status":         "active" if granted_ops else "revoked",
                        "timestamp":      datetime.utcnow().isoformat(),
                        "assisted":       True,
                        "metadata":       {"notes": notes_ops, "branch": "All"},
                    }
                    result = _exec_consent(payload, actor=user)
                    if result["status"] == "success":
                        record = result["record"]
                        _show_consent_artefact(record)
                        st.rerun()
                    else:
                        st.error(f"{t('error_capturing_consent')}: {result.get('message', t('unknown_error'))}")

        # ── DPO / Auditor: cannot create consent — governance view only ────────
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

        if not records:
            st.info(t("no_records_match_filters"))
        else:
            rows = []
            for r in records:
                masked       = _mask_consent_for_display(r, role)
                rows.append({
                    t("id"):         r["consent_id"],
                    t("customer"):   masked.get("data_principal_id", masked.get("customer_id", "")),
                    t("purpose"):    r["purpose"],
                    t("status"):     t(r["status"].lower()),
                    t("channel"):    r.get("channel", "Self Service"),
                    t("district"):   r.get("district", "—"),
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

            # ── Export: permitted roles only ──────────────────────────────────
            if _can_export():
                export_data(pd.DataFrame(rows), "consent_register")
            else:
                st.caption(
                    "🔒 Data export is available to authorised roles only "
                    "(DPO, Auditor, Privacy Operations, Board)."
                )

    # ─────────────────────────────────────────────────────────────────────────
    # TAB 3 — Revoke / Renew
    # Governance matrix:
    #   - Customer: may revoke/renew OWN consent
    #   - Privacy Operations + DPO: may revoke/renew on behalf
    #   - Customer Support Officer: NO — may only register, not modify
    #   - Branch Privacy Coordinator: NO — monitor only
    # ─────────────────────────────────────────────────────────────────────────
    with tab3:
        st.subheader(t("revoke_renew"))

        if is_auditor:
            st.info(t("auditor_no_revoke_renew"))
        elif not can_revoke_renew:
            # Customer Support Officers, Branch Privacy Coordinators, and other
            # restricted roles explicitly denied — they may NOT modify consent records
            st.info(
                "🔒 Your role does not have permission to revoke or renew consent records. "
                "Revocation must be initiated by the customer or processed by Privacy Operations / DPO."
            )
        elif is_customer:
            st.info(t("customer_revoke_info"))
            st.caption("To revoke your own consent, contact your branch officer or DPO.")
        else:
            # DPO and Privacy Operations only reach here
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
                            _cid    = result.get("transaction_id", ren_cid.strip())
                            _expiry = (
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

        if not all_consents:
            st.info(t("no_consent_data"))
        else:
            ac1, ac2 = st.columns(2)

            with ac1:
                status_counts: dict[str, int] = {}
                for c in all_consents:
                    label = t(c["status"].lower())
                    status_counts[label] = status_counts.get(label, 0) + 1

                if sum(status_counts.values()) > 0:
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
                purpose_counts: dict[str, int] = {}
                for c in all_consents:
                    purpose_counts[c["purpose"]] = purpose_counts.get(c["purpose"], 0) + 1

                if purpose_counts:
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

            # Channel breakdown
            n_assisted = sum(1 for c in all_consents if c.get("assisted") or c.get("channel") == "Branch Assisted")
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

            active = sum(1 for c in all_consents if c["status"].lower() in ("active", "renewed"))
            rate   = round(active / len(all_consents) * 100, 1) if all_consents else 0
            colour = "#1a9e5c" if rate >= 70 else "#f0a500" if rate >= 50 else "#d93025"
            st.markdown(
                f"<div style='background:{colour}18;border:2px solid {colour};"
                f"border-radius:10px;padding:16px 24px;text-align:center;margin-top:16px'>"
                f"<div style='font-size:2rem;font-weight:800;color:{colour}'>{rate}%</div>"
                f"<div style='color:#444'>{t('active_consent_rate')} "
                f"({active} {t('of')} {len(all_consents)} {t('consents_active_or_renewed')})</div>"
                f"</div>",
                unsafe_allow_html=True,
            )