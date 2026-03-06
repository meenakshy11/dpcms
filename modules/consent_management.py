"""
modules/consent_management.py
------------------------------
Consent Management dashboard — DPDP Act 2023 compliant.

Architecture (updated):
    UI  →  orchestration.execute_action()  →  Engine  →  Audit / SLA / Compliance

Role-access model (canonical codes):
  customer                    Create own consent, view/approve/deny official access requests
  customer_assisted           Create consent via branch assistance
  customer_support            Assisted consent capture + submit official access requests
  branch_officer /
  branch_privacy_coordinator  Assisted consent capture + branch register view (monitor only)
  regional_officer /
  regional_compliance_officer Assisted consent capture + regional scope + access requests
  privacy_steward             Assisted consent capture + governance
  privacy_operations          Full governance — capture, operational processing (NO revoke/modify)
  dpo                         Full governance — revoke, renew, analytics (NO consent creation)
  auditor / internal_auditor  Read-only register + analytics

Governance matrix enforced:
  - Customer Support Officer: may register consent, may NOT revoke or modify records
  - Branch Privacy Coordinator: monitor only (read + assisted capture), may NOT modify records
  - Privacy Operations: operational capture + processing, may NOT unilaterally revoke on behalf of customer
  - Customer / Assisted: give or revoke OWN consent only; approve/deny official access requests
  - Export: DPO, Board, Internal Auditor, Privacy Operations only

Consent mediation workflow (DPDP model):
  Official  → requests customer data access (render_official_request_interface)
  Customer  → views, approves, or denies the request (render_customer_requests)
  System    → records consent decision in storage/rights_requests.json
  Official  → queries result status

Access request storage:
  storage/rights_requests.json — shared with the rights portal.
  Official data access requests are identified by:
      request_category == "official_data_access"
  Rights portal entries (corrections, erasures, grievances) are identified by
  the absence of request_category, or request_category == "rights_portal".
  load_access_requests() filters to official_data_access only.
  save_access_requests() preserves all non-official_data_access entries intact.

Customer identity:
  Customers NEVER manually enter customer_id, aadhaar, or account_number.
  All identity fields are auto-loaded from st.session_state at login (auth.py).
  Tab 1 customer form reads identity from session and displays masked values.

Design contract:
  - Consent creation still goes through orchestration.execute_action() via _exec_consent().
  - Access request save/load uses direct file I/O against storage/rights_requests.json.
  - All mutations go through orchestration.execute_action() via _exec_consent().
  - All user-visible strings go through t() — zero hardcoded English strings.
"""

from __future__ import annotations

import json
import os
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
# STEP 1 — Access Request storage path
# Official → Customer data access request mediation (DPDP consent model)
#
# Stored in storage/rights_requests.json — the same file used by the rights
# portal — discriminated by request_category == "official_data_access".
# Rights portal entries (corrections, erasures, grievances) have no
# request_category field, so they are never touched by these functions.
# ---------------------------------------------------------------------------

ACCESS_REQUEST_FILE = "storage/rights_requests.json"

# Discriminator value written to every new official data access request.
# Allows load_access_requests() to filter without corrupting rights portal data.
_ACCESS_REQUEST_CATEGORY = "official_data_access"

# Official roles permitted to submit access requests to customers
OFFICIAL_REQUEST_ROLES: set[str] = {
    "customer_support",
    "branch_officer",
    "branch_privacy_coordinator",
    "regional_officer",
    "regional_compliance_officer",
    "privacy_steward",
    "privacy_operations",
    "dpo",
}

# Data fields officials may request access to
ACCESS_REQUEST_FIELDS: list[str] = [
    "Aadhaar Details",
    "PAN Details",
    "Account Information",
    "Address Information",
    "Transaction History",
    "KYC Documents",
]

# Permitted purposes for official data access requests
ACCESS_REQUEST_PURPOSES: list[str] = [
    "Loan Processing",
    "KYC Verification",
    "Fraud Investigation",
    "Regulatory Compliance",
    "Account Servicing",
    "Credit Assessment",
]

# DPDP denial clause options (Step 10)
DENIAL_CLAUSES: list[str] = [
    "Right to Restrict Processing",
    "Purpose Not Clear",
    "Unnecessary Data Requested",
    "Consent Not Required for Stated Purpose",
    "Data Minimisation Violation",
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
# STEP 2 — Load access requests from shared rights_requests.json
# Filters to official_data_access records only — never touches rights portal
# entries (corrections, erasures, grievances) which have no request_category.
# ---------------------------------------------------------------------------

def load_access_requests() -> list[dict]:
    """
    Load only official data access requests from storage/rights_requests.json.

    The file is shared with the rights portal. Records are distinguished by:
        request_category == "official_data_access"

    Rights portal entries (no request_category field, or request_category ==
    "rights_portal") are filtered out and never returned here.

    Returns an empty list if the file does not yet exist or is malformed.
    """
    if not os.path.exists(ACCESS_REQUEST_FILE):
        return []
    try:
        with open(ACCESS_REQUEST_FILE) as f:
            all_records = json.load(f)
        # Filter: only return official data access requests
        return [
            r for r in all_records
            if r.get("request_category") == _ACCESS_REQUEST_CATEGORY
        ]
    except (json.JSONDecodeError, OSError):
        return []


# ---------------------------------------------------------------------------
# STEP 3 — Persist access requests to shared storage/rights_requests.json
# Preserves ALL existing rights portal entries — only official_data_access
# records are replaced.  Never corrupts grievances, corrections, erasures.
# ---------------------------------------------------------------------------

def save_access_requests(data: list[dict]) -> None:
    """
    Write the updated official data access request list back to
    storage/rights_requests.json, preserving all rights portal entries intact.

    Strategy:
      1. Load the full file (all record categories).
      2. Strip out any existing official_data_access records.
      3. Append the new set of official_data_access records.
      4. Write the merged result back atomically.

    Each record in `data` must already contain:
        request_category == "official_data_access"
    This is enforced by render_official_request_interface() which always sets
    the field before appending.

    Args:
        data: Full list of official_data_access records (the current state
              after any mutations — replaces all previous official_data_access
              entries in the file).
    """
    os.makedirs(os.path.dirname(ACCESS_REQUEST_FILE), exist_ok=True)

    # Load existing file — default to empty list if absent or corrupt
    existing: list[dict] = []
    if os.path.exists(ACCESS_REQUEST_FILE):
        try:
            with open(ACCESS_REQUEST_FILE) as f:
                existing = json.load(f)
        except (json.JSONDecodeError, OSError):
            existing = []

    # Keep rights portal entries; discard old official_data_access records
    preserved = [
        r for r in existing
        if r.get("request_category") != _ACCESS_REQUEST_CATEGORY
    ]

    # Merge: rights portal entries first, then updated official access requests
    merged = preserved + data

    with open(ACCESS_REQUEST_FILE, "w") as f:
        json.dump(merged, f, indent=4)


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
# STEPS 4-6 — Official data access request interface
# Officials request customer data; customer is notified for approval/denial.
# ---------------------------------------------------------------------------

def render_official_request_interface() -> None:
    """
    Render the official data access request form (embedded in Tab 5).
    Officials specify: customer ID, purpose, and requested data fields.
    The request is stored in access_requests.json with status "Pending".
    The customer then sees the request in render_customer_requests() and decides.

    Permitted roles: customer_support, branch_officer, branch_privacy_coordinator,
    regional_officer, regional_compliance_officer, privacy_steward,
    privacy_operations, dpo.
    """
    import auth as _auth
    _cu  = _auth.get_current_user() or {}
    user = _cu.get("username", st.session_state.get("username", "officer"))

    st.subheader("📋 Submit Data Access Request to Customer")
    st.caption(
        "Request access to specific customer data fields for a stated purpose. "
        "The customer will receive this request and must approve or deny it."
    )
    st.info(
        "🔒 **DPDP Act 2023 — Section 7**: Data processing is lawful only with the "
        "customer's explicit consent. Submit this form to notify the customer and "
        "await their decision."
    )

    # ── STEP 4 — Customer ID + Purpose ───────────────────────────────────────
    col1, col2 = st.columns(2)
    with col1:
        customer_id = st.text_input(
            "Customer ID",
            placeholder="e.g. CUST001",
            key="off_access_cid",
        )
        purpose = st.selectbox(
            "Purpose",
            ACCESS_REQUEST_PURPOSES,
            key="off_access_purpose",
        )

    # ── STEP 5 — Select requested data fields ─────────────────────────────────
    with col2:
        fields = st.multiselect(
            "Select Data Fields Required",
            ACCESS_REQUEST_FIELDS,
            key="off_access_fields",
            help="Select only the fields strictly necessary for the stated purpose.",
        )
        justification = st.text_area(
            "Justification / Additional Notes",
            height=100,
            key="off_access_notes",
            placeholder="Briefly explain why these specific fields are needed.",
        )

    if fields:
        st.caption(
            f"⚠️ You are requesting access to **{len(fields)}** field(s): "
            + ", ".join(f"`{f}`" for f in fields)
        )

    # ── STEP 6 — Submit access request ────────────────────────────────────────
    if st.button(
        "📨 Submit Access Request to Customer",
        type="primary",
        use_container_width=True,
        key="off_access_submit",
    ):
        if not customer_id.strip():
            st.error("Customer ID is required.")
        elif not fields:
            st.error("Please select at least one data field to request access to.")
        else:
            all_requests = load_access_requests()
            # Per-field schema — each field carries its own decision + reason slot.
            # UUID-based request_id prevents collision when multiple officials
            # submit requests for the same customer simultaneously (Step 7).
            request_data = {
                "request_id":       f"REQ-{uuid.uuid4().hex[:6].upper()}",
                "request_category": _ACCESS_REQUEST_CATEGORY,   # discriminator — never omit
                "customer_id":      customer_id.strip(),
                "purpose":          purpose,
                "justification":    justification or "",
                "requested_by":     user,
                "requested_role":   st.session_state.get("role", "officer"),
                "status":           "Pending",
                "timestamp":        datetime.utcnow().isoformat(),
                "decided_at":       None,
                "dpdp_clause":      None,
                # Per-field consent tracking — replaces flat fields list
                "fields": [
                    {"field_name": f, "decision": "Pending", "reason": None}
                    for f in fields
                ],
            }
            all_requests.append(request_data)
            save_access_requests(all_requests)
            st.success(
                f"✅ Access request **{request_data['request_id']}** submitted to "
                f"customer **{customer_id.strip()}**. Awaiting their consent decision."
            )
            st.info(
                "The customer will see this request in the **Consent Management → "
                "Access Requests** tab and must approve or deny each field before "
                "you can access the requested data."
            )
            st.rerun()

    # ── Show this official's submitted requests ────────────────────────────────
    st.divider()
    st.subheader("My Submitted Access Requests")
    all_requests = load_access_requests()
    my_requests  = [r for r in all_requests if r.get("requested_by") == user]

    if not my_requests:
        st.info("You have not submitted any access requests yet.")
    else:
        for r in my_requests:
            with st.expander(
                f"**{r['request_id']}** — {r['purpose']} | Customer: `{r['customer_id']}` | "
                f"Status: `{r['status']}` | Submitted: {r['timestamp'][:10]}",
                expanded=False,
            ):
                st.caption(f"Requested by: {r.get('requested_by', '—')} ({r.get('requested_role', '—')})")
                if r.get("justification"):
                    st.caption(f"Justification: {r['justification']}")

                # Per-field decision table
                field_rows = [
                    {
                        "Field":       f["field_name"],
                        "Decision":    f["decision"],
                        "DPDP Reason": f.get("reason") or "—",
                    }
                    for f in r.get("fields", [])
                ]
                if field_rows:
                    st.markdown("**Field-level Consent Decisions:**")
                    st.dataframe(
                        pd.DataFrame(field_rows),
                        use_container_width=True,
                        hide_index=True,
                    )

                st.caption(
                    f"Overall Status: **{r['status']}** | "
                    f"Decided At: {(r.get('decided_at') or '—')[:10]}"
                )


# ---------------------------------------------------------------------------
# STEPS 7-14 — Customer view: approve/deny official access requests
# Also shows consent history, revocation, and artefact download.
# ---------------------------------------------------------------------------

def render_customer_requests() -> None:
    """
    Render the customer-facing access request mediation panel (embedded in Tab 5).

    Allowed actions for the customer:
      ✅ View pending official access requests
      ✅ Approve or deny each request (with DPDP denial clause if denied)
      ✅ View their consent history
      ✅ Revoke an existing consent
      ✅ Download consent artefact as CSV

    Forbidden actions:
      ❌ View other customers' requests
      ❌ Modify consent records directly
      ❌ Access any system or official workflows
    """
    import auth as _auth
    _cu         = _auth.get_current_user() or {}
    user        = _cu.get("username", st.session_state.get("username", "customer"))
    # Customer ID is always auto-loaded — never entered manually
    customer_id = (
        st.session_state.user.get("customer_id")
        if hasattr(st.session_state, "user") and isinstance(st.session_state.user, dict)
        else _cu.get("customer_id", user)
    )

    # Masked identity display
    masked_id = "****" + str(customer_id)[-4:] if customer_id and len(str(customer_id)) > 4 else "****"
    st.info(f"🪪 Your Customer ID: **{masked_id}**")

    # ── STEPS 7-8 — Load and filter pending requests for this customer ────────
    all_requests     = load_access_requests()
    # STEP 10 enforcement: only show own requests
    pending_requests = [
        r for r in all_requests
        if r.get("customer_id") == customer_id and r.get("status") == "Pending"
    ]
    past_requests    = [
        r for r in all_requests
        if r.get("customer_id") == customer_id and r.get("status") != "Pending"
    ]

    # ── Pending access requests ────────────────────────────────────────────────
    if not pending_requests:
        st.success("✅ No pending data access requests. No action required.")
    else:
        st.warning(
            f"⚠️ **{len(pending_requests)}** official data access "
            f"request(s) require your decision."
        )

    for req in pending_requests:
        with st.container(border=True):
            # ── STEP 8 — Display request details ──────────────────────────────
            st.subheader(f"📄 Request ID: `{req['request_id']}`")
            col_info1, col_info2 = st.columns(2)
            with col_info1:
                st.markdown(f"**Requested by:** `{req.get('requested_by', '—')}`")
                st.markdown(f"**Role:** {req.get('requested_role', '—')}")
                st.markdown(f"**Submitted:** {req.get('timestamp', '—')[:10]}")
            with col_info2:
                st.markdown(f"**Purpose:** {req.get('purpose', '—')}")

            if req.get("justification"):
                st.caption(f"Official's justification: {req['justification']}")

            st.markdown(
                "> 🔏 **Your right**: Under **DPDP Act 2023 — Section 6**, you have the "
                "right to grant or deny consent for each data field individually. "
                "Your decisions are final and will be recorded."
            )

            # ── Per-field consent decisions ────────────────────────────────────
            st.markdown("**Decide on each requested data field:**")
            field_updates: list[dict] = []

            for idx, field in enumerate(req.get("fields", [])):
                fname = field["field_name"]
                current_decision = field.get("decision", "Pending")

                # Skip fields already decided in a prior session
                if current_decision != "Pending":
                    badge = "✅" if current_decision == "Approve" else "🚫"
                    st.markdown(
                        f"&nbsp;&nbsp;{badge} **{fname}** — `{current_decision}`"
                        + (f" _(DPDP: {field.get('reason')})_" if field.get("reason") else "")
                    )
                    field_updates.append(field)
                    continue

                fcol1, fcol2 = st.columns([2, 3])
                with fcol1:
                    st.markdown(f"&nbsp;&nbsp;• **{fname}**")
                with fcol2:
                    # ── STEP 9 — Per-field decision radio ─────────────────────
                    field_decision = st.radio(
                        f"Decision for {fname}",
                        ["Approve", "Deny"],
                        key=f"field_decision_{req['request_id']}_{idx}",
                        horizontal=True,
                        label_visibility="collapsed",
                    )

                # ── STEP 10 — Per-field denial clause ─────────────────────────
                field_reason = None
                if field_decision == "Deny":
                    field_reason = st.selectbox(
                        f"DPDP Denial Clause — {fname}",
                        DENIAL_CLAUSES,
                        key=f"field_reason_{req['request_id']}_{idx}",
                    )
                    st.info(
                        f"📖 **{fname}** → **{field_reason}** — "
                        "This will be recorded as the legal basis for your refusal."
                    )

                field_updates.append({
                    "field_name": fname,
                    "decision":   field_decision,
                    "reason":     field_reason,
                })

            # ── STEP 11 — Save per-field decisions and derive overall status ──
            if st.button(
                f"✅ Submit Decisions for {req['request_id']}",
                key=f"submit_decision_{req['request_id']}",
                type="primary",
                use_container_width=True,
            ):
                approved = [f for f in field_updates if f["decision"] == "Approve"]
                denied   = [f for f in field_updates if f["decision"] == "Deny"]
                pending  = [f for f in field_updates if f["decision"] == "Pending"]

                # Derive overall request status from field decisions
                if pending:
                    overall_status = "Partially Processed"
                elif denied and not approved:
                    overall_status = "Denied"
                elif approved and not denied:
                    overall_status = "Approve"
                else:
                    # Mixed: some approved, some denied
                    overall_status = "Partially Approved"

                # Mutate in-place and persist
                for r in all_requests:
                    if r["request_id"] == req["request_id"]:
                        r["fields"]      = field_updates
                        r["status"]      = overall_status
                        r["decided_at"]  = datetime.utcnow().isoformat()
                        # Preserve top-level dpdp_clause for full-denial case
                        if overall_status == "Denied" and denied:
                            r["dpdp_clause"] = denied[0].get("reason")

                save_access_requests(all_requests)

                if overall_status in ("Approve", "Partially Approved"):
                    approved_names = ", ".join(f["field_name"] for f in approved)
                    denied_names   = ", ".join(f["field_name"] for f in denied)
                    msg = f"✅ Decision recorded for `{req['request_id']}`."
                    if approved_names:
                        msg += f" **Approved:** {approved_names}."
                    if denied_names:
                        msg += f" **Denied:** {denied_names}."
                    st.success(msg)
                elif overall_status == "Denied":
                    st.error(
                        f"🚫 All fields denied for request `{req['request_id']}`. "
                        f"DPDP clause recorded: **{denied[0].get('reason', '—')}**."
                    )
                else:
                    st.warning(f"⏳ Request `{req['request_id']}` partially processed.")

                st.rerun()

    # ── Past decisions ─────────────────────────────────────────────────────────
    if past_requests:
        with st.expander(f"📁 Past Decisions ({len(past_requests)})"):
            for r in past_requests:
                st.markdown(
                    f"**{r['request_id']}** — {r.get('purpose', '—')} | "
                    f"Requested by: `{r.get('requested_by', '—')}` | "
                    f"Overall: `{r['status']}` | "
                    f"Decided: {(r.get('decided_at') or '—')[:10]}"
                )
                field_rows = [
                    {
                        "Field":       f["field_name"],
                        "Decision":    f["decision"],
                        "DPDP Reason": f.get("reason") or "—",
                    }
                    for f in r.get("fields", [])
                ]
                if field_rows:
                    st.dataframe(
                        pd.DataFrame(field_rows),
                        use_container_width=True,
                        hide_index=True,
                    )
                st.divider()

    # ── STEP 12 — Consent history ──────────────────────────────────────────────
    st.divider()
    st.subheader("📜 My Consent History")
    all_consents_raw = get_all_consents()
    customer_consents = [
        c for c in all_consents_raw
        if c.get("customer_id") == customer_id or c.get("data_principal_id") == customer_id
    ]

    if not customer_consents:
        st.info("No consent records found for your account.")
    else:
        rows = [
            {
                "Consent ID":  c.get("consent_id", "—"),
                "Purpose":     c.get("purpose", "—"),
                "Status":      c.get("status", "—"),
                "Channel":     c.get("channel", "—"),
                "Created":     str(c.get("created_at", ""))[:10],
                "Expires":     str(c.get("expiry_date", ""))[:10],
            }
            for c in customer_consents
        ]
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

        # ── STEP 13 — Consent revocation ──────────────────────────────────────
        revocable = [
            c for c in customer_consents
            if c.get("status", "").lower() in ("active", "renewed")
        ]
        if revocable:
            st.divider()
            st.subheader("🔓 Revoke a Consent")
            consent_id_to_revoke = st.selectbox(
                "Select Consent to Revoke",
                options=[c["consent_id"] for c in revocable],
                format_func=lambda cid: next(
                    (f"{cid[:8]}… — {c['purpose']}" for c in revocable if c["consent_id"] == cid),
                    cid,
                ),
                key="revoke_consent_selector",
            )
            revoke_reason = st.text_input(
                "Reason for Revocation (optional)",
                placeholder="e.g. No longer consent to this processing",
                key="revoke_reason_input",
            )

            if st.button(
                "🔒 Revoke Selected Consent",
                key="do_revoke_customer",
                type="primary",
                use_container_width=True,
            ):
                result = orchestration.execute_action(
                    action_type="update_consent_status",
                    payload={
                        "customer_id": customer_id,
                        "consent_id":  consent_id_to_revoke,
                        "new_status":  "revoked",
                        "reason":      revoke_reason or "Revoked by customer",
                    },
                    actor=user,
                )
                _ok = result.get("success") or result.get("status") == "success"
                if _ok:
                    st.success(f"✅ Consent `{consent_id_to_revoke[:8]}…` revoked successfully.")
                    st.rerun()
                else:
                    st.error(f"Revocation failed: {result.get('reason', result.get('message', 'Unknown error'))}")

        # ── STEP 14 — Download consent artefact ───────────────────────────────
        st.divider()
        consent_df = pd.DataFrame(rows)
        st.download_button(
            label="⬇️ Download Consent Artefact (CSV)",
            data=consent_df.to_csv(index=False),
            file_name="consent_history.csv",
            mime="text/csv",
            use_container_width=True,
        )


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

    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        t("submit_request"),
        t("consent_register"),
        t("revoke_renew"),
        t("analytics"),
        "🔐 Access Requests",   # Tab 5: consent mediation workflow
    ])

    # ─────────────────────────────────────────────────────────────────────────
    # TAB 1 — Create / Capture Consent
    # ─────────────────────────────────────────────────────────────────────────
    with tab1:
        st.subheader(t("submit_request"))
        more_info(t("consent_creation_info"))

        # ── Customer / Customer Assisted: direct consent creation ─────────────
        if is_customer:
            # ── Identity: auto-loaded from session — NEVER manually entered ────
            # auth.py writes customer_id, aadhaar, account_number, ifsc_code,
            # and district into session state at login time (auth.login()).
            # Customers cannot override these values through any form.
            _sess_cid     = st.session_state.get("customer_id", user)
            _sess_aadhaar = st.session_state.get("aadhaar", "")
            _sess_account = st.session_state.get("account_number", "")
            _sess_ifsc    = st.session_state.get("ifsc_code", "")
            _sess_district = st.session_state.get("district", KERALA_DISTRICTS[0])

            # Display masked identity banner
            import auth as _auth_mod
            st.info(
                f"🪪 **Your Identity** — "
                f"Customer ID: `{_auth_mod.mask_value(_sess_cid)}` &nbsp;|&nbsp; "
                f"Aadhaar: `{_auth_mod.mask_value(_sess_aadhaar)}` &nbsp;|&nbsp; "
                f"Account: `{_auth_mod.mask_value(_sess_account)}`",
            )

            customer_id_val = _sess_cid   # used in payload — raw value, never shown
            col_form1, col_form2 = st.columns(2)
            with col_form1:
                # Customer ID shown as read-only masked display — NOT a text_input
                st.text_input(
                    t("your_customer_id"),
                    value=_auth_mod.mask_value(_sess_cid),
                    disabled=True,
                    key="cust_cid_display",
                    help="Your Customer ID is automatically loaded from your login session.",
                )
                # Aadhaar — masked, disabled
                st.text_input(
                    "Aadhaar Number",
                    value=_auth_mod.mask_value(_sess_aadhaar) if _sess_aadhaar else "",
                    disabled=True,
                    key="cust_aadhaar_display",
                    help="Loaded from your account record. Cannot be changed here.",
                )
                # Account — masked, disabled
                st.text_input(
                    "Account Number",
                    value=_auth_mod.mask_value(_sess_account) if _sess_account else "",
                    disabled=True,
                    key="cust_account_display",
                    help="Loaded from your account record. Cannot be changed here.",
                )
                # IFSC — not sensitive, shown as-is, disabled
                st.text_input(
                    "IFSC Code",
                    value=_sess_ifsc or "",
                    disabled=True,
                    key="cust_ifsc_display",
                )

            with col_form2:
                # District defaults from session; customer may confirm/select
                district_idx = (
                    KERALA_DISTRICTS.index(_sess_district)
                    if _sess_district in KERALA_DISTRICTS else 0
                )
                district = st.selectbox(
                    "District",
                    KERALA_DISTRICTS,
                    index=district_idx,
                    key="cust_district",
                )
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

            # Existing consent status check uses auto-loaded customer ID
            if _sess_cid:
                status_info = get_consent_status(_sess_cid, purpose)
                if status_info["exists"]:
                    st.info(
                        f"{t('existing_consent_found')}: {t('status')}=**{t(status_info['status'].lower())}**  "
                        f"{t('valid')}=**{status_info['valid']}**  "
                        f"{t('expires')}=**{str(status_info['expires_at'])[:10] if status_info['expires_at'] else t('na')}**"
                    )

            if st.button(t("submit_my_consent"), type="primary", use_container_width=True, key="cust_submit"):
                # customer_id always comes from session — never from a text input
                if not _sess_cid:
                    st.error(t("customer_id_required"))
                else:
                    payload = {
                        "customer_id":    _sess_cid,
                        "aadhaar":        _sess_aadhaar or "",
                        "account_number": _sess_account or "",
                        "ifsc_code":      _sess_ifsc or "",
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

    # ─────────────────────────────────────────────────────────────────────────
    # TAB 5 — Access Requests (DPDP Consent Mediation Workflow)
    # ─────────────────────────────────────────────────────────────────────────
    # STEP 15 — Role routing:
    #   Customer              → render_customer_requests()  (view + approve/deny)
    #   Official roles        → render_official_request_interface() (submit requests)
    #   Auditor / DPO / Ops   → read-only summary of all access requests
    # ─────────────────────────────────────────────────────────────────────────
    with tab5:
        # ── STEP 15: Dispatch by role ─────────────────────────────────────────
        if is_customer:
            # Customers view, approve, or deny official access requests.
            # They also see their consent history, can revoke, and download artefacts.
            render_customer_requests()

        elif role in OFFICIAL_REQUEST_ROLES and not is_dpo and not is_privacy_ops:
            # Branch officers, customer support, regional officers:
            # submit access requests directed to customers.
            render_official_request_interface()

        elif is_privacy_ops or is_dpo:
            # Privacy Operations and DPO see the full access request register.
            st.subheader("🔐 Official Data Access Request Register")
            st.caption(
                "Full view of all official access requests and customer consent decisions. "
                "This is a governance read view; individual customer mediation is in "
                "the customer portal."
            )
            all_access_reqs = load_access_requests()
            if not all_access_reqs:
                st.info("No access requests have been submitted yet.")
            else:
                _pending  = sum(1 for r in all_access_reqs if r["status"] == "Pending")
                _approved = sum(1 for r in all_access_reqs if r["status"] in ("Approve", "Partially Approved"))
                _denied   = sum(1 for r in all_access_reqs if r["status"] in ("Denied", "Deny"))
                _partial  = sum(1 for r in all_access_reqs if r["status"] == "Partially Processed")

                a1, a2, a3, a4 = st.columns(4)
                with a1:
                    st.metric("Total Requests", len(all_access_reqs))
                with a2:
                    st.metric("Pending Customer Decision", _pending)
                with a3:
                    st.metric("Approved (full/partial)", _approved)
                with a4:
                    st.metric("Denied", _denied)

                fa_status = st.multiselect(
                    "Filter by Status",
                    ["Pending", "Approve", "Partially Approved", "Partially Processed", "Denied", "Deny"],
                    default=[],
                    key="dpo_access_filter",
                )
                filtered_access = all_access_reqs
                if fa_status:
                    filtered_access = [r for r in all_access_reqs if r["status"] in fa_status]

                rows = [
                    {
                        "Request ID":    r["request_id"],
                        "Customer ID":   r["customer_id"],
                        "Requested By":  r.get("requested_by", "—"),
                        "Role":          r.get("requested_role", "—"),
                        "Purpose":       r["purpose"],
                        "Fields": ", ".join(
                            f["field_name"] if isinstance(f, dict) else str(f)
                            for f in r.get("fields", [])
                        ),
                        "Field Decisions": ", ".join(
                            f"{f['field_name']}: {f['decision']}"
                            for f in r.get("fields", [])
                            if isinstance(f, dict)
                        ) or "—",
                        "Status":        r["status"],
                        "Submitted":     r["timestamp"][:10],
                        "Decided At":    (r.get("decided_at") or "—")[:10],
                        "DPDP Clause":   r.get("dpdp_clause") or "—",
                    }
                    for r in filtered_access
                ]
                st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

                if _can_export():
                    export_data(pd.DataFrame(rows), "access_requests")

        elif is_auditor:
            # Auditors see a read-only summary
            st.subheader("🔍 Access Request Audit View (Read Only)")
            st.info("🔒 Read-only view. Auditors may not submit or modify access requests.")
            all_access_reqs = load_access_requests()
            if not all_access_reqs:
                st.info("No access requests recorded.")
            else:
                rows = [
                    {
                        "Request ID":  r["request_id"],
                        "Purpose":     r["purpose"],
                        "Fields": ", ".join(
                            f["field_name"] if isinstance(f, dict) else str(f)
                            for f in r.get("fields", [])
                        ),
                        "Status":      r["status"],
                        "Submitted":   r["timestamp"][:10],
                        "Decided At":  (r.get("decided_at") or "—")[:10],
                    }
                    for r in all_access_reqs
                ]
                st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
                if _can_export():
                    export_data(pd.DataFrame(rows), "access_requests_audit")

        else:
            st.info("Access request management is not available for your role.")