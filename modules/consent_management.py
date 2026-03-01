"""
modules/consent_management.py
------------------------------
Consent Management dashboard — DPDP Act 2023 compliant.

Role-access model (updated):
  Customer        Create own consent (Tab 1 — direct)
  branch_officer  Assisted consent capture only (Tab 1 — assisted mode)
  DPO             Full visibility — revoke, renew, analytics (NO consent creation)
  Auditor         Read-only — register and analytics only
  SystemAdmin     Access restricted

Key compliance rules enforced:
  - Only customers give consent (DPDP S.6)
  - Officers use assisted_consent_capture(); they are never the initiator
  - Language field removed from consent object (UI-level only)
  - Expiry fully automated from policy engine; no manual input
  - SLA registered with engine.sla_engine on every consent save
  - SMS expiry warning triggered 7 days before expiry
  - Expired status auto-updated via update_expired_consents()
  - Sensitive ID fields masked for non-DPO roles
  - Consent immutability preserved; modifications create new versioned record

Architecture
------------
    UI  ->  process_event()  ->  DecisionEngine  ->  Audit
    Customer UI  ->  create_consent()        (direct)
    Officer UI   ->  assisted_consent_capture()  (branch walk-in)
    DPO / Auditor -> view / revoke / renew only
"""

import uuid
import streamlit as st
import pandas as pd
import plotly.graph_objects as go
from datetime import datetime, timedelta

from engine.audit_ledger import audit_log
from engine.orchestration import process_event, trigger_notification
from engine.consent_validator import (
    revoke_consent,
    renew_consent,
    get_all_consents,
    get_consent_status,
    PURPOSE_EXPIRY_DAYS,
)
from engine.sla_engine import register_sla
from auth import get_role, get_branch, require_role
from utils.i18n import t
from utils.export_utils import export_data
from utils.explainability import explain_dynamic
from utils.ui_helpers import more_info, mask_identifier
from utils.dpdp_clauses import get_clause

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

CONSENT_STATUSES = ["Draft", "Active", "Expired", "Revoked", "Renewed", "Superseded"]

# Internal status → badge colour map (dot only, no text)
STATUS_COLOUR = {
    "Draft":      "#546e7a",
    "Active":     "#1a9e5c",
    "Expired":    "#f0a500",
    "Revoked":    "#d93025",
    "Renewed":    "#7B5EA7",
    "Superseded": "#444444",
}

PURPOSE_LABELS = list(PURPOSE_EXPIRY_DAYS.keys())

# Default retention period (days) — overridden per-purpose from policy engine
DEFAULT_RETENTION_DAYS = 365


# ---------------------------------------------------------------------------
# Helper — status dot badge (no text, colour only)
# ---------------------------------------------------------------------------

def _status_badge(status: str) -> str:
    colour = STATUS_COLOUR.get(status.title(), "#546e7a")
    return (
        f'<span style="display:inline-block;width:11px;height:11px;'
        f'border-radius:50%;background-color:{colour};margin-right:6px;"></span>'
    )


# ---------------------------------------------------------------------------
# Helper — generate unique consent ID
# ---------------------------------------------------------------------------

def _generate_id() -> str:
    return f"CNS-{uuid.uuid4().hex[:10].upper()}"


# ---------------------------------------------------------------------------
# Core consent creation — CUSTOMER ONLY
# ---------------------------------------------------------------------------

@require_role(["customer"])
def create_consent(customer_id: str, purpose: str, granted: bool,
                   actor: str, metadata: dict | None = None) -> dict:
    """
    Direct consent creation.
    Only callable by role=customer.
    Expiry is fully automated from PURPOSE_EXPIRY_DAYS (no manual input).
    Language field is intentionally excluded from the consent object.
    """
    metadata = metadata or {}
    retention_days = PURPOSE_EXPIRY_DAYS.get(purpose, DEFAULT_RETENTION_DAYS)
    expiry_date = datetime.utcnow() + timedelta(days=retention_days)

    consent = {
        "consent_id":        _generate_id(),
        "data_principal_id": customer_id,
        "initiator_role":    "customer",
        "submitted_by":      actor,
        "assisted":          False,
        "purpose":           purpose,
        "granted":           granted,
        "created_at":        datetime.utcnow().isoformat(),
        "expiry_date":       expiry_date.isoformat(),
        "status":            "active" if granted else "denied",
        "version":           1,
        "previous_version_id": None,
        "metadata":          metadata,
    }

    _save_consent(consent)

    register_sla(
        request_id=consent["consent_id"],
        module="consent_expiry",
        sla_days=retention_days,
    )

    audit_log(
        event="CONSENT_CREATED",
        actor=actor,
        details={
            "consent_id": consent["consent_id"],
            "customer_id": customer_id,
            "purpose": purpose,
            "granted": granted,
        },
    )

    return consent


# ---------------------------------------------------------------------------
# Assisted consent capture — BRANCH OFFICER ONLY
# ---------------------------------------------------------------------------

@require_role(["branch_officer"])
def assisted_consent_capture(customer_id: str, consent_payload: dict,
                              officer_id: str) -> dict:
    """
    Branch walk-in assisted consent capture.
    The officer facilitates but the DATA PRINCIPAL (customer) is always the initiator.
    Officer appears only in submitted_by, never as initiator_role.
    Expiry is fully automated; no manual expiry input accepted.
    Language field is intentionally excluded from the consent object.
    """
    purpose = consent_payload["purpose"]
    granted = consent_payload.get("granted", True)

    retention_days = PURPOSE_EXPIRY_DAYS.get(purpose, DEFAULT_RETENTION_DAYS)
    expiry_date = datetime.utcnow() + timedelta(days=retention_days)

    consent = {
        "consent_id":           _generate_id(),
        "data_principal_id":    customer_id,
        "initiator_role":       "customer",          # Always customer — not officer
        "submitted_by":         "branch_officer",
        "submitted_by_id":      officer_id,
        "assisted":             True,
        "verification_mode":    "physical_signature_verified",
        "purpose":              purpose,
        "granted":              granted,
        "created_at":           datetime.utcnow().isoformat(),
        "expiry_date":          expiry_date.isoformat(),
        "status":               "active" if granted else "denied",
        "version":              1,
        "previous_version_id":  None,
        "metadata":             consent_payload.get("metadata", {}),
    }

    _save_consent(consent)

    register_sla(
        request_id=consent["consent_id"],
        module="consent_expiry",
        sla_days=retention_days,
    )

    audit_log(
        event="ASSISTED_CONSENT_CAPTURED",
        actor=officer_id,
        details={
            "consent_id":   consent["consent_id"],
            "customer_id":  customer_id,
            "purpose":      purpose,
            "assisted":     True,
            "verification": "physical_signature_verified",
        },
    )

    return consent


# ---------------------------------------------------------------------------
# Expiry automation — called by background scheduler
# ---------------------------------------------------------------------------

def update_expired_consents(customer_phone_lookup: dict | None = None):
    """
    Daily scheduled job.
    - Marks active consents as 'expired' when expiry_date has passed.
    - Sends SMS warning 7 days before expiry.
    customer_phone_lookup: optional dict mapping data_principal_id -> phone number.
    """
    customer_phone_lookup = customer_phone_lookup or {}
    consents = get_all_consents()
    now = datetime.utcnow()

    for consent in consents:
        if consent.get("status") not in ("active", "Active"):
            continue

        expiry = datetime.fromisoformat(consent["expiry_date"])
        customer_phone = customer_phone_lookup.get(consent["data_principal_id"])

        # Auto-expire
        if now > expiry:
            consent["status"] = "expired"
            _save_consent(consent)
            _trigger_expiry_notification(consent, customer_phone)
            audit_log(
                event="CONSENT_AUTO_EXPIRED",
                actor="system",
                details={"consent_id": consent["consent_id"]},
            )

        # 7-day warning SMS
        elif now > expiry - timedelta(days=7) and customer_phone:
            trigger_notification(
                channel="sms",
                recipient=customer_phone,
                message=(
                    f"Your consent for '{consent['purpose']}' "
                    "will expire in 7 days. Please renew to avoid interruption."
                ),
            )


def _trigger_expiry_notification(consent: dict, phone: str | None):
    """Send expiry notification if phone is available."""
    if phone:
        trigger_notification(
            channel="sms",
            recipient=phone,
            message=(
                f"Your consent for '{consent['purpose']}' has expired. "
                "Please renew your consent to continue services."
            ),
        )


# ---------------------------------------------------------------------------
# Consent versioning — called on modification (immutability preserved)
# ---------------------------------------------------------------------------

def create_consent_version(old_consent: dict, updated_fields: dict,
                            actor: str) -> dict:
    """
    Consent immutability: no in-place edits to purpose, created_at, or consent_id.
    Any modification creates a new versioned record; old record becomes 'superseded'.
    Fields that cannot be updated: consent_id, created_at, data_principal_id, initiator_role.
    """
    IMMUTABLE_FIELDS = {"consent_id", "created_at", "data_principal_id", "initiator_role"}
    for field in IMMUTABLE_FIELDS:
        updated_fields.pop(field, None)

    new_consent = old_consent.copy()
    new_consent.update(updated_fields)
    new_consent["consent_id"]          = _generate_id()
    new_consent["version"]             = old_consent.get("version", 1) + 1
    new_consent["previous_version_id"] = old_consent["consent_id"]
    new_consent["created_at"]          = datetime.utcnow().isoformat()

    # Automate expiry on new version
    purpose = new_consent.get("purpose", "")
    retention_days = PURPOSE_EXPIRY_DAYS.get(purpose, DEFAULT_RETENTION_DAYS)
    new_consent["expiry_date"] = (
        datetime.utcnow() + timedelta(days=retention_days)
    ).isoformat()
    new_consent.pop("language", None)  # Ensure language never stored

    # Supersede old record
    old_consent["status"] = "superseded"
    _save_consent(old_consent)

    _save_consent(new_consent)

    register_sla(
        request_id=new_consent["consent_id"],
        module="consent_expiry",
        sla_days=retention_days,
    )

    audit_log(
        event="CONSENT_VERSIONED",
        actor=actor,
        details={
            "new_consent_id":  new_consent["consent_id"],
            "old_consent_id":  old_consent["consent_id"],
            "new_version":     new_consent["version"],
        },
    )

    return new_consent


# ---------------------------------------------------------------------------
# Masking helper — used when returning consent data to non-DPO roles
# ---------------------------------------------------------------------------

def _mask_consent_for_display(consent: dict, role: str) -> dict:
    """
    Return a display-safe copy with sensitive fields masked for non-privileged roles.

    DPO and Auditor see full identifiers; all other roles see masked values.
    Role is always resolved from st.session_state (the single source of truth)
    and the `role` argument is used only as a fallback for test contexts.
    """
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
# Internal persistence stub (delegates to consent_validator store)
# ---------------------------------------------------------------------------

def _save_consent(consent: dict):
    """Persist consent record. Delegates to the consent_validator store."""
    from engine.consent_validator import _persist_consent  # internal store
    _persist_consent(consent)


# ---------------------------------------------------------------------------
# Main Streamlit show()
# ---------------------------------------------------------------------------

def show():
    role = get_role()

    ALLOWED_ROLES = ("DPO", "Officer", "branch_officer", "Auditor", "customer")
    if role not in ALLOWED_ROLES:
        st.warning(t("access_restricted"))
        st.info(t("contact_dpo_access"))
        return

    st.header(t("consent_management"))
    st.caption(t("consent_lifecycle_caption"))

    more_info(t("consent_lifecycle_info"))

    user        = st.session_state.get("username", "system")
    user_branch = get_branch()

    is_auditor  = role == "Auditor"
    is_officer  = role in ("Officer", "branch_officer")
    is_dpo      = role == "DPO"
    is_customer = role == "customer"

    # ── Load & filter consents ───────────────────────────────────────────────
    all_consents_raw = get_all_consents()

    if is_officer and user_branch and user_branch != "All":
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
            <p style="color:#6B7A90;">{t("this_branch") if is_officer else t("all_records")}</p>
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

            # Expiry is automated — show read-only info to customer
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

            if st.button(t("submit_my_consent"), type="primary", use_container_width=True):
                if not customer_id.strip():
                    st.error(t("customer_id_required"))
                else:
                    cid = customer_id.strip()
                    context = {
                        "event":       "CONSENT_ACTIVATION",
                        "customer_id": cid,
                        "purpose":     purpose,
                        "user":        user,
                    }
                    allowed, decision = process_event(context)
                    if not allowed:
                        st.error(t("consent_blocked_rule_engine"))
                    else:
                        try:
                            record = create_consent(
                                customer_id=cid,
                                purpose=purpose,
                                granted=granted,
                                actor=user,
                                metadata={"notes": notes, "branch": user_branch or "All"},
                            )
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
                        except Exception as exc:
                            st.error(f"{t('error_creating_consent')}: {exc}")

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

            # Expiry is automated — show read-only info
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
                    cid = customer_id.strip()
                    context = {
                        "event":       "CONSENT_ACTIVATION",
                        "customer_id": cid,
                        "purpose":     purpose,
                        "user":        user,
                    }
                    allowed, decision = process_event(context)
                    if not allowed:
                        st.error(t("consent_blocked_rule_engine"))
                    else:
                        try:
                            record = assisted_consent_capture(
                                customer_id=cid,
                                consent_payload={
                                    "purpose":  purpose,
                                    "granted":  granted,
                                    "metadata": {"notes": notes, "branch": user_branch or "All"},
                                },
                                officer_id=user,
                            )
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
                        except Exception as exc:
                            st.error(f"{t('error_capturing_consent')}: {exc}")

        # ── DPO / Auditor: cannot create consent ──────────────────────────────
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
                masked = _mask_consent_for_display(r, role)
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
                t("full_ids_visible") if is_dpo or is_auditor
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
        else:
            op_col1, op_col2 = st.columns(2)

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
                        try:
                            record = revoke_consent(
                                rev_cid.strip(), rev_purpose,
                                reason=rev_reason or t("revoked_by_officer_default"),
                                actor=user,
                            )
                            st.success(
                                f"{t('consent_revoked_success')} **{record['consent_id']}**"
                            )
                            clause = get_clause("consent_required")
                            explain_dynamic(
                                title=t("consent_revoked_title"),
                                reason=t("consent_revoked_reason"),
                                old_clause=clause["old"],
                                new_clause=clause["new"],
                            )
                            st.rerun()
                        except ValueError as e:
                            st.error(f"{t('revocation_failed')}: {e}")

            with op_col2:
                st.markdown(f"#### {t('renew_consent')}")
                ren_cid     = st.text_input(t("customer_id"), key="ren_cid")
                ren_purpose = st.selectbox(t("purpose"), PURPOSE_LABELS, key="ren_purpose")

                # Renewal expiry is also automated
                renewal_days    = PURPOSE_EXPIRY_DAYS.get(ren_purpose, DEFAULT_RETENTION_DAYS)
                renewal_preview = (datetime.utcnow() + timedelta(days=renewal_days)).strftime("%Y-%m-%d")
                st.info(
                    f"{t('renewal_expiry_info')} **{renewal_preview}** ({t('automated')}, {renewal_days} {t('days')})."
                )

                if st.button(t("renew"), use_container_width=True, key="do_renew"):
                    if not ren_cid.strip():
                        st.error(t("customer_id_required"))
                    else:
                        try:
                            record = renew_consent(ren_cid.strip(), ren_purpose, actor=user)
                            new_expiry = str(record.get("expiry_date", record.get("expires_at", "")))[:10]
                            st.success(
                                f"{t('consent_renewed_success')} **{record['consent_id']}**  "
                                f"{t('version')}: **{record['version']}** | "
                                f"{t('new_expiry')}: **{new_expiry}**"
                            )
                            clause = get_clause("consent_required")
                            explain_dynamic(
                                title=t("consent_renewed_title"),
                                reason=t("consent_renewed_reason"),
                                old_clause=clause["old"],
                                new_clause=clause["new"],
                            )
                            st.rerun()
                        except ValueError as e:
                            st.error(f"{t('renewal_failed')}: {e}")

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
                    # Use translated label for display; internal key for lookup
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