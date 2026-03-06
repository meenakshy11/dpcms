"""
modules/notices.py
------------------
Privacy Notice Management — DPDP Act 2023 Section 5.

Architecture:
    UI  →  orchestration.execute_action()  →  Engine  →  Audit / Compliance

Role-access model (canonical codes only — no legacy display names):
  dpo                          Full access — save draft, publish, approve pending drafts
  privacy_operations           Draft creation only — cannot publish
  branch_officer /
  branch_privacy_coordinator   Draft creation only — cannot publish
  auditor / internal_auditor   Read-only — notice history, version diff, preview
  board_member                 Executive summary KPIs only — no notice content, no write
  customer / customer_assisted Active published notices only — read-only, no write

Roles explicitly DENIED (blocked before any notice data is loaded):
  customer_support             Intake role only — no notice management
  soc_analyst                  SOC uses Breach module
  regional_officer /
  regional_compliance_officer /
  privacy_steward              Not in scope for notice creation or review

Immutable publish rule (enforced by orchestration):
  - Published notices can NEVER be edited or overwritten.
  - Superseding creates a new version; old becomes "superseded".
  - Orchestration computes SHA-256 hash of content and freezes it.

Re-consent triggering (enforced by orchestration):
  - Orchestration compares previous clause set to new clause set.
  - If changed → marks affected users for re-consent.
  - Module must NOT compute clause delta.

Design contract:
  - NO storage reads/writes (json.load / json.dump).
  - NO audit_log() calls.
  - NO hash generation (orchestration owns SHA-256 freeze).
  - NO clause delta computation.
  - NO re-consent flag calculation.
  - NO compliance_engine calls.
  - NO direct status mutation.
  - All mutations go through orchestration.execute_action().
  - UI validates only input format (empty check); orchestration validates clause registry.
  - All user-visible strings go through t().
  - Role sourced exclusively from get_current_user()["role"] (canonical code).
  - require_session() called first in show() before any notice data is loaded.

Change log:
  ✔ Removed `from auth import get_role_display as get_role` — returned legacy display
    names ("DPO", "Officer", "Auditor") that silently broke access for every canonical
    role. Replaced with `import auth as _auth` + get_current_user()["role"].
  ✔ ALLOWED_ROLES rebuilt with canonical codes:
      Added: privacy_operations, branch_officer, branch_privacy_coordinator,
             internal_auditor, board_member, customer, customer_assisted
      Removed: "DPO", "Officer", "Auditor" (legacy display names)
  ✔ _DENIED_ROLES set added — explicit deny for customer_support, soc_analyst,
    regional roles that should not access notices.
  ✔ require_session() added as first statement in show() (auth Step 6 contract).
  ✔ _init_notices() moved to after session guard (was called before any role check).
  ✔ actor sourced from get_current_user()["username"] (canonical, not session.get).
  ✔ is_officer now covers all draft-creation roles: privacy_operations,
    branch_officer, branch_privacy_coordinator (per governance matrix).
  ✔ is_auditor now covers both "auditor" and "internal_auditor" (canonical).
  ✔ Board view (Step 9): dedicated KPI summary block — board_member returns after
    the KPI strip with no access to notice content or write controls.
  ✔ Customer view (Step 5): customer and customer_assisted see active published
    notices only; no write controls, no history tab, no KPI strip.
  ✔ Page header upgraded from bare st.header() to inline-styled container div,
    consistent with compliance.py, breach.py, audit.py, and cookie_consent.py.
  ✔ Global CSS table styling injected once via st.markdown (Step 10 alignment).
  ✔ t_safe() helper added for defensive i18n (new strings may not yet have keys).
"""

from __future__ import annotations

import pandas as pd
import streamlit as st

import engine.orchestration as orchestration
from utils.i18n import t, translate_en_to_ml, normalize_malayalam
from utils.export_utils import export_data
from utils.ui_helpers import more_info
from utils.explainability import explain_dynamic
from utils.dpdp_clauses import get_clause


# ---------------------------------------------------------------------------
# i18n safe helper — never raises; returns fallback if key missing
# ---------------------------------------------------------------------------

def t_safe(key: str, fallback: str = "") -> str:
    try:
        result = t(key)
        return result if result != key else (fallback or key)
    except Exception:
        return fallback or key


# ---------------------------------------------------------------------------
# Constants — canonical role codes only
# ---------------------------------------------------------------------------

# Roles with full read + write access
_DPO_ROLES: frozenset[str] = frozenset({"dpo"})

# Roles that may create drafts but not publish
_DRAFT_ROLES: frozenset[str] = frozenset({
    "privacy_operations",
    "branch_officer",
    "branch_privacy_coordinator",
})

# Roles with read-only access to full notice history
_AUDIT_ROLES: frozenset[str] = frozenset({"auditor", "internal_auditor"})

# Board: KPI summary only — no notice content, no write
_BOARD_ROLES: frozenset[str] = frozenset({"board_member"})

# Customers: active published notices only — read-only
_CUSTOMER_ROLES: frozenset[str] = frozenset({"customer", "customer_assisted"})

_ALL_ALLOWED_ROLES: frozenset[str] = (
    _DPO_ROLES | _DRAFT_ROLES | _AUDIT_ROLES | _BOARD_ROLES | _CUSTOMER_ROLES
)

# Roles explicitly denied — checked before general gate
_DENIED_ROLES: frozenset[str] = frozenset({
    "customer_support",               # intake role only
    "soc_analyst",                    # Breach module only
    "regional_officer",               # not in scope for notice management
    "regional_compliance_officer",
    "privacy_steward",
})

STATUS_COLOUR: dict[str, str] = {
    "published":  "#1a9e5c",
    "draft":      "#f0a500",
    "superseded": "#9e9e9e",
}

PRODUCT_OPTIONS: list[str] = [
    "Savings Account", "Digital Lending", "UPI Services",
    "Mobile Banking", "Credit Card", "Fixed Deposit", "Insurance Products",
]

ALL_CLAUSE_KEYS: list[str] = [
    "consent_lifecycle", "rights_management", "breach_reporting",
    "data_minimisation", "audit_integrity", "sla_governance",
    "dpia", "security_safeguards",
]


# ---------------------------------------------------------------------------
# Sample seed notices — session bootstrap only (never written back)
# ---------------------------------------------------------------------------

_SEED_NOTICES: list[dict] = [
    {
        "notice_id":           "NTC-SEED-0001",
        "title":               "Savings Account Privacy Notice",
        "product":             "Savings Account",
        "content_en": (
            "This notice explains how Kerala Bank processes your personal data "
            "for Savings Account services under DPDP Act 2023 Section 5. "
            "Data is collected for account management, KYC, and regulatory compliance. "
            "Retention period: 10 years. You may exercise your rights via our Rights Portal."
        ),
        "content_ml":          "",
        "linked_clauses":      ["consent_lifecycle", "rights_management"],
        "version":             1,
        "version_note":        "Initial publication.",
        "previous_version_id": None,
        "created_by":          "dpo_admin",
        "created_at":          "2026-01-10T09:00:00+00:00",
        "published_on":        "2026-01-10",
        "published_by":        "dpo_admin",
        "status":              "published",
        "requires_reconsent":  False,
        "affected_users":      [],
    },
    {
        "notice_id":           "NTC-SEED-0002",
        "title":               "Digital Lending Privacy Notice",
        "product":             "Digital Lending",
        "content_en": (
            "Kerala Bank processes your personal and financial data to evaluate "
            "your creditworthiness and disburse loans under DPDP Act 2023. "
            "Third-party credit bureaus may receive your data. "
            "Retention: 7 years post-loan closure."
        ),
        "content_ml":          "",
        "linked_clauses":      ["consent_lifecycle", "breach_reporting", "data_minimisation"],
        "version":             1,
        "version_note":        "Updated data sharing clause for CIBIL integration.",
        "previous_version_id": None,
        "created_by":          "dpo_admin",
        "created_at":          "2026-02-05T09:00:00+00:00",
        "published_on":        "2026-02-05",
        "published_by":        "dpo_admin",
        "status":              "published",
        "requires_reconsent":  False,
        "affected_users":      [],
    },
    {
        "notice_id":           "NTC-SEED-0003",
        "title":               "UPI Services Privacy Notice",
        "product":             "UPI Services",
        "content_en": (
            "Your transaction data processed under UPI services is governed by "
            "DPDP Act 2023 and NPCI guidelines. Data is used solely for payment "
            "processing and fraud prevention. Retention: 5 years."
        ),
        "content_ml":          "",
        "linked_clauses":      ["consent_lifecycle"],
        "version":             1,
        "version_note":        "Pending DPO review.",
        "previous_version_id": None,
        "created_by":          "officer_01",
        "created_at":          "2026-02-20T09:00:00+00:00",
        "published_on":        None,
        "published_by":        None,
        "status":              "draft",
        "requires_reconsent":  False,
        "affected_users":      [],
    },
]


# ---------------------------------------------------------------------------
# Session bootstrap
# ---------------------------------------------------------------------------

def _init_notices() -> None:
    """Seed session state on first load from orchestration, falling back to sample data."""
    if "notices" not in st.session_state:
        result = orchestration.execute_action(
            action_type="query_notices",
            payload={},
            actor=st.session_state.get("username", "system"),
        )
        if result.get("status") == "success" and result.get("records"):
            st.session_state.notices = result["records"]
        else:
            st.session_state.notices = list(_SEED_NOTICES)


# ---------------------------------------------------------------------------
# Read helpers (no writes)
# ---------------------------------------------------------------------------

def _resolve_content(notice: dict) -> str:
    """Return locale-appropriate content."""
    lang = st.session_state.get("language", "en")
    if lang == "ml":
        return notice.get("content_ml") or notice.get("content_en", "")
    return notice.get("content_en", "")


def _status_colour(status: str) -> str:
    return STATUS_COLOUR.get(status.lower(), "#9e9e9e")


# ---------------------------------------------------------------------------
# UI-level input format validation (format only — registry validation in orchestration)
# ---------------------------------------------------------------------------

def _pre_validate_inputs(notice_text: str, linked_clauses: list[str]) -> list[str]:
    """
    Validate input format before calling orchestration.
    Orchestration performs deep clause registry validation.
    """
    errors: list[str] = []
    if not notice_text.strip():
        errors.append(t("notice_content_empty"))
    if not linked_clauses:
        errors.append(t("notice_clause_required"))
    return errors


# ---------------------------------------------------------------------------
# Orchestration result handler
# ---------------------------------------------------------------------------

def _handle_result(result: dict, success_msg: str) -> bool:
    """Display success or error. Returns True on success."""
    if result.get("status") == "success":
        st.success(success_msg)
        return True
    st.error(f"{t('action_failed')}: {result.get('message', t('unknown_error'))}")
    return False


# ===========================================================================
# Main Streamlit entry point
# ===========================================================================

def show() -> None:
    import auth as _auth

    # ── STEP 6: Session guard — halts rendering before any notice data loaded ──
    if not _auth.require_session():
        return

    # ── Canonical user from session — single source of truth ──────────────────
    current_user = _auth.get_current_user()
    if not current_user:
        st.error(t("session_not_found"))
        st.info(t("notices_contact_dpo"))
        return

    role  = current_user["role"]       # canonical code — always
    actor = current_user["username"]   # used in all orchestration calls

    # ── STEP 1 — Explicit deny: roles with no notice access ───────────────────
    if role in _DENIED_ROLES:
        st.warning(
            t_safe(
                "notices_access_denied",
                "Privacy Notices are not available for your role. "
                "Please use the Rights Portal or Consent Management module.",
            )
        )
        st.info(t("notices_contact_dpo"))
        return

    # ── General access gate — catch any other unlisted role ───────────────────
    if role not in _ALL_ALLOWED_ROLES:
        st.warning(t_safe("notices_access_restricted", "You do not have permission to access Privacy Notices."))
        st.info(t("notices_contact_dpo"))
        return

    # ── Role convenience flags — canonical codes only ──────────────────────────
    is_dpo         = role in _DPO_ROLES
    is_draft_role  = role in _DRAFT_ROLES       # privacy_operations + branch officers
    is_auditor     = role in _AUDIT_ROLES        # auditor + internal_auditor
    is_board       = role in _BOARD_ROLES        # board_member
    is_customer    = role in _CUSTOMER_ROLES     # customer + customer_assisted

    # For tab/write-control logic — roles that can create/edit notices
    can_write      = is_dpo or is_draft_role
    # Only DPO may publish; draft roles save drafts only
    can_publish    = is_dpo

    # ── STEP 5 — Customer view: active published notices only ─────────────────
    # Customers never see KPI strip, tabs, history, or write controls.
    if is_customer:
        st.markdown(
            '<div style="background:#f4f6fa;padding:18px 24px;border-radius:8px;'
            'border:1px solid #e5e9ef;margin-bottom:20px;">'
            f'<h2 style="margin:0;color:#0A3D91;">{t_safe("active_privacy_notices", "Active Privacy Notices")}</h2>'
            '</div>',
            unsafe_allow_html=True,
        )
        st.caption(t_safe("customer_notices_caption", "These notices explain how Kerala Bank processes your personal data."))

        _init_notices()
        active_notices = [n for n in st.session_state.notices if n.get("status") == "published"]

        if not active_notices:
            st.info(t_safe("no_active_notices", "No active privacy notices are currently published."))
            return

        for notice in active_notices:
            content = _resolve_content(notice)
            st.markdown(
                f"""
                <div style="
                    background:#f8faff;
                    border-left:4px solid #0A3D91;
                    border-radius:8px;
                    padding:20px 24px;
                    margin-bottom:16px;
                ">
                    <div style="font-weight:700;font-size:1.05rem;color:#0A3D91;margin-bottom:8px;">
                        {notice['title']}
                        <span style="font-size:0.8rem;color:#888;margin-left:8px;">
                            v{notice.get('version', 1)} · {notice.get('published_on', '—')}
                        </span>
                    </div>
                    <div style="font-size:0.93rem;color:#333;line-height:1.7;">{content}</div>
                    <div style="margin-top:12px;font-size:0.8rem;color:#666;">
                        <b>{t_safe('product_label', 'Product')}:</b> {notice.get('product', '—')} &nbsp;·&nbsp;
                        <b>{t_safe('linked_clauses_label', 'Clauses')}:</b>
                        {', '.join(notice.get('linked_clauses', []))}
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        return   # Customers exit here — everything below is staff/governance only

    # ── All non-customer roles: initialise notice state ───────────────────────
    _init_notices()

    # ── STEP 2 — Page header — inline-styled container ────────────────────────
    st.markdown(
        '<div style="background:#f4f6fa;padding:18px 24px;border-radius:8px;'
        'border:1px solid #e5e9ef;margin-bottom:20px;">'
        f'<h2 style="margin:0;color:#0A3D91;">{t_safe("notices_title", "Privacy Notices &amp; Disclosures")}</h2>'
        '</div>',
        unsafe_allow_html=True,
    )
    st.caption(t("notices_caption"))
    more_info(t("notices_more_info"))

    # ── STEP 10 — Global CSS table styling — injected once ───────────────────
    st.markdown(
        """
        <style>
        /* Notices module table styling */
        div[data-testid="stMarkdownContainer"] table {
            border-collapse: collapse;
            width: 100%;
        }
        div[data-testid="stMarkdownContainer"] th {
            background-color: #003366;
            color: white;
            padding: 10px 12px;
            text-align: left;
            font-size: 14px;
        }
        div[data-testid="stMarkdownContainer"] td {
            padding: 8px 10px;
            border-bottom: 1px solid #ddd;
        }
        div[data-testid="stMarkdownContainer"] tr:hover td {
            background-color: #f5f8ff;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

    # ── KPI Strip ─────────────────────────────────────────────────────────────
    all_notices = st.session_state.notices
    _total      = len(all_notices)
    _published  = sum(1 for n in all_notices if n.get("status") == "published")
    _draft      = sum(1 for n in all_notices if n.get("status") == "draft")
    _superseded = sum(1 for n in all_notices if n.get("status") == "superseded")
    _products   = len({n["product"] for n in all_notices})

    k1, k2, k3, k4, k5 = st.columns(5)
    for col, label_key, val, colour, sub_key in [
        (k1, "total_versions", _total,      "#0A3D91", "all_time"),
        (k2, "published",      _published,  "#1a9e5c", "live"),
        (k3, "drafts",         _draft,      "#f0a500", "pending_review"),
        (k4, "superseded",     _superseded, "#9e9e9e", "archived"),
        (k5, "products",       _products,   "#0A3D91", "journeys_covered"),
    ]:
        col.markdown(
            f'<div class="kpi-card" style="border-top-color:{colour};">'
            f'<h4>{t(label_key)}</h4>'
            f'<h2 style="color:{colour};">{val}</h2>'
            f'<p style="color:{colour};">{t(sub_key)}</p>'
            f'</div>',
            unsafe_allow_html=True,
        )

    st.divider()

    # ── STEP 9 — Board view: KPI summary only, then return ───────────────────
    # Board members see aggregate KPIs above; no tab content, no write controls.
    if is_board:
        st.subheader(t_safe("board_notices_summary", "Notice Summary"))
        b1, b2 = st.columns(2)
        b1.metric(t_safe("total_notices", "Total Notices"), _total)
        b2.metric(t_safe("active_notices", "Active Notices"), _published)

        open_drafts = _draft
        if open_drafts > 0:
            st.warning(
                f"⚠️ **{open_drafts} draft notice(s) pending DPO approval** — "
                "review with DPO before next board meeting."
            )
        else:
            st.success("✅ All notices published — no pending drafts.")

        st.caption(
            t_safe(
                "board_notices_caption",
                "🔒 Full notice content and management is available to DPO and Privacy Operations roles.",
            )
        )
        return   # Board exits here

    # ── Role banners for non-board non-customer staff ─────────────────────────
    if is_auditor:
        st.info(t("auditor_read_only"))
    elif is_draft_role and not is_dpo:
        st.info(t("officer_draft_only"))

    # ── STEP 8 — Auditor view: read-only dataframe of all notices ────────────
    if is_auditor:
        st.subheader(t_safe("notice_compliance_review", "Notice Compliance Review"))
        if not all_notices:
            st.info(t("no_notices_recorded"))
        else:
            rows = []
            for n in all_notices:
                rows.append({
                    t("notice_id"):      n.get("notice_id", "—"),
                    t("product"):        n.get("product", "—"),
                    t("version"):        f"v{n.get('version', 1)}",
                    t("status"):         t(n.get("status", "draft")),
                    t("clauses_linked"): ", ".join(n.get("linked_clauses", [])),
                    t("reconsent"):      t("yes") if n.get("requires_reconsent") else t("no"),
                    t("published_on"):   n.get("published_on") or "—",
                    t("by"):             n.get("published_by") or n.get("created_by", "—"),
                    t("created_at"):     (n.get("created_at", "—"))[:16],
                    t("version_note"):   n.get("version_note", "—"),
                })
            df_audit = pd.DataFrame(rows)
            st.dataframe(df_audit, use_container_width=True, hide_index=True, height=420)
            export_data(df_audit, "privacy_notices_audit_review")
            more_info(t("notice_history_more_info"))
        return   # Auditors exit here — no write controls below

    # =========================================================================
    # Tab-based interface: DPO + draft roles (privacy_operations, branch officers)
    # =========================================================================
    tabs     = [t("create_version_notice"), t("notice_history"), t("notice_preview")]
    tab_objects = st.tabs(tabs)

    # =========================================================================
    # TAB 0 — Create / Version Notice
    # DPO: save draft OR publish directly
    # draft roles: save draft only — DPO must approve before publication
    # =========================================================================
    with tab_objects[0]:
        st.subheader(t("create_or_version_notice"))
        st.caption(t("create_notice_caption"))

        product = st.selectbox(t("product_journey"), PRODUCT_OPTIONS)

        # Detect existing published notice — display only, no mutation
        existing = next(
            (n for n in reversed(all_notices)
             if n["product"] == product and n["status"] == "published"),
            None,
        )
        if existing:
            st.info(
                f"{t('active_version_for')} **{product}**: "
                f"v{existing['version']} — *{existing.get('version_note', '—')}*"
            )

        notice_title = st.text_input(
            t("notice_title"),
            value=f"{product} Privacy Notice",
        )
        notice_text = st.text_area(
            t("notice_content_english"),
            value=(
                existing.get("content_en", "")
                if existing else (
                    "This notice explains how your personal data will be processed "
                    "by Kerala Bank in accordance with the Digital Personal Data "
                    "Protection Act 2023. We collect your data for the purposes of "
                    "[Purpose] and retain it for [Retention Period]. You have the "
                    "right to access, correct, erase, or withdraw consent at any "
                    "time through our Rights Portal."
                )
            ),
            height=200,
        )

        # Clause linkage (UI collects; orchestration validates registry)
        default_clauses = existing.get("linked_clauses", ["consent_lifecycle"]) if existing else ["consent_lifecycle"]
        linked_clauses = st.multiselect(
            t("linked_dpdp_clauses"),
            options=ALL_CLAUSE_KEYS,
            default=[c for c in default_clauses if c in ALL_CLAUSE_KEYS],
            help=t("linked_clauses_help"),
        )
        version_note = st.text_input(
            t("version_note"),
            placeholder=t("version_note_placeholder"),
        )

        # Malayalam preview — display only; orchestration computes canonical ML on save
        with st.expander(t("preview_malayalam"), expanded=False):
            if notice_text:
                ml_preview = normalize_malayalam(translate_en_to_ml(notice_text))
                st.text_area(t("malayalam_content"), value=ml_preview, height=150, disabled=True)
            else:
                st.caption(t("enter_english_to_preview"))

        st.caption(t("hash_freeze_note"))

        # ── STEP 6 — Draft roles: save draft only ────────────────────────────
        if is_draft_role and not is_dpo:
            st.caption(t("officer_draft_caption"))
            if st.button(t("save_draft"), type="primary", use_container_width=True):
                errs = _pre_validate_inputs(notice_text, linked_clauses)
                if errs:
                    for e in errs:
                        st.error(e)
                else:
                    result = orchestration.execute_action(
                        action_type="create_notice_version",
                        payload={
                            "title":               notice_title,
                            "content_en":          notice_text,
                            "product":             product,
                            "linked_clauses":      linked_clauses,
                            "version_note":        version_note,
                            "previous_version_id": existing["notice_id"] if existing else None,
                            "target_status":       "draft",
                        },
                        actor=actor,
                    )
                    if _handle_result(
                        result,
                        f"{t('draft')} {t('saved_for')} **{product}**. {t('pending_dpo_review')}",
                    ):
                        st.session_state.notices.append(result["record"])
                        st.rerun()

        # ── STEP 7 — DPO: save draft OR publish ──────────────────────────────
        elif is_dpo:
            col1, col2 = st.columns(2)

            with col1:
                if st.button(t("save_draft"), use_container_width=True):
                    errs = _pre_validate_inputs(notice_text, linked_clauses)
                    if errs:
                        for e in errs:
                            st.error(e)
                    else:
                        result = orchestration.execute_action(
                            action_type="create_notice_version",
                            payload={
                                "title":               notice_title,
                                "content_en":          notice_text,
                                "product":             product,
                                "linked_clauses":      linked_clauses,
                                "version_note":        version_note,
                                "previous_version_id": existing["notice_id"] if existing else None,
                                "target_status":       "draft",
                            },
                            actor=actor,
                        )
                        if _handle_result(
                            result,
                            f"{t('draft')} {t('saved_for')} **{product}**.",
                        ):
                            st.session_state.notices.append(result["record"])
                            st.rerun()

            with col2:
                if st.button(t("publish_notice"), type="primary", use_container_width=True):
                    errs = _pre_validate_inputs(notice_text, linked_clauses)
                    if errs:
                        for e in errs:
                            st.error(e)
                    else:
                        # Orchestration will:
                        #   1. Validate clause registry
                        #   2. Compute SHA-256 content hash (freeze)
                        #   3. Compare clauses → set requires_reconsent
                        #   4. Supersede previous published notice
                        #   5. Identify and notify affected users
                        #   6. Write audit log and trigger compliance
                        result = orchestration.execute_action(
                            action_type="publish_notice",
                            payload={
                                "title":               notice_title,
                                "content_en":          notice_text,
                                "product":             product,
                                "linked_clauses":      linked_clauses,
                                "version_note":        version_note,
                                "previous_version_id": existing["notice_id"] if existing else None,
                            },
                            actor=actor,
                        )
                        if result.get("status") == "success":
                            record        = result["record"]
                            reconsent_msg = (
                                f" **{t('reconsent_required')}**"
                                if record.get("requires_reconsent") else ""
                            )
                            affected      = result.get("affected_users_count", 0)
                            affected_msg  = (
                                f" {affected} {t('users_notified_sms')}"
                                if affected else ""
                            )
                            st.success(
                                f"{t('notice')} v{record['version']} "
                                f"{t('published_for')} **{product}**."
                                + reconsent_msg + affected_msg
                            )
                            clause_info = get_clause("consent_lifecycle") or {}
                            explain_dynamic(
                                title=t("notice_published"),
                                reason=t("notice_published_reason"),
                                old_clause=clause_info.get("old", ""),
                                new_clause=clause_info.get("new", ""),
                            )
                            refresh = orchestration.execute_action(
                                action_type="query_notices",
                                payload={},
                                actor=actor,
                            )
                            if refresh.get("status") == "success":
                                st.session_state.notices = refresh["records"]
                            else:
                                st.session_state.notices.append(record)
                            st.rerun()
                        else:
                            st.error(
                                f"{t('publish_failed')}: "
                                f"{result.get('message', t('unknown_error'))}"
                            )

    # =========================================================================
    # TAB 1 — Notice History (DPO + draft roles)
    # =========================================================================
    with tab_objects[1]:
        st.subheader(t("notice_version_history"))

        if not all_notices:
            st.info(t("no_notices_recorded"))
        else:
            fcol1, fcol2, fcol3 = st.columns(3)
            with fcol1:
                f_product = st.multiselect(
                    t("filter_by_product"),
                    sorted({n["product"] for n in all_notices}),
                    default=[],
                )
            with fcol2:
                f_status = st.multiselect(
                    t("filter_by_status"),
                    ["published", "draft", "superseded"],
                    default=[],
                )
            with fcol3:
                f_reconsent = st.checkbox(t("requires_reconsent_only"), value=False)

            filtered = list(all_notices)
            if f_product:   filtered = [n for n in filtered if n["product"] in f_product]
            if f_status:    filtered = [n for n in filtered if n.get("status") in f_status]
            if f_reconsent: filtered = [n for n in filtered if n.get("requires_reconsent")]

            if filtered:
                rows = []
                for n in filtered:
                    affected_count = len(n.get("affected_users", []))
                    rows.append({
                        t("notice_id"):      n.get("notice_id", "—"),
                        t("product"):        n["product"],
                        t("version"):        f"v{n['version']}",
                        t("status"):         t(n.get("status", "draft")),
                        t("clauses_linked"): ", ".join(n.get("linked_clauses", [])),
                        t("reconsent"):      t("yes") if n.get("requires_reconsent") else t("no"),
                        t("affected_users"): affected_count if affected_count else "—",
                        t("version_note"):   n.get("version_note", "—"),
                        t("published_on"):   n.get("published_on") or "—",
                        t("by"):             n.get("published_by") or n.get("created_by", "—"),
                        t("created_at"):     n.get("created_at", "—")[:16],
                    })

                df = pd.DataFrame(rows)
                st.dataframe(df, use_container_width=True, hide_index=True, height=420)
                st.caption(f"{len(filtered)} {t('notice_versions_shown')}")
                export_data(df, "privacy_notices_history")
                more_info(t("notice_history_more_info"))
            else:
                st.info(t("no_notices_match_filters"))

            # ── DPO: approve / publish pending drafts from history tab ────────
            if is_dpo:
                drafts = [n for n in st.session_state.notices if n.get("status") == "draft"]
                if drafts:
                    st.divider()
                    st.subheader(t("publish_pending_drafts"))

                    draft_labels = [
                        f"{n['product']} — v{n['version']} ({n.get('version_note', '—')[:40]})"
                        for n in drafts
                    ]
                    sel_label = st.selectbox(t("select_draft_to_publish"), draft_labels)
                    sel_idx   = draft_labels.index(sel_label)
                    sel_draft = drafts[sel_idx]

                    if st.button(t("publish_selected_draft"), type="primary"):
                        result = orchestration.execute_action(
                            action_type="publish_notice",
                            payload={
                                "notice_id": sel_draft["notice_id"],
                                "product":   sel_draft["product"],
                            },
                            actor=actor,
                        )
                        if result.get("status") == "success":
                            record      = result["record"]
                            clause_info = get_clause("consent_lifecycle") or {}
                            explain_dynamic(
                                title=t("notice_published"),
                                reason=t("notice_published_reason"),
                                old_clause=clause_info.get("old", ""),
                                new_clause=clause_info.get("new", ""),
                            )
                            st.success(
                                f"{t('draft')} v{sel_draft['version']} "
                                f"{t('published_for')} **{sel_draft['product']}**."
                            )
                            refresh = orchestration.execute_action(
                                action_type="query_notices",
                                payload={},
                                actor=actor,
                            )
                            if refresh.get("status") == "success":
                                st.session_state.notices = refresh["records"]
                            st.rerun()
                        else:
                            st.error(
                                f"{t('publish_failed')}: "
                                f"{result.get('message', t('unknown_error'))}"
                            )

    # =========================================================================
    # TAB 2 — Notice Preview (localised)
    # =========================================================================
    with tab_objects[2]:
        st.subheader(t("notice_preview"))
        st.caption(t("preview_language_caption"))

        published_notices = [n for n in all_notices if n.get("status") == "published"]

        if not published_notices:
            st.info(t("no_published_notices_preview"))
        else:
            product_opts = sorted({n["product"] for n in published_notices})
            sel_product  = st.selectbox(t("select_product"), product_opts, key="preview_product")

            sel_notice = next(
                (n for n in reversed(published_notices) if n["product"] == sel_product),
                None,
            )

            if sel_notice:
                lang_opt = st.radio(
                    t("display_language"),
                    [t("english"), t("malayalam")],
                    horizontal=True,
                )
                display_lang = "ml" if lang_opt == t("malayalam") else "en"
                content      = (
                    sel_notice.get("content_ml") or sel_notice.get("content_en", "")
                    if display_lang == "ml"
                    else sel_notice.get("content_en", "")
                )

                st.markdown(
                    f"""
                    <div style="
                        background:#f8faff;
                        border-left:4px solid #0A3D91;
                        border-radius:8px;
                        padding:20px 24px;
                        margin-bottom:16px;
                    ">
                        <div style="font-weight:700;font-size:1.05rem;color:#0A3D91;margin-bottom:8px;">
                            {sel_notice['title']}
                            <span style="font-size:0.8rem;color:#888;margin-left:8px;">
                                v{sel_notice['version']} · {sel_notice.get('published_on', '—')}
                            </span>
                        </div>
                        <div style="font-size:0.93rem;color:#333;line-height:1.7;">
                            {content}
                        </div>
                        <div style="margin-top:12px;font-size:0.78rem;color:#666;">
                            {t('linked_clauses_label')}: {', '.join(sel_notice.get('linked_clauses', []))}
                            {'&nbsp;·&nbsp;<b style="color:#c62828;">' + t('reconsent_required') + '</b>'
                             if sel_notice.get('requires_reconsent') else ''}
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

                if sel_notice.get("previous_version_id"):
                    prev = next(
                        (n for n in all_notices
                         if n.get("notice_id") == sel_notice["previous_version_id"]),
                        None,
                    )
                    if prev:
                        with st.expander(t("view_superseded_version")):
                            st.caption(
                                f"v{prev['version']} — {prev.get('version_note', '—')} "
                                f"| {t('superseded_on')} {sel_notice.get('published_on', '—')}"
                            )
                            st.write(
                                prev.get("content_ml" if display_lang == "ml" else "content_en", "")
                            )