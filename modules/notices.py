"""
modules/notices.py
------------------
Privacy Notice Management — Step 12 Regulatory-Grade Refactor.

Role-access model:
  DPO              Full access — create, publish, version, outdated-consent scan
  Officer          Draft creation only — cannot publish
  Auditor          Read-only — notice history and version diff
  Others           Access restricted

Step 12 changes:
  12A  Role gate: only DPO / Officer may create; only DPO may publish
  12B  Standardised notice object with notice_id, content_en, content_ml,
       linked_clauses, version int, previous_version_id, requires_reconsent
  12C  Automatic versioning — old notice superseded, new version created
  12D  Clause linkage validated against dpdp_clauses registry
  12E  Deterministic Malayalam translation + normalisation on save
  12F  Outdated-consent detection — consents with older notice_version flagged
  12G  Notification trigger for each affected user
  12H  Re-consent flag set when linked_clauses change between versions
  12I  Localised display — content_ml served when session language == "ml"
  12J  No in-place edit / delete — notices are immutable once saved
  12K  Audit log on every create / publish / version action

DPDP Act 2023 — Section 5 (Notice), Section 6 (Consent), Section 11-13 (Rights)
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import pandas as pd
import streamlit as st

from auth import get_role_display as get_role
from engine.audit_ledger import append_audit_log
from utils.i18n import t, translate_en_to_ml, normalize_malayalam
from utils.export_utils import export_data
from utils.ui_helpers import more_info
from utils.explainability import explain_dynamic
from utils.dpdp_clauses import get_clause

# Optional notification trigger — graceful fallback if not yet wired
try:
    from engine.orchestration import trigger_notification
except ImportError:
    def trigger_notification(channel: str, recipient: str, message: str) -> None:
        pass   # no-op until orchestration module is live

# Optional customer phone lookup
try:
    from registry.customer_registry import get_customer_phone
except ImportError:
    def get_customer_phone(user_id: str) -> str:
        return ""

# Optional consent registry
try:
    from registry.consent_registry import get_all_consents
except ImportError:
    def get_all_consents() -> list[dict]: return []


# ---------------------------------------------------------------------------
# Storage path — notices persist across Streamlit reruns
# ---------------------------------------------------------------------------

_NOTICES_PATH = Path(os.getenv("NOTICES_PATH", "storage/notices.json"))


def _ensure_store() -> None:
    _NOTICES_PATH.parent.mkdir(parents=True, exist_ok=True)
    if not _NOTICES_PATH.exists():
        _NOTICES_PATH.write_text(json.dumps(_SEED_NOTICES, indent=2), encoding="utf-8")


def _load_notices() -> list[dict]:
    _ensure_store()
    raw = _NOTICES_PATH.read_text(encoding="utf-8").strip()
    data = json.loads(raw) if raw else []
    return data if isinstance(data, list) else []


def _save_notices(notices: list[dict]) -> None:
    _NOTICES_PATH.write_text(
        json.dumps(notices, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# Step 12B — Standardised notice structure builder
# ---------------------------------------------------------------------------

def _generate_notice_id() -> str:
    return f"NTC-{uuid.uuid4().hex[:10].upper()}"


def _build_notice(
    title: str,
    content_en: str,
    product: str,
    linked_clauses: list[str],
    created_by: str,
    status: str = "draft",
    version: int = 1,
    previous_version_id: Optional[str] = None,
    version_note: str = "",
    requires_reconsent: bool = False,
    affected_users: Optional[list[str]] = None,
) -> dict[str, Any]:
    """
    Build a standardised notice object. (Step 12B)
    Malayalam content is derived deterministically from English. (Step 12E)
    """
    content_ml = normalize_malayalam(translate_en_to_ml(content_en))  # Step 12E

    return {
        "notice_id":           _generate_notice_id(),
        "title":               title,
        "product":             product,
        "content_en":          content_en,
        "content_ml":          content_ml,
        "linked_clauses":      linked_clauses,
        "version":             version,
        "version_note":        version_note,
        "previous_version_id": previous_version_id,
        "created_by":          created_by,
        "created_at":          datetime.now(timezone.utc).isoformat(),
        "published_on":        None,
        "published_by":        None,
        "status":              status,           # "draft" | "published" | "superseded"
        "requires_reconsent":  requires_reconsent,
        "affected_users":      affected_users or [],
    }


# ---------------------------------------------------------------------------
# Step 12D — Clause linkage validation
# ---------------------------------------------------------------------------

def _validate_clauses(clause_list: list[str]) -> list[str]:
    """
    Validate that every clause code resolves in the DPDP clause registry.
    Returns list of invalid codes (empty = all valid).
    """
    invalid = []
    for code in clause_list:
        if not get_clause(code):
            invalid.append(code)
    return invalid


# ---------------------------------------------------------------------------
# Step 12F — Outdated-consent detection
# ---------------------------------------------------------------------------

def _find_outdated_users(product: str, new_version: int) -> list[str]:
    """
    Return IDs of data principals whose consent references an older
    notice version for this product. (Step 12F)
    """
    consents = get_all_consents()
    outdated = []
    for c in consents:
        if (
            c.get("product") == product
            and int(c.get("notice_version", 0)) < new_version
        ):
            uid = c.get("data_principal_id") or c.get("customer_id")
            if uid and uid not in outdated:
                outdated.append(uid)
    return outdated


# ---------------------------------------------------------------------------
# Step 12G — Notify outdated-consent users
# ---------------------------------------------------------------------------

def _notify_affected_users(user_ids: list[str]) -> None:
    """
    Trigger SMS notification to each user whose consent is now outdated.
    Falls back silently if orchestration is not yet wired. (Step 12G)
    """
    for uid in user_ids:
        phone = get_customer_phone(uid)
        if phone:
            trigger_notification(
                channel="sms",
                recipient=phone,
                message=(
                    "Your privacy notice has been updated. "
                    "Please review and reconfirm your consent at your earliest convenience."
                ),
            )


# ---------------------------------------------------------------------------
# Step 12C — Versioning engine
# ---------------------------------------------------------------------------

def _create_new_version(
    old_notice: dict,
    content_en: str,
    linked_clauses: list[str],
    version_note: str,
    created_by: str,
) -> tuple[dict, dict]:
    """
    Supersede old_notice and return (superseded_old, new_version_notice).
    Sets requires_reconsent if linked_clauses changed. (Step 12H)
    Detects affected users and triggers notifications. (Step 12F / 12G)
    """
    superseded = dict(old_notice)
    superseded["status"] = "superseded"

    new_version     = old_notice["version"] + 1
    clauses_changed = set(old_notice.get("linked_clauses", [])) != set(linked_clauses)

    affected_users = _find_outdated_users(old_notice["product"], new_version)
    _notify_affected_users(affected_users)

    new_notice = _build_notice(
        title=old_notice["title"],
        content_en=content_en,
        product=old_notice["product"],
        linked_clauses=linked_clauses,
        created_by=created_by,
        status="draft",
        version=new_version,
        previous_version_id=old_notice["notice_id"],
        version_note=version_note,
        requires_reconsent=clauses_changed,
        affected_users=affected_users,
    )

    return superseded, new_notice


# ---------------------------------------------------------------------------
# Seed notices in standardised format
# ---------------------------------------------------------------------------

def _make_seed() -> list[dict]:
    seeds = []

    n1 = _build_notice(
        title="Savings Account Privacy Notice",
        content_en=(
            "This notice explains how Kerala Bank processes your personal data "
            "for Savings Account services under DPDP Act 2023 Section 5. "
            "Data is collected for account management, KYC, and regulatory compliance. "
            "Retention period: 10 years. You may exercise your rights via our Rights Portal."
        ),
        product="Savings Account",
        linked_clauses=["consent_lifecycle", "rights_management"],
        created_by="dpo_admin",
        status="published",
        version=1,
        version_note="Initial publication.",
    )
    n1["published_on"] = "2026-01-10"
    n1["published_by"] = "dpo_admin"
    seeds.append(n1)

    n2 = _build_notice(
        title="Digital Lending Privacy Notice",
        content_en=(
            "Kerala Bank processes your personal and financial data to evaluate "
            "your creditworthiness and disburse loans under DPDP Act 2023. "
            "Third-party credit bureaus may receive your data. "
            "Retention: 7 years post-loan closure."
        ),
        product="Digital Lending",
        linked_clauses=["consent_lifecycle", "breach_reporting", "data_minimisation"],
        created_by="dpo_admin",
        status="published",
        version=1,
        version_note="Updated data sharing clause for CIBIL integration.",
    )
    n2["published_on"] = "2026-02-05"
    n2["published_by"] = "dpo_admin"
    seeds.append(n2)

    n3 = _build_notice(
        title="UPI Services Privacy Notice",
        content_en=(
            "Your transaction data processed under UPI services is governed by "
            "DPDP Act 2023 and NPCI guidelines. Data is used solely for payment "
            "processing and fraud prevention. Retention: 5 years."
        ),
        product="UPI Services",
        linked_clauses=["consent_lifecycle"],
        created_by="officer_01",
        status="draft",
        version=1,
        version_note="Pending DPO review.",
    )
    seeds.append(n3)

    return seeds


_SEED_NOTICES: list[dict] = _make_seed()


# ---------------------------------------------------------------------------
# Internal session-state bootstrap
# ---------------------------------------------------------------------------

def _init_notices() -> None:
    """Load from persistent store into session state on first run."""
    if "notices" not in st.session_state:
        st.session_state.notices = _load_notices()
        if not st.session_state.notices:
            st.session_state.notices = list(_SEED_NOTICES)
            _save_notices(st.session_state.notices)


# ---------------------------------------------------------------------------
# Audit log helper — Step 12K
# ---------------------------------------------------------------------------

def _audit(action: str, notice: dict, actor: str) -> None:
    append_audit_log(
        action=action,
        user=actor,
        metadata={
            "module":     "notice",
            "notice_id":  notice.get("notice_id"),
            "product":    notice.get("product"),
            "version":    notice.get("version"),
            "status":     notice.get("status"),
        },
    )


# ---------------------------------------------------------------------------
# Localised content resolver — Step 12I
# ---------------------------------------------------------------------------

def _resolve_content(notice: dict) -> str:
    lang = st.session_state.get("language", "en")
    if lang == "ml":
        return notice.get("content_ml") or notice.get("content_en", "")
    return notice.get("content_en", "")


# ---------------------------------------------------------------------------
# Score colour helper (unchanged from original)
# ---------------------------------------------------------------------------

def _status_colour(status: str) -> str:
    return {"published": "#1a9e5c", "draft": "#f0a500", "superseded": "#9e9e9e"}.get(
        status.lower(), "#9e9e9e"
    )


# ---------------------------------------------------------------------------
# Main show()
# ---------------------------------------------------------------------------

def show() -> None:
    _init_notices()

    # ── Step 12A — Role gate ──────────────────────────────────────────────────
    role = get_role()

    ALLOWED_ROLES = ("DPO", "Officer", "Auditor")
    if role not in ALLOWED_ROLES:
        st.warning(t("notices_access_restricted"))
        st.info(t("notices_contact_dpo"))
        return

    is_dpo     = role == "DPO"
    is_officer = role == "Officer"
    is_auditor = role == "Auditor"
    actor      = st.session_state.get("username", role.lower())

    # ── Header ────────────────────────────────────────────────────────────────
    st.header(t("notices"))
    st.caption(t("notices_caption"))

    more_info(t("notices_more_info"))

    # ── KPI Strip ─────────────────────────────────────────────────────────────
    all_notices = st.session_state.notices
    _total       = len(all_notices)
    _published   = sum(1 for n in all_notices if n.get("status") == "published")
    _draft       = sum(1 for n in all_notices if n.get("status") == "draft")
    _superseded  = sum(1 for n in all_notices if n.get("status") == "superseded")
    _products    = len({n["product"] for n in all_notices})

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

    if is_auditor:
        st.info(t("auditor_read_only"))
    elif is_officer:
        st.info(t("officer_draft_only"))

    # ── Tabs ──────────────────────────────────────────────────────────────────
    tabs = [t("notice_history"), t("notice_preview")]
    if not is_auditor:
        tabs = [t("create_version_notice")] + tabs
    tab_objects = st.tabs(tabs)

    tab_idx = 0

    # =========================================================================
    # TAB — Create / Version Notice (DPO + Officer only, Step 12A / 12J)
    # =========================================================================
    if not is_auditor:
        with tab_objects[tab_idx]:
            st.subheader(t("create_or_version_notice"))
            st.caption(t("create_notice_caption"))

            # ── Form inputs ───────────────────────────────────────────────────
            product = st.selectbox(
                t("product_journey"),
                [
                    "Savings Account", "Digital Lending", "UPI Services",
                    "Mobile Banking", "Credit Card", "Fixed Deposit", "Insurance Products",
                ],
            )

            # Detect existing published notice for this product to show version diff
            existing = next(
                (
                    n for n in reversed(all_notices)
                    if n["product"] == product and n["status"] == "published"
                ),
                None,
            )
            if existing:
                st.info(
                    f"{t('active_version_for')} **{product}**: "
                    f"v{existing['version']} — *{existing.get('version_note','—')}*"
                )

            notice_title = st.text_input(
                t("notice_title"),
                value=f"{product} Privacy Notice",
            )

            notice_text = st.text_area(
                t("notice_content_english"),
                value=(
                    existing.get("content_en", "")
                    if existing
                    else (
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

            # ── Step 12D — Clause linkage ──────────────────────────────────────
            all_clause_keys = [
                "consent_lifecycle", "rights_management", "breach_reporting",
                "data_minimisation", "audit_integrity", "sla_governance",
                "dpia", "security_safeguards",
            ]
            default_clauses = (
                existing.get("linked_clauses", ["consent_lifecycle"])
                if existing else ["consent_lifecycle"]
            )
            linked_clauses = st.multiselect(
                t("linked_dpdp_clauses"),
                options=all_clause_keys,
                default=[c for c in default_clauses if c in all_clause_keys],
                help=t("linked_clauses_help"),
            )

            version_note = st.text_input(
                t("version_note"),
                placeholder=t("version_note_placeholder"),
            )

            # Preview Malayalam translation
            with st.expander(t("preview_malayalam"), expanded=False):
                if notice_text:
                    ml_preview = normalize_malayalam(translate_en_to_ml(notice_text))
                    st.text_area(t("malayalam_content"), value=ml_preview, height=150, disabled=True)
                else:
                    st.caption(t("enter_english_to_preview"))

            # ── Validation ────────────────────────────────────────────────────
            def _pre_validate() -> list[str]:
                errors = []
                if not notice_text.strip():
                    errors.append(t("notice_content_empty"))
                if not linked_clauses:
                    errors.append(t("notice_clause_required"))
                invalid_clauses = _validate_clauses(linked_clauses)
                if invalid_clauses:
                    errors.append(f"{t('invalid_clause_codes')}: {', '.join(invalid_clauses)}")
                return errors

            # ── Officer path: save draft only ─────────────────────────────────
            if is_officer:
                st.caption(t("officer_draft_caption"))
                if st.button(t("save_draft"), type="primary", use_container_width=True):
                    errs = _pre_validate()
                    if errs:
                        for e in errs:
                            st.error(e)
                    else:
                        new_n = _build_notice(
                            title=notice_title,
                            content_en=notice_text,
                            product=product,
                            linked_clauses=linked_clauses,
                            created_by=actor,
                            status="draft",
                            version=((existing["version"] + 1) if existing else 1),
                            previous_version_id=existing["notice_id"] if existing else None,
                            version_note=version_note,
                        )
                        st.session_state.notices.append(new_n)
                        _save_notices(st.session_state.notices)
                        _audit(
                            f"Notice Draft Saved | product={product} | v{new_n['version']}",
                            new_n, actor,
                        )
                        st.success(
                            f"{t('draft')} v{new_n['version']} {t('saved_for')} **{product}**. "
                            f"{t('pending_dpo_review')}"
                        )

            # ── DPO path: draft or publish ─────────────────────────────────────
            elif is_dpo:
                col1, col2 = st.columns(2)

                with col1:
                    if st.button(t("save_draft"), use_container_width=True):
                        errs = _pre_validate()
                        if errs:
                            for e in errs: st.error(e)
                        else:
                            new_n = _build_notice(
                                title=notice_title,
                                content_en=notice_text,
                                product=product,
                                linked_clauses=linked_clauses,
                                created_by=actor,
                                status="draft",
                                version=((existing["version"] + 1) if existing else 1),
                                previous_version_id=existing["notice_id"] if existing else None,
                                version_note=version_note,
                            )
                            st.session_state.notices.append(new_n)
                            _save_notices(st.session_state.notices)
                            _audit(
                                f"Notice Draft Saved | product={product} | v{new_n['version']}",
                                new_n, actor,
                            )
                            st.success(f"{t('draft')} v{new_n['version']} {t('saved_for')} **{product}**.")

                with col2:
                    if st.button(t("publish_notice"), type="primary", use_container_width=True):
                        errs = _pre_validate()
                        if errs:
                            for e in errs: st.error(e)
                        else:
                            notices = st.session_state.notices

                            # Step 12C — supersede existing published version
                            if existing:
                                superseded, new_n = _create_new_version(
                                    old_notice=existing,
                                    content_en=notice_text,
                                    linked_clauses=linked_clauses,
                                    version_note=version_note,
                                    created_by=actor,
                                )
                                # Replace old entry with superseded copy
                                for i, n in enumerate(notices):
                                    if n["notice_id"] == existing["notice_id"]:
                                        notices[i] = superseded
                                        break
                            else:
                                new_n = _build_notice(
                                    title=notice_title,
                                    content_en=notice_text,
                                    product=product,
                                    linked_clauses=linked_clauses,
                                    created_by=actor,
                                    status="draft",
                                    version=1,
                                    version_note=version_note,
                                )

                            # Publish
                            new_n["status"]       = "published"
                            new_n["published_on"] = datetime.now(timezone.utc).strftime("%Y-%m-%d")
                            new_n["published_by"] = actor

                            notices.append(new_n)
                            st.session_state.notices = notices
                            _save_notices(notices)

                            _audit(
                                f"Privacy Notice Published | product={product} | v{new_n['version']}",
                                new_n, actor,
                            )

                            reconsent_msg = ""
                            if new_n.get("requires_reconsent"):
                                reconsent_msg = f" **{t('reconsent_required')}**"
                            affected = new_n.get("affected_users", [])
                            affected_msg = (
                                f" {len(affected)} {t('users_notified_sms')}" if affected else ""
                            )

                            st.success(
                                f"{t('notice')} v{new_n['version']} {t('published_for')} **{product}**."
                                + reconsent_msg + affected_msg
                            )

                            clause_info = get_clause("consent_lifecycle") or {}
                            explain_dynamic(
                                title=t("notice_published"),
                                reason=t("notice_published_reason"),
                                old_clause=clause_info.get("old", ""),
                                new_clause=clause_info.get("new", ""),
                            )

                            st.rerun()

        tab_idx += 1

    # =========================================================================
    # TAB — Notice History
    # =========================================================================
    with tab_objects[tab_idx]:
        st.subheader(t("notice_version_history"))

        if is_auditor:
            st.info(t("auditor_history_view"))

        # Filters
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
        if f_product:    filtered = [n for n in filtered if n["product"] in f_product]
        if f_status:     filtered = [n for n in filtered if n.get("status") in f_status]
        if f_reconsent:  filtered = [n for n in filtered if n.get("requires_reconsent")]

        if filtered:
            rows = []
            for n in filtered:
                affected_count = len(n.get("affected_users", []))
                rows.append({
                    t("notice_id"):       n.get("notice_id", "—"),
                    t("product"):         n["product"],
                    t("version"):         f"v{n['version']}",
                    t("status"):          t(n.get("status", "draft")),
                    t("clauses_linked"):  ", ".join(n.get("linked_clauses", [])),
                    t("reconsent"):       t("yes") if n.get("requires_reconsent") else t("no"),
                    t("affected_users"):  affected_count if affected_count else "—",
                    t("version_note"):    n.get("version_note", "—"),
                    t("published_on"):    n.get("published_on") or "—",
                    t("by"):              n.get("published_by") or n.get("created_by", "—"),
                    t("created_at"):      n.get("created_at", "—")[:16],
                })

            df = pd.DataFrame(rows)
            st.dataframe(df, use_container_width=True, hide_index=True, height=420)
            st.caption(f"{len(filtered)} {t('notice_versions_shown')}")

            export_data(df, "privacy_notices_history")

            more_info(t("notice_history_more_info"))
        else:
            st.info(t("no_notices_match_filters"))

        # ── DPO: publish pending drafts from history tab ──────────────────────
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
                    notices = st.session_state.notices

                    # Supersede any currently published version for same product
                    for i, n in enumerate(notices):
                        if n["product"] == sel_draft["product"] and n["status"] == "published":
                            notices[i] = dict(n)
                            notices[i]["status"] = "superseded"

                    # Publish the draft
                    for i, n in enumerate(notices):
                        if n["notice_id"] == sel_draft["notice_id"]:
                            notices[i] = dict(n)
                            notices[i]["status"]       = "published"
                            notices[i]["published_on"] = datetime.now(timezone.utc).strftime("%Y-%m-%d")
                            notices[i]["published_by"] = actor

                            # Step 12F — detect affected users now
                            affected = _find_outdated_users(
                                notices[i]["product"], notices[i]["version"]
                            )
                            notices[i]["affected_users"] = affected
                            _notify_affected_users(affected)
                            break

                    st.session_state.notices = notices
                    _save_notices(notices)

                    _audit(
                        f"Draft Published | product={sel_draft['product']} | v{sel_draft['version']}",
                        sel_draft, actor,
                    )

                    clause_info = get_clause("consent_lifecycle") or {}
                    explain_dynamic(
                        title=t("notice_published"),
                        reason=t("notice_published_reason"),
                        old_clause=clause_info.get("old", ""),
                        new_clause=clause_info.get("new", ""),
                    )

                    st.success(
                        f"{t('draft')} v{sel_draft['version']} {t('published_for')} **{sel_draft['product']}**."
                    )
                    st.rerun()

    tab_idx += 1

    # =========================================================================
    # TAB — Notice Preview (localised display, Step 12I)
    # =========================================================================
    with tab_objects[tab_idx]:
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
                # Step 12I — language-aware content resolution
                display_lang = "ml" if lang_opt == t("malayalam") else "en"
                content = (
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
                                v{sel_notice['version']} · {sel_notice.get('published_on','—')}
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
                                f"v{prev['version']} — {prev.get('version_note','—')} "
                                f"| {t('superseded_on')} {sel_notice.get('published_on','—')}"
                            )
                            st.write(
                                prev.get("content_ml" if display_lang == "ml" else "content_en", "")
                            )