"""
modules/audit.py
----------------
Audit Log Viewer — read-only governance interface for the append-only,
hash-chained audit ledger.

Architecture:
    UI  →  audit_ledger API (read-only)  →  display

Role-access model (canonical codes only — no legacy display names):
  dpo               Full view — all entries, integrity metadata, root hash, export
  auditor           Full view — identical to DPO (read-only by nature), export
  internal_auditor  Full view — governance alias for auditor, export
  board_member      Executive summary only — KPI strip, no raw log table, no export

Roles explicitly DENIED (blocked before any ledger data is fetched):
  customer           Access denied
  customer_assisted  Access denied (defensive — not in VALID_ROLES)
  customer_support   Access denied
  soc_analyst        Routed to Breach module
  branch_officer / branch_privacy_coordinator /
  regional_officer / regional_compliance_officer /
  privacy_steward /
  privacy_operations Access denied — compliance and breach modules only

Design contract:
  - STRICTLY READ-ONLY. No writes, no mutations, no test entries.
  - Audit entries originate ONLY from orchestration. The UI never calls audit_log().
  - Chain integrity is verified on every page load before any data is displayed.
  - If verify_chain() returns False → st.error() + st.stop(). No partial display.
  - Root hash is fetched from the ledger API and displayed as a read-only governance signal.
  - No "Developer Tools" tab, no "Write Test Entry" form, no delete / clear controls.
  - All user-visible strings go through t().
  - Role sourced exclusively from get_current_user()["role"] (canonical code).
  - require_session() called first in show() before any ledger data is fetched.
  - Export gated to dpo, auditor, internal_auditor only (not board_member).
  - Board view: KPI summary only — no raw log table, no hash inspector, no export.

Change log:
  ✔ Removed `from auth import get_role_display as get_role` — returned legacy display
    names that silently broke the role gate. Replaced with `import auth as _auth` and
    get_current_user()["role"] for canonical codes, consistent with compliance.py /
    breach.py.
  ✔ _ALLOWED_ROLES rebuilt with canonical codes only:
      Added: "internal_auditor", "board_member"
      Removed: "DPO", "Auditor", "Board", "SystemAdmin" (legacy display names)
  ✔ _DENIED_ROLES set added — explicit deny block checked before general gate,
    consistent with compliance.py and breach.py.
  ✔ require_session() added as first statement in show() (auth Step 6 contract).
  ✔ Board view (Step 10): dedicated KPI-only block added — board_member returns
    after the KPI strip with no access to the log table, hash inspector, or export.
  ✔ Export now gated to _EXPORT_PERMITTED (dpo, auditor, internal_auditor).
    board_member is NOT in _EXPORT_PERMITTED — raw audit logs must not leave via board.
    Both export_data() and st.download_button() wrapped in _can_export().
  ✔ _mask_id() now checks canonical role codes only (removed "DPO", "Auditor",
    "SystemAdmin" legacy strings).
  ✔ Page header upgraded from bare st.header() to inline-styled container div,
    consistent with compliance.py and breach.py.
  ✔ t_safe() helper added for defensive i18n (keys may not exist yet for new strings).
  ✔ All role convenience flags defined from canonical codes.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pandas as pd
import streamlit as st

from engine.audit_ledger import get_logs, verify_chain, ledger_stats, get_root_hash
from utils.dpdp_clauses import get_clause
from utils.export_utils import export_data
from utils.explainability import explain_dynamic
from utils.i18n import t
from utils.ui_helpers import mask_identifier, more_info


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
# Constants — canonical role codes only (no legacy display names)
# ---------------------------------------------------------------------------

# Full access: all log entries, integrity metadata, root hash, export
_FULL_ACCESS_ROLES: frozenset[str] = frozenset({
    "dpo",
    "auditor",
    "internal_auditor",   # governance alias — same read-only scope as auditor
})

# Board: executive summary KPIs only — no raw log table, no export
_BOARD_ROLES: frozenset[str] = frozenset({"board_member"})

_ALLOWED_ROLES: frozenset[str] = _FULL_ACCESS_ROLES | _BOARD_ROLES

# Roles explicitly denied — checked before _ALLOWED_ROLES gate
_DENIED_ROLES: frozenset[str] = frozenset({
    "customer",
    "customer_assisted",            # not in VALID_ROLES; defensive catch
    "customer_support",
    "soc_analyst",                  # SOC uses Breach module
    "branch_officer",
    "branch_privacy_coordinator",
    "regional_officer",
    "regional_compliance_officer",
    "privacy_steward",
    "privacy_operations",
})

# Export permitted: DPO and Auditors only — board_member excluded
# Raw audit ledger must not be downloadable from the board summary view
_EXPORT_PERMITTED: frozenset[str] = frozenset({
    "dpo",
    "auditor",
    "internal_auditor",
})

_DATE_CUTOFFS: dict[str, timedelta] = {
    "last_24h":     timedelta(hours=24),
    "last_7_days":  timedelta(days=7),
    "last_30_days": timedelta(days=30),
}


# ---------------------------------------------------------------------------
# Read-only ledger helpers
# ---------------------------------------------------------------------------

def _truncate_hash(h: str, chars: int = 16) -> str:
    return h[:chars] + "…" if h and len(h) > chars else (h or "—")


def _parse_ts(ts: str) -> datetime:
    dt = datetime.fromisoformat(ts)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _block_user(block: dict) -> str:
    return block.get("data", {}).get("user") or block.get("user", "—")


def _block_action(block: dict) -> str:
    return block.get("data", {}).get("action") or block.get("action", "—")


def _block_metadata(block: dict) -> dict:
    return block.get("data", {}).get("metadata") or block.get("metadata") or {}


def _block_label(block: dict) -> str:
    idx = block.get("index", "?")
    ts  = (block.get("timestamp", "")[:19]).replace("T", " ")
    return f"#{idx} — {ts}"


def _mask_id(raw_id: str) -> str:
    """
    Unmask for roles with full identity visibility; mask for all others.
    Uses canonical role codes only — no legacy display names.
    """
    role = st.session_state.get("role", "")
    if role in _FULL_ACCESS_ROLES:
        return raw_id
    return mask_identifier(raw_id, role=role)


def _can_export() -> bool:
    """Return True only for roles permitted to download the audit ledger."""
    return st.session_state.get("role", "") in _EXPORT_PERMITTED


# ===========================================================================
# Main entry point
# ===========================================================================

def show() -> None:
    import auth as _auth

    # ── STEP 6: Session guard — halts rendering before any ledger data fetched ─
    if not _auth.require_session():
        return

    # ── Canonical user from session — single source of truth ──────────────────
    current_user = _auth.get_current_user()
    if not current_user:
        st.error(t("session_not_found"))
        st.info(t("audit_contact_dpo"))
        return

    role = current_user["role"]    # canonical code — always
    user = current_user["username"]

    # ── STEP 1 — Explicit deny: non-audit roles blocked before any data load ───
    if role in _DENIED_ROLES:
        st.warning(
            t_safe(
                "audit_access_denied",
                "The Audit Ledger module is not available for your role. "
                "Please use the Compliance or Breach module.",
            )
        )
        st.info(t("audit_contact_dpo"))
        return

    # ── General access gate — catch any other unlisted role ───────────────────
    if role not in _ALLOWED_ROLES:
        st.warning(t_safe("audit_access_restricted", "You do not have permission to access the Audit module."))
        st.info(t("audit_contact_dpo"))
        return

    # ── Role convenience flags — canonical codes only ─────────────────────────
    is_full_access = role in _FULL_ACCESS_ROLES   # dpo, auditor, internal_auditor
    is_board       = role in _BOARD_ROLES         # board_member
    is_auditor     = role in ("auditor", "internal_auditor")
    is_dpo         = role == "dpo"

    # ── STEP 2 — Page header — inline-styled container ────────────────────────
    st.markdown(
        '<div style="background:#f4f6fa;padding:18px 24px;border-radius:8px;'
        'border:1px solid #e5e9ef;margin-bottom:20px;">'
        f'<h2 style="margin:0;color:#0A3D91;">'
        f'{t_safe("audit_title", "Audit Evidence &amp; Ledger Review")}'
        f'</h2>'
        '</div>',
        unsafe_allow_html=True,
    )
    st.caption(t("audit_caption"))
    more_info(t("audit_more_info"))

    if is_auditor:
        st.info(t_safe("auditor_read_only", "📖 Audit View — Read-only access. No modifications permitted."))

    # =========================================================================
    # STEP 8 — Chain integrity verification (must pass before any data shown)
    # Applies to ALL roles including board — tamper detection is universal.
    # =========================================================================
    chain_valid, chain_message = verify_chain()
    clause = get_clause("security_safeguards") or {}

    st.subheader(t("ledger_integrity"))

    if chain_valid:
        st.success(t("audit_chain_valid"), icon="✅")
        explain_dynamic(
            title=t("ledger_integrity_verified"),
            reason=t("ledger_verified_reason"),
            old_clause=clause.get("old", ""),
            new_clause=clause.get("new", ""),
        )
    else:
        st.error(
            f"{t('audit_chain_broken')}  \n"
            f"{t('tamper_detail')}: `{chain_message}`",
            icon="⚠️",
        )
        explain_dynamic(
            title=t("ledger_integrity_breach"),
            reason=t("ledger_breach_reason"),
            old_clause=clause.get("old", ""),
            new_clause=clause.get("new", ""),
        )
        # Chain broken → block all further UI interaction for all roles
        st.stop()

    # =========================================================================
    # KPI strip — reachable only if chain is valid; shown to all allowed roles
    # =========================================================================
    stats = ledger_stats()

    k1, k2, k3, k4 = st.columns(4)
    with k1:
        st.markdown(f'''<div class="kpi-card">
            <h4>{t("total_log_entries")}</h4>
            <h2>{stats["total_entries"]}</h2>
            <p style="color:#6B7A90;">{t("all_records")}</p>
        </div>''', unsafe_allow_html=True)
    with k2:
        st.markdown(f'''<div class="kpi-card">
            <h4>{t("unique_actors")}</h4>
            <h2>{stats["unique_actors"]}</h2>
            <p style="color:#6B7A90;">{t("distinct_users")}</p>
        </div>''', unsafe_allow_html=True)
    with k3:
        latest = (stats.get("latest_entry") or "—")[:19].replace("T", " ")
        st.markdown(f'''<div class="kpi-card">
            <h4>{t("latest_entry")}</h4>
            <h2 style="font-size:1.1rem;">{latest}</h2>
            <p style="color:#6B7A90;">{t("most_recent_log")}</p>
        </div>''', unsafe_allow_html=True)
    with k4:
        st.markdown(f'''<div class="kpi-card">
            <h4>{t("chain_valid")}</h4>
            <h2 style="color:#1a9e5c;">{t("yes")}</h2>
            <p style="color:#1a9e5c;">{t("verified")}</p>
        </div>''', unsafe_allow_html=True)

    more_info(t("audit_kpi_more_info"))

    # =========================================================================
    # STEP 10 — Board summary view: KPI strip only, then return
    # Board members see aggregate indicators; no raw log table, no export.
    # =========================================================================
    if is_board:
        st.divider()
        st.subheader(t_safe("board_audit_summary", "Audit Summary"))
        st.caption(
            t_safe(
                "board_audit_caption",
                "Executive view — aggregate indicators only. "
                "Full ledger access is available to DPO and Auditor roles.",
            )
        )

        # Additional board-specific aggregate metrics
        b1, b2 = st.columns(2)
        with b1:
            st.metric(
                t_safe("total_audit_events", "Total Audit Events"),
                stats["total_entries"],
            )
        with b2:
            st.metric(
                t_safe("unique_actors_label", "Unique Actors"),
                stats["unique_actors"],
            )

        # Chain status summary — board should know if there's a tamper alert
        st.success(
            t_safe("ledger_integrity_board_ok", "✅ Ledger integrity verified — no tampering detected.")
        )
        st.caption(
            t_safe(
                "board_no_export_note",
                "🔒 Raw audit log export is restricted to DPO and Auditor roles.",
            )
        )
        return   # Board exit — everything below is full-access only

    # =========================================================================
    # Full-access view: DPO, Auditor, Internal Auditor
    # =========================================================================

    # ── Root hash display (governance transparency) ───────────────────────────
    st.divider()
    st.subheader(t("ledger_root_hash"))
    st.caption(t("root_hash_caption"))

    try:
        root_hash = get_root_hash()
    except Exception:
        root_hash = t("root_hash_unavailable")

    st.code(root_hash, language="text")
    st.caption(t("root_hash_note"))
    more_info(t("root_hash_more_info"))

    st.divider()

    # ── STEP 5 & 6 — Filters: actor, action, date range, row limit ────────────
    st.subheader(t("filter_logs"))

    fcol1, fcol2, fcol3, fcol4 = st.columns([2, 2, 2, 1])

    with fcol1:
        user_filter = st.text_input(
            t("filter_by_actor"),
            placeholder="e.g. officer_01",
        )
    with fcol2:
        action_filter = st.text_input(
            t("filter_by_action"),
            placeholder="e.g. Consent",
        )
    with fcol3:
        # Translated display options mapped to internal cutoff keys
        _date_opts: list[tuple[str, str | None]] = [
            (t("all_time"),     None),
            (t("last_24h"),     "last_24h"),
            (t("last_7_days"),  "last_7_days"),
            (t("last_30_days"), "last_30_days"),
        ]
        _date_labels    = [d[0] for d in _date_opts]
        _date_sel_label = st.selectbox(t("date_range"), _date_labels)
        _date_key       = next(k for lbl, k in _date_opts if lbl == _date_sel_label)

    with fcol4:
        limit = st.number_input(
            t("max_rows"), min_value=10, max_value=500, value=100, step=10
        )

    # Fetch via ledger API — never direct file reads
    entries = get_logs(
        limit=None,
        user_filter=user_filter.strip() or None,
        action_filter=action_filter.strip() or None,
    )

    # Date filter
    if _date_key and _date_key in _DATE_CUTOFFS:
        cutoff  = datetime.now(timezone.utc) - _DATE_CUTOFFS[_date_key]
        entries = [e for e in entries if _parse_ts(e["timestamp"]) >= cutoff]

    entries = entries[:int(limit)]

    st.subheader(f"{t('audit_records')} ({len(entries)} {t('shown')})")

    if entries:
        rows = []
        for e in entries:
            meta       = _block_metadata(e)
            actor      = _block_user(e)
            action     = _block_action(e)
            display_id = e.get("block_id") or str(e.get("index", "—"))
            rows.append({
                t("entry_id"):      display_id,
                t("timestamp"):     e.get("timestamp", "—")[:19].replace("T", " "),
                t("actor"):         _mask_id(actor),
                t("action"):        action,
                t("customer_id"):   _mask_id(meta.get("customer_id", "—")) if meta.get("customer_id") else "—",
                t("previous_hash"): _truncate_hash(e.get("previous_hash", "")),
                t("current_hash"):  _truncate_hash(e.get("hash", "")),
            })

        df = pd.DataFrame(rows)
        st.dataframe(df, use_container_width=True, hide_index=True, height=500)

        # ── STEP 9 — Export: DPO and Auditor roles only ───────────────────────
        # STEP 7: No delete/edit/clear buttons exist anywhere in this file.
        if _can_export():
            export_data(df, "audit_ledger")
            st.download_button(
                label=t("download_logs_csv"),
                data=df.to_csv(index=False).encode("utf-8"),
                file_name=f"audit_log_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv",
                use_container_width=True,
            )
        else:
            st.caption(
                "🔒 Export available to authorised roles only (DPO, Auditor, Internal Auditor)."
            )

        # Full hash inspector (read-only expander — full-access roles only)
        with st.expander(t("inspect_full_hashes")):
            block_labels = [_block_label(e) for e in entries]
            sel_label    = st.selectbox(t("select_entry"), block_labels)
            sel_idx      = block_labels.index(sel_label)
            sel_entry    = entries[sel_idx]

            st.markdown(f"**{t('action')}:** {_block_action(sel_entry)}")
            st.markdown(f"**{t('actor')}:** `{_mask_id(_block_user(sel_entry))}`")
            st.markdown(f"**{t('timestamp')}:** `{sel_entry.get('timestamp', '—')}`")
            st.code(
                f"{t('previous_hash')}:\n{sel_entry.get('previous_hash', '—')}",
                language="text",
            )
            st.code(
                f"{t('current_hash')}:\n{sel_entry.get('hash', '—')}",
                language="text",
            )
            meta = _block_metadata(sel_entry)
            if meta:
                st.json(meta)

    else:
        st.info(t("no_audit_entries"))

    # =========================================================================
    # Integrity metadata footer
    # =========================================================================
    st.divider()
    st.info(t("audit_hash_info"), icon="🔒")

    with st.expander(t("ledger_integrity_metadata")):
        st.markdown(f"**{t('total_entries')}:** {stats['total_entries']}")
        st.markdown(f"**{t('unique_actors')}:** {stats['unique_actors']}")
        st.markdown(f"**{t('chain_status')}:** ✅ {t('verified')}")
        st.markdown(
            f"**{t('latest_entry')}:** "
            f"`{(stats.get('latest_entry') or '—')[:19].replace('T', ' ')}`"
        )
        st.markdown(f"**{t('root_hash')}:**")
        st.code(root_hash, language="text")
        st.caption(t("integrity_metadata_note"))