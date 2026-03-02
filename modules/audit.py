"""
modules/audit.py
----------------
Audit Log Viewer — read-only governance interface for the append-only,
hash-chained audit ledger.

Architecture (updated):
    UI  →  audit_ledger API (read-only)  →  display

Role-access model:
  DPO           Full view — all entries, integrity metadata, root hash
  Auditor       Full view — identical to DPO (read-only by nature)
  Board         Full view — read-only oversight
  Others        Access denied

Design contract:
  - STRICTLY READ-ONLY. No writes, no mutations, no test entries.
  - Audit entries originate ONLY from orchestration. The UI never calls audit_log().
  - Chain integrity is verified on every page load before any data is displayed.
  - If verify_chain() returns False → st.error() + st.stop(). No partial display.
  - Root hash is fetched from the ledger API and displayed as a read-only governance signal.
  - No "Developer Tools" tab, no "Write Test Entry" form, no delete / clear controls.
  - All user-visible strings go through t().
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pandas as pd
import streamlit as st

from auth import get_role_display as get_role
from engine.audit_ledger import get_logs, verify_chain, ledger_stats, get_root_hash
from utils.dpdp_clauses import get_clause
from utils.export_utils import export_data
from utils.explainability import explain_dynamic
from utils.i18n import t
from utils.ui_helpers import mask_identifier, more_info


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_ALLOWED_ROLES: frozenset[str] = frozenset({
    "dpo", "DPO", "auditor", "Auditor", "board", "Board", "SystemAdmin",
})

_DATE_CUTOFFS: dict[str, timedelta] = {
    "last_24h":    timedelta(hours=24),
    "last_7_days": timedelta(days=7),
    "last_30_days":timedelta(days=30),
}


# ---------------------------------------------------------------------------
# Read-only ledger helpers
# ---------------------------------------------------------------------------

def _truncate_hash(h: str, chars: int = 16) -> str:
    return h[:chars] + "…" if h and len(h) > chars else (h or "—")


def _parse_ts(ts_str: str) -> datetime:
    try:
        return datetime.fromisoformat(ts_str)
    except Exception:
        return datetime.min


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
    role = st.session_state.get("role", "")
    if role in ("dpo", "auditor", "system_admin", "DPO", "Auditor", "SystemAdmin"):
        return raw_id
    return mask_identifier(raw_id, role=role)


# ===========================================================================
# Main entry point
# ===========================================================================

def show() -> None:

    # ── Role gate — enforced before any ledger data is fetched ────────────────
    role = get_role()
    if role not in _ALLOWED_ROLES:
        st.warning(t("audit_access_restricted"))
        st.info(t("audit_contact_dpo"))
        return

    # ── Header ────────────────────────────────────────────────────────────────
    st.header(t("audit"))
    st.caption(t("audit_caption"))
    more_info(t("audit_more_info"))

    # =========================================================================
    # STEP 1 — Chain integrity verification (must pass before any data shown)
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
        # Chain broken → block all further UI interaction
        st.stop()

    # =========================================================================
    # STEP 2 — KPI strip (only reachable if chain is valid)
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
    # STEP 3 — Root hash display (governance transparency)
    # =========================================================================
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

    # =========================================================================
    # STEP 4 — Audit records (read-only, filterable)
    # =========================================================================
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
        # Translated display options mapped back to internal keys for cutoff lookup
        _date_opts: list[tuple[str, str | None]] = [
            (t("all_time"),    None),
            (t("last_24h"),    "last_24h"),
            (t("last_7_days"), "last_7_days"),
            (t("last_30_days"),"last_30_days"),
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
        cutoff  = datetime.utcnow() - _DATE_CUTOFFS[_date_key]
        entries = [e for e in entries if _parse_ts(e["timestamp"]) >= cutoff]

    entries = entries[:int(limit)]

    st.subheader(f"{t('audit_records')} ({len(entries)} {t('shown')})")

    if entries:
        rows = []
        for e in entries:
            meta      = _block_metadata(e)
            user      = _block_user(e)
            action    = _block_action(e)
            display_id = e.get("block_id") or str(e.get("index", "—"))
            rows.append({
                t("entry_id"):      display_id,
                t("timestamp"):     e.get("timestamp", "—")[:19].replace("T", " "),
                t("actor"):         _mask_id(user),
                t("action"):        action,
                t("customer_id"):   _mask_id(meta.get("customer_id", "—")) if meta.get("customer_id") else "—",
                t("previous_hash"): _truncate_hash(e.get("previous_hash", "")),
                t("current_hash"):  _truncate_hash(e.get("hash", "")),
            })

        df = pd.DataFrame(rows)
        st.dataframe(df, use_container_width=True, hide_index=True, height=500)
        export_data(df, "audit_ledger")

        # Full hash inspector (read-only expander)
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

        st.download_button(
            label=t("download_logs_csv"),
            data=df.to_csv(index=False).encode("utf-8"),
            file_name=f"audit_log_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
            use_container_width=True,
        )

    else:
        st.info(t("no_audit_entries"))

    # =========================================================================
    # STEP 5 — Integrity metadata footer
    # =========================================================================
    st.divider()
    st.info(t("audit_hash_info"), icon="🔒")

    with st.expander(t("ledger_integrity_metadata")):
        st.markdown(f"**{t('total_entries')}:** {stats['total_entries']}")
        st.markdown(f"**{t('unique_actors')}:** {stats['unique_actors']}")
        st.markdown(f"**{t('chain_status')}:** ✅ {t('verified')}")
        st.markdown(f"**{t('latest_entry')}:** `{(stats.get('latest_entry') or '—')[:19].replace('T', ' ')}`")
        st.markdown(f"**{t('root_hash')}:**")
        st.code(root_hash, language="text")
        st.caption(t("integrity_metadata_note"))